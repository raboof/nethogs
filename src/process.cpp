/*
 * process.cpp
 *
 * Copyright (c) 2004,2005,2008,2011 Arnout Engelen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 *
 */

#include <iostream>
#include <ncurses.h>
#include <set>
#include <string>
#include <strings.h>
#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <asm/types.h>
#endif
#include <map>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "conninode.h"
#include "inode2prog.h"
#include "nethogs.h"
#include "process.h"

extern timeval curtime;
extern bool catchall;
/*
 * connection-inode table. takes information from /proc/net/tcp.
 * key contains source ip, source port, destination ip, destination
 * port in format: '1.2.3.4:5-1.2.3.4:5'
 */
extern std::map<std::string, unsigned long> conninode_tcp;
extern std::map<std::string, unsigned long> conninode_udp;

/* this file includes:
 * - calls to inodeproc to get the pid that belongs to that inode
 */

/*
 * Initialise the global process-list with some special processes:
 * * unknown TCP traffic
 * * UDP traffic
 * * unknown IP traffic
 * We must take care these never get removed from the list.
 */
Process *unknowntcp;
Process *unknownudp;
Process *unknownip;
ProcList *processes;

std::set<pid_t> pidsToWatch;

#define KB (1UL << 10)
#define MB (1UL << 20)
#define GB (1UL << 30)

float tomb(u_int64_t bytes) { return ((double)bytes) / MB; }
float tokb(u_int64_t bytes) { return ((double)bytes) / KB; }

float tokbps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / KB; }
float tombps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / MB; }
float togbps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / GB; }

void process_init() {
  unknowntcp = new Process(0, "", "unknown TCP");
  processes = new ProcList(unknowntcp, NULL);

  if (catchall) {
    unknownudp = new Process(0, "", "unknown UDP");
    processes = new ProcList(unknownudp, processes);
    // unknownip = new Process (0, "", "unknown IP");
    // processes = new ProcList (unknownip, processes);
  }
}

int Process::getLastPacket() {
  int lastpacket = 0;
  for (auto it = connections.begin(); it != connections.end(); ++it) {
    assert(*it != NULL);
    if ((*it)->getLastPacket() > lastpacket)
      lastpacket = (*it)->getLastPacket();
  }
  return lastpacket;
}

/** get total values for this process for only active connections */
static void sum_active_connections(Process *process_ptr, u_int64_t &sum_sent,
                                   u_int64_t &sum_recv) {
  /* walk though all process_ptr process's connections, and sum
   * them up */
  for (auto it = process_ptr->connections.begin();
       it != process_ptr->connections.end();) {
    if ((*it)->getLastPacket() <= curtime.tv_sec - CONNTIMEOUT) {
      /* capture sent and received totals before deleting */
      process_ptr->sent_by_closed_bytes += (*it)->sumSent;
      process_ptr->rcvd_by_closed_bytes += (*it)->sumRecv;
      /* stalled connection, remove. */
      delete (*it);
      it = process_ptr->connections.erase(it);
    } else {
      u_int64_t sent = 0, recv = 0;
      (*it)->sumanddel(curtime, &recv, &sent);
      sum_sent += sent;
      sum_recv += recv;
      ++it;
    }
  }
}

/** Get the kb/s values for this process */
void Process::getkbps(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;

  sum_active_connections(this, sum_sent, sum_recv);
  *recvd = tokbps(sum_recv);
  *sent = tokbps(sum_sent);
}

/** Get the mb/s values for this process */
void Process::getmbps(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;

  sum_active_connections(this, sum_sent, sum_recv);
  *recvd = tombps(sum_recv);
  *sent = tombps(sum_sent);
}

/** Get the gb/s values for this process */
void Process::getgbps(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;

  sum_active_connections(this, sum_sent, sum_recv);
  *recvd = togbps(sum_recv);
  *sent = togbps(sum_sent);
}

/** get total values for this process */
void Process::gettotal(u_int64_t *recvd, u_int64_t *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  for (auto it = this->connections.begin(); it != this->connections.end();
       ++it) {
    Connection *conn = (*it);
    sum_sent += conn->sumSent;
    sum_recv += conn->sumRecv;
  }
  // std::cout << "Sum sent: " << sum_sent << std::endl;
  // std::cout << "Sum recv: " << sum_recv << std::endl;
  *recvd = sum_recv + this->rcvd_by_closed_bytes;
  *sent = sum_sent + this->sent_by_closed_bytes;
}

void Process::gettotalmb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tomb(sum_recv);
  *sent = tomb(sum_sent);
}

/** get total values for this process */
void Process::gettotalkb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tokb(sum_recv);
  *sent = tokb(sum_sent);
}

void Process::gettotalb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  // std::cout << "Total sent: " << sum_sent << std::endl;
  *sent = sum_sent;
  *recvd = sum_recv;
}

/** get only bytes since last request */
void Process::getlast(u_int64_t *recvd, u_int64_t *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  
  *sent = sum_sent - this->sent_last_reported;
  *recvd = sum_recv - this->rcvd_last_reported;

  this->sent_last_reported = *sent;
  this->rcvd_last_reported = *recvd;
}



Process *findProcess(struct prg_node *node) {
  ProcList *current = processes;
  while (current != NULL) {
    Process *currentproc = current->getVal();
    assert(currentproc != NULL);

    if (node->pid == currentproc->pid)
      return current->getVal();
    current = current->next;
  }
  return NULL;
}

/* finds process based on inode, if any */
/* should be done quickly after arrival of the packet,
 * otherwise findPID will be outdated */
Process *findProcess(unsigned long inode) {
  struct prg_node *node = findPID(inode);

  if (node == NULL)
    return NULL;

  return findProcess(node);
}

int ProcList::size() {
  int i = 1;

  if (next != NULL)
    i += next->size();

  return i;
}

void check_all_procs() {
  ProcList *curproc = processes;
  while (curproc != NULL) {
    curproc->getVal()->check();
    curproc = curproc->getNext();
  }
}

/*
 * returns the process from proclist with matching pid
 * if the inode is not associated with any PID, return NULL
 * if the process is not yet in the proclist, add it
 */
Process *getProcess(unsigned long inode, const char *devicename) {
  struct prg_node *node = findPID(inode);

  if (node == NULL) {
    if (DEBUG || bughuntmode)
      std::cout << "No PID information for inode " << inode << std::endl;
    return NULL;
  }

  Process *proc = findProcess(node);

  if (proc != NULL)
    return proc;

  if (!(pidsToWatch.empty()) &&
      pidsToWatch.find(node->pid) == pidsToWatch.end()) {
    return NULL;
  }

  // extract program name and command line from data read from cmdline file
  const char *prgname = node->cmdline.c_str();
  const char *cmdline = prgname + strlen(prgname) + 1;

  Process *newproc = new Process(inode, devicename, prgname, cmdline);
  newproc->pid = node->pid;

  char procdir[100];
  sprintf(procdir, "/proc/%d", node->pid);
  struct stat stats;
  int retval = stat(procdir, &stats);

  /* 0 seems a proper default.
   * used in case the PID disappeared while nethogs was running
   * TODO we can store node->uid this while info on the inodes,
   * right? */
  /*
  if (!ROBUST && (retval != 0))
  {
          std::cerr << "Couldn't stat " << procdir << std::endl;
          assert (false);
  }
  */

  if (retval != 0)
    newproc->setUid(0);
  else
    newproc->setUid(stats.st_uid);

  /*if (getpwuid(stats.st_uid) == NULL) {
          std::stderr << "uid for inode
          if (!ROBUST)
                  assert(false);
  }*/
  processes = new ProcList(newproc, processes);
  return newproc;
}

/*
 * Used when a new connection is encountered. Finds corresponding
 * process and adds the connection. If the connection  doesn't belong
 * to any known process, the process list is updated and a new process
 * is made. If no process can be found even then, it's added to the
 * 'unknown' process.
 */
Process *getProcess(Connection *connection, const char *devicename,
                    short int packettype) {
  std::map<std::string, unsigned long> &conninode =
      (packettype == IPPROTO_TCP) ? conninode_tcp : conninode_udp;
  unsigned long inode = conninode[connection->refpacket->gethashstring()];

  if (inode == 0) {
    // no? refresh and check conn/inode table
    if (bughuntmode) {
      std::cout << "?  new connection not in connection-to-inode table before "
                   "refresh, hash "
                << connection->refpacket->gethashstring() << std::endl;
    }
// refresh the inode->pid table first. Presumably processing the renewed
// connection->inode table
// is slow, making this worthwhile.
// We take the fact for granted that we might already know the inode->pid
// (unlikely anyway if we
// haven't seen the connection->inode yet though).
#ifndef __APPLE__
    reread_mapping();
#endif
    refreshconninode();
    inode = conninode[connection->refpacket->gethashstring()];
    if (bughuntmode) {
      if (inode == 0) {
        std::cout << ":( inode for connection not found after refresh.\n";
      } else {
        std::cout << ":) inode for connection found after refresh.\n";
      }
    }
#if REVERSEHACK
    if (inode == 0) {
      /* HACK: the following is a hack for cases where the
       * 'local' addresses aren't properly recognised, as is
       * currently the case for IPv6 */

      /* we reverse the direction of the stream if
       * successful. */
      Packet *reversepacket = connection->refpacket->newInverted();
      inode = conninode[reversepacket->gethashstring()];

      if (inode == 0) {
        delete reversepacket;
        if (bughuntmode || DEBUG)
          std::cout << "LOC: " << connection->refpacket->gethashstring()
                    << " STILL not in connection-to-inode table - adding to "
                       "the unknown process\n";
        unknowntcp->connections =
            new ConnList(connection, unknowntcp->connections);
        return unknowntcp;
      }

      delete connection->refpacket;
      connection->refpacket = reversepacket;
    }
#endif
  } else if (bughuntmode) {
    std::cout
        << ";) new connection in connection-to-inode table before refresh.\n";
  }

  if (bughuntmode) {
    std::cout << "   inode # " << inode << std::endl;
  }

  Process *proc = NULL;
  if (inode != 0) {
    proc = getProcess(inode, devicename);
  } else {
    if (packettype == IPPROTO_TCP) {
      proc = unknowntcp;
    } else {
      proc = unknownudp;
    }
  }

  if (!(pidsToWatch.empty()) && proc == NULL) {
    proc = (packettype == IPPROTO_TCP) ? unknowntcp : unknownudp;
  }

  if (proc == NULL) {
    proc = new Process(inode, "", connection->refpacket->gethashstring());
    processes = new ProcList(proc, processes);
  }

  proc->connections.insert(connection);
  return proc;
}

void procclean() {
  // delete conninode;
  prg_cache_clear();
}

void remove_timed_out_processes() {
  ProcList *previousproc = NULL;

  for (ProcList *curproc = processes; curproc != NULL;
       curproc = curproc->next) {
    if ((curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <=
         curtime.tv_sec) &&
        (curproc->getVal() != unknowntcp) &&
        (curproc->getVal() != unknownudp) && (curproc->getVal() != unknownip)) {
      if (DEBUG)
        std::cout << "PROC: Deleting process\n";
      ProcList *todelete = curproc;
      Process *p_todelete = curproc->getVal();
      if (previousproc) {
        previousproc->next = curproc->next;
        curproc = curproc->next;
      } else {
        processes = curproc->getNext();
        curproc = processes;
      }
      delete todelete;
      delete p_todelete;
    }
    previousproc = curproc;
  }
}

void garbage_collect_processes() { garbage_collect_inodeproc(); }
