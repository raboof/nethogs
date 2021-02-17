/*
 * process.h
 *
 * Copyright (c) 2004-2006,2008,2011 Arnout Engelen
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

#ifndef __PROCESS_H
#define __PROCESS_H

#include "connection.h"
#include "nethogs.h"
#include <cassert>

extern bool tracemode;
extern bool bughuntmode;

void check_all_procs();

class ConnList {
public:
  ConnList(Connection *m_val, ConnList *m_next) {
    assert(m_val != NULL);
    val = m_val;
    next = m_next;
  }
  ~ConnList() {
    /* does not delete its value, to allow a connection to
     * remove itself from the global connlist in its destructor */
  }
  Connection *getVal() { return val; }
  void setNext(ConnList *m_next) { next = m_next; }
  ConnList *getNext() { return next; }

private:
  Connection *val;
  ConnList *next;
};

class Process {
public:
  /* the process makes a copy of the name. the device name needs to be stable.
   */
  Process(const unsigned long m_inode, const char *m_devicename,
          const char *m_name = NULL, const char *m_cmdline = NULL)
      : inode(m_inode) {
    // std::cout << "ARN: Process created with dev " << m_devicename <<
    // std::endl;
    if (DEBUG)
      std::cout << "PROC: Process created at " << this << std::endl;

    if (m_name == NULL)
      name = NULL;
    else
      name = strdup(m_name);

    if (m_cmdline == NULL)
      cmdline = NULL;
    else
      cmdline = strdup(m_cmdline);

    devicename = m_devicename;
    connections = NULL;
    pid = 0;
    uid = 0;
    sent_by_closed_bytes = 0;
    rcvd_by_closed_bytes = 0;
  }
  void check() { assert(pid >= 0); }

  ~Process() {
    free(name);
    free(cmdline);
    if (DEBUG)
      std::cout << "PROC: Process deleted at " << this << std::endl;
  }
  int getLastPacket();

  void gettotal(u_int64_t *recvd, u_int64_t *sent);
  void getkbps(float *recvd, float *sent);
  void getmbps(float *recvd, float *sent);
  void getgbps(float *recvd, float *sent);
  void gettotalmb(float *recvd, float *sent);
  void gettotalkb(float *recvd, float *sent);
  void gettotalb(float *recvd, float *sent);

  char *name;
  char *cmdline;
  const char *devicename;
  int pid;
  u_int64_t sent_by_closed_bytes;
  u_int64_t rcvd_by_closed_bytes;

  ConnList *connections;
  uid_t getUid() { return uid; }

  void setUid(uid_t m_uid) { uid = m_uid; }

  unsigned long getInode() { return inode; }

private:
  const unsigned long inode;
  uid_t uid;
};

class ProcList {
public:
  ProcList(Process *m_val, ProcList *m_next) {
    assert(m_val != NULL);
    val = m_val;
    next = m_next;
  }
  int size();
  Process *getVal() { return val; }
  ProcList *getNext() { return next; }
  ProcList *next;

private:
  Process *val;
};

Process *getProcess(Connection *connection, const char *devicename = NULL,
                    short int packettype = IPPROTO_TCP);

void process_init();

void refreshconninode();

void procclean();

void remove_timed_out_processes();

void garbage_collect_processes();

#endif
