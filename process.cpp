#include <iostream>
#include <strings.h>
#include <string>
#include <ncurses.h>
#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <map>

#include "process.h"
#include "hashtbl.h"
#include "nethogs.h"
#include "inodeproc.cpp"

extern timeval curtime;
extern std::string * caption;
extern local_addr * local_addrs;

class ProcList
{
public:
	ProcList (Process * m_val, ProcList * m_next)
	{
		if (DEBUG)
			assert (m_val != NULL);
		val = m_val; next = m_next;
	}
	Process * getVal () { return val; }
	ProcList * getNext () { return next; }
	ProcList * next;
private:
	Process * val;
};

/* 
 * connection-inode table. takes information from /proc/net/tcp.
 * key contains source ip, source port, destination ip, destination 
 * port in format: '1.2.3.4:5-1.2.3.4:5'
 */
//HashTable * conninode = new HashTable (256);
std::map <std::string, unsigned long *> conninode;

Process * unknownproc = new Process (0, "", "unknown");
ProcList * processes = new ProcList (unknownproc, NULL);

int Process::getLastPacket()
{
	int lastpacket=0;
	ConnList * curconn=connections;
	while (curconn != NULL)
	{
		if (DEBUG)
		{
			assert (curconn != NULL);
			assert (curconn->getVal() != NULL);
		}
		if (curconn->getVal()->getLastPacket() > lastpacket)
			lastpacket = curconn->getVal()->getLastPacket();
		curconn = curconn->getNext();
	}
	return lastpacket;
}

/*
 * parses a /proc/net/tcp-line of the form:
 *     sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
 *     10: 020310AC:1770 9DD8A9C3:A525 01 00000000:00000000 00:00000000 00000000     0        0 2119 1 c0f4f0c0 206 40 10 3 -1                            
 *     11: 020310AC:0404 936B2ECF:0747 01 00000000:00000000 00:00000000 00000000  1000        0 2109 1 c0f4fc00 368 40 20 2 -1                            
 *
 * and of the form:
 *      2: 0000000000000000FFFF0000020310AC:0016 0000000000000000FFFF00009DD8A9C3:A526 01 00000000:00000000 02:000A7214 00000000     0        0 2525 2 c732eca0 201 40 1 2 -1
 *
 */
void addtoconninode (char * buffer)
{
	short int sa_family;
    	struct in6_addr result_addr_local;
    	struct in6_addr result_addr_remote;

	char rem_addr[128], local_addr[128];
	int local_port, rem_port;
    	struct in6_addr in6_local;
    	struct in6_addr in6_remote;

	// the following leaks some memory.
	unsigned long * inode = (unsigned long *) malloc (sizeof(unsigned long));

	int matches = sscanf(buffer, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
		local_addr, &local_port, rem_addr, &rem_port, inode);

	if (matches != 5) {
		fprintf(stderr,"Unexpected buffer: '%s'\n",buffer);
		exit(0);
	}
	
	if (*inode == 0) {
		/* connection is in TIME_WAIT state. We rely on 
		 * the old data still in the table. */
		return;
	}

	if (strlen(local_addr) > 8)
	{
		/* this is an IPv6-style row */

		/* Demangle what the kernel gives us */
		sscanf(local_addr, "%08X%08X%08X%08X", 
			&in6_local.s6_addr32[0], &in6_local.s6_addr32[1],
			&in6_local.s6_addr32[2], &in6_local.s6_addr32[3]);
		sscanf(rem_addr, "%08X%08X%08X%08X",
			&in6_remote.s6_addr32[0], &in6_remote.s6_addr32[1],
		       	&in6_remote.s6_addr32[2], &in6_remote.s6_addr32[3]);

		if ((in6_local.s6_addr32[0] == 0x0) && (in6_local.s6_addr32[1] == 0x0)
		    && (in6_local.s6_addr32[2] == 0xFFFF0000))
		{
			/* IPv4-compatible address */
			result_addr_local  = *((struct in6_addr*) &(in6_local.s6_addr32[3]));
			result_addr_remote = *((struct in6_addr*) &(in6_remote.s6_addr32[3]));
			sa_family = AF_INET;
		} else {
			/* real IPv6 address */
			//inet_ntop(AF_INET6, &in6_local, addr6, sizeof(addr6));
			//INET6_getsock(addr6, (struct sockaddr *) &localaddr);
			//inet_ntop(AF_INET6, &in6_remote, addr6, sizeof(addr6));
			//INET6_getsock(addr6, (struct sockaddr *) &remaddr);
			//localaddr.sin6_family = AF_INET6;
			//remaddr.sin6_family = AF_INET6;
			result_addr_local  = in6_local;
			result_addr_remote = in6_remote;
			sa_family = AF_INET6;
		}
	}
	else
	{
		/* this is an IPv4-style row */
		sscanf(local_addr, "%X", (unsigned int *) &result_addr_local);
		sscanf(rem_addr, "%X",   (unsigned int *) &result_addr_remote);
		sa_family = AF_INET;
	}

	char * hashkey = (char *) malloc (HASHKEYSIZE * sizeof(char));
	char * local_string = (char*) malloc (50);
	char * remote_string = (char*) malloc (50);
	inet_ntop(sa_family, &result_addr_local,  local_string,  49);
	inet_ntop(sa_family, &result_addr_remote, remote_string, 49);

	snprintf(hashkey, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d", local_string, local_port, remote_string, rem_port);
	free (local_string);

	//if (DEBUG)
	//	fprintf (stderr, "Hashkey: %s\n", hashkey);

	//std::cout << "Adding to conninode\n" << std::endl;

	conninode[hashkey] = inode;

	/* workaround: sometimes, when a connection is actually from 172.16.3.1 to
	 * 172.16.3.3, packages arrive from 195.169.216.157 to 172.16.3.3, where
	 * 172.16.3.1 and 195.169.216.157 are the local addresses of different 
	 * interfaces */
	struct local_addr * current_local_addr = local_addrs;
	while (current_local_addr != NULL) {
		/* TODO maybe only add the ones with the same sa_family */
		snprintf(hashkey, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d", current_local_addr->string, local_port, remote_string, rem_port);
		conninode[hashkey] = inode;
		current_local_addr = current_local_addr->next;
	}
	free (hashkey);
	free (remote_string);
}

int addprocinfo (const char * filename) {
	FILE * procinfo = fopen (filename, "r");

	char buffer[8192];

	if (procinfo == NULL)
		return 0;
	
	fgets(buffer, sizeof(buffer), procinfo);

	do
	{
		if (fgets(buffer, sizeof(buffer), procinfo))
			addtoconninode(buffer);
	} while (!feof(procinfo));

	fclose(procinfo);

	return 1;
}

std::map <unsigned long, prg_node *> inodeproc;

/* this should be done quickly after the packet
 * arrived, since the inode disappears from the table
 * quickly, too :) */
struct prg_node * findPID (unsigned long inode)
{
	/* we first look in inodeproc */
	struct prg_node * node = inodeproc[inode];
	
	if (node != NULL)
		return node;

	node = prg_cache_get(inode);
	if (node != NULL && node->pid == 1)
	{
		if (DEBUG)
			std::cout << "ITP: clearing and reloading cache\n";
		prg_cache_clear();
		prg_cache_load();
		node = prg_cache_get(inode);
		// this still happens sometimes...
		//assert (node->pid != 1);
	} 

	if (node == NULL)
	{
		if (DEBUG)
			std::cout << "ITP: inode " << inode << " not in inode-to-pid-mapping - reloading." << endl;
		prg_cache_clear();
		prg_cache_load();
		node = prg_cache_get(inode);
		if (node == NULL)
		{
			if (DEBUG)
				std::cout << "ITP: inode " << inode << " STILL not in inode-to-pid-mapping." << endl;
			return NULL;
		}
	} else if (DEBUG)
		std::cout << "ITP: inode " << inode << " found in inode-to-pid-mapping." << endl;

	inodeproc[inode] = node;

	return node;
}

Process * findProcess (struct prg_node * node)
{
	ProcList * current = processes;
	while (current != NULL)
	{
		if (node->pid == current->getVal()->pid)
			return current->getVal();
		current = current->next;
	}
	return NULL;
}

/* finds process based on inode, if any */
/* should be done quickly after arrival of the packet, 
 * otherwise findPID will be outdated */
Process * findProcess (unsigned long inode)
{
	struct prg_node * node = findPID(inode);

	if (node == NULL)
		return NULL;

	return findProcess (node);
}

/* check if we have identified any previously unknown
 * connections are now known */
void reviewUnknown ()
{
	ConnList * curr_conn = unknownproc->connections;
	ConnList * previous_conn = NULL;

	while (curr_conn != NULL) {
		unsigned long * inode = conninode[curr_conn->getVal()->refpacket->gethashstring()];
		if (inode != NULL)
		{
			Process * proc = findProcess (*inode);
			if (proc != unknownproc && proc != NULL)
			{
				if (DEBUG)
					std::cout << "ITP: WARNING: Previously unknown inode " << *inode << " now got process...??\n";
				/* Yay! - but how could this happen? */
				//assert(false);
				if (previous_conn != NULL)
				{
					previous_conn->setNext (curr_conn->getNext());
					proc->connections = new ConnList (curr_conn->getVal(), proc->connections);
					delete curr_conn;
					curr_conn = previous_conn;
				}
				else
				{
					unknownproc->connections = curr_conn->getNext();
					proc->connections = new ConnList (curr_conn->getVal(), proc->connections);
					delete curr_conn;
					curr_conn = unknownproc->connections;
				}
			}
		}
		previous_conn = curr_conn;
		if (curr_conn != NULL)
			curr_conn = curr_conn->getNext();
	}
}

void refreshconninode ()
{
	/* we don't forget old mappings, just overwrite */
	//delete conninode;
	//conninode = new HashTable (256);

	if (! addprocinfo ("/proc/net/tcp"))
	{
		std::cout << "Error: couldn't open /proc/net/tcp\n";
		exit(0);
	}
	addprocinfo ("/proc/net/tcp6");

	reviewUnknown();

}

float tokbps (u_int32_t bytes)
{
	return (((double)bytes) / PERIOD) / 1024;
}

char * uid2username (int uid)
{
	struct passwd * pwd; 
	/* getpwuid() allocates space for this itself, 
	 * which we shouldn't free */
	pwd = getpwuid(uid);
	if (pwd == NULL)
	{
		assert(false);
		return strdup ("unlisted");
	} else {
		return strdup(pwd->pw_name);
	}
}

class Line 
{
public:
	Line (const char * name, double n_sent_kbps, double n_recv_kbps, int pid, uid_t uid, const char * n_devicename)
	{
		m_name = name; 
		sent_kbps = n_sent_kbps; 
		recv_kbps = n_recv_kbps;
		devicename = n_devicename;
		m_pid = pid; 
		m_uid = uid;
		assert (m_uid >= 0);
		assert (m_pid >= 0);
	}

	void show (int row);
	
	double sent_kbps;
	double recv_kbps; 
private:
	const char * m_name;
	const char * devicename;
	int m_pid;
	int m_uid;
};

void Line::show (int row)
{
	if (DEBUG || tracemode)
	{
		assert (m_uid >= 0);
		assert (m_pid >= 0);

		std::cout << m_name << '/' << m_pid << '/' << m_uid << "\t" << sent_kbps << "\t" << recv_kbps << std::endl;
		return;
	}

	mvprintw (3+row, 0, "%d", m_pid);
	char * username = uid2username(m_uid);
	mvprintw (3+row, 6, "%s", username);
	free (username);
	mvprintw (3+row, 6 + 9, "%s", m_name);
	mvprintw (3+row, 6 + 9 + PROGNAME_WIDTH + 2, "%s", devicename);
	mvprintw (3+row, 6 + 9 + PROGNAME_WIDTH + 2 + 6, "%10.3f", sent_kbps);
	mvprintw (3+row, 6 + 9 + PROGNAME_WIDTH + 2 + 6 + 9 + 3, "%10.3f", recv_kbps);
	mvprintw (3+row, 6 + 9 + PROGNAME_WIDTH + 2 + 6 + 9 + 3 + 11, "KB/sec", recv_kbps);
}

int GreatestFirst (const void * ma, const void * mb)
{
	Line ** pa = (Line **)ma;
	Line ** pb = (Line **)mb;
	Line * a = *pa;
	Line * b = *pb;
	if (a->recv_kbps > b->recv_kbps)
	{
		return -1;
	}
	if (a->recv_kbps == b->recv_kbps)
	{
		return 0;
	} 
	return 1;
}

int count_processes()
{
	int i = 0;
	ProcList * curproc = processes;
	while (curproc != NULL)
	{
		i++; 
		curproc = curproc->getNext();
	}
	return i;
}

// Display all processes and relevant network traffic using show function
void do_refresh()
{
	refreshconninode();
	if (DEBUG || tracemode)
	{
		std::cout << "\n\nRefreshing:\n";
	}
	else
	{
		clear();
		mvprintw (0, 0, "%s", caption->c_str());
		attron(A_REVERSE);
		mvprintw (2, 0, "  PID USER     PROGRAM                      DEV        SENT      RECEIVED       ");
		attroff(A_REVERSE);
	}
	ProcList * curproc = processes;
	ProcList * previousproc = NULL;
	int nproc = count_processes();
	/* initialise to null pointers */
	Line * lines [nproc];
	int n = 0, i = 0;
	double sent_global = 0;
	double recv_global = 0;

	if (DEBUG)
	{
		// initialise to null pointers
		for (int i = 0; i < nproc; i++)
			lines[i] = NULL;
	}

	while (curproc != NULL)
	{
		// walk though its connections, summing up their data, and 
		// throwing away connections that haven't received a package 
		// in the last PROCESSTIMEOUT seconds.
		if (DEBUG)
		{
			assert (curproc != NULL);
			assert (curproc->getVal() != NULL);
		}
		/* do not remove the unknown process */
		if ((curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <= curtime.tv_sec) && (curproc->getVal() != unknownproc))
		{
			/* remove process */
			if (DEBUG)
				std::cout << "PROC: Deleting process\n";
			ProcList * todelete = curproc;
			Process * p_todelete = curproc->getVal();
			if (previousproc)
			{
				previousproc->next = curproc->next;
				curproc = curproc->next;
			} else {
				processes = curproc->getNext();
				curproc = processes;
			}
			delete todelete;
			delete p_todelete;
			nproc--;
			//continue;
		}
		else{

		u_int32_t sum_sent = 0, 
			  sum_recv = 0;

		/* walk though all this process's connections, and sum them
		 * up */
		ConnList * curconn = curproc->getVal()->connections;
		ConnList * previous = NULL;
		while (curconn != NULL)
		{
			if (curconn->getVal()->getLastPacket() <= curtime.tv_sec - CONNTIMEOUT)
			{
				/* stalled connection, remove. */
				ConnList * todelete = curconn;
				Connection * conn_todelete = curconn->getVal();
				curconn = curconn->getNext();
				if (todelete == curproc->getVal()->connections)
					curproc->getVal()->connections = curconn;
				if (previous != NULL)
					previous->setNext(curconn);
				delete (todelete);
				delete (conn_todelete);
			} 
			else 
			{
				u_int32_t sent = 0, recv = 0;
				curconn->getVal()->sumanddel(curtime, &sent, &recv);
				sum_sent += sent;
				sum_recv += recv;
				previous = curconn;
				curconn = curconn->getNext();
			}
		}
		if (DEBUG) 
		{
			assert (curproc->getVal()->getUid() >= 0);
		}
		lines[n] = new Line (curproc->getVal()->name, tokbps(sum_sent), tokbps(sum_recv), 
				curproc->getVal()->pid, curproc->getVal()->getUid(), curproc->getVal()->devicename);
		previousproc = curproc;
		curproc = curproc->next;
		n++;
		}
	}

	/* sort the accumulated lines */
	qsort (lines, nproc, sizeof(Line *), GreatestFirst);

	/* print them */
	for (i=0; i<nproc; i++)
	{
		lines[i]->show(i);
		recv_global += lines[i]->recv_kbps;
		sent_global += lines[i]->sent_kbps;
		delete lines[i];
	}
	if (tracemode || DEBUG) {
		/* print the 'unknown' connections, for debugging */
		ConnList * curr_unknownconn = unknownproc->connections;
		while (curr_unknownconn != NULL) {
			std::cout << "Unknown connection: " << 
				curr_unknownconn->getVal()->refpacket->gethashstring() << std::endl;

			curr_unknownconn = curr_unknownconn->getNext();
		}
	}

	if ((!tracemode) && (!DEBUG)){
		attron(A_REVERSE);
		mvprintw (3+1+i, 0, "  TOTAL                                           %10.3f  %10.3f KB/sec ", sent_global, recv_global);
		attroff(A_REVERSE);
		mvprintw (4+1+i, 0, "");
		refresh();
	}
}

/* 
 * returns the process from proclist with matching pid
 * if the inode is not associated with any PID, return the unknown process
 * if the process is not yet in the proclist, add it
 */
Process * getProcess (unsigned long inode, char * devicename)
{
	struct prg_node * node = findPID(inode);
	
	if (node == NULL)
		return unknownproc;

	Process * proc = findProcess (node);

	if (proc != NULL)
		return proc;

	Process * newproc = new Process (inode, strdup(devicename));
	newproc->name = strdup(node->name);
	newproc->pid = node->pid;

	char procdir [100];
	sprintf(procdir , "/proc/%d", node->pid);
	struct stat stats;
	stat(procdir, &stats);
	newproc->setUid(stats.st_uid);

	processes = new ProcList (newproc, processes);
	return newproc;
}

/* 
 * Used when a new connection is encountered. Finds corresponding
 * process and adds the connection. If the connection  doesn't belong
 * to any known process, the process list is updated and a new process
 * is made. If no process can be found even then, it's added to the 
 * 'unknown' process.
 */
Process * getProcess (Connection * connection, char * devicename)
{
	unsigned long * inode = conninode[connection->refpacket->gethashstring()];

	if (inode == NULL)
	{
		// no? refresh and check conn/inode table
#if DEBUG
		std::cout << "LOC: new connection not in connection-to-inode table.\n"; 
#endif
		refreshconninode();
		inode = conninode[connection->refpacket->gethashstring()];
		if (inode == NULL)
		{
			/* HACK: the following is a hack for cases where the 
			 * 'local' addresses aren't properly recognised, as is 
			 * currently the case for IPv6 */

		 	/* we reverse the direction of the stream if 
			 * successful. */

			Packet * reversepacket = connection->refpacket->newInverted();
			inode = conninode[reversepacket->gethashstring()];

			if (inode == NULL)
			{
				delete reversepacket;
				if (DEBUG)
					std::cout << "LOC: " << connection->refpacket->gethashstring() << " STILL not in connection-to-inode table - adding to the unknown process\n";
				unknownproc->connections = new ConnList (connection, unknownproc->connections);
				return unknownproc;
			}

			delete connection->refpacket;
			connection->refpacket = reversepacket;
		}
	}

	Process * proc = getProcess(*inode, devicename);
	proc->connections = new ConnList (connection, proc->connections);
	return proc;
}

void procclean ()
{
	//delete conninode;
	prg_cache_clear();
}
