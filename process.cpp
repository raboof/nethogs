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

#include "process.h"
#include "hashtbl.h"
#include "nethogs.h"
#include "inodeproc.cpp"
//#include "inet6.c"

extern timeval curtime;
extern std::string * caption;
extern local_addr * local_addrs;

static int INET6_getsock(char *bufp, struct sockaddr *sap)
{
    struct sockaddr_in6 *sin6;

    sin6 = (struct sockaddr_in6 *) sap;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = 0;

    if (inet_pton(AF_INET6, bufp, sin6->sin6_addr.s6_addr) <= 0)
	return (-1);

    return 16;			/* ?;) */
}

static int INET6_input(int type, char *bufp, struct sockaddr *sap)
{
	return (INET6_getsock(bufp, sap));
}

struct aftype {
    char *name;
    char *title;
    int af;
    int alen;
    char *(*print) (unsigned char *);
    char *(*sprint) (struct sockaddr *, int numeric);
    int (*input) (int type, char *bufp, struct sockaddr *);
    void (*herror) (char *text);
    int (*rprint) (int options);
    int (*rinput) (int typ, int ext, char **argv);

    /* may modify src */
    int (*getmask) (char *src, struct sockaddr * mask, char *name);

    int fd;
    char *flag_file;
};
/* 
 * connection-inode table. takes information from /proc/net/tcp.
 * key contains source ip, source port, destination ip, destination 
 * port in format: '1.2.3.4:5-1.2.3.4:5'
 */
HashTable * conninode = new HashTable (256);

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
// TODO check what happens to the 'content' field of the hash
void addtoconninode (char * buffer)
{
	short int sa_family;
    	struct in6_addr result_addr_local;
    	struct in6_addr result_addr_remote;

	char rem_addr[128], local_addr[128];
	int local_port, rem_port;
    	struct sockaddr_in6 localaddr, remaddr;
    	char addr6[INET6_ADDRSTRLEN];
    	struct in6_addr in6_local;
    	struct in6_addr in6_remote;
    	extern struct aftype inet6_aftype;
	// the following line leaks memory.
	unsigned long * inode = (unsigned long *) malloc (sizeof(unsigned long));

	// TODO check it matched
	sscanf(buffer, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*lX:%*lX %*X:%*lX %*lX %*d %*d %ld %*512s\n",
		local_addr, &local_port, rem_addr, &rem_port, inode);

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
			inet_ntop(AF_INET6, &in6_local, addr6, sizeof(addr6));
			INET6_getsock(addr6, (struct sockaddr *) &localaddr);
			inet_ntop(AF_INET6, &in6_remote, addr6, sizeof(addr6));
			INET6_getsock(addr6, (struct sockaddr *) &remaddr);
			localaddr.sin6_family = AF_INET6;
			remaddr.sin6_family = AF_INET6;
			result_addr_local  = in6_local;
			result_addr_remote = in6_remote;
			sa_family = AF_INET6;
		}
	}
	else
	{
		/* this is an IPv4-style row */
		sscanf(local_addr, "%X", &result_addr_local);
		sscanf(rem_addr, "%X",   &result_addr_remote);
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

	conninode->add(hashkey, (void *)inode);

	/* workaround: sometimes, when a connection is actually from 172.16.3.1 to
	 * 172.16.3.3, packages arrive from 195.169.216.157 to 172.16.3.3, where
	 * 172.16.3.1 and 195.169.216.157 are the local addresses of different 
	 * interfaces */
	struct local_addr * current_local_addr = local_addrs;
	while (current_local_addr != NULL) {
		hashkey = (char *) malloc (HASHKEYSIZE * sizeof(char));
		snprintf(hashkey, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d", current_local_addr->string, local_port, remote_string, rem_port);
		conninode->add(hashkey, (void *)inode);
		current_local_addr = current_local_addr->next;
	}
	free (remote_string);
}

void refreshconninode ()
{
	delete conninode;
	conninode = new HashTable (256);

	char buffer[8192];
	FILE * procinfo = fopen ("/proc/net/tcp", "r");


	// TODO use helper function
	if (procinfo)
	{
		fgets(buffer, sizeof(buffer), procinfo);
		do
		{
			if (fgets(buffer, sizeof(buffer), procinfo))
				addtoconninode(buffer); 
		} while (!feof(procinfo));
		fclose(procinfo);
	}
	else
	{
		std::cout << "Error: couldn't open /proc/net/tcp\n";
		exit(0);
	}

	procinfo = fopen ("/proc/net/tcp6", "r");
	if (procinfo != NULL) {
		fgets(buffer, sizeof(buffer), procinfo);
		do {
			if (fgets(buffer, sizeof(buffer), procinfo))
				addtoconninode(buffer);
		} while (!feof(procinfo));
		fclose (procinfo);
	}
}

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

Process * unknownproc = new Process (0, "", "unknown");
ProcList * processes = new ProcList (unknownproc, NULL);

float tokbps (bpf_u_int32 bytes)
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
		return strdup ("unlisted");
	} else {
		return strdup(pwd->pw_name);
	}
}


class Line 
{
public:
	Line (const char * name, double n_sent_kbps, double n_recv_kbps, int pid, int uid, const char * n_devicename)
	{
		m_name = name; 
		sent_kbps = n_sent_kbps; 
		recv_kbps = n_recv_kbps;
		devicename = n_devicename;
		m_pid = pid; 
		m_uid = uid;
	}

	void show (int row)
	{
		if (DEBUG || tracemode)
		{
			std::cout << m_name << "\t" << sent_kbps << "\t" << recv_kbps << std::endl;
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

	double sent_kbps;
	double recv_kbps; 
private:
	const char * m_name;
	const char * devicename;
	int m_pid;
	int m_uid;
};

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
	if (DEBUG || tracemode)
	{
		std::cout << "Refreshing:\n";
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
	ProcList * lastproc = NULL;
	int nproc = count_processes();
	Line * lines [nproc];
	int n = 0, i = 0;
	double sent_global = 0;
	double recv_global = 0;

	while (curproc != NULL)
	{
		// walk though its connections, summing up
		// their data, and throwing away old stuff.
		// if the last packet is older than PROCESSTIMEOUT seconds, discard.
		if (DEBUG)
		{
			assert (curproc != NULL);
			assert (curproc->getVal() != NULL);
		}
		if ((curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <= curtime.tv_sec) && (curproc->getVal() != unknownproc))
		{
			if (lastproc)
			{
				lastproc->next = curproc->next;
				ProcList * newcur = curproc->next;
				delete curproc;
				curproc = newcur;
				nproc--;
			} else {
				processes = curproc->getNext();
				delete curproc;
				curproc = processes;
				nproc--;
			}
		}
		else
		{
			bpf_u_int32 sum = 0, 
				    sum_local = 0,
				    sum_conn = 0,
				    sum_connLocal = 0;	
			ConnList * curconn = curproc->getVal()->connections;
			while (curconn != NULL)
			{
				curconn->getVal()->sumanddel(curtime, &sum, &sum_local);
				sum_connLocal+=sum_local;
				sum_conn+=sum;
				curconn = curconn->getNext();
			}
			lines[n] = new Line (curproc->getVal()->name, tokbps(sum_conn), tokbps(sum_connLocal), curproc->getVal()->pid, curproc->getVal()->uid, curproc->getVal()->devicename);
			lastproc = curproc;
			curproc = curproc->next;
			n++;
		}
	}
	qsort (lines, nproc, sizeof(Line *), GreatestFirst);
	for (i=0; i<nproc; i++)
	{
		lines[i]->show(i);
		recv_global += lines[i]->recv_kbps;
		sent_global += lines[i]->sent_kbps;
		delete lines[i];
	}

	if ((!tracemode) && (!DEBUG)){
		attron(A_REVERSE);
		mvprintw (3+1+i, 0, "  TOTAL                                           %10.3f  %10.3f KB/sec ", sent_global, recv_global);
		attroff(A_REVERSE);
		mvprintw (4+1+i, 0, "");
		refresh();
	}
}

/* returns the process from proclist with matching pid
 * if none, creates it */
Process * getProcess (unsigned long inode, char * devicename)
{
	struct prg_node * node = prg_cache_get(inode);

	if (node == NULL)
	{
		prg_cache_clear();
		prg_cache_load();
		node = prg_cache_get(inode);
		if (node == NULL)
		{
			if (DEBUG)
				std::cerr << "Unknown inode " << inode << ", assuming unknown." << endl;
			return unknownproc;
		}
	}

	ProcList * current = processes;
	while (current != NULL)
	{
		if (node->pid == current->getVal()->pid)
			return current->getVal();
		current = current->next;
	}

	Process * newproc = new Process (inode, strdup(devicename));
	newproc->name = strdup(node->name);
	newproc->pid = node->pid;

	char procdir [100];
	sprintf(procdir , "/proc/%d", node->pid);
	struct stat stats;
	stat(procdir, &stats);
	newproc->uid = stats.st_uid;

	processes = new ProcList (newproc, processes);
	return newproc;
}

/* Used when a new connection is encountered. Finds corresponding
 * process and adds the connection. If the connection  doesn't belong
 * to any known process, the process list is updated and a new process
 * is made. If no process can be found even then, it's added to the 
 * 'unknown' process.
 */
Process * getProcess (Connection * connection, char * devicename)
{
	ProcList * curproc = processes;

	// see if we already know the inode for this connection
	if (DEBUG)
	{
		std::cout << "New connection reference packet.. ";
		std::cout << connection->refpacket << std::endl;
	}

	unsigned long * inode = (unsigned long *) conninode->get(connection->refpacket->gethashstring());

	if (inode == NULL)
	{
		// no? refresh and check conn/inode table
#if DEBUG
		std::cerr << "Not in table, refreshing table from /proc/net/tcp.\n"; 
#endif
		refreshconninode();
		inode = (unsigned long *) conninode->get(connection->refpacket->gethashstring());
		if (inode == NULL)
		{
			/* HACK: the following is a hack for cases where the 'local' addresses
			 * aren't properly recognised, as is currently the case for IPv6 */

		 	/* we reverse the direction of the stream if successful. */

			Packet * reversepacket = connection->refpacket->newInverted();
			//inode = (unsigned long *) conninode->get(reversepacket->gethashstring());

			if (inode == NULL)
			{
				delete reversepacket;
				if (DEBUG)
					std::cerr << connection->refpacket->gethashstring() << " STILL not in table - adding to the unknown process\n";
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
	delete conninode;
	prg_cache_clear();
}
