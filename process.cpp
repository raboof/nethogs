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

extern local_addr * local_addrs;

;

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
	} 

	/* make copy of returned node, add it to map, and return it */
	if (node != NULL)
	{
		struct prg_node * tempnode = (struct prg_node *) malloc (sizeof (struct prg_node));
		memcpy (tempnode, node, sizeof (struct prg_node));
		inodeproc[inode] = tempnode;
		return tempnode;
	}
	else
		return NULL;
}

Process * findProcess (struct prg_node * node)
{
	ProcList * current = processes;
	while (current != NULL)
	{
		Process * currentproc = current->getVal();
		assert (currentproc != NULL);
		
		if (node->pid == currentproc->pid)
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

int ProcList::size ()
{
	int i=1;

	if (next != NULL)
		i += next->size();

	return i;
}

void check_all_procs ()
{
	ProcList * curproc = processes;
	while (curproc != NULL)
	{
		curproc->getVal()->check();
		curproc = curproc->getNext();
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
