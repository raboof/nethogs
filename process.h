#ifndef __PROCESS_H
#define __PROCESS_H

#include <assert.h>
#include "nethogs.h"
#include "connection.h"

extern bool tracemode;

class ConnList
{
public:
	ConnList (Connection * m_val, ConnList * m_next)
	{
		if (DEBUG)
			assert (m_val != NULL);
		val = m_val; next = m_next;
	}
	~ConnList ()
	{
		/* does not delete its value, to allow a connection to
		 * remove itself from the global connlist in its destructor */
	}
	Connection * getVal ()
	{
		return val;
	}
	ConnList * setNext (ConnList * m_next)
	{
		next = m_next;
	}
	ConnList * getNext ()
	{
		return next;
	}
private:
	Connection * val;
	ConnList * next;
};

class Process
{
public:
	Process (unsigned long m_inode, char * m_devicename, char * m_name = NULL)
	{
		inode = m_inode;
		name = m_name;
		devicename = m_devicename;
		connections = NULL;
		pid = 0;
		uid = 0;
	}
	int getLastPacket ()
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

	const char * name;
	const char * devicename;
	int pid;
	int uid;

	unsigned long inode;
	ConnList * connections;
};

Process * getProcess (Connection * connection, char * devicename = NULL);
void do_refresh ();

void procclean ();

#endif
