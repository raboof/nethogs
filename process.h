#ifndef __PROCESS_H
#define __PROCESS_H

#include <assert.h>
#include "nethogs.h"
#include "connection.h"

class ConnList
{
public:
	ConnList (Connection * m_val, ConnList * m_next)
	{
		if (DEBUG)
			assert (m_val != NULL);
		val = m_val; next = m_next;
	}
	Connection * getVal ()
	{
		return val;
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
		incoming = NULL;
		outgoing = NULL;
	}
	int getLastPacket ()
	{
		int lastpacket=0;
		ConnList * curconn=incoming;
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
	ConnList * incoming;
	ConnList * outgoing;
};

Process * getProcess (Connection * connection, char * devicename = NULL);
void do_refresh ();

void procclean ();

#endif
