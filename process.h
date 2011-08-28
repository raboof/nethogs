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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


#ifndef __PROCESS_H
#define __PROCESS_H

#include <assert.h>
#include "nethogs.h"
#include "connection.h"

extern bool tracemode;
extern bool bughuntmode;

void check_all_procs ();

class ConnList
{
public:
	ConnList (Connection * m_val, ConnList * m_next)
	{
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
	void setNext (ConnList * m_next)
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
	/* the process makes a copy of the device name and name. */
	Process (unsigned long m_inode, const char * m_devicename, const char * m_name = NULL)
	{
		//std::cout << "ARN: Process created with dev " << m_devicename << std::endl;
		if (DEBUG)
			std::cout << "PROC: Process created at " << this << std::endl;
		inode = m_inode;

		if (m_name == NULL)
			name = NULL;
		else
			name = strdup(m_name);

		devicename = strdup(m_devicename);
		connections = NULL;
		pid = 0;
		uid = 0;
	}
	void check () {
		assert (pid >= 0);
	}
	
	~Process ()
	{
		free (name);
		free (devicename);
		if (DEBUG)
			std::cout << "PROC: Process deleted at " << this << std::endl;
	}
	int getLastPacket ();

	char * name;
	char * devicename;
	int pid;

	unsigned long inode;
	ConnList * connections;
	uid_t getUid()
	{
		return uid;
	}

	void setUid(uid_t m_uid)
	{
		uid = m_uid;
	}
private:
	uid_t uid;
};

class ProcList
{
public:
	ProcList (Process * m_val, ProcList * m_next)
	{
		assert (m_val != NULL);
		val = m_val; next = m_next;
	}
	int size (); 
	Process * getVal () { return val; }
	ProcList * getNext () { return next; }
	ProcList * next;
private:
	Process * val;
};

Process * getProcess (Connection * connection, const char * devicename = NULL);

void process_init ();

void refreshconninode ();

void procclean ();

#endif
