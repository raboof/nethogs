/* 
 * refresh.cpp
 *
 * Copyright (c) 2004 Arnout Engelen
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


#include <iostream>
#include <csignal>
#include <unistd.h>
#include "process.h"

extern bool needrefresh;
extern unsigned refreshdelay;
extern timeval curtime;

void alarm_cb (int /*i*/)
{
    needrefresh = true;
    //cout << "Setting needrefresh\n";

    signal (SIGALRM, &alarm_cb);
    alarm(refreshdelay);
}


float tomb (u_int32_t bytes)
{
	return ((double)bytes) / 1024 / 1024;
}
float tokb (u_int32_t bytes)
{
	return ((double)bytes) / 1024;
}

float tokbps (u_int32_t bytes)
{
	return (((double)bytes) / PERIOD) / 1024;
}

/** Get the kb/s values for this process */
void getkbps (Process * curproc, float * recvd, float * sent)
{
	u_int32_t sum_sent = 0,
	  	sum_recv = 0;

	/* walk though all this process's connections, and sum
	 * them up */
	ConnList * curconn = curproc->connections;
	ConnList * previous = NULL;
	while (curconn != NULL)
	{
		if (curconn->getVal()->getLastPacket() <= curtime.tv_sec - CONNTIMEOUT)
		{
			/* stalled connection, remove. */
			ConnList * todelete = curconn;
			Connection * conn_todelete = curconn->getVal();
			curconn = curconn->getNext();
			if (todelete == curproc->connections)
				curproc->connections = curconn;
			if (previous != NULL)
				previous->setNext(curconn);
			delete (todelete);
			delete (conn_todelete);
		}
		else
		{
			u_int32_t sent = 0, recv = 0;
			curconn->getVal()->sumanddel(curtime, &recv, &sent);
			sum_sent += sent;
			sum_recv += recv;
			previous = curconn;
			curconn = curconn->getNext();
		}
	}
	*recvd = tokbps(sum_recv);
	*sent = tokbps(sum_sent);
}

/** get total values for this process */
void gettotal(Process * curproc, u_int32_t * recvd, u_int32_t * sent)
{
	u_int32_t sum_sent = 0,
	  	sum_recv = 0;
	ConnList * curconn = curproc->connections;
	while (curconn != NULL)
	{
		Connection * conn = curconn->getVal();
		sum_sent += conn->sumSent;
		sum_recv += conn->sumRecv;
		curconn = curconn->getNext();
	}
	//std::cout << "Sum sent: " << sum_sent << std::endl;
	//std::cout << "Sum recv: " << sum_recv << std::endl;
	*recvd = sum_recv;
	*sent = sum_sent;
}

void gettotalmb(Process * curproc, float * recvd, float * sent)
{
	u_int32_t sum_sent = 0,
	  	sum_recv = 0;
	gettotal(curproc, &sum_recv, &sum_sent);
	*recvd = tomb(sum_recv);
	*sent = tomb(sum_sent);
}

/** get total values for this process */
void gettotalkb(Process * curproc, float * recvd, float * sent)
{
	u_int32_t sum_sent = 0,
	  	sum_recv = 0;
	gettotal(curproc, &sum_recv, &sum_sent);
	*recvd = tokb(sum_recv);
	*sent = tokb(sum_sent);
}

void gettotalb(Process * curproc, float * recvd, float * sent)
{
	u_int32_t sum_sent = 0,
	  	sum_recv = 0;
	gettotal(curproc, &sum_recv, &sum_sent);
	//std::cout << "Total sent: " << sum_sent << std::endl;
	*sent = sum_sent;
	*recvd = sum_recv;
}
