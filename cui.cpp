/* 
 * cui.cpp
 *
 * Copyright (c) 2004-2006,2008,2010,2011 Arnout Engelen
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


/* NetHogs console UI */
#include <string>
#include <pwd.h>
#include <sys/types.h>
#include <cstdlib>
#include <cerrno>
#include <cstdlib>
#include <algorithm>

#include <ncurses.h>
#include "nethogs.h"
#include "process.h"


std::string * caption;
extern const char version[];
extern ProcList * processes;
extern timeval curtime;

extern Process * unknowntcp;
extern Process * unknownudp;
extern Process * unknownip;

extern bool sortRecv;

extern int viewMode;

extern unsigned refreshlimit;
extern unsigned refreshcount;

#define PID_MAX 4194303

class Line
{
public:
	Line (const char * name, double n_recv_value, double n_sent_value, pid_t pid, uid_t uid, const char * n_devicename)
	{
		assert (pid >= 0);
		assert (pid <= PID_MAX);
		m_name = name;
		sent_value = n_sent_value;
		recv_value = n_recv_value;
		devicename = n_devicename;
		m_pid = pid;
		m_uid = uid;
		assert (m_pid >= 0);
	}

	void show (int row, unsigned int proglen);
	void log ();

	double sent_value;
	double recv_value;
	//Made it public, best idea?
	const char * m_name;
private:

	const char * devicename;
	pid_t m_pid;
	uid_t m_uid;
};

#include <sstream>

std::string itoa(int i)
{
	std::stringstream out;
	out << i;
	return out.str();
}

/**
 * @returns the username that corresponds to this uid 
 */
std::string uid2username (uid_t uid)
{
	struct passwd * pwd = NULL;
	errno = 0;

	/* points to a static memory area, should not be freed */
	pwd = getpwuid(uid);

	if (pwd == NULL)
		if (errno == 0)
			return itoa(uid);
		else
			forceExit(false, "Error calling getpwuid(3) for uid %d: %d %s", uid, errno, strerror(errno));
	else
		return std::string(pwd->pw_name);
}


void Line::show (int row, unsigned int proglen)
{
	assert (m_pid >= 0);
	assert (m_pid <= PID_MAX);

	if (m_pid == 0)
		mvprintw (row, 6, "?");
	else
		mvprintw (row, 0, "%7d", m_pid);
	std::string username = uid2username(m_uid);
	mvprintw (row, 8, "%s", username.c_str());
	if (strlen (m_name) > proglen) {
		// truncate oversized names
		char * tmp = strdup(m_name);
		char * start = tmp + strlen (m_name) - proglen;
		start[0] = '.';
		start[1] = '.';
		mvprintw (row, 8 + 9, "%s", start);
		free (tmp);
	} else {
		mvprintw (row, 8 + 9, "%s", m_name);
	}
	mvprintw (row, 8 + 9 + proglen + 2, "%s", devicename);
	mvprintw (row, 8 + 9 + proglen + 2 + 6, "%10.3f", sent_value);
	mvprintw (row, 8 + 9 + proglen + 2 + 6 + 9 + 3, "%10.3f", recv_value);
	if (viewMode == VIEWMODE_KBPS)
	{
		mvprintw (row, 8 + 9 + proglen + 2 + 6 + 9 + 3 + 11, "KB/sec");
	}
	else if (viewMode == VIEWMODE_TOTAL_MB)
	{
		mvprintw (row, 8 + 9 + proglen + 2 + 6 + 9 + 3 + 11, "MB    ");
	}
	else if (viewMode == VIEWMODE_TOTAL_KB)
	{
		mvprintw (row, 8 + 9 + proglen + 2 + 6 + 9 + 3 + 11, "KB    ");
	}
	else if (viewMode == VIEWMODE_TOTAL_B)
	{
		mvprintw (row, 8 + 9 + proglen + 2 + 6 + 9 + 3 + 11, "B     ");
	}
}

//Match process with same name in the same position
int getPosition(Line actual, Line* new_lines[], int nproc){
	
	for (int i = 0; i<nproc; i++){
		if ( new_lines[i] != NULL && !strcmp(new_lines[i]->m_name,actual.m_name) ){
			return i;
		}
	}

	return -1;
}

//Instead overriding values, we add them
/*TODO: Combine differents devices
firefox eth0 100 0
firefox tun0 10 10
*/
void show_stats(Line * lines[], int nproc){
	std::cout << "\nStats:\n";
	
	Line * new_lines[nproc];
	int lastProc = 0;
	
	for (int i=0; i<nproc; i++)
		new_lines[i] = NULL;
	
	for (int i=0; i<nproc; i++)
	{
		int position = getPosition(*lines[i], new_lines, nproc);
		//std::cout << "\nGot position for: "<< lines[i]->m_name << " is "<< position << std::endl;
		if (position == -1) {
			position = lastProc;
			lastProc++;
			
			new_lines[position] = lines[i];
		}	
		else{
			new_lines[position]->sent_value += lines[i]->sent_value;
			new_lines[position]->recv_value += lines[i]->recv_value;
		}
		//std::cout << "\nFinal position: "<< lines[i]->m_name << " is "<< position << std::endl;
		//Here we have in new_lines[position] the connection with m_name
		
	}
	
	/* print only with useful information*/
	for (int i=0; i<lastProc; i++)
	{
		new_lines[i]->log();
	}
	
	/* Erase everything with duplicated/old info */
	for (int i=0; i<nproc; i++)
	{
		delete lines[i];
	}
	
	/* print the 'unknown' connections, for debugging */
	ConnList * curr_unknownconn = unknowntcp->connections;
	while (curr_unknownconn != NULL) {
		std::cout << "Unknown connection: " <<
			curr_unknownconn->getVal()->refpacket->gethashstring() << std::endl;

		curr_unknownconn = curr_unknownconn->getNext();
	}
	
}

void Line::log() {
	if ( stats ){
		std::string str(this->m_name);
		size_t lastSlash = str.find_last_of("/");
		str = str.substr(lastSlash+1);
		
		std::cout << str << "\t" << sent_value << "\t" << recv_value << std::endl;
	}
	else
		std::cout << m_name << '/' << m_pid << '/' << m_uid << "\t" << sent_value << "\t" << recv_value << std::endl;
}

int GreatestFirst (const void * ma, const void * mb)
{
	Line ** pa = (Line **)ma;
	Line ** pb = (Line **)mb;
	Line * a = *pa;
	Line * b = *pb;
	double aValue;
	if (sortRecv)
	{
		aValue = a->recv_value;
	}
	else
	{
		aValue = a->sent_value;
	}

	double bValue;
	if (sortRecv)
	{
		bValue = b->recv_value;
	}
	else
	{
		bValue = b->sent_value;
	}

	if (aValue > bValue)
	{
		return -1;
	}
	if (aValue == bValue)
	{
		return 0;
	}
	return 1;
}

void init_ui ()
{
	WINDOW * screen = initscr();
	raw();
	noecho();
	cbreak();
	nodelay(screen, TRUE);
	caption = new std::string ("NetHogs");
	caption->append(getVersion());
	//caption->append(", running at ");
}

void exit_ui ()
{
	clear();
	endwin();
	delete caption;
}

void ui_tick ()
{
	switch (getch()) {
		case 'q':
			/* quit */
			quit_cb(0);
			break;
		case 's':
			/* sort on 'sent' */
			sortRecv = false;
			break;
		case 'r':
			/* sort on 'received' */
			sortRecv = true;
			break;
		case 'm':
			/* switch mode: total vs kb/s */
			viewMode = (viewMode + 1) % VIEWMODE_COUNT;
			break;
	}
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

void show_trace(Line * lines[], int nproc) {
	std::cout << "\nRefreshing:\n";

	/* print them */
	for (int i=0; i<nproc; i++)
	{
		lines[i]->log();
		delete lines[i];
	}

	/* print the 'unknown' connections, for debugging */
	ConnList * curr_unknownconn = unknowntcp->connections;
	while (curr_unknownconn != NULL) {
		std::cout << "Unknown connection: " <<
			curr_unknownconn->getVal()->refpacket->gethashstring() << std::endl;

		curr_unknownconn = curr_unknownconn->getNext();
	}
}

void show_ncurses(Line * lines[], int nproc) {
	int rows; // number of terminal rows
	int cols; // number of terminal columns
	unsigned int proglen; // max length of the "PROGRAM" column

	double sent_global = 0;
	double recv_global = 0;

	getmaxyx(stdscr, rows, cols);	 /* find the boundaries of the screeen */

	if (cols < 62) {
		clear();
		mvprintw(0,0, "The terminal is too narrow! Please make it wider.\nI'll wait...");
		return;
	}

	if (cols > PROGNAME_WIDTH) cols = PROGNAME_WIDTH;

	proglen = cols - 55;

	clear();
	mvprintw (0, 0, "%s", caption->c_str());
	attron(A_REVERSE);
	mvprintw (2, 0, "    PID USER     %-*.*s  DEV        SENT      RECEIVED       ", proglen, proglen, "PROGRAM");
	attroff(A_REVERSE);

	/* print them */
	int i;
	for (i=0; i<nproc; i++)
	{
		if (i+3 < rows)
			lines[i]->show(i+3, proglen);
		recv_global += lines[i]->recv_value;
		sent_global += lines[i]->sent_value;
		delete lines[i];
	}

	attron(A_REVERSE);
	int totalrow = std::min(rows-1, 3+1+i);
	mvprintw (totalrow, 0, "  TOTAL        %-*.*s          %10.3f  %10.3f ", proglen, proglen, " ", sent_global, recv_global);
	if (viewMode == VIEWMODE_KBPS)
	{
		mvprintw (3+1+i, cols - 7, "KB/sec ");
	} else if (viewMode == VIEWMODE_TOTAL_B) {
		mvprintw (3+1+i, cols - 7, "B      ");
	} else if (viewMode == VIEWMODE_TOTAL_KB) {
		mvprintw (3+1+i, cols - 7, "KB     ");
	} else if (viewMode == VIEWMODE_TOTAL_MB) {
		mvprintw (3+1+i, cols - 7, "MB     ");
	}
	attroff(A_REVERSE);
	mvprintw (totalrow+1, 0, "");
	refresh();
}

// Display all processes and relevant network traffic using show function
void do_refresh()
{
	refreshconninode();
	refreshcount++;

	ProcList * curproc = processes;
	ProcList * previousproc = NULL;
	int nproc = processes->size();
	/* initialise to null pointers */
	Line * lines [nproc];
	int n = 0;

#ifndef NDEBUG
	// initialise to null pointers
	for (int i = 0; i < nproc; i++)
		lines[i] = NULL;
#endif

	while (curproc != NULL)
	{
		// walk though its connections, summing up their data, and
		// throwing away connections that haven't received a package
		// in the last PROCESSTIMEOUT seconds.
		assert (curproc != NULL);
		assert (curproc->getVal() != NULL);
		assert (nproc == processes->size());

		/* remove timed-out processes (unless it's one of the the unknown process) */
		
		/*if ( stats == true ){
			std::cout << "stats activated, not deleting entries" << std::endl;
		}*/
		
		//Collecting stats we do not want to remove anything
		if ( (!stats)
				&& (curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <= curtime.tv_sec)
				&& (curproc->getVal() != unknowntcp)
				&& (curproc->getVal() != unknownudp)
				&& (curproc->getVal() != unknownip))
		{
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
		else
		{
			// add a non-timed-out process to the list of stuff to show
			float value_sent = 0,
				value_recv = 0;

			if (viewMode == VIEWMODE_KBPS)
			{
				//std::cout << "kbps viemode" << std::endl;
				getkbps (curproc->getVal(), &value_recv, &value_sent);
			}
			else if (viewMode == VIEWMODE_TOTAL_KB)
			{
				//std::cout << "total viemode" << std::endl;
				gettotalkb(curproc->getVal(), &value_recv, &value_sent);
			}
			else if (viewMode == VIEWMODE_TOTAL_MB)
			{
				//std::cout << "total viemode" << std::endl;
				gettotalmb(curproc->getVal(), &value_recv, &value_sent);
			}
			else if (viewMode == VIEWMODE_TOTAL_B)
			{
				//std::cout << "total viemode" << std::endl;
				gettotalb(curproc->getVal(), &value_recv, &value_sent);
			}
			else
			{
				forceExit(false, "Invalid viewMode: %d", viewMode);
			}
			uid_t uid = curproc->getVal()->getUid();
#ifndef NDEBUG
			struct passwd * pwuid = getpwuid(uid);
			assert (pwuid != NULL);
			// value returned by pwuid should not be freed, according to
			// Petr Uzel.
			//free (pwuid);
#endif
			assert (curproc->getVal()->pid >= 0);
			assert (n < nproc);

			lines[n] = new Line (curproc->getVal()->name, value_recv, value_sent,
					curproc->getVal()->pid, uid, curproc->getVal()->devicename);
			previousproc = curproc;
			curproc = curproc->next;
			n++;
#ifndef NDEBUG
			assert (nproc == processes->size());
			if (curproc == NULL)
				assert (n-1 < nproc);
			else
				assert (n < nproc);
#endif
		}
	}

	/* sort the accumulated lines */
	//In stats-mode this is not necessary
	qsort (lines, nproc, sizeof(Line *), GreatestFirst);

	if (stats)
		show_stats(lines,nproc);
	else if (tracemode || DEBUG)
		show_trace(lines, nproc);
	else
		show_ncurses(lines, nproc);

	if (refreshlimit != 0 && refreshcount >= refreshlimit)
		quit_cb(0);
}
