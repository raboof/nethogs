/* NetHogs console UI */
#include <string>
#include <pwd.h>
#include <sys/types.h>

#include <ncurses.h>
#include "nethogs.h"
#include "process.h"

std::string * caption;
//extern char [] version;
const char version[] = " version " VERSION "." SUBVERSION "." MINORVERSION;
extern ProcList * processes;
extern timeval curtime;
extern Process * unknownproc;

class Line 
{
public:
	Line (const char * name, double n_sent_kbps, double n_recv_kbps, pid_t pid, uid_t uid, const char * n_devicename)
	{
		if (!ROBUST) 
		{
			assert (uid >= 0);
			assert (pid >= 0);
		}
		m_name = name; 
		sent_kbps = n_sent_kbps; 
		recv_kbps = n_recv_kbps;
		devicename = n_devicename;
		m_pid = pid; 
		m_uid = uid;
		if (!ROBUST) 
		{
			assert (m_uid >= 0);
			assert (m_pid >= 0);
		}
	}

	void show (int row);
	
	double sent_kbps;
	double recv_kbps; 
private:
	const char * m_name;
	const char * devicename;
	pid_t m_pid;
	uid_t m_uid;
};

char * uid2username (uid_t uid)
{
	struct passwd * pwd = NULL; 
	/* getpwuid() allocates space for this itself, 
	 * which we shouldn't free */
	pwd = getpwuid(uid);

	if (pwd == NULL)
	{
		if (!ROBUST)
		{
			assert(false);
		}
		return strdup ("unlisted");
	} else {
		return strdup(pwd->pw_name);
	}
}


void Line::show (int row)
{
	if (!ROBUST)
	{
		assert (m_uid >= 0);
		assert (m_pid >= 0);
	}

	if (DEBUG || tracemode)
	{
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

void init_ui ()
{
	WINDOW * screen = initscr();
	raw();
	noecho();
	cbreak();
	nodelay(screen, TRUE);
	caption = new std::string ("NetHogs");
	caption->append(version);
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
			break;
		case 'r':
			/* sort on 'received' */
			break;
	}
}

float tokbps (u_int32_t bytes)
{
	return (((double)bytes) / PERIOD) / 1024;
}

// Display all processes and relevant network traffic using show function
void do_refresh()
{
	refreshconninode();
	if (DEBUG || tracemode)
	{
		std::cout << "\nRefreshing:\n";
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
	int nproc = processes->size();
	/* initialise to null pointers */
	Line * lines [nproc];
	int n = 0, i = 0;
	double sent_global = 0;
	double recv_global = 0;

	if (!ROBUST)
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
		if (!ROBUST)
		{
			assert (curproc != NULL);
			assert (curproc->getVal() != NULL);
			assert (nproc == processes->size());
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
		else
		{

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
			uid_t uid = curproc->getVal()->getUid();
			if (!ROBUST)
			{
				assert (getpwuid(uid) != NULL);
				assert (curproc->getVal()->pid >= 0);
				assert (n < nproc);
			}
			lines[n] = new Line (curproc->getVal()->name, tokbps(sum_sent), tokbps(sum_recv), 
					curproc->getVal()->pid, uid, curproc->getVal()->devicename);
			previousproc = curproc;
			curproc = curproc->next;
			n++;
			if (!ROBUST)
			{
				assert (nproc == processes->size());
				if (curproc == NULL)
					assert (n-1 < nproc);
				else
					assert (n < nproc);

			}
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


