/* nethogs.cpp */

#include "nethogs.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <string>
#include <string.h>

#include <ncurses.h>

extern "C" {
	#include <pcap.h>
}

#include "packet.h"
#include "connection.h"
#include "process.h"
#include "refresh.h"

unsigned refreshdelay = 1;
bool tracemode = false;
bool needrefresh = true;

char * currentdevice = NULL;

const char version[] = " version " VERSION "." SUBVERSION "." MINORVERSION;

timeval curtime;
std::string * caption;

bool local_addr::contains (const in_addr_t & n_addr) {
	if (n_addr == addr)
		return true;
	if (next == NULL)
		return false;
	return next->contains(n_addr);
}

void process (u_char * args, const struct pcap_pkthdr * header, const u_char * m_packet)
{
	curtime = header->ts;

	Packet * packet = getPacket (header, m_packet);
	if (packet == NULL)
		return;

	Connection * connection = findConnection(packet);

	if (connection != NULL)
	{
		/* add packet to the connection */
		connection->add(packet);
	} else {
		/* else: unknown connection, create new */
		connection = new Connection (packet);
		Process * process = getProcess(connection, currentdevice);
	}

	if (needrefresh)
	{
		do_refresh();
		needrefresh = false;
	}
}

void quit_cb (int i)
{
	procclean();
	clear();
	endwin();
	exit(0);
}

void forceExit(const char *msg)
{
	if ((!tracemode)&&(!DEBUG)){
	        clear();
	        endwin();
	}
	std::cerr << msg << std::endl;
        exit(0);
}

static void versiondisplay(void)
{

	std::cerr << version << "\n";
}

static void help(void)
{
	std::cerr << "usage: nethogs [-V] [-d] [device]\n";
	std::cerr << "		-V : prints version.\n";
	std::cerr << "		-d : delay for update refresh rate in seconds. default is 1.\n";
	std::cerr << "		-t : tracemode.\n";
	std::cerr << "		device : device to monitor. default is eth0\n";
}

class device {
public:
	device (char * m_name, device * m_next = NULL)
	{
		name = m_name; next = m_next;
	}
	char * name;
	device * next;
};

class handle {
public:
	handle (pcap_t * m_handle, char * m_devicename = NULL, handle * m_next = NULL) {
		content = m_handle; next = m_next; devicename = m_devicename;
	}
	pcap_t * content;
	char * devicename;
	handle * next;
};

int main (int argc, char** argv)
{
	device * devices = NULL;

	for (argv++; *argv; argv++)
	{
		if (**argv=='-')
		{
			(*argv)++;
			switch(**argv)
			{
				case 'V': versiondisplay();
					  exit(0);
				case 'h': help();
					  exit(0);
				case 't': tracemode = true;
					  break;
				case 'd': if (argv[1])
					  {
						argv++;
						refreshdelay=atoi(*argv);
					  }
					  break;
				default : help();
					  exit(0);
			}
		}
		else
		{
			devices = new device (strdup(*argv), devices);
		}
	}

	if (devices == NULL)
		devices = new device (strdup("eth0"));

	if ((!tracemode) && (!DEBUG)){
		WINDOW * screen = initscr();
		raw();
		noecho();
		cbreak();
		nodelay(screen, TRUE);
		caption = new std::string ("NetHogs");
		caption->append(version);
		caption->append(", running at ");
	}

	if (NEEDROOT && (getuid() != 0))
		forceExit("You need to be root to run NetHogs !");

	char errbuf[PCAP_ERRBUF_SIZE];

	handle * handles = NULL;
	device * current_dev = devices;
	while (current_dev != NULL) {
		getLocal(current_dev->name);
		if ((!tracemode) && (!DEBUG)){
			caption->append(current_dev->name);
			caption->append(" ");
		}

		pcap_t * newhandle = pcap_open_live(current_dev->name, BUFSIZ, 0, 100, errbuf); 
		if (newhandle != NULL)
		{
			handles = new handle (newhandle, current_dev->name, handles);
		}

		current_dev = current_dev->next;
	}

	signal (SIGALRM, &alarm_cb);
	signal (SIGINT, &quit_cb);
	alarm (refreshdelay);
	while (1)
	{
		handle * current_handle = handles;
		while (current_handle != NULL)
		{
			currentdevice = current_handle->devicename;
			pcap_dispatch (current_handle->content, -1, process, NULL);
			current_handle = current_handle->next;
		}

		if ((!DEBUG)&&(!tracemode)) {
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
		if (needrefresh)
		{
			do_refresh(); 
			needrefresh = false;
		}
	}
}

