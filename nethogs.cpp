/* nethogs.cpp
 *
 */

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

bool needrefresh = false;
unsigned refreshdelay = 1;

const char version[] = " version " VERSION "." SUBVERSION "." MINORVERSION;

timeval curtime;
std::string * caption;



void process (u_char * args, const struct pcap_pkthdr * header, const u_char * m_packet)
{
	curtime = header->ts;

	Packet * packet = getPacket (header, m_packet);
	if (packet == NULL)
		return;

	Connection * connection = findConnection(packet);
	if (connection != NULL)
	{
		connection->add(packet);
		return;
	}
	connection = new Connection (packet);
	Process * process = getProcess(connection);
	//process->addConnection (connection);
	
	if (needrefresh)
	{
		do_refresh();
		needrefresh = false;
	}

	return;
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
        clear();
        endwin();
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
	std::cerr << "		device : device to monitor. default is eth0\n";
}

int main (int argc, char** argv)
{
	char* dev = strdup("eth0");

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
			dev = strdup(*argv);
		}
	}
#if DEBUG
#else
	initscr();
	raw();
	noecho();
	cbreak();
#endif
	getLocal(dev);

	caption = new std::string ("NetHogs");
	caption->append(version);
	caption->append(", running at ");
	caption->append(dev);

	if (NEEDROOT && (getuid() != 0))
		forceExit("You need to be root to run NetHogs !");

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t * handle;
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);

	if (!handle)
		forceExit("Device is not active");

	signal (SIGALRM, &alarm_cb);
	signal (SIGINT, &quit_cb);
	alarm (refreshdelay);
	while (1)
	{
		pcap_dispatch (handle, -1, process, NULL);
		if (needrefresh)
		{
			do_refresh(); 
			needrefresh = false;
		}
	}
}

