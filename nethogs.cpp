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

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "cui.h"

extern "C" {
	#include "decpcap.h"
}

#include "packet.h"
#include "connection.h"
#include "process.h"
#include "refresh.h"

unsigned refreshdelay = 1;
bool tracemode = false;
bool needrefresh = true;
//packet_type packettype = packet_ethernet;
//dp_link_type linktype = dp_link_ethernet;
const char version[] = " version " VERSION "." SUBVERSION "." MINORVERSION;

char * currentdevice = NULL;

timeval curtime;

bool local_addr::contains (const in_addr_t & n_addr) {
	if ((sa_family == AF_INET)
	    && (n_addr == addr))
		return true;
	if (next == NULL)
		return false;
	return next->contains(n_addr);
}

bool local_addr::contains(const struct in6_addr & n_addr) {
	if (sa_family == AF_INET6)
	{
		/*
		if (DEBUG) {
			char addy [50];
			std::cerr << "Comparing: ";
			inet_ntop (AF_INET6, &n_addr, addy, 49);
			std::cerr << addy << " and ";
			inet_ntop (AF_INET6, &addr6, addy, 49);
			std::cerr << addy << std::endl;
		}
		*/
		//if (addr6.s6_addr == n_addr.s6_addr)
		if (memcmp (&addr6, &n_addr, sizeof(struct in6_addr)) == 0)
		{
			if (DEBUG)
				std::cerr << "Match!" << std::endl;
			return true;
		}
	}
	if (next == NULL)
		return false;
	return next->contains(n_addr);
}

struct dpargs {
	int sa_family;
	in_addr ip_src;
	in_addr ip_dst;
	in6_addr ip6_src;
	in6_addr ip6_dst;
};

int process_tcp (u_char * userdata, const dp_header * header, const u_char * m_packet) {
	struct dpargs * args = (struct dpargs *) userdata;
	struct tcphdr * tcp = (struct tcphdr *) m_packet;

	curtime = header->ts;

	/* TODO get info from userdata, then call getPacket */
	Packet * packet; 
	switch (args->sa_family)
	{
		case (AF_INET):
			packet = new Packet (args->ip_src, ntohs(tcp->source), args->ip_dst, ntohs(tcp->dest), header->len, header->ts);
			break;
		case (AF_INET6):
			packet = new Packet (args->ip6_src, ntohs(tcp->source), args->ip6_dst, ntohs(tcp->dest), header->len, header->ts);
			break;
	}

	//if (DEBUG)
	//	std::cout << "Got packet from " << packet->gethashstring() << std::endl;

	Connection * connection = findConnection(packet);

	if (connection != NULL)
	{
		/* add packet to the connection */
		connection->add(packet);
		delete packet;
	} else {
		/* else: unknown connection, create new */
		connection = new Connection (packet);
		getProcess(connection, currentdevice);
	}

	if (needrefresh)
	{
		do_refresh();
		needrefresh = false;
	}

	/* we're done now. */
	return true;
}

int process_ip (u_char * userdata, const dp_header * header, const u_char * m_packet) {
	struct dpargs * args = (struct dpargs *) userdata;
	struct ip * ip = (struct ip *) m_packet;
	args->sa_family = AF_INET;
	args->ip_src = ip->ip_src;
	args->ip_dst = ip->ip_dst;

	/* we're not done yet - also parse tcp :) */
	return false;
}

int process_ip6 (u_char * userdata, const dp_header * header, const u_char * m_packet) {
	struct dpargs * args = (struct dpargs *) userdata;
	const struct ip6_hdr * ip6 = (struct ip6_hdr *) m_packet;
	args->sa_family = AF_INET6;
	args->ip6_src = ip6->ip6_src;
	args->ip6_dst = ip6->ip6_dst;

	/* we're not done yet - also parse tcp :) */
	return false;
}

void quit_cb (int i)
{
	procclean();
	if ((!tracemode) && (!DEBUG))
		exit_ui();
	exit(0);
}

void forceExit(const char *msg)
{
	if ((!tracemode)&&(!DEBUG)){
		exit_ui();
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
	//std::cerr << "usage: nethogs [-V] [-d seconds] [-t] [-p] [-f (eth|ppp))] [device [device [device ...]]]\n";
	std::cerr << "usage: nethogs [-V] [-d seconds] [-t] [-p] [device [device [device ...]]]\n";
	std::cerr << "		-V : prints version.\n";
	std::cerr << "		-d : delay for update refresh rate in seconds. default is 1.\n";
	std::cerr << "		-t : tracemode.\n";
	//std::cerr << "		-f : format of packets on interface, default is eth.\n";
	std::cerr << "		-p : sniff in promiscious mode (not recommended).\n";
	std::cerr << "		device : device(s) to monitor. default is eth0\n";
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
	handle (dp_handle * m_handle, char * m_devicename = NULL, 
			handle * m_next = NULL) {
		content = m_handle; next = m_next; devicename = m_devicename;
	}
	dp_handle * content;
	char * devicename;
	handle * next;
};

int main (int argc, char** argv)
{
	process_init();

	device * devices = NULL;
	//dp_link_type linktype = dp_link_ethernet;
	int promisc = 0;

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
				case 'p': promisc = 1;
					  break;
				case 'd': if (argv[1])
					  {
						argv++;
						refreshdelay=atoi(*argv);
					  }
					  break;
				/*case 'f': if (argv[1])
					  {
						argv++;
						if (strcmp (*argv, "ppp") == 0)
							linktype = dp_link_ppp;
						else if (strcmp (*argv, "eth") == 0)
							linktype = dp_link_ethernet;
					  }
					  break;
					  */
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
		init_ui();
	}

	if (NEEDROOT && (getuid() != 0))
		forceExit("You need to be root to run NetHogs !");

	char errbuf[PCAP_ERRBUF_SIZE];

	handle * handles = NULL;
	device * current_dev = devices;
	while (current_dev != NULL) {
		getLocal(current_dev->name);
		if ((!tracemode) && (!DEBUG)){
			//caption->append(current_dev->name);
			//caption->append(" ");
		}

		dp_handle * newhandle = dp_open_live(current_dev->name, BUFSIZ, promisc, 100, errbuf); 
		dp_addcb (newhandle, dp_packet_ip, process_ip);
		dp_addcb (newhandle, dp_packet_ip6, process_ip6);
		dp_addcb (newhandle, dp_packet_tcp, process_tcp);
		if (newhandle != NULL)
		{
			/* The following code solves sf.net bug 1019381, but is only available
			 * in newer versions of libpcap */

			/*if (pcap_setnonblock (newhandle, 1, errbuf) == -1)
			{
			  // ERROR
			}*/
			handles = new handle (newhandle, current_dev->name, handles);
		}

		current_dev = current_dev->next;
	}

	signal (SIGALRM, &alarm_cb);
	signal (SIGINT, &quit_cb);
	alarm (refreshdelay);
	fprintf(stderr, "Waiting for first packet to arrive (see sourceforge.net bug 1019381)\n");
	while (1)
	{
		handle * current_handle = handles;
		while (current_handle != NULL)
		{
			struct dpargs * userdata = (dpargs *) malloc (sizeof (struct dpargs));
			userdata->sa_family = AF_UNSPEC;
			currentdevice = current_handle->devicename;
			dp_dispatch (current_handle->content, -1, (u_char *)userdata, sizeof (struct dpargs));
			free (userdata);
			current_handle = current_handle->next;
		}

		if ((!DEBUG)&&(!tracemode)) {
			ui_tick();
		}
		if (needrefresh)
		{
			do_refresh(); 
			needrefresh = false;
		}
	}
}

