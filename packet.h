#ifndef __PACKET_H
#define __PACKET_H

#define _BSD_SOURCE 1
#include <net/ethernet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nethogs.h"

enum direction {
  dir_unknown, 
  dir_incoming, 
  dir_outgoing
};

/* To initialise this module, call getLocal with the currently
 * monitored device (e.g. "eth0:1") */
void getLocal (const char *device);

class Packet
{
public:
	in6_addr sip6;
	in6_addr dip6;
	in_addr sip;
	in_addr dip;
	unsigned short sport;
	unsigned short dport;
	u_int32_t len;
	timeval time;

	Packet (in_addr m_sip, unsigned short m_sport, in_addr m_dip, unsigned short m_dport, u_int32_t m_len, timeval m_time, direction dir = dir_unknown);
	Packet (in6_addr m_sip, unsigned short m_sport, in6_addr m_dip, unsigned short m_dport, u_int32_t m_len, timeval m_time, direction dir = dir_unknown);
	/* copy constructor */
	Packet (const Packet &old);
	~Packet ()
	{
		if (hashstring != NULL)
		{
			free (hashstring);
			hashstring = NULL;
		}
	}
	/* Packet (const Packet &old_packet); */
	/* copy constructor that turns the packet around */
	Packet * newInverted ();

	bool isOlderThan(timeval t);
	/* is this packet coming from the local host? */
	bool Outgoing ();

	bool match (Packet * other);
	/* returns '1.2.3.4:5-1.2.3.4:6'-style string */
	char * gethashstring();
private:
	direction dir;
	short int sa_family;
	char * hashstring;
};

#endif
