/* 
 * packet.cpp
 *
 * Copyright (c) 2004-2006,2008 Arnout Engelen
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


#include "nethogs.h"
#include <iostream>
#include "packet.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <malloc.h>
#include <assert.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>
#include <stdio.h>
// #include "inet6.c"

local_addr * local_addrs = NULL;

/* moves the pointer right until a non-space is seen */
char * stripspaces (char * input)
{
	char * retval = input;
	while (*retval == ' ')
	  retval++;
	return retval;
}

/*
 * getLocal
 *	device: This should be device explicit (e.g. eth0:1)
 *
 * uses ioctl to get address of this device, and adds it to the
 * local_addrs-list.
 */
void getLocal (const char *device, bool tracemode)
{
	/* get local IPv4 addresses */
	int sock;
	struct ifreq iFreq;
	struct sockaddr_in *saddr;

	if((sock=socket(AF_INET, SOCK_RAW, htons(0x0806)))<0){
		forceExit("creating socket failed while establishing local IP - are you root?", -3);
	}
	strcpy(iFreq.ifr_name, device);
	if(ioctl(sock, SIOCGIFADDR, &iFreq)<0){
		forceExit("ioctl failed while establishing local IP for selected device %s. You may specify the device on the command line.", -4, device);
	}
	saddr=(struct sockaddr_in*)&iFreq.ifr_addr;
	local_addrs = new local_addr (saddr->sin_addr.s_addr, local_addrs);

	if (tracemode || DEBUG) {
		printf ("Adding local address: %s\n", inet_ntoa(saddr->sin_addr));
	}

	/* also get local IPv6 addresses */
	FILE * ifinfo = fopen ("/proc/net/if_inet6", "r");
	char buffer [500];
	if (ifinfo)
	{
		do
		{
			if (fgets(buffer, sizeof(buffer), ifinfo))
			{
				char address [33];
				char ifname [9];
				int n_results = sscanf (buffer, "%32[0-9a-f] %*d %*d %*d %*d %8[0-9a-zA-Z]", address, ifname);
				assert (n_results = 2);

				if (strcmp (stripspaces(ifname), device) == 0)
				{
					local_addrs = new local_addr (address, local_addrs);
				}
#if DEBUG
				else
				{
				  	std::cerr << "Address skipped for interface " << ifname << std::endl;
				}
#endif
			}
		} while (!feof(ifinfo));
		fclose(ifinfo);
	}
}

typedef u_int32_t tcp_seq;

/* ppp header, i hope ;) */
/* glanced from ethereal, it's 16 bytes, and the payload packet type is
 * in the last 2 bytes... */
struct ppp_header {
	u_int16_t dummy1;
	u_int16_t dummy2;
	u_int16_t dummy3;
	u_int16_t dummy4;
	u_int16_t dummy5;
	u_int16_t dummy6;
	u_int16_t dummy7;

	u_int16_t packettype;
};

/* TCP header */
// TODO take from elsewhere.
struct tcp_hdr {
       u_short th_sport; /* source port */
       u_short th_dport; /* destination port */
       tcp_seq th_seq; /* sequence number */
       tcp_seq th_ack; /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
       u_int th_x2:4, /* (unused) */
       th_off:4; /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
       u_int th_off:4, /* data offset */
       th_x2:4; /* (unused) */
#endif
       u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
       u_short th_win; /* window */
       u_short th_sum; /* checksum */
       u_short th_urp; /* urgent pointer */
};
Packet::Packet (in_addr m_sip, unsigned short m_sport, in_addr m_dip, unsigned short m_dport, u_int32_t m_len, timeval m_time, direction m_dir)
{
	sip = m_sip; sport = m_sport;
	dip = m_dip; dport = m_dport;
	len = m_len; time = m_time;
	dir = m_dir; sa_family = AF_INET;
	hashstring = NULL;
}

Packet::Packet (in6_addr m_sip, unsigned short m_sport, in6_addr m_dip, unsigned short m_dport, u_int32_t m_len, timeval m_time, direction m_dir)
{
	sip6 = m_sip; sport = m_sport;
	dip6 = m_dip; dport = m_dport;
	len = m_len; time = m_time;
	dir = m_dir; sa_family = AF_INET6;
	hashstring = NULL;
}

Packet * Packet::newInverted () {
	/* TODO if this is a bottleneck, we can calculate the direction */
	if (sa_family == AF_INET)
		return new Packet (dip, dport, sip, sport, len, time, dir_unknown);
	else
		return new Packet (dip6, dport, sip6, sport, len, time, dir_unknown);
}

/* constructs returns a new Packet() structure with the same contents as this one */
Packet::Packet (const Packet &old_packet) {
    	sip = old_packet.sip; sport = old_packet.sport;
    	sip6 = old_packet.sip6;
    	dip6 = old_packet.dip6;
    	dip = old_packet.dip; dport = old_packet.dport;
    	len = old_packet.len; time = old_packet.time;
	sa_family = old_packet.sa_family;
    	if (old_packet.hashstring == NULL)
		hashstring = NULL;
    	else
    		hashstring = strdup(old_packet.hashstring);
	dir = old_packet.dir;
}

bool sameinaddr(in_addr one, in_addr other)
{
	return one.s_addr == other.s_addr;
}

bool Packet::isOlderThan (timeval t) {
	std::cout << "Comparing " << time.tv_sec << " <= " << t.tv_sec << std::endl;
	return (time.tv_sec <= t.tv_sec);
}

bool Packet::Outgoing () {
	/* must be initialised with getLocal("eth0:1");) */
	assert (local_addrs != NULL);

	switch (dir) {
	  case dir_outgoing:
		return true;
	  case dir_incoming:
		return false;
	  case dir_unknown:
		bool islocal;
		if (sa_family == AF_INET)
			islocal = local_addrs->contains(sip.s_addr);
		else
			islocal = local_addrs->contains(sip6);
		if (islocal) {
		  	dir = dir_outgoing;
		  	return true;
		} else {
		  	/*if (DEBUG) {
				if (sa_family == AF_INET)
					islocal = local_addrs->contains(dip.s_addr);
				else
					islocal = local_addrs->contains(dip6);
				if (!islocal) {
					std::cerr << "Neither dip nor sip are local: ";
					char addy [50];
					inet_ntop (AF_INET6, &sip6, addy, 49);
					std::cerr << addy << std::endl;
					inet_ntop (AF_INET6, &dip6, addy, 49);
					std::cerr << addy << std::endl;

					return false;
				}
		  	}*/
		  	dir = dir_incoming;
		  	return false;
		}
	}
	return false;
}

/* returns the packet in '1.2.3.4:5-1.2.3.4:5'-form, for use in the 'conninode' table */
/* '1.2.3.4' should be the local address. */
/* the calling code should take care of deletion of the hash string */
char * Packet::gethashstring ()
{
	if (hashstring != NULL)
	{
		return hashstring;
	}

	hashstring = (char *) malloc (HASHKEYSIZE * sizeof(char));

	char * local_string  = (char *) malloc (50);
	char * remote_string = (char *) malloc (50);
	if (sa_family == AF_INET) {
		inet_ntop(sa_family, &sip, local_string,  49);
		inet_ntop(sa_family, &dip, remote_string, 49);
	} else {
		inet_ntop(sa_family, &sip6, local_string,  49);
		inet_ntop(sa_family, &dip6, remote_string, 49);
	}
	if (Outgoing()) {
		snprintf(hashstring, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d", local_string, sport, remote_string, dport);
	} else {
		snprintf(hashstring, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d", remote_string, dport, local_string, sport);
	}
	free (local_string);
	free (remote_string);
	//if (DEBUG)
	//	std::cout << "Returning newly created hash string: " << hashstring << std::endl;
	return hashstring;
}

/* 2 packets match if they have the same
 * source and destination ports and IP's. */
bool Packet::match (Packet * other)
{
	return (sport == other->sport) && (dport == other->dport)
		&& (sameinaddr(sip, other->sip)) && (sameinaddr(dip, other->dip));
}
