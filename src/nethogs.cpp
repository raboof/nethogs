/*
 * `nethogs.cpp`
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 *
 */

#include "nethogs.h"

#include <cassert>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <string>
#include <unistd.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "cui.h"

extern "C" {
#include "decpcap.h"
}

#include "connection.h"
#include "devices.h"
#include "packet.h"
#include "process.h"

extern Process *unknownudp;

time_t refreshdelay = 1;
unsigned refreshlimit = 0;
unsigned refreshcount = 0;
unsigned processlimit = 0;
bool tracemode = false;
bool bughuntmode = false;
// sort on sent or received?
bool sortRecv = true;
bool showcommandline = false;
bool showBasename = false;
// viewMode: kb/s or total
int viewMode = VIEWMODE_KBPS;
const char version[] = " version " VERSION;
timeval curtime;

bool local_addr::contains(const in_addr_t &n_addr) {
  if ((sa_family == AF_INET) && (n_addr == addr))
    return true;
  if (next == NULL)
    return false;
  return next->contains(n_addr);
}

bool local_addr::contains(const struct in6_addr &n_addr) {
  if (sa_family == AF_INET6) {
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
    // if (addr6.s6_addr == n_addr.s6_addr)
    if (memcmp(&addr6, &n_addr, sizeof(struct in6_addr)) == 0) {
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
  const char *device;
  int sa_family;
  in_addr ip_src;
  in_addr ip_dst;
  in6_addr ip6_src;
  in6_addr ip6_dst;
};

const char *getVersion() { return version; }

int process_tcp(u_char *userdata, const dp_header *header,
                const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  struct tcphdr *tcp = (struct tcphdr *)m_packet;

  curtime = header->ts;

  /* get info from userdata, then call getPacket */
  Packet *packet;
  switch (args->sa_family) {
  case AF_INET:
#if defined(__APPLE__) || defined(__FreeBSD__)
    packet = new Packet(args->ip_src, ntohs(tcp->th_sport), args->ip_dst,
                        ntohs(tcp->th_dport), header->len, header->ts);
#else
    packet = new Packet(args->ip_src, ntohs(tcp->source), args->ip_dst,
                        ntohs(tcp->dest), header->len, header->ts);
#endif
    break;
  case AF_INET6:
#if defined(__APPLE__) || defined(__FreeBSD__)
    packet = new Packet(args->ip6_src, ntohs(tcp->th_sport), args->ip6_dst,
                        ntohs(tcp->th_dport), header->len, header->ts);
#else
    packet = new Packet(args->ip6_src, ntohs(tcp->source), args->ip6_dst,
                        ntohs(tcp->dest), header->len, header->ts);
#endif
    break;
  default:
    std::cerr << "Invalid address family for TCP packet: " << args->sa_family
              << std::endl;
    return true;
  }

  Connection *connection = findConnection(packet, IPPROTO_TCP);

  if (connection != NULL) {
    /* add packet to the connection */
    connection->add(packet);
  } else {
    /* else: unknown connection, create new */
    connection = new Connection(packet);
    getProcess(connection, args->device, IPPROTO_TCP);
  }
  delete packet;

  /* we're done now. */
  return true;
}

int process_udp(u_char *userdata, const dp_header *header,
                const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  struct udphdr *udp = (struct udphdr *)m_packet;

  curtime = header->ts;

  Packet *packet;
  switch (args->sa_family) {
  case AF_INET:
#if defined(__APPLE__) || defined(__FreeBSD__)
    packet = new Packet(args->ip_src, ntohs(udp->uh_sport), args->ip_dst,
                        ntohs(udp->uh_dport), header->len, header->ts);
#else
    packet = new Packet(args->ip_src, ntohs(udp->source), args->ip_dst,
                        ntohs(udp->dest), header->len, header->ts);
#endif
    break;
  case AF_INET6:
#if defined(__APPLE__) || defined(__FreeBSD__)
    packet = new Packet(args->ip6_src, ntohs(udp->uh_sport), args->ip6_dst,
                        ntohs(udp->uh_dport), header->len, header->ts);
#else
    packet = new Packet(args->ip6_src, ntohs(udp->source), args->ip6_dst,
                        ntohs(udp->dest), header->len, header->ts);
#endif
    break;
  default:
    std::cerr << "Invalid address family for UDP packet: " << args->sa_family
              << std::endl;
    return true;
  }

  // if (DEBUG)
  //	std::cout << "Got packet from " << packet->gethashstring() << std::endl;

  Connection *connection = findConnection(packet, IPPROTO_UDP);

  if (connection != NULL) {
    /* add packet to the connection */
    connection->add(packet);
  } else {
    /* else: unknown connection, create new */
    connection = new Connection(packet);
    getProcess(connection, args->device, IPPROTO_UDP);
  }
  delete packet;

  /* we're done now. */
  return true;
}

int process_ip(u_char *userdata, const dp_header * /* header */,
               const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  struct ip *ip = (struct ip *)m_packet;
  args->sa_family = AF_INET;
  args->ip_src = ip->ip_src;
  args->ip_dst = ip->ip_dst;

  /* we're not done yet - also parse tcp :) */
  return false;
}

int process_ip6(u_char *userdata, const dp_header * /* header */,
                const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  const struct ip6_hdr *ip6 = (struct ip6_hdr *)m_packet;
  args->sa_family = AF_INET6;
  args->ip6_src = ip6->ip6_src;
  args->ip6_dst = ip6->ip6_dst;

  /* we're not done yet - also parse tcp :) */
  return false;
}

class handle {
public:
  handle(dp_handle *m_handle, const char *m_devicename = NULL,
         handle *m_next = NULL) {
    content = m_handle;
    next = m_next;
    devicename = m_devicename;
  }
  dp_handle *content;
  const char *devicename;
  handle *next;
};
