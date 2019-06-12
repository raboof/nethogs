/*
 * packet.h
 *
 * Copyright (c) 2004,2006 Arnout Engelen
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

#ifndef __PACKET_H
#define __PACKET_H

#define _BSD_SOURCE 1
#include <net/ethernet.h>

#include "nethogs.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

enum direction { dir_unknown, dir_incoming, dir_outgoing };

/* To initialise this module, call getLocal with the currently
 * monitored device (e.g. "eth0:1") */
bool getLocal(const char *device, bool tracemode);

class Packet {
public:
  in6_addr sip6;
  in6_addr dip6;
  in_addr sip;
  in_addr dip;
  unsigned short sport;
  unsigned short dport;
  u_int32_t len;
  timeval time;

  Packet(in_addr m_sip, unsigned short m_sport, in_addr m_dip,
         unsigned short m_dport, u_int32_t m_len, timeval m_time,
         direction dir = dir_unknown);
  Packet(in6_addr m_sip, unsigned short m_sport, in6_addr m_dip,
         unsigned short m_dport, u_int32_t m_len, timeval m_time,
         direction dir = dir_unknown);
  /* copy constructor */
  Packet(const Packet &old);
  ~Packet() {
    if (hashstring != NULL) {
      free(hashstring);
      hashstring = NULL;
    }
  }
  /* Packet (const Packet &old_packet); */
  /* copy constructor that turns the packet around */
  Packet *newInverted();

  bool isOlderThan(timeval t);
  /* is this packet coming from the local host? */
  bool Outgoing();

  bool match(Packet *other);
  bool matchSource(Packet *other);
  /* returns '1.2.3.4:5-1.2.3.4:6'-style string */
  char *gethashstring();

private:
  direction dir;
  short int sa_family;
  char *hashstring;
};

#endif
