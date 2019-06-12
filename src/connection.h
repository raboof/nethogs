/*
 * connection.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 *
 */
#ifndef __CONNECTION_H
#define __CONNECTION_H

#include "packet.h"
#include <iostream>

class PackListNode {
public:
  PackListNode(Packet *m_val, PackListNode *m_next = NULL) {
    val = m_val;
    next = m_next;
  }
  ~PackListNode() {
    delete val;
    if (next != NULL)
      delete next;
  }
  PackListNode *next;
  Packet *val;
};

class PackList {
public:
  PackList() { content = NULL; }
  PackList(Packet *m_val) {
    assert(m_val != NULL);
    content = new PackListNode(m_val);
  }
  ~PackList() {
    if (content != NULL)
      delete content;
  }

  /* sums up the total bytes used and removes 'old' packets */
  u_int64_t sumanddel(timeval t);

  /* calling code may delete packet */
  void add(Packet *p);

private:
  PackListNode *content;
};

class Connection {
public:
  /* constructs a connection, makes a copy of
   * the packet as 'refpacket', and adds the
   * packet to the packlist */
  /* packet may be deleted by caller */
  Connection(Packet *packet);

  ~Connection();

  /* add a packet to the packlist
   * will delete the packet structure
   * when it is 'merged with' (added to) another
   * packet
   */
  void add(Packet *packet);

  int getLastPacket() { return lastpacket; }

  /* sums up the total bytes used
   * and removes 'old' packets. */
  void sumanddel(timeval curtime, u_int64_t *recv, u_int64_t *sent);

  /* for checking if a packet is part of this connection */
  /* the reference packet is always *outgoing*. */
  Packet *refpacket;

  /* total sum or sent/received bytes */
  u_int64_t sumSent;
  u_int64_t sumRecv;

private:
  PackList *sent_packets;
  PackList *recv_packets;
  int lastpacket;
};

/* Find the connection this packet belongs to */
/* (the calling code may free the packet afterwards) */
Connection *findConnection(Packet *packet, short int packettype);

#endif
