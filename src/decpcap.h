/*
 * decpcap.h
 *
 * Copyright (c) 2004-2006,2011 Arnout Engelen
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
#ifndef __DECPCAP_H
#define __DECPCAP_H

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define DP_ERRBUF_SIZE PCAP_ERRBUF_SIZE
extern bool catchall;
/* definitions */

enum dp_packet_type {
  dp_packet_ethernet,
  dp_packet_ppp,
  dp_packet_sll,
  dp_packet_ip,
  dp_packet_ip6,
  dp_packet_tcp,
  dp_packet_udp,
  dp_n_packet_types
};

/*enum dp_link_type {
        dp_link_ethernet,
        dp_link_ppp,
        dp_n_link_types
};*/

/*struct dp_header {
 * pcap
};*/
typedef struct pcap_pkthdr dp_header;

typedef int (*dp_callback)(u_char *, const dp_header *, const u_char *);

struct dp_handle {
  pcap_t *pcap_handle;
  dp_callback callback[dp_n_packet_types];
  int linktype;
  u_char *userdata;
  int userdata_size;
};

/* functions to set up a handle (which is basically just a pcap handle) */

struct dp_handle *dp_open_live(const char *device, int snaplen, int promisc,
                               int to_ms, char *filter, char *errbuf);
struct dp_handle *dp_open_offline(char *fname, char *ebuf);

/* functions to add callbacks */

void dp_addcb(struct dp_handle *handle, enum dp_packet_type type,
              dp_callback callback);

/* functions to parse payloads */

void dp_parse(enum dp_packet_type type, void *packet);

/* functions to start monitoring */

int dp_dispatch(struct dp_handle *handler, int count, u_char *user, int size);

/* functions that simply call libpcap */

int dp_datalink(struct dp_handle *handle);

int dp_setnonblock(struct dp_handle *handle, int i, char *errbuf);

char *dp_geterr(struct dp_handle *handle);

#endif
