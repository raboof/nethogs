/*
 * decpcap.c
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

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <string.h> // for memcpy
#include <pcap.h>
#include "decpcap.h"

#define DP_DEBUG 0

/* functions to set up a handle (which is basically just a pcap handle) */

struct dp_handle *dp_fillhandle(pcap_t *phandle) {
  struct dp_handle *retval =
      (struct dp_handle *)malloc(sizeof(struct dp_handle));
  int i;
  retval->pcap_handle = phandle;

  for (i = 0; i < dp_n_packet_types; i++) {
    retval->callback[i] = NULL;
  }

  retval->linktype = pcap_datalink(retval->pcap_handle);

  switch (retval->linktype) {
  case (DLT_EN10MB):
    fprintf(stdout, "Ethernet link detected\n");
    break;
  case (DLT_PPP):
    fprintf(stdout, "PPP link detected\n");
    break;
  case (DLT_LINUX_SLL):
    fprintf(stdout, "Linux Cooked Socket link detected\n");
    break;
  default:
    fprintf(stdout, "No PPP or Ethernet link: %d\n", retval->linktype);
    // TODO maybe error? or 'other' callback?
    break;
  }

  return retval;
}

struct dp_handle *dp_open_offline(char *fname, char *ebuf) {
  pcap_t *temp = pcap_open_offline(fname, ebuf);

  if (temp == NULL) {
    return NULL;
  }

  return dp_fillhandle(temp);
}

struct dp_handle *dp_open_live(const char *device, int snaplen, int promisc,
                               int to_ms, char *errbuf) {
  pcap_t *temp = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);

  if (temp == NULL) {
    return NULL;
  }

  return dp_fillhandle(temp);
}

/* functions to add callbacks */

void dp_addcb(struct dp_handle *handle, enum dp_packet_type type,
              dp_callback callback) {
  handle->callback[type] = callback;
}

/* functions for parsing the payloads */

void dp_parse_tcp(struct dp_handle *handle, const dp_header *header,
                  const u_char *packet) {
  // const struct tcphdr * tcp = (struct tcphdr *) packet;
  // u_char * payload = (u_char *) packet + sizeof (struct tcphdr);

  if (handle->callback[dp_packet_tcp] != NULL) {
    int done =
        (handle->callback[dp_packet_tcp])(handle->userdata, header, packet);
    if (done)
      return;
  }
  // TODO: maybe `pass on' payload to lower-level protocol parsing
}

void dp_parse_ip(struct dp_handle *handle, const dp_header *header,
                 const u_char *packet) {
  const struct ip *ip = (struct ip *)packet;
  if (DP_DEBUG) {
    fprintf(stdout, "Looking at packet with length %ud\n", header->len);
  }
  u_char *payload = (u_char *)packet + sizeof(struct ip);

  if (handle->callback[dp_packet_ip] != NULL) {
    int done =
        (handle->callback[dp_packet_ip])(handle->userdata, header, packet);
    if (done)
      return;
  }
  switch (ip->ip_p) {
  case IPPROTO_TCP:
    dp_parse_tcp(handle, header, payload);
    break;
  default:
    // TODO: maybe support for non-tcp IP packets
    break;
  }
}

void dp_parse_ip6(struct dp_handle *handle, const dp_header *header,
                  const u_char *packet) {
  const struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  u_char *payload = (u_char *)packet + sizeof(struct ip6_hdr);

  if (handle->callback[dp_packet_ip6] != NULL) {
    int done =
        (handle->callback[dp_packet_ip6])(handle->userdata, header, packet);
    if (done)
      return;
  }
  switch ((ip6->ip6_ctlun).ip6_un1.ip6_un1_nxt) {
  case IPPROTO_TCP:
    dp_parse_tcp(handle, header, payload);
    break;
  default:
    // TODO: maybe support for non-tcp ipv6 packets
    break;
  }
}

void dp_parse_ethernet(struct dp_handle *handle, const dp_header *header,
                       const u_char *packet) {
  const struct ether_header *ethernet = (struct ether_header *)packet;
  u_char *payload = (u_char *)packet + sizeof(struct ether_header);
  u_int16_t protocol = 0;

  /* call handle if it exists */
  if (handle->callback[dp_packet_ethernet] != NULL) {
    int done = (handle->callback[dp_packet_ethernet])(handle->userdata, header,
                                                      packet);

    /* return if handle decides we're done */
    if (done)
      return;
  }

  /* parse payload */
  protocol = ntohs(ethernet->ether_type);
  switch (protocol) {
  case ETHERTYPE_IP:
    dp_parse_ip(handle, header, payload);
    break;
  case ETHERTYPE_IPV6:
    dp_parse_ip6(handle, header, payload);
    break;
  default:
    // TODO: maybe support for other protocols apart from IPv4 and IPv6
    break;
  }
}

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

void dp_parse_ppp(struct dp_handle *handle, const dp_header *header,
                  const u_char *packet) {
  const struct ppp_header *ppp = (struct ppp_header *)packet;
  u_char *payload = (u_char *)packet + sizeof(struct ppp_header);
  u_int16_t protocol = 0;

  /* call handle if it exists */
  if (handle->callback[dp_packet_ppp] != NULL) {
    int done =
        (handle->callback[dp_packet_ppp])(handle->userdata, header, packet);

    /* return if handle decides we're done */
    if (done)
      return;
  }

  /* parse payload */
  protocol = ntohs(ppp->packettype);
  switch (protocol) {
  case ETHERTYPE_IP:
    dp_parse_ip(handle, header, payload);
    break;
  case ETHERTYPE_IPV6:
    dp_parse_ip6(handle, header, payload);
    break;
  default:
    // TODO: support for other than IPv4 and IPv6
    break;
  }
}

/* linux cooked header, i hope ;) */
/* glanced from libpcap/ssl.h */
#define SLL_ADDRLEN 8 /* length of address field */
struct sll_header {
  u_int16_t sll_pkttype;          /* packet type */
  u_int16_t sll_hatype;           /* link-layer address type */
  u_int16_t sll_halen;            /* link-layer address length */
  u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
  u_int16_t sll_protocol;         /* protocol */
};

void dp_parse_linux_cooked(struct dp_handle *handle, const dp_header *header,
                           const u_char *packet) {
  const struct sll_header *sll = (struct sll_header *)packet;
  u_char *payload = (u_char *)packet + sizeof(struct sll_header);
  u_int16_t protocol = 0;

  /* call handle if it exists */
  if (handle->callback[dp_packet_sll] != NULL) {
    int done =
        (handle->callback[dp_packet_sll])(handle->userdata, header, packet);

    /* return if handle decides we're done */
    if (done)
      return;
  }

  /* parse payload */
  protocol = ntohs(sll->sll_protocol);
  switch (protocol) {
  case ETHERTYPE_IP:
    dp_parse_ip(handle, header, payload);
    break;
  case ETHERTYPE_IPV6:
    dp_parse_ip6(handle, header, payload);
    break;
  default:
    // TODO: support for other than IPv4 / IPv6
    break;
  }
}

/* functions to do the monitoring */
void dp_pcap_callback(u_char *u_handle, const struct pcap_pkthdr *header,
                      const u_char *packet) {
  struct dp_handle *handle = (struct dp_handle *)u_handle;
  struct dp_header;

  /* make a copy of the userdata for every packet */
  u_char *userdata_copy = (u_char *)malloc(handle->userdata_size);
  memcpy(userdata_copy, handle->userdata, handle->userdata_size);

  switch (handle->linktype) {
  case (DLT_EN10MB):
    dp_parse_ethernet(handle, header, packet);
    break;
  case (DLT_PPP):
    dp_parse_ppp(handle, header, packet);
    break;
  case (DLT_LINUX_SLL):
    dp_parse_linux_cooked(handle, header, packet);
    break;
  case (DLT_RAW):
  case (DLT_NULL):
    // hope for the best
    dp_parse_ip(handle, header, packet);
    break;
  default:
    fprintf(stdout, "Unknown linktype %d", handle->linktype);
    break;
  }
  free(userdata_copy);
}

int dp_dispatch(struct dp_handle *handle, int count, u_char *user, int size) {
  handle->userdata = user;
  handle->userdata_size = size;
  return pcap_dispatch(handle->pcap_handle, count, dp_pcap_callback,
                       (u_char *)handle);
}

int dp_setnonblock(struct dp_handle *handle, int i, char *errbuf) {
  return pcap_setnonblock(handle->pcap_handle, i, errbuf);
}

char *dp_geterr(struct dp_handle *handle) {
  return pcap_geterr(handle->pcap_handle);
}
