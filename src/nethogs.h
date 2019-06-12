/*
 * nethogs.h
 *
 * Copyright (c) 2004-2006,2008,2010 Arnout Engelen
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

#ifndef __NETHOGS_H
#define __NETHOGS_H

#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __APPLE__
#include <sys/malloc.h>
#elif __FreeBSD__
#include <stdlib.h>
#else
#include <malloc.h>
#endif
#include <iostream>

#define _BSD_SOURCE 1

/* take the average speed over the last 5 seconds */
#define PERIOD 5

/* the amount of time after the last packet was received
 * after which a process is removed */
#define PROCESSTIMEOUT 150

/* the amount of time after the last packet was received
 * after which a connection is removed */
#define CONNTIMEOUT 50

#define DEBUG 0

#define REVERSEHACK 0

// 2 times: 32 characters, 7 ':''s, a ':12345'.
// 1 '-'
// -> 2*45+1=91. we make it 92, for the null.
#define HASHKEYSIZE 92

#define PROGNAME_WIDTH 512

// viewMode: how to represent numbers
enum {
  VIEWMODE_KBPS,
  VIEWMODE_TOTAL_KB,
  VIEWMODE_TOTAL_B,
  VIEWMODE_TOTAL_MB,
  VIEWMODE_MBPS,
  VIEWMODE_GBPS,
  VIEWMODE_COUNT
};

#define NORETURN __attribute__((__noreturn__))

void forceExit(bool success, const char *msg, ...) NORETURN;

class local_addr {
public:
  /* ipv4 constructor takes an in_addr_t */
  local_addr(in_addr_t m_addr, local_addr *m_next = NULL) {
    addr = m_addr;
    next = m_next;
    sa_family = AF_INET;
    string = (char *)malloc(16);
    inet_ntop(AF_INET, &m_addr, string, 15);
  }
  /* this constructor takes an char address[33] */
  local_addr(struct in6_addr *m_addr, local_addr *m_next = NULL) {
    addr6 = *m_addr;
    next = m_next;
    sa_family = AF_INET6;
    string = (char *)malloc(64);
    inet_ntop(AF_INET6, &m_addr, string, 63);
  }

  bool contains(const in_addr_t &n_addr);
  bool contains(const struct in6_addr &n_addr);
  char *string;
  local_addr *next;

private:
  in_addr_t addr;
  struct in6_addr addr6;
  short int sa_family;
};

void quit_cb(int i);

const char *getVersion();

#endif
