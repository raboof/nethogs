/*
 * decpcap_test.cpp
 *
 * Copyright (c) 2006,2011 Arnout Engelen
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

#include <iostream>

extern "C" {
#include "decpcap.h"
}

int process_tcp(u_char * /* userdata */, const dp_header * /* header */,
                const u_char * /* m_packet */) {
  std::cout << "Callback for processing TCP packet called" << std::endl;
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    std::cout << "Please, enter a filename" << std::endl;
  }

  char *errbuf = new char[DP_ERRBUF_SIZE];

  dp_handle *newhandle = dp_open_offline(argv[1], errbuf);
  dp_addcb(newhandle, dp_packet_tcp, process_tcp);
  int ret = dp_dispatch(newhandle, -1, NULL, 0);
  if (ret == -1) {
    std::cout << "Error dispatching: " << dp_geterr(newhandle);
  }
}
