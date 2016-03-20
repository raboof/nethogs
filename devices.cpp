/*
 * devices.cpp
 *
 * Copyright (c) 2011 Arnout Engelen
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

#include "devices.h"

#include <iostream>
#include <cstring>

#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

device *get_default_devices() {
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    std::cerr << "Fail to get interface addresses" << std::endl;
    // perror("getifaddrs");
    return NULL;
  }

  device *devices = NULL;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    // The interface is up, not a loopback and running ?
    if (!(ifa->ifa_flags & IFF_LOOPBACK) && (ifa->ifa_flags & IFF_UP) &&
        (ifa->ifa_flags & IFF_RUNNING)) {
      // Check if the interface is already known by going through all the
      // devices
      bool found = false;
      device *pIter = devices;
      while (pIter != NULL) {
        if (strcmp(ifa->ifa_name, pIter->name) == 0) {
          found = true;
        }
        pIter = pIter->next;
      }

      // We found a new interface, let's add it
      if (found == false) {
        devices = new device(strdup(ifa->ifa_name), devices);
      }
    }
  }

  freeifaddrs(ifaddr);
  return devices;
}
