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

#include <cstring>
#include <iostream>

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>

bool selected(int devc, char **devicenames, char *devicename) {
  if (devc == 0)
    return true;

  for (int i = 0; i < devc; i++)
    if (strcmp(devicenames[i], devicename) == 0)
      return true;

  return false;
}

bool already_seen(device *devices, char *devicename) {
  for (class device *current_device = devices; current_device != NULL;
       current_device = current_device->next) {
    if (strcmp(current_device->name, devicename) == 0)
      return true;
  }
  return false;
}

// The interface is up, not a loopback and running?
bool up_running(int ifa_flags) {
  return !(ifa_flags & IFF_LOOPBACK) && (ifa_flags & IFF_UP) &&
         (ifa_flags & IFF_RUNNING);
}

/**
 * This function can return null, if no good interface is found
 * When 'all' is set to 'false', the function avoids loopback interface and
 * down/not running interfaces
 */
device *get_devices(int devc, char **devicenames, bool all) {
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    std::cerr << "Failed to get interface addresses" << std::endl;
    // perror("getifaddrs");
    return NULL;
  }

  device *devices = NULL;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;
    if (!selected(devc, devicenames, ifa->ifa_name))
      continue;
    if (already_seen(devices, ifa->ifa_name))
      continue;
    if (!all && !up_running(ifa->ifa_flags))
      continue;

    devices = new device(strdup(ifa->ifa_name), devices);
  }

  freeifaddrs(ifaddr);
  return devices;
}

device *get_default_devices() { return get_devices(0, NULL, false); }
