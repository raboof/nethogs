/*
 * devices.h
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

#ifndef __DEVICES_H
#define __DEVICES_H

#include <cstddef> // NULL

class device {
public:
  device(const char *m_name, device *m_next = NULL) {
    name = m_name;
    next = m_next;
  }
  const char *name;
  device *next;
};

/**
 * This function can return null, if no good interface is found
 * The function avoids loopback interface and down/not running interfaces
 */
device *get_default_devices();

#endif
