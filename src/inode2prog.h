/*
 * inode2prog.h
 *
 * Copyright (c) 2005,2008 Arnout Engelen
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
#ifndef __INODE2PROG_h
#define __INODE2PROG_h

/* this should be called quickly after the packet
 * arrived, since the inode may disappear from the table
 * quickly, too :) */

#include "nethogs.h"

struct prg_node {
  long inode;
  pid_t pid;
  std::string cmdline;
};

struct prg_node *findPID(unsigned long inode);

void prg_cache_clear();

// reread the inode-to-prg_node-mapping
void reread_mapping();

void garbage_collect_inodeproc();

#endif
