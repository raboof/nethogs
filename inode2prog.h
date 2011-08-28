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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */


/* this should be called quickly after the packet
 * arrived, since the inode may disappear from the table
 * quickly, too :) */

#include "nethogs.h"
// #define PROGNAME_WIDTH 200

struct prg_node {
    long inode;
    int pid;
    char name[PROGNAME_WIDTH];
};

struct prg_node * findPID (unsigned long inode);

void prg_cache_clear();
 
// reread the inode-to-prg_node-mapping
void reread_mapping ();
