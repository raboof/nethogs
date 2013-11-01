/* 
 * refresh.cpp
 *
 * Copyright (c) 2004 Arnout Engelen
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


#include <iostream>
#include <csignal>
#include <unistd.h>
#include "nethogs.h"

extern bool needrefresh;
extern unsigned refreshdelay;

void alarm_cb (int /*i*/)
{
    needrefresh = true;
    //cout << "Setting needrefresh\n";

    signal (SIGALRM, &alarm_cb);
    alarm(refreshdelay);
}

void manual_refresh_cb (int /*i*/)
{
    needrefresh = true;

    signal (SIGUSR1, &manual_refresh_cb);
}
