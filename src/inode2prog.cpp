/*
 * inode2prog.cpp
 *
 * Copyright (c) 2005,2006,2008,2009 Arnout Engelen
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

#include <sys/types.h>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <ctype.h>
#include <cstdlib>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <string>
#include <map>
#include <sys/stat.h>
#include <fcntl.h>
#include <climits>

#include "inode2prog.h"

extern bool bughuntmode;

// Not sure, but assuming there's no more PID's than go into 64 unsigned bits..
const int MAX_PID_LENGTH = 20;

// Max length of filenames in /proc/<pid>/fd/*. These are numeric, so 10 digits
// seems like a safe assumption.
const int MAX_FDLINK = 10;

/* maps from inode to program-struct */
std::map<unsigned long, prg_node *> inodeproc;

bool is_number(const char *string) {
  while (*string) {
    if (!isdigit(*string))
      return false;
    string++;
  }
  return true;
}

unsigned long str2ulong(const char *ptr) {
  unsigned long retval = 0;

  while ((*ptr >= '0') && (*ptr <= '9')) {
    retval *= 10;
    retval += *ptr - '0';
    ptr++;
  }
  return retval;
}

int str2int(const char *ptr) {
  int retval = 0;

  while ((*ptr >= '0') && (*ptr <= '9')) {
    retval *= 10;
    retval += *ptr - '0';
    ptr++;
  }
  return retval;
}

static bool read_file(int fd, std::string& content) {
  char buf[255];

  int length;
  while ((length = read(fd, buf, sizeof(buf))) > 0) {
    content.append(buf, length);
  }

  return length >= 0;
}

static bool read_file(const char *filepath, std::string& content) {
  int fd = open(filepath, O_RDONLY);

  if (fd < 0) {
    return false;
  }

  bool result = read_file(fd, content);
  close(fd);

  return result;
}

bool getcmdline(pid_t pid, std::string& cmdline) {
  const int maxfilenamelen = 14 + MAX_PID_LENGTH + 1;
  char filename[maxfilenamelen];

  std::snprintf(filename, maxfilenamelen, "/proc/%d/cmdline", pid);

  bool replace_null = false;
  cmdline.clear();
  if (!read_file(filename, cmdline)) {
    return false;
  }

  if (cmdline.empty() || cmdline[cmdline.length() - 1] != '\0') {
    // invalid content of cmdline file. Add null char to allow further
    // processing.
    cmdline.append(1, '\0');
  }

  // join parameters, keep prgname separate, don't overwrite trailing null
  for (size_t idx = 0; idx < (cmdline.length() - 1); idx++) {
    if (cmdline[idx] == 0x00) {
      if (replace_null) {
        cmdline[idx] = ' ';
      }
      replace_null = true;
    }
  }

  return true;
}

void setnode(unsigned long inode, pid_t pid) {
  prg_node *current_value = inodeproc[inode];

  if (current_value == NULL || current_value->pid != pid) {
    prg_node *newnode = new prg_node;
    newnode->inode = inode;
    newnode->pid = pid;
    bool result = getcmdline(pid, newnode->cmdline);
    if (result) {
      inodeproc[inode] = newnode;
    } else {
      inodeproc.erase(inode);
      if (bughuntmode) {
        if (errno == ENOENT || errno == ESRCH) {
          std::cout << "Process " << pid << " exited during getcmdline()\n";
        } else {
          std::cerr << "Error getcmdline() on process " << pid << ": "
                    << strerror(errno) << std::endl;
        }
      }
    }

    delete current_value;
  }
}

void get_info_by_linkname(const char *pid, const char *linkname) {
  if (strncmp(linkname, "socket:[", 8) == 0) {
    setnode(str2ulong(linkname + 8), str2int(pid));
  }
}

/* updates the `inodeproc' inode-to-prg_node
 * for all inodes belonging to this PID
 * (/proc/pid/fd/42)
 * */
void get_info_for_pid(const char *pid) {
  char dirname[10 + MAX_PID_LENGTH];

  size_t dirlen = 10 + strlen(pid);
  snprintf(dirname, dirlen, "/proc/%s/fd", pid);

  DIR *dir = opendir(dirname);

  if (!dir) {
    if (bughuntmode) {
      std::cout << "Couldn't open dir " << dirname << ": " << strerror(errno)
                << "\n";
    }
    return;
  }

  /* walk through /proc/%s/fd/... */
  dirent *entry;
  while ((entry = readdir(dir))) {
    if (entry->d_type != DT_LNK)
      continue;
    // std::cout << "Looking at: " << entry->d_name << std::endl;

    size_t fromlen = dirlen + strlen(entry->d_name) + 1;
    char fromname[10 + MAX_PID_LENGTH + 1 + MAX_FDLINK];
    snprintf(fromname, fromlen, "%s/%s", dirname, entry->d_name);

    // std::cout << "Linking from: " << fromname << std::endl;

    int linklen = 80;
    char linkname[linklen];
    int usedlen = readlink(fromname, linkname, linklen - 1);
    if (usedlen == -1) {
      continue;
    }
    assert(usedlen < linklen);
    linkname[usedlen] = '\0';
    get_info_by_linkname(pid, linkname);
  }
  closedir(dir);
}

/* updates the `inodeproc' inode-to-prg_node mapping
 * for all processes in /proc */
void reread_mapping() {
  DIR *proc = opendir("/proc");

  if (proc == 0) {
    std::cerr << "Error reading /proc, needed to get inode-to-pid-maping\n";
    exit(1);
  }

  dirent *entry;

  while ((entry = readdir(proc))) {
    if (entry->d_type != DT_DIR)
      continue;

    if (!is_number(entry->d_name))
      continue;

    get_info_for_pid(entry->d_name);
  }
  closedir(proc);
}

struct prg_node *findPID(unsigned long inode) {
  /* we first look in inodeproc */
  struct prg_node *node = inodeproc[inode];

  if (node != NULL) {
    if (bughuntmode) {
      std::cout << ":) Found pid in inodeproc table" << std::endl;
    }
    return node;
  }

#ifndef __APPLE__
  reread_mapping();
#endif

  struct prg_node *retval = inodeproc[inode];
  if (bughuntmode) {
    if (retval == NULL) {
      std::cout << ":( No pid after inodeproc refresh" << std::endl;
    } else {
      std::cout << ":) Found pid after inodeproc refresh" << std::endl;
    }
  }
  return retval;
}

void prg_cache_clear(){};

/*void main () {
        std::cout << "Fooo\n";
        reread_mapping();
        std::cout << "Haihai\n";
}*/
