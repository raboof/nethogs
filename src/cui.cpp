/*
 * cui.cpp
 *
 * Copyright (c) 2004-2006,2008,2010,2011 Arnout Engelen
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

/* NetHogs console UI */
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <pwd.h>
#include <string>
#include <strings.h>
#include <sys/types.h>

#include <iomanip>
#include <iostream>
#include <locale>
#include <sstream>

#include "nethogs.h"
#include "process.h"
#include <ncurses.h>

std::string *caption;
static int cursOrig;
extern const char version[];
extern ProcList *processes;
extern timeval curtime;

extern Process *unknowntcp;
extern Process *unknownudp;
extern Process *unknownip;

extern bool sortRecv;

extern int viewMode;
extern bool showcommandline;
extern bool showBasename;

extern unsigned refreshlimit;
extern unsigned refreshcount;

#define PID_MAX 4194303

const int COLUMN_WIDTH_PID = 7;
const int COLUMN_WIDTH_USER = 8;
const int MAX_COLUMN_WIDTH_DEV = 15;
const int MIN_COLUMN_WIDTH_DEV = 5;
const int COLUMN_WIDTH_SENT = 11;
const int COLUMN_WIDTH_RECEIVED = 11;
const int COLUMN_WIDTH_UNIT = 6;
const int NUMBER_OF_DECIMALS_SENT = 1;
const int NUMBER_OF_DECIMALS_RECEIVED = 1;

const char *COLUMN_FORMAT_PID = "%7d";

const char *COLUMN_FORMAT_SENT = "%s";
const char *COLUMN_FORMAT_RECEIVED = "%s";

// All descriptions are padded to 6 characters in length with spaces
const char *const desc_view_mode[VIEWMODE_COUNT] = {
    "KB/s  ", "KB    ", "B     ", "MB    ", "MB/s  ", "GB/s  "};

constexpr char FILE_SEPARATOR = '/';

std::string prettyFloat(double val, int decimals, int maxWidth);

class Line {
public:
  Line(const char *name, const char *cmdline, double n_recv_value,
       double n_sent_value, pid_t pid, uid_t uid, const char *n_devicename) {
    assert(pid >= 0);
    assert(pid <= PID_MAX);
    m_name = name;
    m_cmdline = cmdline;
    sent_value = n_sent_value;
    recv_value = n_recv_value;
    devicename = n_devicename;
    m_pid = pid;
    m_uid = uid;
    assert(m_pid >= 0);
  }

  void show(int row, unsigned int proglen, unsigned int devlen);
  void log();

  double sent_value;
  double recv_value;
  const char *devicename;

private:
  const char *m_name;
  const char *m_cmdline;
  pid_t m_pid;
  uid_t m_uid;
};

#include <sstream>

std::string itoa(int i) {
  std::stringstream out;
  out << i;
  return out.str();
}

/**
 * @returns the username that corresponds to this uid
 */
std::string uid2username(uid_t uid) {
  struct passwd *pwd = NULL;
  errno = 0;

  /* points to a static memory area, should not be freed */
  pwd = getpwuid(uid);

  if (pwd == NULL)
    if (errno == 0)
      return itoa(uid);
    else
      forceExit(false, "Error calling getpwuid(3) for uid %d: %d %s", uid,
                errno, strerror(errno));
  else
    return std::string(pwd->pw_name);
}

/**
 * Render the provided text at the specified location, truncating if the length
 * of the text exceeds a maximum. If the
 * text must be truncated, the text will be rendered up to max_len - 2
 * characters and then ".." will be rendered.
 */
static void mvaddstr_truncate_trailing(int row, int col, const char *str,
                                       std::size_t str_len,
                                       std::size_t max_len) {
  if (str_len < max_len) {
    mvaddstr(row, col, str);
  } else {
    mvaddnstr(row, col, str, max_len - 2);
    addstr("..");
  }
}

/**
 * Render the provided progname and cmdline at the specified location,
 * truncating if the length of the values exceeds a maximum.
 * If the text must be truncated, the text will be rendered up to max_len - 2
 * characters and then ".." will be rendered.
 * cmdline is truncated first and then progname.
 */
static void mvaddstr_truncate_cmdline(int row, int col, const char *progname,
                                      const char *cmdline,
                                      std::size_t max_len) {
  if (showBasename) {
    if (index(progname, FILE_SEPARATOR) != NULL) {
      progname = rindex(progname, FILE_SEPARATOR) + 1;
    }
  }

  std::size_t proglen = strlen(progname);
  std::size_t max_cmdlen;

  if (proglen > max_len) {
    mvaddnstr(row, col, progname, max_len - 2);
    addstr("..");
    max_cmdlen = 0;
  } else {
    mvaddstr(row, col, progname);
    max_cmdlen = max_len - proglen - 1;
  }

  if (showcommandline && cmdline) {

    std::size_t cmdlinelen = strlen(cmdline);

    if ((cmdlinelen + 1) > max_cmdlen) {
      if (max_cmdlen >= 3) {
        mvaddnstr(row, col + proglen + 1, cmdline, max_cmdlen - 3);
        addstr("..");
      }
    } else {
      mvaddstr(row, col + proglen + 1, cmdline);
    }
  }
}

void Line::show(int row, unsigned int proglen, unsigned int devlen) {
  assert(m_pid >= 0);
  assert(m_pid <= PID_MAX);

  const int column_offset_pid = 0;
  const int column_offset_user = column_offset_pid + COLUMN_WIDTH_PID + 1;
  const int column_offset_program = column_offset_user + COLUMN_WIDTH_USER + 1;
  const int column_offset_dev = column_offset_program + proglen + 2;
  const int column_offset_sent = column_offset_dev + devlen + 1;
  const int column_offset_received = column_offset_sent + COLUMN_WIDTH_SENT + 1;
  const int column_offset_unit =
      column_offset_received + COLUMN_WIDTH_RECEIVED + 1;

  // PID column
  if (m_pid == 0)
    mvaddch(row, column_offset_pid + COLUMN_WIDTH_PID - 1, '?');
  else
    mvprintw(row, column_offset_pid, COLUMN_FORMAT_PID, m_pid);

  std::string username = uid2username(m_uid);
  mvaddstr_truncate_trailing(row, column_offset_user, username.c_str(),
                             username.size(), COLUMN_WIDTH_USER);

  mvaddstr_truncate_cmdline(row, column_offset_program, m_name, m_cmdline,
                            proglen);

  mvaddstr(row, column_offset_dev, devicename);

  mvprintw(row, column_offset_sent, COLUMN_FORMAT_SENT,
           prettyFloat(sent_value, NUMBER_OF_DECIMALS_SENT, COLUMN_WIDTH_SENT)
               .c_str());

  mvprintw(row, column_offset_received, COLUMN_FORMAT_RECEIVED,
           prettyFloat(recv_value, NUMBER_OF_DECIMALS_RECEIVED,
                       COLUMN_WIDTH_RECEIVED)
               .c_str());

  mvaddstr(row, column_offset_unit, desc_view_mode[viewMode]);
}

void Line::log() {
  std::cout << m_name;
  if (showcommandline && m_cmdline)
    std::cout << ' ' << m_cmdline;
  std::cout << '/' << m_pid << '/' << m_uid << "\t" << sent_value << "\t"
            << recv_value << std::endl;
}

int get_devlen(Line *lines[], int nproc, int rows) {
  int devlen = MIN_COLUMN_WIDTH_DEV;
  int curlen;
  for (int i = 0; i < nproc; i++) {
    if (i + 3 < rows) {
      curlen = strlen(lines[i]->devicename);
      if (curlen > devlen)
        curlen = devlen;
    }
  }

  if (devlen > MAX_COLUMN_WIDTH_DEV)
    devlen = MAX_COLUMN_WIDTH_DEV;

  return devlen;
}

int GreatestFirst(const void *ma, const void *mb) {
  Line **pa = (Line **)ma;
  Line **pb = (Line **)mb;
  Line *a = *pa;
  Line *b = *pb;
  double aValue;
  if (sortRecv) {
    aValue = a->recv_value;
  } else {
    aValue = a->sent_value;
  }

  double bValue;
  if (sortRecv) {
    bValue = b->recv_value;
  } else {
    bValue = b->sent_value;
  }

  if (aValue > bValue) {
    return -1;
  }
  if (aValue == bValue) {
    return 0;
  }
  return 1;
}

void init_ui() {
  WINDOW *screen = initscr();
  cursOrig = curs_set(0);
  raw();
  noecho();
  cbreak();
  nodelay(screen, TRUE);
  caption = new std::string("NetHogs");
  caption->append(getVersion());
  // caption->append(", running at ");
}

void exit_ui() {
  clear();
  endwin();
  delete caption;
  if (cursOrig != ERR)
    curs_set(cursOrig);
}

void ui_tick() {
  switch (getch()) {
  case 'q':
    /* quit */
    quit_cb(0);
    break;
  case 's':
    /* sort on 'sent' */
    sortRecv = false;
    break;
  case 'r':
    /* sort on 'received' */
    sortRecv = true;
    break;
  case 'l':
    /* show cmdline' */
    showcommandline = !showcommandline;
    break;
  case 'm':
    /* switch mode: total vs kb/s */
    viewMode = (viewMode + 1) % VIEWMODE_COUNT;
    break;
  case 'b':
    /* show only the process basename */
    showBasename = !showBasename;
    break;
  }
}

void show_trace(Line *lines[], int nproc) {
  std::cout << "\nRefreshing:\n";

  /* print them */
  for (int i = 0; i < nproc; i++) {
    lines[i]->log();
    delete lines[i];
  }

  /* print the 'unknown' connections, for debugging */
  for (auto it = unknowntcp->connections.begin();
       it != unknowntcp->connections.end(); ++it) {
    std::cout << "Unknown connection: " << (*it)->refpacket->gethashstring()
              << std::endl;
  }
}

void show_ncurses(Line *lines[], int nproc) {
  int rows;             // number of terminal rows
  int cols;             // number of terminal columns
  unsigned int proglen; // max length of the "PROGRAM" column

  double sent_global = 0;
  double recv_global = 0;

  getmaxyx(stdscr, rows, cols); /* find the boundaries of the screen */

  if (cols < 62) {
    erase();
    mvprintw(0, 0,
             "The terminal is too narrow! Please make it wider.\nI'll wait...");
    return;
  }

  if (cols > PROGNAME_WIDTH)
    cols = PROGNAME_WIDTH;

  // issue #110 - maximum devicename length min=5, max=15
  int devlen = get_devlen(lines, nproc, rows);

  proglen = cols - 50 - devlen;

  erase();
  mvprintw(0, 0, "%s", caption->c_str());
  attron(A_REVERSE);
  mvprintw(2, 0,
           "    PID USER     %-*.*s  %-*.*s       SENT      RECEIVED       ",
           proglen, proglen, "PROGRAM", devlen, devlen, "DEV");
  attroff(A_REVERSE);

  /* print them */
  int i;
  for (i = 0; i < nproc; i++) {
    if (i + 3 < rows)
      lines[i]->show(i + 3, proglen, devlen);
    recv_global += lines[i]->recv_value;
    sent_global += lines[i]->sent_value;
    delete lines[i];
  }
  attron(A_REVERSE);
  int totalrow = std::min(rows - 1, 3 + 1 + i);
  mvprintw(totalrow, 0, "  TOTAL        %-*.*s %-*.*s    %s %s ", proglen,
           proglen, "", devlen, devlen, "",
           prettyFloat(sent_global, NUMBER_OF_DECIMALS_SENT, COLUMN_WIDTH_SENT)
               .c_str(),
           prettyFloat(recv_global, NUMBER_OF_DECIMALS_RECEIVED,
                       COLUMN_WIDTH_RECEIVED)
               .c_str());

  mvprintw(3 + 1 + i, cols - COLUMN_WIDTH_UNIT, "%s", desc_view_mode[viewMode]);
  attroff(A_REVERSE);
  mvprintw(totalrow + 1, 0, "%s", "");
  refresh();
}

// Display all processes and relevant network traffic using show function
void do_refresh() {
  refreshconninode();
  refreshcount++;

  if (viewMode == VIEWMODE_KBPS || viewMode == VIEWMODE_MBPS ||
      viewMode == VIEWMODE_GBPS) {
    remove_timed_out_processes();
  }

  ProcList *curproc = processes;
  int nproc = processes->size();

  /* initialize to null pointers */
  Line *lines[nproc];
  for (int i = 0; i < nproc; i++)
    lines[i] = NULL;

  int n = 0;

  while (curproc != NULL) {
    // walk though its connections, summing up their data, and
    // throwing away connections that haven't received a package
    // in the last CONNTIMEOUT seconds.
    assert(curproc->getVal() != NULL);
    assert(nproc == processes->size());

    float value_sent = 0, value_recv = 0;

    if (viewMode == VIEWMODE_KBPS) {
      curproc->getVal()->getkbps(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_MBPS) {
      curproc->getVal()->getmbps(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_GBPS) {
      curproc->getVal()->getgbps(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_KB) {
      curproc->getVal()->gettotalkb(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_MB) {
      curproc->getVal()->gettotalmb(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_B) {
      curproc->getVal()->gettotalb(&value_recv, &value_sent);
    } else {
      forceExit(false, "Invalid viewMode: %d", viewMode);
    }
    uid_t uid = curproc->getVal()->getUid();
    assert(curproc->getVal()->pid >= 0);
    assert(n < nproc);

    lines[n] = new Line(curproc->getVal()->name, curproc->getVal()->cmdline,
                        value_recv, value_sent, curproc->getVal()->pid, uid,
                        curproc->getVal()->devicename);
    curproc = curproc->next;
    n++;
  }

  /* sort the accumulated lines */
  qsort(lines, nproc, sizeof(Line *), GreatestFirst);

  if (tracemode || DEBUG)
    show_trace(lines, nproc);
  else
    show_ncurses(lines, nproc);

  if (refreshlimit != 0 && refreshcount >= refreshlimit)
    quit_cb(0);
}

// . Returns a String with a nice representation of the floating point value
// 'val' . There will be 'decimals' number of digits after the decimal point .
// There will be thousand separators as "'", independent of the user locale .
// String will have width 'maxWidth', the value is aligned to the right, the
// padding
//   values at the left are white spaces.
// . If the the resulting number-string is bigger in than 'maxWidth' a
//   default string "ERR:tooBig" is returned, padded to maxWidth.
// . test with something like:
//   std::cout << "Test di prettyFloat: " << prettyFloat(123456.123456, 1, 15)
//   << "\n";
// . Adapted from here: https://stackoverflow.com/a/43482688/2129178
std::string prettyFloat(double val, int decimals, int maxWidth) {

  struct separate_thousands : std::numpunct<char> {
    char_type do_thousands_sep() const override {
      return ',';
    } // separate with commas
    string_type do_grouping() const override {
      return "\3";
    } // groups of 3 digit
  };

  std::stringstream ss1;
  auto thousands = std::make_unique<separate_thousands>();
  ss1.imbue(std::locale(std::cout.getloc(), thousands.release()));
  ss1.setf(std::ios_base::fixed, std::ios_base::floatfield);
  ss1.precision(decimals);
  ss1 << std::setw(maxWidth);
  ss1 << val;
  std::string out = ss1.str();
  if (out.length() > (long unsigned)maxWidth) {
    ss1.str("");
    ss1 << std::setw(maxWidth);
    ss1 << "ERR:tooBig";
    out = ss1.str();
  }
  return out;
};
