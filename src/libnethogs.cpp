extern "C" {
#include "libnethogs.h"
}

#include "nethogs.cpp"
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

//////////////////////////////
extern ProcList *processes;
extern Process *unknowntcp;
extern Process *unknownudp;
extern Process *unknownip;
//////////////////////////////

// The self_pipe is used to interrupt the select() in the main loop
static std::pair<int, int> self_pipe = std::make_pair(-1, -1);

static bool monitor_run_flag = false;
typedef std::map<void *, NethogsMonitorRecord> NethogsRecordMap;
static NethogsRecordMap monitor_record_map;

static int monitor_refresh_delay = 1;
static time_t monitor_last_refresh_time = 0;

// selectable file descriptors for the main loop
static fd_set pc_loop_fd_set;
static std::vector<int> pc_loop_fd_list;
static bool pc_loop_use_select = true;

static handle *handles = NULL;

static std::pair<int, int> create_self_pipe() {
  int pfd[2];
  if (pipe(pfd) == -1)
    return std::make_pair(-1, -1);

  if (fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK) == -1)
    return std::make_pair(-1, -1);

  if (fcntl(pfd[1], F_SETFL, fcntl(pfd[1], F_GETFL) | O_NONBLOCK) == -1)
    return std::make_pair(-1, -1);

  return std::make_pair(pfd[0], pfd[1]);
}

static bool wait_for_next_trigger() {
  if (pc_loop_use_select) {
    FD_ZERO(&pc_loop_fd_set);
    int nfds = 0;
    for (std::vector<int>::const_iterator it = pc_loop_fd_list.begin();
         it != pc_loop_fd_list.end(); ++it) {
      int const fd = *it;
      nfds = std::max(nfds, *it + 1);
      FD_SET(fd, &pc_loop_fd_set);
    }
    timeval timeout = {monitor_refresh_delay, 0};
    if (select(nfds, &pc_loop_fd_set, 0, 0, &timeout) != -1) {
      if (FD_ISSET(self_pipe.first, &pc_loop_fd_set)) {
        return false;
      }
    }
  } else {
    // If select() not possible, pause to prevent 100%
    usleep(1000);
  }
  return true;
}

static int nethogsmonitor_init(int devc, char **devicenames, bool all,
                               char *filter, int to_ms) {
  process_init();

  device *devices = get_devices(devc, devicenames, all);
  if (devices == NULL) {
    std::cerr << "No devices to monitor" << std::endl;
    return NETHOGS_STATUS_NO_DEVICE;
  }

  device *current_dev = devices;

  bool promiscuous = false;

  int nb_devices = 0;
  int nb_failed_devices = 0;

  while (current_dev != NULL) {
    ++nb_devices;

    if (!getLocal(current_dev->name, false)) {
      std::cerr << "getifaddrs failed while establishing local IP."
                << std::endl;
      ++nb_failed_devices;
      continue;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    dp_handle *newhandle = dp_open_live(current_dev->name, BUFSIZ, promiscuous,
                                        to_ms, filter, errbuf);
    if (newhandle != NULL) {
      dp_addcb(newhandle, dp_packet_ip, process_ip);
      dp_addcb(newhandle, dp_packet_ip6, process_ip6);
      dp_addcb(newhandle, dp_packet_tcp, process_tcp);
      dp_addcb(newhandle, dp_packet_udp, process_udp);

      /* The following code solves sf.net bug 1019381, but is only available
       * in newer versions (from 0.8 it seems) of libpcap
       *
       * update: version 0.7.2, which is in debian stable now, should be ok
       * also.
       */
      if (dp_setnonblock(newhandle, 1, errbuf) == -1) {
        fprintf(stderr, "Error putting libpcap in nonblocking mode\n");
      }
      handles = new handle(newhandle, current_dev->name, handles);

      if (pc_loop_use_select) {
        // some devices may not support pcap_get_selectable_fd
        int const fd = pcap_get_selectable_fd(newhandle->pcap_handle);
        if (fd != -1) {
          pc_loop_fd_list.push_back(fd);
        } else {
          pc_loop_use_select = false;
          pc_loop_fd_list.clear();
          fprintf(stderr, "failed to get selectable_fd for %s\n",
                  current_dev->name);
        }
      }
    } else {
      fprintf(stderr, "ERROR: opening handler for device %s: %s\n",
              current_dev->name, strerror(errno));
      ++nb_failed_devices;
    }

    current_dev = current_dev->next;
  }

  if (nb_devices == nb_failed_devices) {
    return NETHOGS_STATUS_FAILURE;
  }

  // use the Self-Pipe trick to interrupt the select() in the main loop
  if (pc_loop_use_select) {
    self_pipe = create_self_pipe();
    if (self_pipe.first == -1 || self_pipe.second == -1) {
      std::cerr << "Error creating pipe file descriptors\n";
      pc_loop_use_select = false;
    } else {
      pc_loop_fd_list.push_back(self_pipe.first);
    }
  }

  return NETHOGS_STATUS_OK;
}

static void nethogsmonitor_handle_update(NethogsMonitorCallback cb) {
  refreshconninode();
  refreshcount++;

  ProcList *curproc = processes;
  ProcList *previousproc = NULL;
  int nproc = processes->size();

  while (curproc != NULL) {
    // walk though its connections, summing up their data, and
    // throwing away connections that haven't received a package
    // in the last PROCESSTIMEOUT seconds.
    assert(curproc != NULL);
    assert(curproc->getVal() != NULL);
    assert(nproc == processes->size());

    /* remove timed-out processes (unless it's one of the unknown process)
     */
    if ((curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <=
         curtime.tv_sec) &&
        (curproc->getVal() != unknowntcp) &&
        (curproc->getVal() != unknownudp) && (curproc->getVal() != unknownip)) {
      if (DEBUG)
        std::cout << "PROC: Deleting process\n";

      NethogsRecordMap::iterator it = monitor_record_map.find(curproc);
      if (it != monitor_record_map.end()) {
        NethogsMonitorRecord &data = it->second;
        (*cb)(NETHOGS_APP_ACTION_REMOVE, &data);
        monitor_record_map.erase(curproc);
      }

      ProcList *todelete = curproc;
      Process *p_todelete = curproc->getVal();
      if (previousproc) {
        previousproc->next = curproc->next;
        curproc = curproc->next;
      } else {
        processes = curproc->getNext();
        curproc = processes;
      }
      delete todelete;
      delete p_todelete;
      nproc--;
      // continue;
    } else {
      const u_int32_t uid = curproc->getVal()->getUid();
      u_int64_t sent_bytes;
      u_int64_t recv_bytes;
      float sent_kbs;
      float recv_kbs;
      curproc->getVal()->getkbps(&recv_kbs, &sent_kbs);
      curproc->getVal()->gettotal(&recv_bytes, &sent_bytes);

      // notify update
      bool const new_data =
          (monitor_record_map.find(curproc) == monitor_record_map.end());
      NethogsMonitorRecord &data = monitor_record_map[curproc];

      bool data_change = false;
      if (new_data) {
        data_change = true;
        static int record_id = 0;
        ++record_id;
        memset(&data, 0, sizeof(data));
        data.record_id = record_id;
        data.name = curproc->getVal()->name;
        data.pid = curproc->getVal()->pid;
      }

      data.device_name = curproc->getVal()->devicename;

#define NHM_UPDATE_ONE_FIELD(TO, FROM)                                         \
  if ((TO) != (FROM)) {                                                        \
    TO = FROM;                                                                 \
    data_change = true;                                                        \
  }

      NHM_UPDATE_ONE_FIELD(data.uid, uid)
      NHM_UPDATE_ONE_FIELD(data.sent_bytes, sent_bytes)
      NHM_UPDATE_ONE_FIELD(data.recv_bytes, recv_bytes)
      NHM_UPDATE_ONE_FIELD(data.sent_kbs, sent_kbs)
      NHM_UPDATE_ONE_FIELD(data.recv_kbs, recv_kbs)

#undef NHM_UPDATE_ONE_FIELD

      if (data_change) {
        (*cb)(NETHOGS_APP_ACTION_SET, &data);
      }

      // next
      previousproc = curproc;
      curproc = curproc->next;
    }
  }
}

static void nethogsmonitor_clean_up() {
  // clean up
  handle *current_handle = handles;
  handle *rem;
  while (current_handle != NULL) {
    pcap_close(current_handle->content->pcap_handle);
    rem = current_handle;
    current_handle = current_handle->next;
    free(rem);
  }
  handles = NULL;

  // close file descriptors
  for (std::vector<int>::const_iterator it = pc_loop_fd_list.begin();
       it != pc_loop_fd_list.end(); ++it) {
    close(*it);
  }

  procclean();
}

int nethogsmonitor_loop(NethogsMonitorCallback cb, char *filter, int to_ms) {
    return nethogsmonitor_loop_devices(cb, filter, 0, NULL, false, to_ms);
}

int nethogsmonitor_loop_devices(NethogsMonitorCallback cb, char *filter,
                                int devc, char **devicenames, bool all, int to_ms) {
  if (monitor_run_flag) {
    return NETHOGS_STATUS_FAILURE;
  }

  int return_value = nethogsmonitor_init(devc, devicenames, all, filter, to_ms);
  if (return_value != NETHOGS_STATUS_OK) {
    return return_value;
  }

  monitor_run_flag = true;

  struct dpargs *userdata = (dpargs *)malloc(sizeof(struct dpargs));

  // Main loop
  while (monitor_run_flag) {
    bool packets_read = false;

    handle *current_handle = handles;
    while (current_handle != NULL) {
      userdata->device = current_handle->devicename;
      userdata->sa_family = AF_UNSPEC;
      int retval = dp_dispatch(current_handle->content, -1, (u_char *)userdata,
                               sizeof(struct dpargs));
      if (retval < 0) {
        std::cerr << "Error dispatching: " << retval << std::endl;
      } else if (retval != 0) {
        packets_read = true;
      } else {
        gettimeofday(&curtime, NULL);
      }
      current_handle = current_handle->next;
    }

    time_t const now = ::time(NULL);
    if (monitor_last_refresh_time + monitor_refresh_delay <= now) {
      monitor_last_refresh_time = now;
      nethogsmonitor_handle_update(cb);
    }

    if (!packets_read) {
      if (!wait_for_next_trigger()) {
        break;
      }
    }
  }

  nethogsmonitor_clean_up();

  return NETHOGS_STATUS_OK;
}

void nethogsmonitor_breakloop() {
  monitor_run_flag = false;
  write(self_pipe.second, "x", 1);
}
