#include "nethogs.cpp"
#include <fcntl.h>
#include <set>
#include <vector>
#include <list>

#ifdef __linux__
#include <linux/capability.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#endif

// The self_pipe is used to interrupt the select() in the main loop
static std::pair<int, int> self_pipe = std::make_pair(-1, -1);
static time_t last_refresh_time = 0;

extern std::set<pid_t> pidsToWatch;

// selectable file descriptors for the main loop
static fd_set pc_loop_fd_set;
static std::vector<int> pc_loop_fd_list;
static bool pc_loop_use_select = true;

static void versiondisplay(void) { std::cout << version << "\n"; }

static void help(bool iserror) {
  std::ostream &output = (iserror ? std::cerr : std::cout);

  // output << "usage: nethogs [-V] [-b] [-d seconds] [-t] [-p] [-f (eth|ppp))]
  // [device [device [device ...]]]\n";
  output << "usage: nethogs [-V] [-h] [-x] [-d seconds] [-v mode] [-c count] "
            "[-t] [-p] [-s] [-a] [-l] [-f filter] [-C] [-b] [-P pid] "
            "[device [device [device ...]]]\n";
  output << "		-V : prints version.\n";
  output << "		-h : prints this help.\n";
  output << "		-x : bughunt mode - implies tracemode.\n";
  output << "		-d : delay for update refresh rate in seconds. default "
            "is 1.\n";
  output << "		-v : view mode (0 = kB/s, 1 = total kB, 2 = "
            "total bytes, 3 = total MB, 4 = MB/s, 5 = GB/s). default is 0.\n";
  output << "		-c : number of updates. default is 0 (unlimited).\n";
  output << "		-t : tracemode.\n";
  // output << "		-f : format of packets on interface, default is
  // eth.\n";
  output << "		-p : sniff in promiscious mode (not recommended).\n";
  output << "		-s : sort output by sent column.\n";
  output << "		-l : display command line.\n";
  output << "		-a : monitor all devices, even loopback/stopped "
            "ones.\n";
  output << "		-C : capture TCP and UDP.\n";
  output << "		-g : garbage collection period in number of refresh. "
            "default is 50.\n";
  output << "		-b : Short program name. Displays only the program "
            "name.\n";
  output << "		-f : EXPERIMENTAL: specify string pcap filter (like "
            "tcpdump)."
            " This may be removed or changed in a future version.\n";
  output << "		device : device(s) to monitor. default is all "
            "interfaces up and running excluding loopback\n";
  output << "		-P : Show only processes.\n";
  output << std::endl;
  output << "When nethogs is running, press:\n";
  output << " q: quit\n";
  output << " s: sort by SENT traffic\n";
  output << " r: sort by RECEIVED traffic\n";
  output << " l: display command line\n";
  output << " b: display the program basename instead of the fullpath\n";
  output << " m: switch between total (kB, bytes, MB) and throughput (kB/s, "
            " MB/s, GB/s) mode\n";
}

void quit_cb(int /* i */) {
  if (self_pipe.second != -1) {
    write(self_pipe.second, "x", 1);
  } else {
    exit(0);
  }
}

void forceExit(bool success, const char *msg, ...) {
  if ((!tracemode) && (!DEBUG)) {
    exit_ui();
  }

  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
  std::cerr << std::endl;

  if (success)
    exit(EXIT_SUCCESS);
  else
    exit(EXIT_FAILURE);
}

std::pair<int, int> create_self_pipe() {
  int pfd[2];
  if (pipe(pfd) == -1)
    return std::make_pair(-1, -1);

  if (fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK) == -1)
    return std::make_pair(-1, -1);

  if (fcntl(pfd[1], F_SETFL, fcntl(pfd[1], F_GETFL) | O_NONBLOCK) == -1)
    return std::make_pair(-1, -1);

  return std::make_pair(pfd[0], pfd[1]);
}

bool wait_for_next_trigger() {
  if (pc_loop_use_select) {
    FD_ZERO(&pc_loop_fd_set);
    int nfds = 0;
    for (std::vector<int>::const_iterator it = pc_loop_fd_list.begin();
         it != pc_loop_fd_list.end(); ++it) {
      int const fd = *it;
      nfds = std::max(nfds, *it + 1);
      FD_SET(fd, &pc_loop_fd_set);
    }
    timeval timeout = {refreshdelay, 0};
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

void clean_up() {
  // close file descriptors
  for (std::vector<int>::const_iterator it = pc_loop_fd_list.begin();
       it != pc_loop_fd_list.end(); ++it) {
    close(*it);
  }

  procclean();
  if ((!tracemode) && (!DEBUG))
    exit_ui();
}

int main(int argc, char **argv) {

  int promisc = 0;
  bool all = false;
  char *filter = NULL;
  int garbage_collection_period = 50;

  int opt;
  while ((opt = getopt(argc, argv, "Vhxtpsd:v:c:laf:Cbg:P:")) != -1) {
    switch (opt) {
    case 'V':
      versiondisplay();
      exit(0);
    case 'h':
      help(false);
      exit(0);
    case 'x':
      bughuntmode = true;
      tracemode = true;
      break;
    case 't':
      tracemode = true;
      break;
    case 'p':
      promisc = 1;
      break;
    case 's':
      sortRecv = false;
      break;
    case 'd':
      refreshdelay = (time_t)atoi(optarg);
      break;
    case 'v':
      viewMode = atoi(optarg) % VIEWMODE_COUNT;
      break;
    case 'c':
      refreshlimit = atoi(optarg);
      break;
    case 'l':
      showcommandline = true;
      break;
    case 'a':
      all = true;
      break;
    case 'f':
      filter = optarg;
      break;
    case 'C':
      catchall = true;
      break;
    case 'b':
      showBasename = true;
      break;
    case 'g':
      garbage_collection_period = (time_t)atoi(optarg);
      break;
    case 'P':
      pidsToWatch.insert((pid_t)atoi(optarg));
      break;
    default:
      help(true);
      exit(EXIT_FAILURE);
    }
  }

  process_init();
  device *devices = get_devices(argc - optind, argv + optind, all);
  if (devices == NULL)
    forceExit(false, "No devices to monitor. Use '-a' to allow monitoring "
                     "loopback interfaces or devices that are not up/running");

#ifndef __linux__
  if (geteuid() != 0)
    forceExit(false, "You need to be root to run NetHogs!");
#endif
  // on Linux, we can run as non-root given the cap_net_admin, cap_net_raw,
  // cap_dac_read_search and cap_sys_ptrace capabilities

  // use the Self-Pipe trick to interrupt the select() in the main loop
  self_pipe = create_self_pipe();
  if (self_pipe.first == -1 || self_pipe.second == -1) {
    forceExit(false, "Error creating pipe file descriptors\n");
  } else {
    // add the self-pipe to allow interrupting select()
    pc_loop_fd_list.push_back(self_pipe.first);
  }

  char errbuf[PCAP_ERRBUF_SIZE];

  int nb_devices = 0;
  int nb_failed_devices = 0;

  std::list<handle> handles;
  device *current_dev = devices;
  while (current_dev != NULL) {
    ++nb_devices;

    if (!getLocal(current_dev->name, tracemode)) {
      forceExit(false, "getifaddrs failed while establishing local IP.");
    }

    dp_handle *newhandle =
        dp_open_live(current_dev->name, BUFSIZ, promisc, 100, filter, errbuf);
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
      handles.push_front(handle(newhandle, current_dev->name));

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
      fprintf(stderr, "Error opening handler for device %s\n",
              current_dev->name);
      ++nb_failed_devices;
    }

    current_dev = current_dev->next;
  }

  if (nb_devices == nb_failed_devices) {
    if (geteuid() != 0)
      fprintf(stderr,
              "To run nethogs without being root, you need to enable "
              "capabilities on the program (cap_net_admin, cap_net_raw, "
              "cap_dac_read_search, cap_sys_ptrace). "
              "See the documentation for details.\n");
    forceExit(false, "Error opening pcap handlers for all devices.\n");
  }

  signal(SIGINT, &quit_cb);

  struct dpargs *userdata = (dpargs *)malloc(sizeof(struct dpargs));

  if ((!tracemode) && (!DEBUG)) {
    init_ui();
  }

  // Main loop:
  int refresh_count = 0;
  while (1) {
    bool packets_read = false;

    for (auto current_handle = handles.begin(); current_handle != handles.end(); current_handle ++) {
      userdata->device = current_handle->devicename;
      userdata->sa_family = AF_UNSPEC;
      int retval = dp_dispatch(current_handle->content, -1, (u_char *)userdata,
                               sizeof(struct dpargs));
      if (retval == -1)
        std::cerr << "Error dispatching for device "
                  << current_handle->devicename << ": "
                  << dp_geterr(current_handle->content) << std::endl;
      else if (retval < 0)
        std::cerr << "Error dispatching for device "
                  << current_handle->devicename << ": " << retval << std::endl;
      else if (retval != 0)
        packets_read = true;
    }

    time_t const now = ::time(NULL);
    if (last_refresh_time + refreshdelay <= now) {
      last_refresh_time = now;
      if ((!DEBUG) && (!tracemode)) {
        // handle user input
        ui_tick();
      }
      do_refresh();
      ++refresh_count;

      if ((garbage_collection_period > 0) &&
          (refresh_count % garbage_collection_period == 0)) {
        garbage_collect_processes();
      }
    }

    // if not packets, do a select() until next packet
    if (!packets_read)
      if (!wait_for_next_trigger())
        // Shutdown requested - exit the loop
        break;
  }

  clean_up();
}
