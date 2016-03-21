#include "nethogs.cpp"
#include <fcntl.h>
#include <vector>

//The self_pipe is used to interrupt the select() in the main loop
static std::pair<int,int> self_pipe = std::make_pair(-1, -1);
static time_t last_refresh_time = 0;

//selectable file descriptors for the main loop
static fd_set pc_loop_fd_set;
static std::vector<int> pc_loop_fd_list;
static bool pc_loop_use_select = true;


static void versiondisplay(void)
{
	std::cout << version << "\n";
}

static void help(bool iserror)
{
	std::ostream & output = (iserror ? std::cerr : std::cout);

	//output << "usage: nethogs [-V] [-b] [-d seconds] [-t] [-p] [-f (eth|ppp))] [device [device [device ...]]]\n";
	output << "usage: nethogs [-V] [-h] [-b] [-d seconds] [-v mode] [-c count] [-t] [-p] [-s] [device [device [device ...]]]\n";
	output << "		-V : prints version.\n";
	output << "		-h : prints this help.\n";
	output << "		-b : bughunt mode - implies tracemode.\n";
	output << "		-d : delay for update refresh rate in seconds. default is 1.\n";
	output << "		-v : view mode (0 = KB/s, 1 = total KB, 2 = total B, 3 = total MB). default is 0.\n";
	output << "		-c : number of updates. default is 0 (unlimited).\n";
	output << "		-t : tracemode.\n";
	//output << "		-f : format of packets on interface, default is eth.\n";
	output << "		-p : sniff in promiscious mode (not recommended).\n";
	output << "		-s : sort output by sent column.\n";
  output << "   -a : monitor all devices, even loopback/stopped ones.\n";
	output << "		device : device(s) to monitor. default is all interfaces up and running excluding loopback\n";
	output << std::endl;
	output << "When nethogs is running, press:\n";
	output << " q: quit\n";
	output << " s: sort by SENT traffic\n";
	output << " r: sort by RECEIVE traffic\n";
	output << " m: switch between total (KB, B, MB) and KB/s mode\n";
}


void quit_cb (int /* i */)
{
	if( self_pipe.second != -1 )
	{
		write(self_pipe.second, "x", 1);
	}
	else
	{
		exit(0);
	}
}

void forceExit(bool success, const char *msg, ...)
{
	if ((!tracemode)&&(!DEBUG)){
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

std::pair<int, int> create_self_pipe()
{
	int pfd[2];
	if (pipe(pfd) == -1)
		return std::make_pair(-1, -1);

	if (fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK) == -1)
		return std::make_pair(-1, -1);

    if (fcntl(pfd[1], F_SETFL, fcntl(pfd[1], F_GETFL) | O_NONBLOCK) == -1)
		return std::make_pair(-1, -1);

	return std::make_pair(pfd[0], pfd[1]);
}

bool wait_for_next_trigger()
{
	if( pc_loop_use_select )
	{
		FD_ZERO(&pc_loop_fd_set);
		int nfds = 0;
		for(std::vector<int>::const_iterator it=pc_loop_fd_list.begin();
			it != pc_loop_fd_list.end(); ++it)
		{
			int const fd = *it;
			nfds = std::max(nfds, *it + 1);
			FD_SET(fd, &pc_loop_fd_set);
		}
		timeval timeout = {refreshdelay, 0};
		if( select(nfds, &pc_loop_fd_set, 0, 0, &timeout) != -1 )
		{
			if( FD_ISSET(self_pipe.first, &pc_loop_fd_set) )
			{
				return false;
			}
		}
	}
	else
	{
		// If select() not possible, pause to prevent 100%
		usleep(1000);
	}
	return true;
}


void clean_up()
{
	//close file descriptors
	for(std::vector<int>::const_iterator it=pc_loop_fd_list.begin();
		it != pc_loop_fd_list.end(); ++it)
	{
		close(*it);
	}

	procclean();
	if ((!tracemode) && (!DEBUG))
		exit_ui();
}

int main (int argc, char** argv)
{
	process_init();

	int promisc = 0;
	bool all = false;

	int opt;
	while ((opt = getopt(argc, argv, "Vahbtpd:v:c:sa")) != -1) {
		switch(opt) {
			case 'V':
				versiondisplay();
				exit(0);
			case 'h':
				help(false);
				exit(0);
			case 'b':
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
				refreshdelay = atoi(optarg);
				break;
			case 'v':
				viewMode = atoi(optarg) % VIEWMODE_COUNT;
				break;
			case 'c':
				refreshlimit = atoi(optarg);
				break;
			case 'a':
			  all = true;
				break;
			default:
				help(true);
				exit(EXIT_FAILURE);
		}
	}

	device * devices = get_devices(argc - optind, argv + optind, all);
	if (devices == NULL)
    forceExit(false, "No devices to monitor. Use '-a' to allow monitoring loopback interfaces or devices that are not up/running");

	if ((!tracemode) && (!DEBUG)){
		init_ui();
	}

	if (NEEDROOT && (geteuid() != 0))
		forceExit(false, "You need to be root to run NetHogs!");

	//use the Self-Pipe trick to interrupt the select() in the main loop
	self_pipe = create_self_pipe();
	if( self_pipe.first == -1 || self_pipe.second == -1 )
	{
		forceExit(false, "Error creating pipe file descriptors\n");
	}
	else
	{
		//add the self-pipe to allow interrupting select()
		pc_loop_fd_list.push_back(self_pipe.first);
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	handle * handles = NULL;
	device * current_dev = devices;
	while (current_dev != NULL) {

		if( !getLocal(current_dev->name, tracemode) )
		{
			forceExit(false, "getifaddrs failed while establishing local IP.");
		}

		dp_handle * newhandle = dp_open_live(current_dev->name, BUFSIZ, promisc, 100, errbuf);
		if (newhandle != NULL)
		{
			dp_addcb (newhandle, dp_packet_ip, process_ip);
			dp_addcb (newhandle, dp_packet_ip6, process_ip6);
			dp_addcb (newhandle, dp_packet_tcp, process_tcp);
			dp_addcb (newhandle, dp_packet_udp, process_udp);

			/* The following code solves sf.net bug 1019381, but is only available
			 * in newer versions (from 0.8 it seems) of libpcap
			 *
			 * update: version 0.7.2, which is in debian stable now, should be ok
			 * also.
			 */
			if (dp_setnonblock (newhandle, 1, errbuf) == -1)
			{
				fprintf(stderr, "Error putting libpcap in nonblocking mode\n");
			}
			handles = new handle (newhandle, current_dev->name, handles);

			if( pc_loop_use_select )
			{
				//some devices may not support pcap_get_selectable_fd
				int const fd = pcap_get_selectable_fd(newhandle->pcap_handle);
				if( fd != -1 )
				{
					pc_loop_fd_list.push_back(fd);
				}
				else
				{
					pc_loop_use_select = false;
					pc_loop_fd_list.clear();
					fprintf(stderr, "failed to get selectable_fd for %s\n", current_dev->name);
				}
			}
		}
		else
		{
			fprintf(stderr, "Error opening handler for device %s\n", current_dev->name);
		}

		current_dev = current_dev->next;
	}

	signal (SIGINT, &quit_cb);

	fprintf(stderr, "Waiting for first packet to arrive (see sourceforge.net bug 1019381)\n");
	struct dpargs * userdata = (dpargs *) malloc (sizeof (struct dpargs));

	// Main loop:
	while (1)
	{
		bool packets_read = false;

		for (handle * current_handle = handles; current_handle != NULL; current_handle = current_handle->next)
		{
			userdata->device = current_handle->devicename;
			userdata->sa_family = AF_UNSPEC;
			int retval = dp_dispatch (current_handle->content, -1, (u_char *)userdata, sizeof (struct dpargs));
			if (retval < 0)
				std::cerr << "Error dispatching: " << retval << std::endl;
			else if (retval != 0)
				packets_read = true;
			else
				gettimeofday(&curtime, NULL);
		}

 		if( last_refresh_time + refreshdelay <= curtime.tv_sec )
 		{
 			last_refresh_time = curtime.tv_sec;
 			if ((!DEBUG)&&(!tracemode))
			{
				// handle user input
				ui_tick();
			}
			do_refresh();
		}

		// if not packets, do a select() until next packet
		if (!packets_read)
			if( !wait_for_next_trigger() )
				// Shutdown requested - exit the loop
				break;
	}

	clean_up();
}
