#include "nethogs.cpp"

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
	output << "		device : device(s) to monitor. default is all interfaces up and running excluding loopback\n";
	output << std::endl;
	output << "When nethogs is running, press:\n";
	output << " q: quit\n";
	output << " s: sort by SENT traffic\n";
	output << " r: sort by RECEIVE traffic\n";
	output << " m: switch between total (KB, B, MB) and KB/s mode\n";
}

int main (int argc, char** argv)
{
	process_init();

	device * devices = NULL;
	//dp_link_type linktype = dp_link_ethernet;
	int promisc = 0;

	int opt;
	while ((opt = getopt(argc, argv, "Vhbtpd:v:c:s")) != -1) {
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
			/*
			case 'f':
				argv++;
				if (strcmp (optarg, "ppp") == 0)
					linktype = dp_link_ppp;
				else if (strcmp (optarg, "eth") == 0)
					linktype = dp_link_ethernet;
				}
				break;
			*/
			default:
				help(true);
				exit(EXIT_FAILURE);
		}
	}

	while (optind < argc) {
		devices = new device (strdup(argv[optind++]), devices);
	}

	if (devices == NULL)
	{
		devices = get_default_devices();
        if ( devices == NULL )
        {
            std::cerr << "Not devices to monitor" << std::endl;
            return 0;
        }
	}

	if ((!tracemode) && (!DEBUG)){
		init_ui();
	}

	if (NEEDROOT && (geteuid() != 0))
		forceExit(false, "You need to be root to run NetHogs!");

	char errbuf[PCAP_ERRBUF_SIZE];

	handle * handles = NULL;
	device * current_dev = devices;
	while (current_dev != NULL) {
		getLocal(current_dev->name, tracemode);

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
		}
		else
		{
			fprintf(stderr, "Error opening handler for device %s\n", current_dev->name);
		}

		current_dev = current_dev->next;
	}

	signal (SIGALRM, &alarm_cb);
	signal (SIGINT, &quit_cb);
	alarm (refreshdelay);

	fprintf(stderr, "Waiting for first packet to arrive (see sourceforge.net bug 1019381)\n");
	struct dpargs * userdata = (dpargs *) malloc (sizeof (struct dpargs));

	// Main loop:
	//
	//  Walks though the 'handles' list, which contains handles opened in non-blocking mode.
	//  This causes the CPU utilisation to go up to 100%. This is tricky:
	while (1)
	{
		handle * current_handle = handles;
		while (current_handle != NULL)
		{
			userdata->device = current_handle->devicename;
			userdata->sa_family = AF_UNSPEC;
			int retval = dp_dispatch (current_handle->content, -1, (u_char *)userdata, sizeof (struct dpargs));
			if (retval < 0)
			{
				std::cerr << "Error dispatching: " << retval << std::endl;
			}
			current_handle = current_handle->next;
		}


		if ((!DEBUG)&&(!tracemode))
		{
		    // handle user input
		    ui_tick();
		}
		if (needrefresh)
		{
			do_refresh();
			needrefresh = false;
		}
	}
}

