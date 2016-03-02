#include "libnethogs.h"
#include "nethogs.cpp"

#include <pthread.h>
#include <iostream>
#include <mutex>
#include <atomic>
#include <memory>
#include <thread>

//////////////////////////////
extern ProcList * processes;
extern Process * unknowntcp;
extern Process * unknownudp;
extern Process * unknownip;
//////////////////////////////

static std::shared_ptr<std::thread> monitor_thread_ptr;
static std::atomic_bool monitor_thread_run_flag(false);
static NethogsMonitor::Callback monitor_udpate_callback;
static NethogsMonitorData monitor_data;

bool NethogsMonitor::_trace = false;
bool NethogsMonitor::_promisc = false;

void NethogsMonitor::threadProc()
{
	process_init();
	
	device * devices = get_default_devices();
	if ( devices == NULL )
	{
		std::cerr << "Not devices to monitor" << std::endl;
		return;
	}
	
	handle * handles = NULL;
	device * current_dev = devices;
	
	while (current_dev != NULL) 
	{
		if( !getLocal(current_dev->name, _trace) )
		{
			std::cerr << "getifaddrs failed while establishing local IP." << std::endl;
			continue;
		}
		
		char errbuf[PCAP_ERRBUF_SIZE];
		dp_handle * newhandle = dp_open_live(current_dev->name, BUFSIZ, _promisc, 100, errbuf);
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
			fprintf(stderr, "ERROR: opening handler for device %s: %s\n", 
				current_dev->name, strerror(errno));
		}

		current_dev = current_dev->next;
	}

	signal (SIGALRM, &alarm_cb);
	alarm (refreshdelay);

	fprintf(stderr, "Waiting for first packet to arrive (see sourceforge.net bug 1019381)\n");
	struct dpargs * userdata = (dpargs *) malloc (sizeof (struct dpargs));

	time_t last_event_time = 0;
	// Main loop:
	//  Walks though the 'handles' list, which contains handles opened in non-blocking mode.
	//  This causes the CPU utilisation to go up to 100%. This is tricky:
	while (monitor_thread_run_flag)
	{
		bool packets_read = false;

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
			else if (retval != 0)
			{
				packets_read = true;
			}
			current_handle = current_handle->next;
		}


		if ( packets_read && needrefresh )
		{
			needrefresh = false;
			last_event_time = dp_get_lasttime();
			handleUpdate();
		}

		// If no packets were read at all this iteration, pause to prevent 100%
		// CPU utilisation;
		if (!packets_read)
		{
			usleep(100);
		}
	}	
}

void NethogsMonitor::handleUpdate()
{
	refreshconninode();
	refreshcount++;

	ProcList * curproc = processes;
	ProcList * previousproc = NULL;
	int nproc = processes->size();

	while (curproc != NULL)
	{
		// walk though its connections, summing up their data, and
		// throwing away connections that haven't received a package
		// in the last PROCESSTIMEOUT seconds.
		assert (curproc != NULL);
		assert (curproc->getVal() != NULL);
		assert (nproc == processes->size());

		/* remove timed-out processes (unless it's one of the the unknown process) */
		if ((curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <= curtime.tv_sec)
				&& (curproc->getVal() != unknowntcp)
				&& (curproc->getVal() != unknownudp)
				&& (curproc->getVal() != unknownip))
		{
			if (DEBUG)
				std::cout << "PROC: Deleting process\n";
			ProcList * todelete = curproc;
			Process * p_todelete = curproc->getVal();
			if (previousproc)
			{
				previousproc->next = curproc->next;
				curproc = curproc->next;
			} else {
				processes = curproc->getNext();
				curproc = processes;
			}
			delete todelete;
			delete p_todelete;
			nproc--;
			//continue;
		}
		else
		{			
			NethogsMonitorData::Line& line =  monitor_data.apps_info[curproc->getVal()->name]; 
			if( line.app_name.empty() )
			{
				line.app_name = curproc->getVal()->name;
			}
			if( line.device_name != curproc->getVal()->devicename )
			{
				line.device_name = curproc->getVal()->devicename;
			}
			line.pid = curproc->getVal()->pid;
			line.uid = curproc->getVal()->getUid();
				
			getkbps  (curproc->getVal(), &line.sent_kbs,   &line.recv_kbs);
			gettotal (curproc->getVal(), &line.recv_bytes, &line.sent_bytes);
			
			previousproc = curproc;
			curproc = curproc->next;
		}
	}
	
	monitor_udpate_callback(monitor_data);
}

void NethogsMonitor::start(NethogsMonitor::Callback const& cb)
{
	bool expected = false;
	if( monitor_thread_run_flag.compare_exchange_strong(expected, true) )
	{
		monitor_udpate_callback = cb;
		monitor_thread_ptr = std::make_shared<std::thread>(&threadProc);
	}
}

void NethogsMonitor::stop()
{
	bool expected = true;
	if( monitor_thread_run_flag.compare_exchange_strong(expected, false) )
	{
		monitor_thread_ptr->join();
		monitor_udpate_callback = nullptr;
	}
}
