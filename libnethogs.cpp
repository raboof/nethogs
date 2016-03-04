#include "libnethogs.h"
#include "nethogs.cpp"

#include <pthread.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <thread>
#include <map>

//////////////////////////////
extern ProcList * processes;
extern Process * unknowntcp;
extern Process * unknownudp;
extern Process * unknownip;
//////////////////////////////

static std::shared_ptr<std::thread> monitor_thread_ptr;
static std::atomic_bool monitor_thread_run_flag(false);

std::mutex monitor_exit_event_mutex;
std::condition_variable monitor_exit_event;

static NethogsMonitor::Callback monitor_udpate_callback;

typedef std::map<int, NethogsAppUpdate> NethogsAppUpdateMap;
static NethogsAppUpdateMap monitor_update_data;

static int monitor_refresh_delay = 1;
static int monitor_pc_dispatch_delay_ms = 50;
static time_t monitor_last_refresh_time = 0;

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
	
	bool promiscuous = false;
	
	while (current_dev != NULL) 
	{
		if( !getLocal(current_dev->name, false) )
		{
			std::cerr << "getifaddrs failed while establishing local IP." << std::endl;
			continue;
		}
		
		char errbuf[PCAP_ERRBUF_SIZE];
		dp_handle * newhandle = dp_open_live(current_dev->name, BUFSIZ, promiscuous, 100, errbuf);
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

	fprintf(stderr, "Waiting for first packet to arrive (see sourceforge.net bug 1019381)\n");
	struct dpargs * userdata = (dpargs *) malloc (sizeof (struct dpargs));

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

		time_t const now = ::time(NULL);
		if( monitor_last_refresh_time + monitor_refresh_delay <= now )
		{
			monitor_last_refresh_time = now;
			handleUpdate();
		}

		if (!packets_read)
		{
			std::unique_lock<std::mutex> lk(monitor_exit_event_mutex);
			monitor_exit_event.wait_for(lk, std::chrono::milliseconds(monitor_pc_dispatch_delay_ms));
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

			if( monitor_udpate_callback )
			{
				NethogsAppUpdateMap::iterator it = monitor_update_data.find(curproc->getVal()->pid);
				if( it != monitor_update_data.end() )
				{
					NethogsAppUpdate &data = it->second;
					data.action = NethogsAppUpdate::Remove;
					monitor_udpate_callback(data);
					monitor_update_data.erase(curproc->getVal()->pid);
				}
			}

			ProcList * todelete = curproc;
			Process * p_todelete = curproc->getVal();
			if (previousproc)
			{
				previousproc->next = curproc->next;
				curproc = curproc->next;
			} else 
			{
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
			int const pid = curproc->getVal()->pid;
			u_int32_t sent_bytes;
			u_int32_t recv_bytes;
			float sent_kbs;
			float recv_kbs;
			curproc->getVal()->getkbps  (&recv_kbs,   &sent_kbs);
			curproc->getVal()->gettotal (&recv_bytes, &sent_bytes);
			
			if( monitor_udpate_callback )
			{
				//notify update
				bool const new_process = (monitor_update_data.find(pid) == monitor_update_data.end());
				NethogsAppUpdate &data = monitor_update_data[pid];
	
				bool data_change = false;
	
				#define NHM_UPDATE_ONE_FIELD(TO,FROM) if((TO)!=(FROM)) { TO = FROM; data_change = true; }
				if( new_process )
				{
					NHM_UPDATE_ONE_FIELD( data.pid, pid )
					NHM_UPDATE_ONE_FIELD( data.app_name, curproc->getVal()->name )
				}
				
				NHM_UPDATE_ONE_FIELD( data.uid,         curproc->getVal()->getUid() )
				NHM_UPDATE_ONE_FIELD( data.device_name, curproc->getVal()->devicename )
				NHM_UPDATE_ONE_FIELD( data.sent_bytes,  sent_bytes )
				NHM_UPDATE_ONE_FIELD( data.recv_bytes,  recv_bytes )
				NHM_UPDATE_ONE_FIELD( data.sent_kbs,    sent_kbs )
				NHM_UPDATE_ONE_FIELD( data.recv_kbs,    recv_kbs )
				#undef NHM_UPDATE_ONE_FIELD				
				
				if( data_change )
				{
					data.action = NethogsAppUpdate::Set;
					monitor_udpate_callback(data);
				}
			}
			
			//next
			previousproc = curproc;
			curproc = curproc->next;
		}
	}
}

void NethogsMonitor::registerUpdateCallback(Callback const& cb)
{
	if( !monitor_thread_run_flag )
	{
		monitor_udpate_callback = cb;
	}
}

void NethogsMonitor::setRefreshDelay(int seconds)
{
	monitor_refresh_delay = seconds;
}

void NethogsMonitor::setPcapDispatchDelay(int milliseconds)
{
	monitor_pc_dispatch_delay_ms = milliseconds;
}

void NethogsMonitor::start()
{
	bool expected = false;
	if( monitor_thread_run_flag.compare_exchange_strong(expected, true) )
	{
		monitor_thread_ptr = std::make_shared<std::thread>(&NethogsMonitor::threadProc);
	}
}

void NethogsMonitor::stop()
{
	bool expected = true;
	if( monitor_thread_run_flag.compare_exchange_strong(expected, false) )
	{
		monitor_exit_event.notify_one();
		monitor_thread_ptr->join();
		monitor_udpate_callback = nullptr;
	}
}
