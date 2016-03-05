#ifndef LIBNETHOGS_H_
#define LIBNETHOGS_H_

#include <stdint.h>
#include <stdbool.h>

#define NETHOGS_DSO_VISIBLE __attribute__ ((visibility ("default")))
#define NETHOGS_DSO_HIDDEN  __attribute__ ((visibility ("hidden")))

#define NETHOGS_APP_ACTION_SET	  1
#define NETHOGS_APP_ACTION_REMOVE 2

typedef struct NethogsMonitorUpdate
{
	int		    action;
	int 		pid;
	uint32_t	uid;
	const char* app_name;
	const char* device_name;
	uint32_t	sent_bytes;
	uint32_t	recv_bytes;
	float		sent_kbs;
	float		recv_kbs;
} NethogsMonitorUpdate;

typedef void(*NethogsMonitorCallback)(NethogsMonitorUpdate const*);
	
//register async callback to receive updates
//have to be called before start
NETHOGS_DSO_VISIBLE void nethogsmonitor_register_callback(NethogsMonitorCallback);
	
//start the monitor
NETHOGS_DSO_VISIBLE bool nethogsmonitor_start();

//stop the monitor
NETHOGS_DSO_VISIBLE void nethogsmonitor_stop();

//tuning functions
NETHOGS_DSO_VISIBLE void nethogsmonitor_set_refresh_delay(int seconds);	
NETHOGS_DSO_VISIBLE void nethogsmonitor_set_pcap_dispatch_delay(int milliseconds);


#undef NETHOGS_DSO_VISIBLE
#undef NETHOGS_DSO_HIDDEN

#endif // LIBNETHOGS_H_
