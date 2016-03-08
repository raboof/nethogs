#ifndef LIBNETHOGS_H_
#define LIBNETHOGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#define NETHOGS_DSO_VISIBLE __attribute__ ((visibility ("default")))
#define NETHOGS_DSO_HIDDEN  __attribute__ ((visibility ("hidden")))

#define NETHOGS_APP_ACTION_SET	  1
#define NETHOGS_APP_ACTION_REMOVE 2

#define NETHOGS_STATUS_OK         0 
#define NETHOGS_STATUS_FAILURE    1 //generic error
#define NETHOGS_STATUS_NO_DEVICE  2 //no device foundr

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
	
//start the monitor (return one of the NETHOGS_STATUS above)
NETHOGS_DSO_VISIBLE int nethogsmonitor_start();

//stop the monitor
NETHOGS_DSO_VISIBLE void nethogsmonitor_stop();

#undef NETHOGS_DSO_VISIBLE
#undef NETHOGS_DSO_HIDDEN

#ifdef __cplusplus
}
#endif

#endif // LIBNETHOGS_H_
