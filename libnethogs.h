#ifndef LIBNETHOGS_H_
#define LIBNETHOGS_H_

#include <stdint.h>
#include <inttypes.h>
#include <string>

#define NETHOGS_DSO_VISIBLE __attribute__ ((visibility ("default")))
#define NETHOGS_DSO_HIDDEN  __attribute__ ((visibility ("hidden")))

class NETHOGS_DSO_VISIBLE NethogsAppUpdate
{
public:
	enum Action {Set, Remove};
	NethogsAppUpdate() 
	: action(Set), pid(0), uid(0), sent_kbs(0), recv_kbs(0)
	{
	}
	Action		action;
	int 		pid;
	u_int32_t	uid;
	std::string app_name;
	std::string device_name;
	u_int32_t	sent_bytes;
	u_int32_t	recv_bytes;
	float		sent_kbs;
	float		recv_kbs;
};

class NETHOGS_DSO_VISIBLE NethogsMonitor
{
	NethogsMonitor();
public:
	typedef void(*Callback)(NethogsAppUpdate const&);
	
	//register async callback to receive updates
	//have to be called before start
	static void registerUpdateCallback(Callback const& cb);
		
	//start the monitor
	static void start();
	
	//stop the monitor
	static void stop();
	
private:
	static void threadProc();
	static void handleUpdate();
	
	static bool _trace;
	static bool _promisc;
};

#undef NETHOGS_DSO_VISIBLE
#undef NETHOGS_DSO_HIDDEN

#endif // LIBNETHOGS_H_
