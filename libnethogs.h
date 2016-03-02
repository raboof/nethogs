#ifndef NETHOGSMINITOR_H
#define NETHOGSMINITOR_H

#include <functional>
#include <map>

#define NETHOGS_DSO_VISIBLE __attribute__ ((visibility ("default")))
#define NETHOGS_DSO_HIDDEN  __attribute__ ((visibility ("hidden")))

class NETHOGS_DSO_VISIBLE NethogsMonitorData
{
	public:
	class Line
	{
		public:
		std::string app_name;
		std::string device_name;
		int			uid;
		int 		pid;
		u_int32_t	sent_bytes;
		u_int32_t	recv_bytes;
		float		sent_kbs;
		float		recv_kbs;
	};
	std::map<std::string, Line> apps_info;
};

class NETHOGS_DSO_VISIBLE NethogsMonitor
{
	NethogsMonitor();
public:
	typedef std::function<void(NethogsMonitorData const&)> Callback;
	
	static void start(Callback const& cb);
	static void stop();
	
private:
	static void threadProc();
	static void handleUpdate();
	
	static bool _trace;
	static bool _promisc;
};

#undef NETHOGS_DSO_VISIBLE
#undef NETHOGS_DSO_HIDDEN

#endif // NETHOGSMINITOR_H
