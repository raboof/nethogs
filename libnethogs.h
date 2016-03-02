#ifndef NETHOGSMINITOR_H
#define NETHOGSMINITOR_H

class NethogsMonitor
{
	NethogsMonitor();
public:
	static void start();
	static void stop();
private:
	static void threadProc();
	static void handleUpdate();
	
	static bool _trace;
	static bool _promisc;
};

#endif // NETHOGSMINITOR_H
