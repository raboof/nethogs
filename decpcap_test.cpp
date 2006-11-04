#include <iostream>

extern "C" {
	#include "decpcap.h"
}

int process_tcp (u_char * userdata, const dp_header * header, const u_char * m_packet) {
	std::cout << "Callback for processing TCP packet called" << std::endl;
}
	

int main (int argc, char ** argv)
{
	if (argc < 2)
	{
		std::cout << "Please, enter a filename" << std::endl;
	}

	char* errbuf = new char[DP_ERRBUFF_SIZE];

	dp_handle * newhandle = dp_open_offline(argv[1], errbuf); 
	dp_addcb (newhandle, dp_packet_tcp, process_tcp);
	int ret = dp_dispatch (newhandle, -1, NULL, 0);
	if (ret == -1)
	{
		std::cout << "Error dispatching: " << dp_geterr(newhandle);
	}
  
}
