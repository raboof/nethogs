#ifndef __NETHOGS_H
#define __NETHOGS_H

#include <netinet/in.h>

#define _BSD_SOURCE 1

/* take the average speed over the last 5 seconds */
#define PERIOD 5

/* the amount of time after the last packet was recieved
 * after which a process is removed */
#define PROCESSTIMEOUT 150

/* Set to '0' when compiling for a system that uses Linux Capabilities,
 * like www.adamantix.org: in that case nethogs shouldn't check if it's
 * running as root. Take care to give it sufficient privileges though. */
#ifndef NEEDROOT
#define NEEDROOT 1
#endif

#define DEBUG 0


#define PROGNAME_WIDTH 27

void forceExit(const char *msg);

class local_addr {
public:
	local_addr (in_addr_t m_addr, local_addr * m_next = NULL)
	{
		addr = m_addr;
		next = m_next;
	}
	bool contains (const in_addr_t & n_addr);
	in_addr_t addr;
	local_addr * next;
};

#endif
