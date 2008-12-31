#ifndef __NETHOGS_H
#define __NETHOGS_H

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <string.h>
#include <malloc.h>
#include <iostream>

#define _BSD_SOURCE 1

/* take the average speed over the last 5 seconds */
#define PERIOD 5

/* the amount of time after the last packet was recieved
 * after which a process is removed */
#define PROCESSTIMEOUT 150

/* the amount of time after the last packet was recieved
 * after which a connection is removed */
#define CONNTIMEOUT 50

/* Set to '0' when compiling for a system that uses Linux Capabilities,
 * like www.adamantix.org: in that case nethogs shouldn't check if it's
 * running as root. Take care to give it sufficient privileges though. */
#ifndef NEEDROOT
#define NEEDROOT 1
#endif

#define DEBUG 0

#define REVERSEHACK 0

// 2 times: 32 characters, 7 ':''s, a ':12345'.
// 1 '-'
// -> 2*45+1=91. we make it 92, for the null.
#define HASHKEYSIZE 92

#define PROGNAME_WIDTH 27

void forceExit(const char *msg, ...);

class local_addr {
public:
	/* ipv4 constructor takes an in_addr_t */
	local_addr (in_addr_t m_addr, local_addr * m_next = NULL)
	{
		addr = m_addr;
		next = m_next;
		sa_family = AF_INET;
		string = (char*) malloc (16);
		inet_ntop (AF_INET, &m_addr, string, 15);
	}
	/* this constructor takes an char address[33] */
	local_addr (char m_address [33], local_addr * m_next = NULL)
	{
		next = m_next;
		char address [40];
		address[0] = m_address[0]; address[1] = m_address[1];
		address[2] = m_address[2]; address[3] = m_address[3];
		address[4] = ':';
		address[5] = m_address[4]; address[6] = m_address[5];
		address[7] = m_address[6]; address[8] = m_address[7];
		address[9] = ':';
		address[10] = m_address[8]; address[11] = m_address[9];
		address[12] = m_address[10]; address[13] = m_address[11];
		address[14] = ':';
		address[15] = m_address[12]; address[16] = m_address[13];
		address[17] = m_address[14]; address[18] = m_address[15];
		address[19] = ':';
		address[20] = m_address[16]; address[21] = m_address[17];
		address[22] = m_address[18]; address[23] = m_address[19];
		address[24] = ':';
		address[25] = m_address[20]; address[26] = m_address[21];
		address[27] = m_address[22]; address[28] = m_address[23];
		address[29] = ':';
		address[30] = m_address[24]; address[31] = m_address[25];
		address[32] = m_address[26]; address[33] = m_address[27];
		address[34] = ':';
		address[35] = m_address[28]; address[36] = m_address[29];
		address[37] = m_address[30]; address[38] = m_address[31];
		address[39] = 0;
		string = strdup(address);
		//if (DEBUG)
		//	std::cout << "Converting address " << address << std::endl;

		int result = inet_pton (AF_INET6, address, &addr6);

		assert (result > 0);
		sa_family = AF_INET6;
	}

	bool contains (const in_addr_t & n_addr);
	bool contains (const struct in6_addr & n_addr);
	char * string;
	local_addr * next;
private:

	in_addr_t addr;
	struct in6_addr addr6;
	short int sa_family;
};

void quit_cb (int i);

#endif
