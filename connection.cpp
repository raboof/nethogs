#include <iostream>
#include <assert.h>
#include <malloc.h>
#include "nethogs.h"
#include "connection.h"

class ConnList
{
public:
	ConnList (Connection * m_val = NULL, ConnList * m_next = NULL)
	{
	    val = m_val; next = m_next;
	}
	Connection * val;
	ConnList * next;
};

ConnList * connections = NULL;

void PackList::add (Packet * p)
{
	if (content == NULL)
	{
		content = new PackListNode (p);
		return;
	}

	if (content->val->time.tv_sec == p->time.tv_sec)
	{
		content->val->len += p->len;
		return;
	}

	content = new PackListNode(p, content);
}

/* sums up the total bytes used and removes 'old' packets */
bpf_u_int32 PackList::sumanddel (timeval t)
{
	bpf_u_int32 retval = 0;
	PackListNode * current = content;
	PackListNode * previous = NULL;

	while (current != NULL) 
	{
		if (current->val->isOlderThan(t))
		{
			if (current == content)
				content = NULL;
			else if (previous != NULL)
				previous->next = NULL;
			delete current;
			return retval;
		}
		retval += current->val->len;
		previous = current;
		current = current->next;
	}
	return retval;
}

Connection::Connection (Packet * packet)
{
	if (DEBUG)
		assert (packet != NULL);
	connections = new ConnList (this, connections);
	sent_packets = new PackList ();
	recv_packets = new PackList ();
	if (packet->Outgoing())
	{
		sent_packets->add(packet);
	} else {
		recv_packets->add(packet);
	}
	refpacket = packet->newPacket ();
	lastpacket = packet->time.tv_sec;
	if (DEBUG)
		std::cout << "New reference packet created at " << refpacket << std::endl;
}

Connection::~Connection ()
{
	if (DEBUG)
		std::cout << "Deleting connection" << std::endl;
	delete refpacket;
    	if (sent_packets != NULL)
		delete sent_packets;
    	if (recv_packets != NULL)
		delete recv_packets;
}

void Connection::add (Packet * packet)
{
	lastpacket = packet->time.tv_sec;
	if (packet->Outgoing())
	{
		sent_packets->add (packet);
	} else {
		recv_packets->add (packet);
	}
}

Connection * findConnection (Packet * packet)
{
	ConnList * current = connections;
	while (current != NULL)
	{
		if (packet->match(current->val->refpacket))
			return current->val;

		current = current->next;
	}
	return NULL;
}

/*
 * Connection::sumanddel
 *	
 * sums up the total bytes used
 * and removes 'old' packets. 
 *
 * Returns sum of sent packages (by address)
 *	   sum of recieved packages (by address)
 */
void Connection::sumanddel (timeval t, bpf_u_int32 * sent, bpf_u_int32 * recv)
{
    (*sent)=(*recv)=0;

    *sent = sent_packets->sumanddel(t);
    *recv = recv_packets->sumanddel(t);
}
