#include "nethogs.h"
#include <iostream>
#include "packet.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <malloc.h>
#include <assert.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
// #include "inet6.c"

local_addr * local_addrs = NULL;

/*
 * getLocal
 *	device: This should be device explicit (e.g. eth0:1)
 *
 * uses ioctl to get address of this device, and adds it to the
 * local_addrs-list.
 */
void getLocal (const char *device)
{
	int sock;
	struct ifreq iFreq;
	struct sockaddr_in *saddr;

	if((sock=socket(AF_INET, SOCK_PACKET, htons(0x0806)))<0){
		forceExit("creating socket failed while establishing local IP - are you root?");
	}
	strcpy(iFreq.ifr_name, device);
	if(ioctl(sock, SIOCGIFADDR, &iFreq)<0){
		forceExit("ioctl failed while establishing local IP");
	}
	saddr=(struct sockaddr_in*)&iFreq.ifr_addr;
	local_addrs = new local_addr (saddr->sin_addr.s_addr, local_addrs);
}

typedef u_int32_t tcp_seq;

/* ethernet header */
struct ethernet_hdr {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type; /* IP? */
};

/* IP header */
struct ip_hdr
{
#if BYTE_ORDER == LITTLE_ENDIAN                                                                      
       u_int ip_hl:4, /* header length */                                                                   
       ip_v:4; /* version */                                                                                
#if BYTE_ORDER == BIG_ENDIAN                                                                         
       u_int ip_v:4, /* version */                                                                          
       ip_hl:4; /* header length */                                                                         
#endif                                                                                               
#endif /* not _IP_VHL */                                                                             
       u_char ip_tos; /* type of service */                                                                 
       u_short ip_len; /* total length */                                                                   
       u_short ip_id; /* identification */                                                                  
       u_short ip_off; /* fragment offset field */                                                          
#define IP_RF 0x8000 /* reserved fragment flag */                                                    
#define IP_DF 0x4000 /* dont fragment flag */                                                        
#define IP_MF 0x2000 /* more fragments flag */                                                       
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */                                            
       u_char ip_ttl; /* time to live */                                                                    
       u_char ip_p; /* protocol */                                                                          
       u_short ip_sum; /* checksum */                                                                       
       struct in_addr ip_src,ip_dst; /* source and dest address */                                          
};                                                                                                       

/* TCP header */                                                                                         
struct tcp_hdr {                                                                                       
       u_short th_sport; /* source port */                                                                  
       u_short th_dport; /* destination port */                                                             
       tcp_seq th_seq; /* sequence number */                                                                
       tcp_seq th_ack; /* acknowledgement number */                                                         
#if BYTE_ORDER == LITTLE_ENDIAN                                                                      
       u_int th_x2:4, /* (unused) */                                                                        
       th_off:4; /* data offset */                                                                          
#endif                                                                                               
#if BYTE_ORDER == BIG_ENDIAN                                                                         
       u_int th_off:4, /* data offset */                                                                    
       th_x2:4; /* (unused) */                                                                              
#endif                                                                                               
       u_char th_flags;                                                                                     
#define TH_FIN 0x01                                                                                  
#define TH_SYN 0x02                                                                                  
#define TH_RST 0x04                                                                                  
#define TH_PUSH 0x08                                                                                 
#define TH_ACK 0x10                                                                                  
#define TH_URG 0x20                                                                                  
#define TH_ECE 0x40                                                                                  
#define TH_CWR 0x80                                                                                  
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)                                  
       u_short th_win; /* window */                                                                         
       u_short th_sum; /* checksum */                                                                       
       u_short th_urp; /* urgent pointer */                                                                 
};                                                                                                       

/* Packet 'Constructor' - but returns NULL on failure */
Packet * getPacket (const struct pcap_pkthdr * header, const u_char * packet)
{
	//const struct ethernet_hdr * ethernet = (struct ethernet_hdr *)packet;
	const struct ether_header * ethernet = (struct ether_header *)packet;
	if (ethernet->ether_type != 8)
	{
#if DEBUG
		std::cerr << "Dropped non-ip packet of type " << ethernet->ether_type << std::endl;
#endif
		return NULL;
	}

	const struct ip_hdr * ip = (struct ip_hdr *)(packet + sizeof(ethernet_hdr));
	if (ip->ip_p != 6)
	{
#if DEBUG
		std::cerr << "Dropped non-tcp packet of type " << (int)(ip->ip_p) << std::endl;
#endif
		return NULL;
	}

	const struct tcp_hdr * tcp = (struct tcp_hdr *)(packet + sizeof(ethernet_hdr) + sizeof(ip_hdr));

	return new Packet (ip->ip_src, ntohs(tcp->th_sport), ip->ip_dst, ntohs(tcp->th_dport), header->len, header->ts);
}

Packet::Packet (in_addr m_sip, unsigned short m_sport, in_addr m_dip, unsigned short m_dport, bpf_u_int32 m_len, timeval m_time, direction m_dir)
{
	sip = m_sip; sport = m_sport;
	dip = m_dip; dport = m_dport;
	len = m_len; time = m_time;
	dir = m_dir;
}

Packet * Packet::newInverted () {
	/* TODO if this is a bottleneck, we can calculate the direction */
	return new Packet (dip, dport, sip, sport, len, time, dir_unknown);
}

/* constructs returns a new Packet() structure with the same contents as this one */
/*Packet::Packet (const Packet &old_packet) {
    sip = old_packet.sip; sport = old_packet.sport;
    dip = old_packet.dip; dport = old_packet.dport;
    len = old_packet.len; time = old_packet.time;
}*/

bool sameinaddr(in_addr one, in_addr other)
{
	return one.s_addr == other.s_addr;
}

bool Packet::isOlderThan (timeval t) {
	return (time.tv_sec + PERIOD <= t.tv_sec);
}

bool Packet::Outgoing () {
	/* must be initialised with getLocal("eth0:1");) */
	if (DEBUG)
		assert (local_addrs != NULL);

	switch (dir) {
	  case dir_outgoing:
		return true;
	  case dir_incoming:
		return false;
	  case dir_unknown:
		if (local_addrs->contains(sip.s_addr)) {
		  dir = dir_outgoing;
		  return true;
		} else {
		  dir = dir_incoming;
		  return false;
		}
	}
}

/* returns the packet in '1.2.3.4:5-1.2.3.4:5'-form, for use in the 'conninode' table */
/* '1.2.3.4' should be the local address. */
char * Packet::gethashstring ()
{
	// TODO this needs to be bigger to support ipv6?!
	char * retval = (char *) malloc (92 * sizeof(char));
	if (Outgoing()) {
		snprintf(retval, 92 * sizeof(char), "%s:%d-", inet_ntoa(sip), sport);
		snprintf(retval, 92 * sizeof(char), "%s%s:%d", retval, inet_ntoa(dip), dport);
	} else {
		snprintf(retval, 92 * sizeof(char), "%s:%d-", inet_ntoa(dip), dport);
		snprintf(retval, 92 * sizeof(char), "%s%s:%d", retval, inet_ntoa(sip), sport);
	}
	//if (DEBUG)
		//cout << "hasshtring: " << retval << endl;
	return retval;
}

/* 2 packets match if they have the same 
 * source and destination ports and IP's. */
bool Packet::match (Packet * other)
{
	return (sport == other->sport) && (dport == other->dport) 
		&& (sameinaddr(sip, other->sip)) && (sameinaddr(dip, other->dip));
}
