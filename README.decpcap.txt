This is a brainstorm about a libpcap-wrapper.

It should make it possible to add callbacks requesting specific packets, for example asking
for all TCP packets, whether they are sent over IPv4 or IPv6.

Return value of the callback specifies of the packet should 'fall through', i.e.,
if it should be sent to other callbacks, too.

give the programmer the opportunity to let packages re-enter the 'stream'.

Callbacks should be called from high to low level. When a callback returns 'true', no lower
callbacks should be called. The payload is available in a nice struct (union?), too.

= Examples - how it'd work =

== For the developers of the lib ==

When the sniffer is started, we learn what kind of packets are on the wire 
(ethernet, ppp, etc) and start pcap. Whenever a packet arrives, it is parsed. 
After parsing, if a callback is defined for this type of packet, the callback 
is pushed onto a stack. After that the payload is parsed. This goes on until 
the payload is, as far as we're concerned, raw data. Then the callbacks on 
the stack are called, until one of them returns 'true' ('done parsing this 
packet')
Undefined callbacks move the parser to the next level.

-- alternatively --

When the sniffer is started, we learn what kind of packets are on the wire
(ethernet, ppp, etc) and start pcap. Whenever a packet arrives, it is parsed.
After parsing, if a callback is defined for this type of packet, that
callback is called. If it returns 'true', the packet is 'done', and discarded.
If it returns 'false', it's passed on to the next level, leaving any changes
to the user data intact.

== For the users of the lib ==

If you want to sniff only tcp packets, add a callback for the 'packet_tcp' 
packet type. If you also want to count the total amount of IP traffic, make 
sure the 'packet_tcp' handler returns 'false' - that means after the tcp
callback the packet will go on and be presented to the IP callback also.

If you want to sniff specifically IPv4 TCP packets, you add a callback for 
IPv4 that calls the function to parse the payload directly, and then returns 
'false'. 

If you modify the 'user' data in top-level callbacks which return 'false', 

-- alternatively --

If you want to sniff only tcp packets, simply only add a callback for 
'dp_packet_tcp'. If, on top of that, you also want to count the total amount
of IP traffic, make sure it returns 'false' and return.

If you want to sniff specifically IPv4 TCP packets, you can do 2 things:
add a 'true'-returning callback to everything else apart from IPv4 (which
is ugly), or only add a callback for IPv4 and call the TCP-parsing code
by hand.
