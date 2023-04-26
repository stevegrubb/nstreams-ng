#ifndef PARSE_TCPDUMP_H__
#define PARSE_TCPDUMP_H__

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <pcap.h>

struct ip_addr {
	uint8_t fam; // socket family type
	union {
		struct in_addr ipv4_addr;
		struct in6_addr ipv6_addr;
	}addr;
};

struct tcpdump {
	struct ip_addr src;
	struct ip_addr dst;
	int proto;
	u_short ports[2]; /* sport and dport (udp/tcp),
			     type & code (icmp) */
	int flags;
};

/*
 * TCP flags
 */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define type ports[0]
#define code ports[1]

#define NS_ICMP_ECHO_REQUEST 8
#define NS_ICMP_ECHO_REPLY 0
#define NS_ICMP_UNREACH 3
#define NS_ICMP_TIMXCEED 11
#define NS_ICMP_TIMXCEED_IN_TRANSIT 0

struct tcpdump *parse_tcpdump_line(const u_char *orig, const struct pcap_pkthdr *header);

#endif
