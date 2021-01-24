/* nstreams
 * Copyright (C) 1999 Herve Schauer Consultants and Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * $Id: read_pcap.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 */
#include <includes.h>
#include <pcap.h>
#include "parse_tcpdump.h"
#include "read_pcap.h"

/*
 * pcap packet to a tcpdump struct
 */
struct tcpdump *parse_pcap_entry(u_char *data)
{
	struct tcpdump *ret = malloc(sizeof(struct tcpdump));
	struct iphdr *ip = (struct iphdr *)(data);
	bzero(ret, sizeof(*ret));

	/*
	 * Check that we have an IPv4 packet
	 */
	if (ip->version == 0x04) {
#ifdef DEBUG
#define UNFIX(x) ntohs(x)
		printf("\tip_hl : %d\n", ip->ihl);
		printf("\tip_v  : %d\n", ip->version);
		printf("\tip_tos: %d\n", ip->tos);
		printf("\tip_len: %d\n", UNFIX(ip->tot_len));
		printf("\tip_id : %d\n", ip->id);
		printf("\tip_off: %d\n", UNFIX(ip->frag_off));
		printf("\tip_ttl: %d\n", ip->ttl);

		switch (ip->protocol)
		{
		case IPPROTO_TCP : printf("\tip_p  : IPPROTO_TCP (%d)\n",
					  ip->protocol);
				   break;
		case IPPROTO_UDP : printf("\tip_p  : IPPROTO_UDP (%d)\n",
					  ip->protocol);
				   break;
		case IPPROTO_ICMP: printf("\tip_p  : IPPROTO_ICMP (%d)\n",
					  ip->protocol);
				   break;
		default :
				   printf("\tip_p  : %d\n", ip->protocol);
				   break;
		}

		printf("\tip_sum: 0x%x\n", ip->check);
		printf("\n");
		printf("data[20] : %d\n", data[20]);
#endif
		/*
		 * Get the source and destination addresses
		 */
		ret->src.fam = AF_INET;
		ret->src.addr.ipv4_addr.s_addr = ip->saddr;
		ret->dst.fam = AF_INET;
		ret->dst.addr.ipv4_addr.s_addr = ip->daddr;
		ret->proto = ip->protocol;

		switch(ret->proto)
		{
		case IPPROTO_TCP:
			{
				u_short *sport, *dport;
				u_char *flags;

				/*
				 * read the source and destination ports, then
				 * the TCP flags
				 */
				sport = (u_short *)(data + ip->ihl*4);
				dport = (u_short *)(data + ip->ihl*4 + 2);
				flags = (u_char *)(data + ip->ihl*4 + 13);

				ret->ports[0] = ntohs(*sport);
				ret->ports[1] = ntohs(*dport);
				ret->flags = *flags;
				break;
			}
		case IPPROTO_UDP:
		case IPPROTO_UDPLITE:
			{
				u_short *sport, *dport;

				sport = (u_short *)(data + ip->ihl*4);
				dport = (u_short *)(data + ip->ihl*4 +
						    sizeof(u_short));
				ret->ports[0] = ntohs(*sport);
				ret->ports[1] = ntohs(*dport);
				break;
			}
		case IPPROTO_ICMP:
			{
				u_char *t, *c;

				t = (data + (ip->ihl*4));
				c = (data + (ip->ihl*4) + sizeof(char));

				ret->ports[0] = *t;
				ret->ports[1] = *c;
				break;
			}
		case IPPROTO_IGMP:
			ret->ports[0] = 0;
			ret->ports[1] = 0;
			break;
		default:
			printf("proto:%d\n", ret->proto);
		}
	} else if (ip->version == 0x06) { /* IPv6 */
		struct ip6_hdr *nip = (struct ip6_hdr *)(data);
		/*
		 * Get the source and destination addresses
		 */
		ret->src.fam = AF_INET6;
		memcpy(&ret->src.addr.ipv6_addr, &nip->ip6_src,
		       sizeof(struct in6_addr));
		ret->dst.fam = AF_INET6;
		memcpy(&ret->dst.addr.ipv6_addr, &nip->ip6_dst,
		       sizeof(struct in6_addr));
		ret->proto = nip->ip6_ctlun.ip6_un1.ip6_un1_nxt;

		/*
		 * FIXME: Getting the ports is not straightforward. Might want
		 * to look at the parsing in net/ipv6/output_core.c. In
		 * particular, look at the ip6_find_1stfragopt function and
		 * it's while loop.
		 */
		ret->ports[0] = 0;
		ret->ports[1] = 0;
	} else {
		if (ret->proto)
			fprintf(stderr,
			    "ip version %d isn't known...packet not decoded\n",
			    ret->proto);
		goto stop;
	}
	return ret;

stop :
	free(ret);
	return NULL;
}

