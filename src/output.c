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
 * $Id: output.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 *
 * Author : Renaud Deraison <deraison@cvs.nessus.org>
 *
 */
#include <includes.h>
#include "parse_tcpdump.h"
#include "config_rules.h"
#include "networks.h"
#include "output.h"

extern int reject_syn;
extern int opt_u;
extern int opt_U;
extern int opt_B;


const char *int2proto(int proto)
{
	return(proto==IPPROTO_TCP ? "tcp":
	       proto==IPPROTO_UDP ? "udp":
	       proto==IPPROTO_ICMP ? "icmp":
	       proto==IPPROTO_IGMP ? "igmp":
	       proto==IPPROTO_UDPLITE ? "udp-lite" :
	       proto==IPPROTO_ICMPV6 ? "icmpv6" : NULL);
}


/*
 * free the memory allocated by make_output()
 */
void free_output(struct output *out)
{
	free(out->serv_name);
	free(out->src);
	free(out->dst);
	free(out->sports);
	free(out->dports);
	free(out);
}


struct output *make_output(struct network *nets, struct ip_addr src,
			   struct ip_addr dst, int sport, int dport, int proto,
			   struct config_rules *rule, int shownet, char *iface)
{
	struct output *ret = malloc(sizeof(struct output));
	if (rule)
		ret->serv_name = strdup(rule->name);
	else
		ret->serv_name = strdup("unknown");

	ret->sport = sport;
	ret->dport = dport;
	addr_assign(&(ret->ia_sorig), &src);
	addr_assign(&(ret->ia_dorig), &dst);
	if (shownet) {
		ret->src = strdup(ip_to_network(nets, src,shownet>1));
		ret->dst = strdup(ip_to_network(nets,dst, shownet>1));
		ret->ia_src = get_network_ip(nets, ret->src,shownet>1);
		ret->ia_dst = get_network_ip(nets, ret->dst, shownet>1);
		ret->smask = get_network_mask(nets, ret->src, shownet>1);
		ret->dmask = get_network_mask(nets, ret->dst, shownet>1);

		ret->s_bcast = get_broadcast(&ret->ia_src, ret->smask);
		ret->d_bcast = get_broadcast(&ret->ia_dst, ret->dmask);
	} else {
		ret->src = addr_str(&src, sport);
		ret->dst = addr_str(&dst, dport);
		addr_assign(&ret->ia_src, &src);
		addr_assign(&(ret->ia_dst), &dst);
		ret->smask = ret->dmask = 32;
	}

	ret->proto = proto;
	ret->asc_proto = int2proto(proto);

	if (rule) {
		if (ret->proto != IPPROTO_ICMP) {
			ret->sports = strdup(rule->asc_dports);
			ret->dports = strdup(rule->asc_sports);
		} else {
			ret->sports = strdup(rule->asc_sports);
			ret->dports = strdup(rule->asc_dports);
		}
	} else {
		ret->sports = malloc(10);
		sprintf(ret->sports, "%d", ret->sport);
		ret->sports = realloc(ret->sports, strlen(ret->sports)+1);

		ret->dports = malloc(10);
		sprintf(ret->dports, "%d", ret->dport);
		ret->dports = realloc(ret->dports, strlen(ret->dports)+1);
	}

	ret->show_net = shownet;
	ret->iface = iface;
	return ret;
}



/*
 * The different outputs -- ipfw, ipchains and bare nstreams
 *
 * Note that ipchains and ipfw do not pay attention to the device
 * except if explicitely told so.
 */



/*
 * ipfw
 */
void ipfw_output(struct output *output, int status)
{
	switch (status)
	{
	case OP_START :
		/* initialize the  firewall script */
		printf("#!/bin/sh\n");
		printf("# Flush the old rules : \nipfw -f flush\n\n");
		printf("# Accept the traffic going to the loopback :\n");
		printf("ipfw add allow all from localhost to localhost via lo0\n");
		printf("\n# The streams start here :\n\n\n");
		break;

	case OP_END :
		printf("\n# Deny everything else\n");
		printf("ipfw add deny all from any to any\n");
		break;

	default :
		/*
		 * man ipfw for details
		 */
		if (output->proto == IPPROTO_ICMP) {
			printf("#\n# Accept %s :\n#\n", output->serv_name);
			printf("ipfw add allow %s from %s/%d to %s/%d icmptypes %s",
			       output->asc_proto,
			       output->src, output->smask,
			       output->dst, output->dmask,
			       output->sports);
			if (output->iface)
				printf(" via %s", output->iface);
			printf("\n\n");
		} else {
			int unknown = !strcmp(output->serv_name, "unknown");
			if (unknown && opt_u)
				return;
			if (!unknown && opt_U)
				return;
			printf("#\n# Accept %s : \n#\n\n",output->serv_name);
			/*
			 * Inside --> Outside
			 */
			printf("# Inside -> Outside\n");
			printf("ipfw add allow %s from %s/%d %s to %s/%d %s out",
			       output->asc_proto,
			       output->src,output->smask, output->sports,
			       output->dst, output->dmask,output->dports);
			if (output->iface)
				printf(" via %s", output->iface);
			printf("\n\n");
			/*
			 * Outside --> Inside
			 */
			printf("# Outside -> Inside\n");
			if (reject_syn && (output->proto == IPPROTO_TCP)) {
				printf("# Reject connections from the outside : \n");
				printf("ipfw add deny %s from %s/%d %s to %s/%d %s in setup\n",
				       output->asc_proto,
				       output->dst,output->dmask,
				       output->dports,
				       output->src, output->smask,
				       output->sports);
				printf("# Accept already established connections : \n");
			}

			printf("ipfw add allow %s from %s/%d %s to %s/%d %s in",
			       output->asc_proto,
			       output->dst,output->dmask, output->dports,
			       output->src, output->smask,output->sports);
			if (output->iface)
				printf(" via %s", output->iface);
			printf("\n\n\n");
		}
		break;
	}
}



/*
 * ipchains
 */
void ipchains_output(struct output *output, int status)
{
	switch (status)
	{
	case OP_START :
		printf("#!/bin/sh\n\n");
		printf("# Flushing old rules\n");
		printf("ipchains -F\n");
		printf("ipchains -X\n");
		printf("\n# Setting default policy\n");
		printf("ipchains -P input DENY\n");
		printf("ipchains -P output DENY\n");
		printf("ipchains -P forward DENY\n");
		printf("# Add here your local forward, like : \n");
		printf("# ipchains -A forward -s 192.168.1.0/24 -d 0.0.0.0/0 -j MASQ\n");
		printf("\n# Accepting all packets on all local(s) interface(s)\n");
		printf("ipchains -A input -i lo -j ACCEPT\n");
		printf("ipchains -A output -i lo -j ACCEPT\n");
		printf("ipchains -A forward -i lo -j ACCEPT\n");
		printf("\n# Streams start here :\n\n\n");
		break;

	case OP_END :
		break;

	default :
		{
			char *c_sports = strdup(output->sports);
			char *c_dports = strdup(output->dports);
			char *t;
			/* ipchains has a dumb port range syntax */
			while ((t=strchr(c_sports, '-')))
				t[0]=':';
			while ((t=strchr(c_dports, '-')))
				t[0]=':';

			/* man ipchains for details */
			if (output->proto == IPPROTO_ICMP) {
				printf("# %s - You should delete one of these two lines\n",
				       output->serv_name);
				printf("ipchains -A input -p %s  -s %s/%d -d %s/%d --icmp-type %d",
				       output->asc_proto,
				       output->src, output->smask,
				       output->dst, output->dmask,
				       output->sport);
				if (output->iface)
					printf(" -i %s", output->iface);
				printf("\n");
				printf("ipchains -A output -p %s  -s %s/%d -d %s/%d --icmp-type %d",
				       output->asc_proto,
				       output->src, output->smask,
				       output->dst, output->dmask,
				       output->sport);
				if (output->iface)
					printf(" -i %s", output->iface);
				printf("\n\n");
			} else {
				int unknown = !strcmp(output->serv_name, "unknown");

				if (unknown && opt_u) {
					free(c_sports);
					free(c_dports);
					return;
				}
				if (!unknown && opt_U) {
					free(c_sports);
					free(c_dports);
					return;
				}
				printf("# Accept %s\n\n", output->serv_name);
				/*
				 * Outside --> inside
				 */
				printf("#\n# Outside -> Inside\n#\n");
				printf("ipchains -A input -s %s/%d %s -d %s/%d %s -p %s -j ACCEPT",
				       output->dst, output->dmask, c_dports,
				       output->src, output->smask, c_sports,
				       output->asc_proto);
				if (output->iface)
					printf(" -i %s", output->iface);
				if (reject_syn && (output->proto==IPPROTO_TCP))
					printf(" ! -y");
				printf("\n");
				/*
				 * Inside --> Outside
				 */
				printf("#\n# Inside -> Outside\n#\n");
				printf("ipchains -A output -s %s/%d %s -d %s/%d %s -p %s -j ACCEPT",
				       output->src, output->smask, c_sports,
				       output->dst, output->dmask, c_dports,
				       output->asc_proto);
				if (output->iface)
					printf(" -i %s", output->iface);
				printf("\n\n");
			}

			free(c_sports);
			free(c_dports);
		}
	}
}

void standard_output(struct output *output, int status)
{
	if (status)
		return;

	if (!strcmp(output->serv_name, "unknown")) {
		if(!opt_u) {
			printf("Unknown %s traffic between %s:%d and %s:%d\n",
			       output->asc_proto,
			       output->src, output->sport,
			       output->dst, output->dport);
		}
	} else if (!opt_U) {
		if (output->show_net > 1)
			printf("%s traffic between %s/%d and %s/%d\n",
			       output->serv_name, output->src, output->smask,
			       output->dst, output->dmask);
		else {
			const char *bcast = " (broadcast)";
			const char *net = " (network)";
			const char *s, *d;
			const char *empty = "";
			if (opt_B && addr_equal(&(output->ia_sorig),
				    &(output->s_bcast)) && (output->smask < 32))
				s = bcast;
			else {
				struct ip_addr net_a = get_net(&(output->ia_src),
							       output->smask);

				if (opt_B && addr_equal(&(output->ia_sorig),
					    &(net_a)) && (output->smask < 32) &&
					    (output->smask > 0))
					s = net;
				else
					s = empty;
			}

			if (opt_B && addr_equal(&(output->ia_dorig),
				    &(output->d_bcast)) && (output->dmask < 32))
				d = bcast;
			else {
				struct ip_addr net_a = get_net(&(output->ia_dst),
							       output->dmask);

				if (opt_B && addr_equal(&(output->ia_dorig),
					    &(net_a)) && (output->dmask < 32) &&
					    (output->smask > 0))
					d = net;
				else
					d = empty;
			}

			printf("%s traffic between %s%s and %s%s\n",
			       output->serv_name, output->src,s, output->dst,d);
		}
	}
}

