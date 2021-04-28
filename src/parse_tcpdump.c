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
 * $Id: parse_tcpdump.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 *
 * Author : Renaud Deraison <deraison@cvs.nessus.org>
 *
 */

#include <includes.h>
#include "parse_tcpdump.h"
#include "output.h"

/*
 * returns the number of dots in a string
 */
static int count_dots(char *str)
{
	int r = 0;
	while ((str = strchr(str, '.'))) {
		r++;
		str = str + 1;
	}

	return r;
}


/*
 * converts 1.2.3.4.5 to {1.2.3.4, port = 5}
 */
static struct ip_addr ascaddr2intaddr(char *addr, u_short *port,
				      const char *proto)
{
	int num = count_dots(addr);
	struct ip_addr ret;
	if (num == 4) {
		char *s =  strrchr(addr, '.');
		u_short p;
		s[0] = 0;
		p = atoi(s+1);
		if (!p && strcmp(s+1, "0")) {
			struct servent *se = getservbyname(s+1, proto);
			if (se)
				*port = ntohs(se->s_port);
		} else
			*port = p;
	}
	inet_aton(addr, &ret);
	return ret;
}

/*
 * Returns whether 'c' is a valid TCP flag
 */
static int is_tcp_flag(char c)
{
	if ((c=='.')|| (c=='S')|| (c=='P')|| (c=='F')|| (c=='R'))
		return 1;

	return 0;
}

static int tcp_flag(char c)
{
	switch (c)
	{
	case '.':
		return 0;
	case 'S':
		return TCP_SYN;
	case 'P':
		return TCP_PUSH;
	case 'F':
		return TCP_FIN;
	case 'R':
		return TCP_RST;
	}
	return 0;
}

struct tcpdump *parse_tcpdump_line(char *orig)
{
	char *s, *t;
	struct tcpdump *ret;
	char *src, *dst;
	char *str = strdup(orig);
#ifdef DEBUG
	printf("%s\n", str);
#endif
	ret = malloc(sizeof(struct tcpdump));
	bzero(ret, sizeof(struct tcpdump));

	/*
	 * Identify the SOURCE address
	 */
	s = (char *)strchr(str, ' ');
	if (!s) {
		free(str);
		free(ret);
		return NULL;
	}
	t = strchr(s+1, ' ');
	if (!t) {
		free(str);
		free(ret);
		return NULL;
	}
	t[0] = 0;
	if ((s[1] == '>')||(s[1] == '<')) {
		s += 2;
		t[0] = ' ';
		char *t2 = strchr(t+1, ' ');
		if (t2) {
			t = t2;
			t[0] = 0;
		}
	}
	src = strdup(s+1);

	/*
	 * Identify the DEST address
	 */
	t = strchr(t+1, '>');
	if (!t) {
		free(str);
		free(src);
		free(ret);
		return NULL;
	}
	t += 2;
	s = strchr(t, ':');
	if (!s) {
		free(str);
		free(src);
		free(ret);
		return NULL;
	}
	s[0] = 0;
	s += 2;
	dst = strdup(t);


#ifdef DEBUG
	printf("-> %s:%d\n", inet_ntoa(ret->src), ret->ports[0]);
	printf("-> %s:%d\n", inet_ntoa(ret->dst), ret->ports[1]);
#endif

	/*
	 * Identify the protocol
	 */
	if (is_tcp_flag(s[0])) {
		ret->flags = tcp_flag(s[0]);
		if (is_tcp_flag(s[1])) {
			ret->flags |= tcp_flag(s[1]);
			if (is_tcp_flag(s[2]))
				ret->flags |= tcp_flag(s[2]);
		}
		if (strstr(s, " ack "))
			ret->flags |= TCP_ACK;

		ret->proto = IPPROTO_TCP;
#ifdef DEBUG
		printf("Protocol : TCP\n");
#endif
	} else if (ret->ports[0]) {
		ret->proto = IPPROTO_UDP;
#ifdef DEBUG
		printf("Protocol : UDP\n");
#endif
	} else if (!strncmp(s, "icmp", 4)) {
		t = strchr(s, ':');
		if (t) {
			t += 2;
			if (!strncmp(t, "echo", strlen("echo"))) {
				char *s2 =  strchr(t, ' ');
				if (s2) {
					s2++;
					if (!strncmp(s2, "request",
						     strlen("request"))) {
						ret->type= NS_ICMP_ECHO_REQUEST;
						ret->code = 0;
					} else if (!strncmp(s2, "reply",
							    strlen("reply"))) {
						ret->type = NS_ICMP_ECHO_REPLY;
						ret->code = 0;
					}
				}
#ifdef DEBUG
				else
					printf("Parse error : %s -- unknown echo type\n", t);
#endif
			} else if (!strncmp(t, "time exceeded in-transit",
					 strlen("time exceeded in-transit"))) {
				ret->type = NS_ICMP_TIMXCEED;
				ret->code = NS_ICMP_TIMXCEED_IN_TRANSIT;
			} else if (!strncmp(t, "host ", strlen("host "))||
				!strncmp(t, "net ", strlen("net "))) {
				char *v;

				if (!strncmp(t, "net ", strlen("net ")))
					v = t + strlen("net ");
				else
					v = t + strlen("host ");

				v = strchr(v, ' ');
				if (v) {
					v++;
					if (!strncmp(v, "unreachable",
						     strlen("unreachable"))) {
						ret->type = NS_ICMP_UNREACH;
						ret->code = 0; /* not implemented yet */
					}
				}
			} else {
				char *d = strrchr(t, ' ');
				if (!strncmp(d+1, "unreachable",
					    strlen("unreachable"))) {
					ret->type = NS_ICMP_UNREACH;
					ret->code = 0; /* very likely to be a given udp port */
				}
			}
		}
		ret->proto = IPPROTO_ICMP;
#ifdef DEBUG
		printf("Protocol : ICMP\n");
#endif
	}

#ifdef BE_VERBOSE
	else {
		printf("%s", orig);
		printf("---> Unknown protocol\n");
	}
#endif
	ret->src = ascaddr2intaddr(src, &ret->ports[0], int2proto(ret->proto));
	ret->dst = ascaddr2intaddr(dst, &ret->ports[1], int2proto(ret->proto));
	free(src);
	free(dst);
	free(str);
	return ret;
}

