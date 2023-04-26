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
 * $Id: config_rules.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 *
 * Author : Renaud Deraison <deraison@cvs.nessus.org>
 *
 */
#include <includes.h>
#include "parse_tcpdump.h"
#include "ports.h"
#include "config_rules.h"
#include "networks.h"

/*
 * This part of the source is in charge of reading /etc/nstreams-services
 * and to determine whether a stream matches a given service or not
 */


/*
 * get the rule that matches the properties of the stream
 */

struct config_rules *get_rule(struct config_rules *cr, struct tcpdump *dump)
{
	while (cr) {
		/*
		 * first check that the prototypes are the same
		 */
		if (cr->proto == dump->proto) {
			int s = 0, d = 0; /* s = source, d = dest */

			/*
			 * check that the first end of the stream matches
			 * either the source (s) or the destination (d)
			 */
			if ((s = port_in_ports(dump->ports[0], cr->sports,
					       cr->num_sport)) ||
			    (d=port_in_ports(dump->ports[0], cr->dports,
					     cr->num_dport))) {
				if ((dump->proto == IPPROTO_ICMP) && d) {
				/* don't mix types and codes with ICMP */
					cr = cr->next;
					continue;
				}
				/*
				 * and check that the other end matches the other end
				 */
				if (port_in_ports(dump->ports[1],
						  s ? cr->dports : cr->sports,
						  s ? cr->num_dport :
						  cr->num_sport)) {
					if (s) {
						if ((dump->flags != TCP_SYN)) {
							/* don't mix ICMP */
							if (dump->proto != IPPROTO_ICMP) {
							/*
							 * We need to swap the source and the destination, since
							 * we found it the other way
							 *
							 * 'src' must be the server, and 'dst' the client
							 *
							 */
								struct ip_addr t;
								int port;

								addr_assign(&t, &(dump->src));
								port = dump->ports[0];
								dump->ports[0] = dump->ports[1];
								dump->ports[1] = port;
								addr_assign(&(dump->src), &(dump->dst));
								addr_assign(&(dump->dst), &t);
							}
						} else {
							cr = cr->next;
							continue;
						}
					}

					/* ok, found. Return it */
					return(cr);
				}
			}
		}
		cr = cr->next;
	}
	/* no rule match this one */
	return NULL;
}


/*
 * Initialize the rules table. We use a caching technique
 * in ports.c to reduce memory consumption. And this works :)
 */
struct config_rules *read_config(FILE *fd)
{
	struct config_rules *cr, *c, *old = NULL;
	char *str;
	const char *any = "1-65535";

	c = cr = calloc(sizeof(struct config_rules), 1);
	str = malloc(1024);

	while (fgets(str, 1023, fd)) {
		/* str : one line in our configuration file */
		char *s = str;

		/* skip the first spaces and/or tabs */
		while ((s[0]==' ')||(s[0]=='\t'))
			s++;

		/* remove the carriage returns */
		while (strlen(s) && ((s[strlen(s)-1]=='\n') ||
				    (s[strlen(s)-1]=='\r')))
			s[strlen(s)-1] = 0;

		/* remove the trailing spaces */
		while (strlen(s) && ((s[strlen(s)-1]==' ') ||
				     (s[strlen(s)-1]=='\t')))
			s[strlen(s)-1] = 0;

		/*
		 * Treat this entry if and only if it's not a comment
		 * (not starting by '#')
		 */
		if ((s[0]!='#')&&(strlen(s)>1)) {
			/*
			 * the syntax of the configuration file is
			 * 'servicename:ports/proto:ports'
			 */

			char *t = strchr(s, ':');

			/*
			 * t points on the first ':'. that is,
			 * t = ':ports/proto:ports'
			 */

			if (!t) {
				printf("Syntax error in the configuration file:\n\t%s\n", str);
				exit(1);
			}

			/*
			 * end the string
			 */
			t[0] = 0;


			/*
			 * Copy the service name.
			 */
			c->name = strdup(s);

			/*
			 * restore the string
			 */
			t[0] = ':';


			/*
			 * s=t+1, that is 'ports/proto:ports'
			 */
			s = t+1;


			t = strchr(s, '/');
			/*
			 * t = '/proto:ports'
			 */
			if (!t) {
				printf("Syntax error in the configuration file:\n\t%s\n", str);
				exit(1);
			}

			t[0] = 0;

			/*
			 * s = 'ports'. Do a expression-to-array conversion
			 */
			c->sports = getports(s, &c->num_sport);
			if (strcmp(s, "any"))
				c->asc_sports = strdup(s);
			else
				c->asc_sports = strdup(any);

			/* restore the string */
			t[0] = '/';
			s = t+1;
			/*
			 * s = 'proto:ports'
			 */


			/*
			 * t = ':ports'
			 */
			t = strchr(s, ':');

			if (!t) {
				printf("Syntax error in the configuration file:\n\t%s\n", str);
				exit(1);
			}
			t[0] = 0;

			/*
			 * do a char * to int conversion
			 */
			if (!strcmp(s,"tcp"))
				c->proto = IPPROTO_TCP;
			else if(!strcmp(s, "udp"))
				c->proto = IPPROTO_UDP;
			else if(!strcmp(s, "icmp"))
				c->proto = IPPROTO_ICMP;
			else if(!strcmp(s, "icmpv6"))
				c->proto = IPPROTO_ICMPV6;
			else if(!strcmp(s, "igmp"))
				c->proto = IPPROTO_IGMP;
			else {
				printf("Unknown protocol '%s'\n",s);
				exit(1);
			}
			t[0] = ':';
			s = t+1;
			/*
			 * s = ports
			 */
			c->dports = getports(s, &c->num_dport);
			if (strcmp(s, "any"))
				c->asc_dports = strdup(s);
			else
				c->asc_dports = strdup(any);

			/*
			 * Done. Prepare space for the other
			 * entries in the configuration file
			 */

			c->next = calloc(sizeof(struct config_rules), 1);
			old = c;

			/*
			 * sanity check
			 */
			if (c->proto != IPPROTO_ICMP &&
						c->proto != IPPROTO_ICMPV6 &&
						c->proto != IPPROTO_IGMP) {
				if ((port_in_ports(0, c->dports,
						   c->num_dport)) ||
				   (port_in_ports(0, c->sports, c->num_sport))){
					printf("Error. You specified a null port for an tcp or udp prototype\n");
					printf("Offending line :  '%s'\n", str);
					exit(1);
				}
			}
			c = c->next;
		}
	}

	/*
	 * since we allocated memory ahead of time,
	 * the last entry is not used
	 */
	if (old) {
		free(old->next);
		old->next = NULL;
	}
	free(str);
	return cr;
}

void free_rules(struct config_rules *c)
{
	struct config_rules *next;

	do {
		next = c->next;
		free(c->name);
		free(c->asc_dports);
		free(c->asc_sports);
		free(c);
		c = next;
	} while (c);
}

