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
 * $Id: cache.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 *
 * Author : Renaud Deraison <deraison@cvs.nessus.org>
 *
 */
#include <includes.h>
#include "parse_tcpdump.h"
#include "cache.h"
#include "networks.h"

/*
 * The 'cache' is used to determine whether we should
 * print a stream on the screen or not (no need to say the
 * same thing twice).
 *
 * The 'cache' structure is a simply linked list. Because the order is not
 * important, we add elements in front of the list.
 */

/*
 * returns 1 if the stream in 'dump' is already present
 * in the cache
 */
int present_in_cache(struct cache *cache, const char *name,
		     struct tcpdump *dump)
{
	while (cache) {
		if ((cache->proto == dump->proto) &&
		   !strcmp(name, cache->name)) {
			/*
			 * the prototype between dump and cache are the
			 * same, and so is the service name. We only have
			 * to check for the addresses
			 */

			if (addr_equal(&(cache->src), &(dump->src))) {
				/*
				 * check that the streams have at least one
				 * port in common
				 */
				if (addr_equal(&(cache->dst), &(dump->dst))) {

					/*
					 * Only pay attention to the server port
					 * for non icmp streams
					 */
					if (dump->proto != IPPROTO_ICMP) {
						if (dump->ports[1] ==
								cache->dport)
							return 1;
					} else if (dump->ports[0] ==
								cache->sport)
						return 1;
				}
			}
		}
		cache = cache->next;
	}
	return 0;
}


/*
 * add the stream in 'dump' in the cache.
 */
void add_in_cache(struct cache **pcache, const char *name, struct tcpdump *dump)
{
	struct cache * toadd;

	toadd = (struct cache *) malloc(sizeof(struct cache));
	toadd->name = name;
	addr_assign(&(toadd->src), &(dump->src));
	addr_assign(&(toadd->dst), &(dump->dst));
	toadd->sport = dump->ports[0];
	toadd->dport = dump->ports[1];
	toadd->proto = dump->proto;

	toadd->next = *pcache;
	*pcache = toadd;
}

void free_cache(struct cache *c)
{
	struct cache *next;

	do {
		next = c->next;
		free(c);
		c = next;
	} while (c);
}

