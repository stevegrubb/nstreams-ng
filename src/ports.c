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
 * $Id: ports.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 *
 * Author : Renaud Deraison <deraison@cvs.nessus.org>
 *
 *
 * This file contains function that regard ports. Especially :
 *
 *	- functions to convert strings to array of ports
 *	- functions to NOT create twice the same array
 *	  of ports (to save memory)
 *	- functions to determine quickly whether a value is
 *	  in an array
 */

#include <includes.h>
#include "ports.h"


/*
 * This structure is used to save memory, as you'll
 * see later in this file
 */
struct port_range {
	char *name;
	int num;
	u_short *data;
	struct port_range *next;
};
struct port_range *PortRange = NULL;	



/* 
 * Entry point to convert a string to an array
 * of port without wasting memory.
 *
 * How this works (there's nothing smart, don't
 * hold your breath)
 *
 * Since our arrays of ports are read-only, and since
 * each one can take up to 128KB, we have an handy
 * structure which keeps track of the conversion
 * we made, as well as their results. So, if
 * we happen to have twice the same port range
 * (very likely), then the second time, we will
 * determine we have already converted this, and we
 * will return the pointer we created before.
 *
 */

u_short *getports(const char *expr, int *num)
{
	int n = 0;
	u_short *ret = NULL;
	struct port_range *pr;
	struct port_range *p;


	/*
	 * did we already convert this expression to an array
	 * of ports ?
	 */
	if (PortRange) {
		pr = PortRange;
		while (pr) {
			if (!strcmp(pr->name, expr)) {
				/*
				 * We did. So we return what we had converted
				 * the first time
				 */
				*num = pr->num;
				return pr->data;
			}
			pr = pr->next;
		}
	}


	/*
	 * we have never converted this expression to
	 * an array of port. Let's do it.
	 */
	ret = getpts(expr, &n);

	/*
	 * add the result of this conversion to
	 * our structure
	 */
	pr = malloc(sizeof(struct port_range));
	bzero(pr, sizeof(struct port_range));
	pr->name = strdup(expr);
	pr->data = ret;
	pr->num = n;
	if (!PortRange)
		PortRange = pr;
	else {
		p = PortRange;
		while (p->next)
			p = p->next;
		p->next = pr;
	}
	*num = n;
	return ret;
}


/*
 * comparison function used in qsort()
 */
int compar(const void *a, const void *b)
{
	u_short *aa = (u_short *)a;
	u_short *bb = (u_short *)b;

	return *aa-*bb;
}
/*
 * getpts()
 *
 * This function is (c) Fyodor <fyodor@dhp.com> and was taken from
 * his excellent and outstanding scanner Nmap
 * See http://www.insecure.org/nmap/ for details about
 * Nmap
 */
static const char *all = "1-65535";


/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array
   of port numbers*/
unsigned short *getpts(const char *origexpr, int *num)
{
	unsigned int exlen, i, j;
	int start, end;
	char *p, *q;
	unsigned short *tmp, *ports;
	char *expr;
	char *mem;

	if (!strcmp(origexpr, "any"))
		origexpr = all;
	expr = strdup(origexpr);
	exlen = strlen(origexpr);
	mem = expr;

	ports = malloc(65536 * sizeof(short));
	for(j=0, i=0; j < exlen; j++) {
		if (expr[j] != ' ')
			expr[i++] = expr[j];
	}
	expr[i] = '\0';
	exlen = i;
	i = 0;
	while ((p = (char *)strchr(expr,','))) {
		*p = '\0';
		if (*expr == '-') {
			start = 1;
			end = strtol(expr+ 1, NULL, 10);
		} else {
			start = end = strtol(expr, NULL, 10);
			if ((q = (char*)strchr(expr,'-')) && *(q+1) )
				end = strtol(q + 1, NULL, 10);
			else if (q && !*(q+1))
				end = 65535;
		}

		if (start < 0)
			start = 0;
		if (end < 0)
			end = 0;
		if (start > 65535)
			start = 65535;
		if (end > 65535)
			end = 65535;
		if (start > end) {
			free(mem);
			free(ports);
			return NULL; /* invalid spec */
		}
		for (j=start; j <= (unsigned)end; j++)
			ports[i++] = j;
		expr = p + 1;
	}
	if (*expr == '-') {
		start = 1;
		end = strtol(expr+ 1, NULL, 10);
	} else {
		start = end = strtol(expr, NULL, 10);
		if ((q =  (char*)strchr(expr,'-')) && *(q+1))
			end = strtol(q+1, NULL, 10);
		else if (q && !*(q+1))
			end = 65535;
	}

	if (end < 0)
		end = 0;
	if(start > 65535)
		start = 65535;
	if (end > 65535)
		end = 65535;
	if (start < 0 || start > end) {
		free(mem);
		free(ports);
		return NULL;
	}
	for (j=start; j <= (unsigned)end; j++)
		ports[i++] = j;

	tmp = realloc(ports, (i+1) * sizeof(short));
	*num = i;
	qsort(tmp, i, sizeof(u_short), compar);

	free(mem);
	return tmp;
}




/*
 * Determine is <port> is in <ports>, recursively. In less than 15
 * comparisons for 65535 elements.
 */
bool rec_pip(u_short port, u_short *ports, unsigned int s, unsigned int e)
{
	if (s == e)
		return (ports[s] == port);
	else {
		unsigned int mid = (e + s) / 2;
		if (port > ports[mid])
			return (rec_pip(port, ports, mid+1, e));

		return (rec_pip(port, ports, s, mid));
	}
}


/*
 * is a port in our port list ?
 *
 * We use the function rec_pip(), which is
 * recursive, and which will determine if
 * a port is present by dichotomy.
 *
 */
bool port_in_ports(u_short port, u_short *ports, unsigned int len)
{
	unsigned int mid = (len-1) / 2;
	int ret;

	if (port > ports[mid])
		ret = rec_pip(port, ports, mid, len);
	else
		ret = rec_pip(port, ports, 0, mid);

	return ret;
}

