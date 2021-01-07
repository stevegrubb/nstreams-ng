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
 * $Id: networks.c,v 1.1.1.1 2000/07/26 16:18:01 renaud Exp $
 *
 * Author : Renaud Deraison <deraison@cvs.nessus.org>
 *
 *
 * Network management routines. This file contains mainly functions
 * which determine if a given host belongs to a given network, 
 * and the function which reads /etc/nstreams-networks.
 *
 */
 
#include <includes.h>
#include "networks.h"


/*
 * return the network address.
 *
 * ie : 192.168.1.12/24 --> 192.168.1.0
 */
struct in_addr 
get_net(addr, mask)
 	struct in_addr addr;
	int mask;
{
 struct in_addr net_a;
 
 net_a.s_addr = ntohl(addr.s_addr) >> (32 - mask);
 net_a.s_addr = htonl(net_a.s_addr << (32 - mask));
 return(net_a);
}

/*
 * returns the broadcast address of a network.
 *
 * ie : 192.168.1.12/24 --> 192.168.1.255
 */
struct in_addr
get_broadcast(addr, mask)
	struct in_addr addr;
	int mask;
{
 struct in_addr net_a;
 
  net_a.s_addr = (ntohl(addr.s_addr) >> (32 - mask)) + 1;
  net_a.s_addr = htonl((net_a.s_addr << (32 - mask)) - 1);
  return(net_a);
}


/*
 * Read the networks file.
 */

struct network * 
read_networks(fd)
 FILE * fd;
{
 struct network * ret = malloc(sizeof(struct network));
 char * str = malloc(1024);
 struct network * n = ret;
 struct network * old = NULL;
 
 
 bzero(str, 1024);
 bzero(ret, sizeof(struct network));
 
 while((fgets(str, 1023, fd)))
 {
  char * s = str;
  char * t;
  
  /*
   * skip the first spaces and tabs
   */
  while((s[0]==' ')||(s[0]=='\t'))s++;
  
  /* suppress the trailing garbage */
  while(strlen(s) && (
        (s[strlen(s)-1]=='\n')||(s[strlen(s)-1]=='\r')||
        (s[strlen(s)-1]==' ') || (s[strlen(s)-1]=='\t')))s[strlen(s)-1]=0;
	
	
  /*
   * process this line if and only if it's not a comment
   */
  if((s[0]!='#') && (strlen(s)>1))
  {
   /* 
    * the network file line format is :
    * 'name:ip/netmask'
    */
   
   /* 
    * t = ':ip/netmask'
    */
   t = strchr(s, ':');
   if(!t){
   	printf("Syntax error in the networks file : \n");
	printf("%s", str);
	exit(1);
	}
  
   /* 
    * end the line
    */
   t[0]=0;
   
   /*
    * copy the name of the network
    */
   n->name = strdup(s);
   
   /*
    * restore the line
    */
   t[0] = ':';
   
   /*
    * s = 'ip/mask'
    */
   s = t+1;
   
   /*
    * t = /mask
    */
   t = strchr(s, '/');
   
   /* 
    * if no netmask is specified, then
    * consider it's 32
    */
   if(!t)n->mask = 32;
   else {
        /* t+1 = 'mask' */
   	n->mask = atoi(t+1);
	
	/* finish the line */
   	t[0]=0;
	}
   
   /*
    * s = 'addess'
    */
   inet_aton(s, &n->addr);
   
   /*
    * convert the IP to the network IP (using the
    * mask
    */
   n->addr = get_net(n->addr, n->mask);
   
   /*
    * and have a copy of the ascii version of the network
    * IP around
    */
   n->asc_addr = strdup(inet_ntoa(n->addr));
   
   old = n;
   /* prepare memory for the next entry */
   n->next = malloc(sizeof(struct network));
   n = n->next;
   
  }
 }
 if(old){
 	/* delete the last entry */
 	free(old->next);
	old->next = NULL;
	}
 free(str);
 return(ret);
}

void free_networks(struct network *n)
{
	struct network *next;

	do {
		next = n->next;
		free(n->asc_addr);
		free(n->name);
		free(n);
		n = next;
	} while (n);
}

/*
 * returns the mask of the network <name>
 */
int get_network_mask(nets, name, numeric)
 struct network * nets;
 char * name;
 int numeric;
{
 while(nets)
 {
  if(numeric){if(!strcmp(nets->asc_addr, name))return(nets->mask);}
  else if(!strcmp(nets->name, name))return(nets->mask);
  nets = nets->next;
 }
 return(32);
}


/*
 * get the name of the network to which the
 * ip <ip> belongs
 */
char * ip_to_network(nets, ip,numeric)
 struct network * nets;
 struct in_addr ip;
 int numeric;
{
 struct in_addr i;
 struct network * match = NULL;
 
 /*
  * in ip_to_network() we want the name of the
  * network, not just a /32 host. So, we use <match>
  * which will contain the first occurence of
  * the network that matches the IP, and if no better
  * has been found, we return it
  */
 
 while(nets)
 {
  if(!nets->mask && !match){
  	if(numeric)return(nets->asc_addr);
	else return(nets->name);
	}
  i.s_addr = ip.s_addr;
  ip = get_net(ip, nets->mask);
  if(ip.s_addr == nets->addr.s_addr){
#ifdef USELESS_FEATURE
  	if(nets->mask == 32)match = nets;
	else 
#endif	
	{
  	 if(numeric)return(nets->asc_addr);
  	 else return(nets->name);
	 }
	}
  nets = nets->next;
  ip.s_addr = i.s_addr;
 }
 
 if(match)
 {
  if(numeric)return(match->asc_addr);
  else return(match->name);
 }
 /*
  * Nothing matched - return the IP
  */
 return(inet_ntoa(ip));
}


/*
 * get the IP of the network <name>.
 * If <numeric> is set to 1, then return
 * the IP adress of the network in ascii
 */
struct in_addr 
get_network_ip(nets, name,numeric)
 struct network * nets;
 char * name;
 int numeric;
{
 struct in_addr nothing;
 nothing.s_addr = 0;
 while(nets)
 {
  if(numeric){if(!strcmp(nets->asc_addr, name))return(nets->addr);}
  else if(!strcmp(nets->name, name))return(nets->addr);
  nets = nets->next;
 }
 return(nothing);
}
