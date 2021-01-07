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

struct bogus_iphdr
  {
#ifndef WORDS_BIGENDIAN
    unsigned int ihl:4;
    unsigned int version:4;
#else
    unsigned int version:4;
    unsigned int ihl:4;
#endif
    u_char tos;
    u_short tot_len;
    u_short id;
    u_short frag_off;
    u_char ttl;
    u_char protocol;
    u_short check;
    u_int saddr;
    u_int daddr;
 };


/*
 * pcap packet to a tcpdump struct
 */
struct tcpdump *
parse_pcap_entry(data)
 u_char * data;
{
 struct tcpdump * ret = malloc(sizeof(struct tcpdump));
 struct bogus_iphdr * ip = (struct bogus_iphdr*)(data);
 bzero(ret, sizeof(*ret));

 /*
  * Check that we have an IPv4 packet
  */

 if(ip->version!=0x04)goto stop;
#ifdef DEBUG
#define UNFIX(x) ntohs(x)
    printf("\tip_hl : %d\n", ip->ihl);
    printf("\tip_v  : %d\n", ip->version);
    printf("\tip_tos: %d\n", ip->tos);
    printf("\tip_len: %d\n", UNFIX(ip->tot_len));
    printf("\tip_id : %d\n", ip->id);
    printf("\tip_off: %d\n", UNFIX(ip->frag_off));
    printf("\tip_ttl: %d\n", ip->ttl);

    switch(ip->protocol)
    {
     case IPPROTO_TCP : printf("\tip_p  : IPPROTO_TCP (%d)\n", ip->protocol);
     		        break;
     case IPPROTO_UDP : printf("\tip_p  : IPPROTO_UDP (%d)\n", ip->protocol);
     			break;
     case IPPROTO_ICMP: printf("\tip_p  : IPPROTO_ICMP (%d)\n", ip->protocol);
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
  * Get the source and destination adresses
  */
  ret->src.s_addr = ip->saddr;
  ret->dst.s_addr = ip->daddr;
  
  ret->proto = ip->protocol;
  switch(ret->proto)
  {
   case IPPROTO_TCP :
   	{
	struct bogus_tcphdr * tcp = (struct bogus_tcphdr*)(data + ip->ihl*4);
	u_short * sport, * dport;
	u_char * flags;
	
	/* 
	 * read the source and destination ports, then
	 * the TCP flags
	 */
	sport = (u_short*)(data + ip->ihl*4);
	dport = (u_short*)(data + ip->ihl*4 + 2);
	flags = (u_char*)(data + ip->ihl*4 + 13);
	
	ret->ports[0] = ntohs(*sport);
	ret->ports[1] = ntohs(*dport);
	ret->flags = *flags;
        break;
      }
   case IPPROTO_UDP :
   	{
	 u_short * sport, * dport;
	 
	 sport = (u_short*)(data + ip->ihl*4);
	 dport = (u_short*)(data + ip->ihl*4 + sizeof(u_short));
	 ret->ports[0] = ntohs(*sport);
	 ret->ports[1] = ntohs(*dport);
	 break;
	}
  case IPPROTO_ICMP :
       {
        u_char * t, * c;
	
	t = (data + (ip->ihl*4));
	c = (data + (ip->ihl*4) + sizeof(char));
	
	ret->ports[0] = *t;
	ret->ports[1] = *c;
	break;
      }
    } 
  
  return(ret);
  

stop :
 free(ret);
 return(NULL);
}

