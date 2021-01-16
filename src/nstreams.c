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
 * $Id: nstreams.c,v 1.2 2000/08/01 09:58:11 renaud Exp $
 *
 * Network Streams -- a tcpdump analyzer tool.
 *
 * (C) 1999 Renaud Deraison and Hervé Schauer Consultant -- http://www.hsc.fr
 *
 */
#include <includes.h>
#include "parse_tcpdump.h"
#include "config_rules.h"
#include "cache.h"
#include "networks.h"
#include "output.h"
#include "read_pcap.h"
#include <pcap.h>
/*
 * Declaration of the 'data to struct tcpdump' type
 */

typedef struct tcpdump*(*parser_func_t)(char *);

/* 
 * list of the supported output formats
 */
const char * formats = "\t\tipfw ipchains nstreams";

/*
 * Global variables
 */
int reject_syn = 0;
int opt_u = 0;
int opt_U = 0;
int opt_B = 0;

volatile int signal_received = 0;

/*
 * print the command line options and
 * quit
 */
void usage()
{
 printf("Usage : nstreams [-v] [-c <nstreams-services file> ]\
 [ -n <networks-file> ] [ -N [ -i ] [ -I ]]\
 [ -O <format> [ -D <interface> ] [ -Y ]] [ -u ] [ -U ] [ -B ] [ -f file ]...\n");
 printf("\t-c <nstreams-services file> : the nstreams services file\n");
 printf("\t-n <networks-file> : the nstreams networks file\n");
 printf("\t-v : version\n");
 printf("\t-N : show networks, not IP addresses (use twice to show nets IPs)\n");
 printf("\t-r : redundancy (show several times the same streams)\n");
 printf("\t-O <format> : output format. The currently supported formats are \n%s\n", formats);
 printf("\t-u : do not print unknown streams\n");
 printf("\t-U : only print unknown streams\n");
 printf("\t-B : notify of broadcasts and networks\n");
 printf("\t-l <iface> : listen directly on interface <iface>\n"); 
 printf("\t-f <file> : read a tcpdump output file\n");
 printf("\n");
 printf("\t-O additional options : \n");
 printf("\t\t-D <interface> : apply the rules to <interface> (ie: eth0)\n");
 printf("\t\t-Y : reject packets that attempt to establish a connection from\n");
 printf("\t\t     the outside\n\n");
 printf("\t-N additional options : \n");
 printf("\t\t-i : show intra-network traffic\n");
 printf("\t\t-I : only show intra-network traffic\n");
 
 exit(1);
}


/*
 * show the version number
 * and quit
 */
void version()
{
 printf("This is nstreams %s\n", VERSION);
 printf("Copyright (C) 1999 Renaud Deraison <deraison@nessus.org>\n");
 printf("                   and Hervé Schauer Consultants -- http://www.hsc.fr\n"); 
 printf("\n\n");
 exit(0);
}


void signal_handler(int signum)
{
 signal_received = 1;
}

/*
 * select the output function for the given
 * format. See output.c for details
 */
output_func_t 
output_function(name)
 char * name;
{
 if(!strcmp(name, "ipfw"))return(ipfw_output);
 if(!strcmp(name, "nstreams"))return(standard_output);
 if(!strcmp(name, "ipchains"))return(ipchains_output);
 else {
 printf("Output '%s' not supported\n",  name);
 exit(1);
 }
 return(NULL);
}

int
main(argc, argv)
 int argc;
 char * argv[];
{

 output_func_t  output_func; 	/* function in charge of the output */
 pcap_t * pcap = NULL;

 char * config_file = ETC_NSTREAMS_SERVICES;
 char * networks = ETC_NSTREAMS_NETWORKS;
 
 /* the name of the tcpdump file -- if any */
 char * dump_file = NULL;

 /*
  * pcap errbuf
  */
 char * pcap_err = malloc(PCAP_ERRBUF_SIZE); 
 int datalink; /* datalink type */
 int offset = 0; /* datalink size */
 struct pcap_pkthdr  hdr;
 /* 
  * conf : configuration file
  * net_conf : networks file
  * fd : the entry file
  */
 FILE * conf, * net_conf, *fd;
 
 char * str;
 struct config_rules * cr;
 struct cache * cache = NULL;
 struct network * nets = NULL;
 parser_func_t parser;

 /* 
  * command line options 
  */
 int c;
 int r = 0;	/* redundant output                        */
 int n = 0;	/* show by network                         */
 int O = 0;	/* output			           */
 int i = 0;	/* show intra network traffic              */
 int I = 0;	/* show only intra network traffic    	   */
 int D = 0;	/* apply the ruls to the interface <iface> */
 int f = 0;	/* read a tcpdump output file		   */ 
 int l = 0;	/* listen on an interface		   */
 char *  iface =  NULL;
 char * iface_listen = NULL;
 char * output_name = NULL;



 parser = parse_tcpdump_line;
 /*
  * process the command line options
  */
 while((c=getopt(argc, argv, "f:BuUc:n:NvhrO:iID:Yl:"))!=-1)
 {
 switch(c)
 {
  case 'f' :
	if(!optarg)usage();
	dump_file = strdup(optarg);
	f++;
	/* 
         * Change the parser to the pcap parser
	 */
	parser = parse_pcap_entry;
	break;	
  case 'B' :				/* show broadcast      */
  	opt_B++;
	break;
  case 'c' :				/* -c config file      */
  	if(!optarg)usage();
	config_file = strdup(optarg);
	break;
  case 'N':				/* show networks       */
  	n++;
	break;
  case 'n':				/* -n networks-file    */
  	if(!optarg)usage();
	networks = strdup(optarg);
	n++;
	break;
  case 'v' :				/* show version number */
  	version();
	break;
  case 'h' :				/* help		       */
  	usage();
	break;
  case 'u' :				/* don't print unknown streams */
  	opt_u++;
	break;
  case 'U' :				/* only print unknown streams  */
  	opt_U++;
	break;
  case 'r' :				/* -r[edundant]		*/
  	r++;
	break;
  case 'O' :				/* -O format (ouput)	*/
  	O++;
	if(!optarg)usage();
	output_name = strdup(optarg);
	break;
  case 'D':
  	D++;
	if(!optarg)usage();
	iface = strdup(optarg);
	break;	
  case 'i' :				/* -Ni : also show intranet traffic */
  	i++;
	break;
  case 'I' :				/* -NI only show intranet traffic */
  	I++;
	break;	

  case 'Y' :
  	reject_syn++;
	break;
	
  case 'l' :
  	if(!optarg)usage();
	l++;f++;
	/* 
         * Change the parser to the pcap parser
	 */
	parser = parse_pcap_entry;
	iface_listen = strdup(optarg);
	break;
		
  default :
  	if(!argv[optind])usage();
	if(argv[optind] && argv[optind][0]=='-')usage();
	break;
  }
 }
 
 /*
  * Signal handler
  */
 signal(SIGTERM, signal_handler);
 signal(SIGINT, signal_handler);
 
  
 /*
  * open the configuration file (/etc/nstreams-services)
  */
 if(!(conf = fopen(config_file, "r")))
 {
  printf("Could not open %s\n", config_file);
  perror("open ");
  exit(1);
 }
 
 /*
  * Sanity check
  */
 if((i || I)&&!n){
 	printf("-i and -I options must be used with -N\n");
	exit(1);
	}
	
 /*
  * -O must be used with -NN - set -N to -NN silently
  */	
 if(O && n)n++;
 
 
 /*
  * -D must be used with -O
  */
  if(D && !O){
  	printf("-D must be used with -O\n");
	exit(1);
	}

 /*
  * -Y must be used with -O
  */
  if(reject_syn && !O)
  { 
  	printf("-Y must be used with -O\n");
	exit(1);
  }
  
 /*
  * -u et -U can't be used at the same time
  */
 if(opt_u && opt_U)
 {
  printf("-u and -U can not be used altogether\n");
  exit(1);
 }

 /*
  * the output is done via a function we 
  * point onto
  */
 if(!O)output_func = standard_output;
 else output_func = output_function(output_name);
 free(output_name);
 
 if((!dump_file) && (argc > optind))dump_file = argv[optind];
 
 /*
  * open the networks file
  */
 if(!(net_conf = fopen(networks, "r")))
 {
  if(n){
  	printf("Could not open %s\n", networks);
	perror("open ");
	exit(1);
	}
 }
 
 else {
 	/*
	 * initialize the list of networks.
	 */
 	nets = read_networks(net_conf); 
	fclose(net_conf);
      }
 
 
 
 /*
  * open the entry file, if we got a name for it,
  * or use stdin
  */
 if(dump_file||l)
 {
  if(!f && !l) /* not a tcpdump output file */
  {
   if(!(fd = fopen(dump_file, "r")))
   {
   printf("Could not open %s\n", dump_file);
   perror("open ");
   exit(1);
   }
  }
 else
  {
   f++;
   if(l)
   {
    pcap = pcap_open_live(iface_listen, 1500, 1, 1000, pcap_err);
    if(!pcap) {
    	fprintf(stderr, "Could not open interface %s - %s\n", iface_listen, pcap_err);
        exit(1);
	}
    free(iface_listen);
   }
   else
   {
   /* 
    * tcpdump output file that we must open using the 
    * libpcap functions 
    */
    pcap = pcap_open_offline(dump_file, pcap_err);
    if(!pcap) {
	fprintf(stderr, "Could not open %s - %s\n", 
			dump_file, pcap_err);
	      exit(1);
	 }
    } 

 datalink = pcap_datalink(pcap);
 if (datalink < 0) {
   fprintf(stderr, "Error getting datalink: %s\n", pcap_geterr(pcap));
   exit(1);
 }
 switch(datalink) {
  case DLT_EN10MB: offset = 14; break;
  case DLT_IEEE802: offset = 22; break;
  case DLT_NULL: offset = 4; break;
  case DLT_SLIP: offset = 16; break;
#ifdef DLT_SLIP_BSDOS
  case DLT_SLIP_BSDOS: offset = 24; break;
#endif
  case DLT_PPP: 
#if (__FreeBSD__ || OPENBSD || NETBSD || BSDI)
    offset = 4;
#else
#ifdef SOLARIS
 offset = 8;
#else
    offset = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
    break;
  case DLT_RAW: offset = 0; break;
#ifdef DLT_LINUX_SLL
  case DLT_LINUX_SLL: offset=16; break;
#endif
#ifdef DLT_FDDI
  case DLT_FDDI: offset=21; break;
#endif
   
  default: 
    fprintf(stderr, "pcap datalink type %d not supported.\n", datalink);
    exit(1);
  }
 }
 }
 else fd = stdin;
 
 
 /* 
  * initialize the configuration, according to /etc/nstreams-services
  */
 cr = read_config(conf);
 fclose(conf);
 
 /* 
  * Tell the output function we start
  */
 (*output_func)(NULL, OP_START);
 
 
 /* XXX */ 
 while(!signal_received)
 {
  struct tcpdump * dump;
  struct config_rules *c;
  char buffer[1024];
  char *str;
 
  /*
   * Depending on  the input we were given, there are
   * differents way to read it
   */ 
  if(!f) {
	str = fgets(buffer, 1023, fd);
	if (!str)
	  break;
  }
  else {
	str = (char*)pcap_next(pcap, &hdr); 
	if(str)
	  str+=offset;
	else
	  if( l != 0 ) continue; /* pcap_next returned NULL, no packet arrived */
	  else break;
  }

  /*
   * translate the string to a 
   * structure we understand. The conversion
   * may return NULL if the protocol is unsupported
   * (arp), or if an error occured
   */
  dump = (*parser)(str);
  if(dump)
  {
   char * name = "unknown";
   
   if(dump->proto)
   {
    c = get_rule(cr, dump);
    if( r 
       || !present_in_cache(cache, c?c->name:name, dump))
    {
     struct output * output = make_output(nets, dump->src, dump->dst,
     			   dump->ports[0], dump->ports[1],
			   dump->proto, c, n,iface);
     char * name = "unknown";
     int intra = 0;
     
   
     
     /*
      * don't show the intra-network traffic
      * except if we are asked to
      */
     if(addr_equal(&(output->ia_dst), &(output->ia_src)))
     {
      if(!(i+I)){
     	free(dump);
	free_output(output);
	continue; 
	}
      else intra++;
      addr_assign(&(output->ia_dst), &(dump->dst));
      addr_assign(&(output->ia_src), &(dump->src));
      free(output->src);
      free(output->dst);
      output->src = addr_str(&dump->src, dump->ports[0]);
      output->dst = addr_str(&dump->dst, dump->ports[1]);
     }
     else
     {
     addr_assign(&(dump->src), &(output->ia_src));
     addr_assign(&(dump->dst), &(output->ia_dst));
     }
     if(c)name = c->name;
    
    
     /*
      * only print the stream if it has not been printed
      * already (or if -r has been set)
      */
     if(!present_in_cache(cache, name, dump)||r)
     { 
      if(!r){
      	  /*
      	   * if this stream has been identified, then we
           * put it in the cache
           */ 
      	   if(c)add_in_cache(&cache, c->name, dump);
      	   else add_in_cache(&cache, "unknown", dump);
	   }
      
      if(I){if(intra)(*output_func)(output,0);}
      else (*output_func)(output,0);
     }
     free_output(output);
   }
    fflush(stdout);
  }
    free(dump);
  }
 }
 if(pcap)pcap_close(pcap);
 free_networks(nets);
 free_cache(cache);
 free_rules(cr);
 free(pcap_err);
 free(iface);
 (*output_func)(NULL, OP_END);
 return(0);
}
