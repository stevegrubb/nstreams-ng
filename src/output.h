#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "config_rules.h"
#include "networks.h"

struct output {
	char *serv_name;	/* service name            */
	int sport;		/* source port             */
	int dport;		/* destination port        */
	char *src;		/* source IP (in ascii)    */
	char *dst;		/* dest IP (in ascii )     */
	struct ip_addr ia_src;  /* source IP 		   */
	struct ip_addr ia_dst;  /* dest IP		   */

	struct ip_addr s_bcast;	/* broadcast of the source */
	struct ip_addr d_bcast; /* broadcast of the dest   */
	struct ip_addr ia_sorig;/* original ip 		   */
	struct ip_addr ia_dorig;/* original ip		   */
	int smask;		/* source netmask          */
	int dmask;		/* dest netmask		   */
	int proto;		/* prototype		   */
	const char *asc_proto;	/* prototype in ascii      */
	char *sports;
	char *dports;
	int show_net;
	char *iface;
};

#define OP_START 1
#define OP_END 2

typedef void(*output_func_t)(struct output *, int);

void free_output(struct output *out);

struct output *make_output(struct network *nets,
			   struct ip_addr src, struct ip_addr dst,
			   int sport, int dport, int proto,
			   struct config_rules *rule, int shownet, char *iface);

void standard_output(struct output *output, int status);
void ipfw_output(struct output *output, int status);
void ipchains_output(struct output *output, int status);
const char *int2proto(int proto);

#endif
