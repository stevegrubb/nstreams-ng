#ifndef __OUTPUT_H__
#define __OUTPUT_H__


struct output {
	char * serv_name;	/* service name            */
	int sport;		/* source port             */
	int dport;		/* destination port        */
	char * src;		/* source IP (in ascii)    */
	char * dst;		/* dest IP (in ascii )     */
	struct ip_addr ia_src;  /* source IP 		   */
	struct ip_addr ia_dst;  /* dest   IP		   */
	
	struct ip_addr s_bcast;	/* broadcast of the source */
	struct ip_addr d_bcast; /* broadcast of the dest   */
	struct ip_addr ia_sorig;/* original ip 		   */
	struct ip_addr ia_dorig;/* original ip		   */
	int smask;		/* source netmask          */
	int dmask;		/* dest netmask		   */
	int proto;		/* prototype		   */
	char * asc_proto;	/* prototype in ascii      */
	char * sports;
	char * dports;
	int show_net;
	char * iface;
	};
#define OP_START 1
#define OP_END 2
typedef void(*output_func_t)(struct output *,int);	
	
void free_output(struct output *);

struct output * make_output(
 struct network *,
 struct ip_addr,struct ip_addr,
 int,int,int,
 struct config_rules *,int, char *);
 
void standard_output(struct output *, int);
void ipfw_output(struct output *, int);
void ipchains_output(struct output *, int);
char *int2proto(int);

#endif
