#ifndef NETWORKS_H__
#define NETWORKS_H__

struct network {
  	char * name;
	char * asc_addr;
	struct in_addr addr;
	int mask;
	struct network * next;
	};
	
struct network * read_networks(FILE *);
void free_networks(struct network *n);
char * ip_to_network(struct network*, struct in_addr,int);
struct in_addr  get_network_ip(struct network*, char *,int);
int get_network_mask(struct network *, char *,int);
struct in_addr get_net(struct in_addr, int);
struct in_addr get_broadcast(struct in_addr, int);
#endif
