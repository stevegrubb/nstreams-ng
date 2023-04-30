#ifndef NETWORKS_H__
#define NETWORKS_H__

#include "parse_tcpdump.h"

struct network {
	char *name;
	char *asc_addr;
	struct ip_addr addr;
	int mask;
	struct network *next;
};

struct network *read_networks(FILE *fd);
void free_networks(struct network *n);
char *ip_to_network(struct network *nets, struct ip_addr ip, int numeric);
struct ip_addr get_network_ip(struct network *nets, char *name, int numeric);
int get_network_mask(struct network *nets, char *name, int numeric);
struct ip_addr get_net(struct ip_addr *addr, int mask);
struct ip_addr get_broadcast(struct ip_addr *addr, int mask);
int addr_equal(struct ip_addr *a1, struct ip_addr *a2);
char *addr_str(struct ip_addr *a1, int port);
static inline void addr_assign(struct ip_addr *a1, struct ip_addr *a2) {
	a1->fam = a2->fam;
	memcpy(&(a1->addr.ipv6_addr), &(a2->addr.ipv6_addr),
	       sizeof(struct in6_addr));
}

#endif

