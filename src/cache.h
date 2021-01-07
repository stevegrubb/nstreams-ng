#ifndef CACHE_H__
#define CACHE_H__

struct cache {
	char * name;
	struct in_addr src;
	struct in_addr dst;
	u_short sport;
	u_short dport;
	int proto;
	struct cache * next;
	};
int present_in_cache(struct cache *, char *, struct tcpdump *);
void add_in_cache(struct cache **, char *, struct tcpdump *);
void free_cache(struct cache *c);
	
#endif
