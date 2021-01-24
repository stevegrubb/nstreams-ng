#ifndef CACHE_H__
#define CACHE_H__

struct cache {
	const char *name;
	struct ip_addr src;
	struct ip_addr dst;
	u_short sport;
	u_short dport;
	int proto;
	struct cache *next;
};

int present_in_cache(struct cache *cache, const char *name,
		     struct tcpdump *dump);
void add_in_cache(struct cache **pcache, const char *name,
		  struct tcpdump *dump);
void free_cache(struct cache *c);

#endif
