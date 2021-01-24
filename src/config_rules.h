#ifndef CONFIG_H____
#define CONFIG_H____

struct config_rules {
	char *name;
	u_short *sports;
	int num_sport;
	int proto;
	u_short *dports;
	int num_dport;
	char *asc_sports;
	char *asc_dports;
	struct config_rules *next;
};

struct config_rules *get_rule(struct config_rules *cr, struct tcpdump *dump);
struct config_rules *read_config(FILE *fd);
void free_rules(struct config_rules *c);

#endif
