#ifndef PORTS_H__
#define PORTS_H__

#include <stdbool.h>

bool port_in_ports(u_short port, u_short *ports, unsigned int len);
u_short *getports(const char *expr, int *num);
u_short *getpts(const char *origexpr, int *num);

#endif
