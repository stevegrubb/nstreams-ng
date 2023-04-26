#ifndef READ_PCAP_H__
#define READ_PCAP_H__

#include <pcap.h>
struct tcpdump *parse_pcap_entry(const u_char *data, const struct pcap_pkthdr *header);

#endif
