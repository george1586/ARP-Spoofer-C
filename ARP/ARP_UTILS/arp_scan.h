#ifndef ARP_SCAN_H
#define ARP_SCAN_H

#include <stdint.h>

struct Victim {
    unsigned char ip[4];
    unsigned char mac[6];
};

unsigned char* get_mac_from_ip(unsigned char* target_ip);
struct Victim* scan_network(unsigned char* gateway_ip, int* out_count);

#endif