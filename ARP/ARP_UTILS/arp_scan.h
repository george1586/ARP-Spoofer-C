#ifndef ARP_SCAN_H
#define ARP_SCAN_H

#include <stdint.h>

struct Victim {
    unsigned char ip[4];
    unsigned char mac[6];
};

struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t cookie;
    uint8_t options[308];
};

unsigned char* get_mac_from_ip(unsigned char* target_ip);
struct Victim* scan_network(unsigned char* gateway_ip, int* out_count);

#endif