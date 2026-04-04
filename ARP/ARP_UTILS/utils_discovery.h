#ifndef UTILS_DISCOVERY_H
#define UTILS_DISCOVERY_H
unsigned char *get_own_ip();
unsigned char *get_own_mac();
unsigned char *get_netmask();
unsigned char *get_default_gateway_ip();
unsigned char *get_own_ipv6_ll();
unsigned char *get_gateway_ipv6_ll();
int enable_ip_forwarding();
#endif
