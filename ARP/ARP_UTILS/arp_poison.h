#ifndef ARP_POISON_H
#define ARP_POISON_H

#include <stdint.h>
#include "arp_scan.h"

int send_arp_reply(int sockfd, unsigned char *target_mac, unsigned char *target_ip, unsigned char *spoofed_mac, unsigned char *spoofed_ip);
void start_poisoning(struct Victim *victims, int victim_count, unsigned char *gateway_ip, unsigned char *gateway_mac, unsigned char *gateway_ipv6_ll);
void heal_arp(struct Victim *victims, int victim_count, unsigned char *gateway_ip, unsigned char *gateway_mac);

#endif
