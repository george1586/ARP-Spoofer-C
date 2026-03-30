#ifndef ARP_POISON_H
#define ARP_POISON_H

#include <stdint.h>

int send_arp_reply(int sockfd, unsigned char *target_mac, unsigned char *target_ip, unsigned char *spoofed_mac, unsigned char *spoofed_ip);
void start_poisoning(unsigned char *victim_ip, unsigned char *victim_mac, unsigned char *gateway_ip, unsigned char *gateway_mac);
void heal_arp(unsigned char *victim_ip, unsigned char *victim_mac, unsigned char *gateway_ip, unsigned char *gateway_mac);

#endif
