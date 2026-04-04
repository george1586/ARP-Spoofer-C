#ifndef UTILS_FIREWALL_H
#define UTILS_FIREWALL_H

#include "arp_scan.h" // For struct Victim definition

/**
 * Sets up arptables rules to block legitimate ARP traffic from the router to victims.
 * 
 * @param gateway_mac The MAC address of the real gateway.
 * @param victims Array of discovered victims.
 * @param victim_count Number of victims.
 * @return 0 on success, -1 if arptables is missing or rule fails.
 */
int setup_arp_block(unsigned char *gateway_mac, struct Victim *victims, int victim_count);

/**
 * Cleans up and flushes the arptables rules created by this tool.
 * 
 * @return 0 on success.
 */
int cleanup_arp_block(void);

#endif
