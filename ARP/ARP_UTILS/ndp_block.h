#ifndef NDP_BLOCK_H
#define NDP_BLOCK_H

#include <netinet/in.h>

/**
 * Sends a forged ICMPv6 Router Advertisement with a lifetime of 0.
 * This instructs nodes on the segment that the sender is not a router,
 * discouraging the use of IPv6 and forcing fallback to IPv4.
 * 
 * @param sockfd Raw socket (AF_PACKET) to send through.
 * @param src_mac The MAC address to use in the Ethernet header.
 * @param src_ipv6 The link-local IPv6 address (gateway's) to spoof.
 * @return 0 on success, -1 on failure.
 */
int send_ndp_ra_block(int sockfd, unsigned char *src_mac, unsigned char *src_ipv6);

#endif
