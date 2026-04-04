#include "ndp_block.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// ICMPv6 pseudo-header for checksum calculation
struct pseudo_header6 {
  struct in6_addr src;
  struct in6_addr dst;
  uint32_t len;
  uint8_t zero[3];
  uint8_t next_header;
} __attribute__((packed));

// Standard 16-bit checksum
unsigned short checksum(void *b, int len) {
  unsigned short *buf = b;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

int send_ndp_ra_block(int sockfd, unsigned char *src_mac,
                      unsigned char *src_ipv6) {
  struct ifreq if_idx;
  struct sockaddr_ll socket_address;
  char ifName[IFNAMSIZ] = "eth0";

  // Get interface index
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    return -1;
  }

  // Target all-nodes multicast address
  unsigned char dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
  struct in6_addr dst_ipv6;
  inet_pton(AF_INET6, "ff02::1", &dst_ipv6);

  // Prepare socket address
  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, dst_mac, 6);

  // Packet size: ETH(14) + IP(40) + ICMPv6(16) + SLLA Option(8) = 78 bytes
  int packet_len = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) +
                   sizeof(struct nd_router_advert) + 8;
  unsigned char *buffer = malloc(packet_len);
  if (!buffer)
    return -1;
  memset(buffer, 0, packet_len);

  // 1. Ethernet Header
  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, src_mac, 6);
  memcpy(eth->h_dest, dst_mac, 6);
  eth->h_proto = htons(ETH_P_IPV6);

  // 2. IPv6 Header
  struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
  ip6->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
  ip6->ip6_plen = htons(sizeof(struct nd_router_advert) + 8);
  ip6->ip6_nxt = 58;         // ICMPv6
  ip6->ip6_hlim = 255;        // Must be 255 for NDP
  memcpy(&ip6->ip6_src, src_ipv6, 16);
  memcpy(&ip6->ip6_dst, &dst_ipv6, 16);

  // 3. ICMPv6 Router Advertisement Header
  struct nd_router_advert *ra =
      (struct nd_router_advert *)(buffer + sizeof(struct ethhdr) +
                                  sizeof(struct ip6_hdr));
  ra->nd_ra_type = 134; // Type RA
  ra->nd_ra_code = 0;
  ra->nd_ra_curhoplimit = 64;
  ra->nd_ra_flags_reserved = 0x00; // No Managed or Other config
  ra->nd_ra_router_lifetime = htons(0); // KEY: Lifetime 0 = Blocking
  ra->nd_ra_reachable = htonl(0);
  ra->nd_ra_retransmit = htonl(0);

  // 4. Source Link-Layer Address Option
  unsigned char *opt = (unsigned char *)(ra + 1);
  opt[0] = 1; // Type: Source Link-Layer Address
  opt[1] = 1; // Length: 8 bytes (including type/len)
  memcpy(opt + 2, src_mac, 6);

  // 5. Checksum (Pseudo-header + ICMPv6 message)
  struct pseudo_header6 ps;
  memcpy(&ps.src, src_ipv6, 16);
  memcpy(&ps.dst, &dst_ipv6, 16);
  ps.len = htonl(sizeof(struct nd_router_advert) + 8);
  memset(ps.zero, 0, 3);
  ps.next_header = 58;

  int pseudo_len = sizeof(struct pseudo_header6) +
                   sizeof(struct nd_router_advert) + 8;
  unsigned char *pseudo_buf = malloc(pseudo_len);
  if (pseudo_buf) {
    memcpy(pseudo_buf, &ps, sizeof(struct pseudo_header6));
    memcpy(pseudo_buf + sizeof(struct pseudo_header6), ra,
           sizeof(struct nd_router_advert) + 8);
    ra->nd_ra_cksum = checksum(pseudo_buf, pseudo_len);
    free(pseudo_buf);
  }

  // Send packet
  if (sendto(sockfd, buffer, packet_len, 0, (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
    perror("sendto (NDP RA)");
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}
