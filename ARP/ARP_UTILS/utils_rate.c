#include "utils_rate.h"
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

static pthread_t g_monitor_thread;
static int g_keep_running = 1;
static float g_adaptive_interval = 2.0; // Default to 2.0 seconds
static pthread_mutex_t g_rate_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned char g_target_mac[6];
static int g_has_ipv6 = 0;

void *monitor_router_heartbeat(void *arg) {
    (void)arg;
    int sockfd;
    unsigned char buffer[2048];
    struct timeval last_packet_time;
    gettimeofday(&last_packet_time, NULL);

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("Socket error in rate monitor");
        return NULL;
    }

    printf("[MONITOR] Heartbeat sniffer active. Tuning poisoning rate...\n");

    while (g_keep_running) {
        int bytes_received = recvfrom(sockfd, buffer, 2048, 0, NULL, NULL);
        if (bytes_received < 14) continue;

        struct ethhdr *eth = (struct ethhdr *)buffer;
        
        // Only care about packets FROM the gateway
        if (memcmp(eth->h_source, g_target_mac, 6) == 0) {
            uint16_t eth_type = ntohs(eth->h_proto);

            // Respond to ARP (0x0806) or IPv6 (0x86DD) ICMPv6
            if (eth_type == ETH_P_ARP || eth_type == ETH_P_IPV6) {
                struct timeval current_time;
                gettimeofday(&current_time, NULL);

                long seconds = current_time.tv_sec - last_packet_time.tv_sec;
                long useconds = current_time.tv_usec - last_packet_time.tv_usec;
                float interval = seconds + useconds / 1000000.0;

                // Only update if it's a "frequent" but not accidental burst (e.g. > 0.5s)
                if (interval > 0.5) {
                    pthread_mutex_lock(&g_rate_mutex);
                    // Defensive target: poisoned rate = half of router interval
                    // If router sends every 30s, we send every 15s.
                    // If router sends every 4s, we send every 2s.
                    float new_interval = interval / 2.0;
                    
                    // Clamp to safe boundaries
                    if (new_interval < 1.0) new_interval = 1.0;
                    if (new_interval > 10.0) new_interval = 10.0;
                    
                    if (new_interval != g_adaptive_interval) {
                        g_adaptive_interval = new_interval;
                        printf("[ADAPTIVE] Router heartbeat detected (%.2fs). Adjusting poisoning rate to %.2fs.\n", 
                               interval, g_adaptive_interval);
                    }
                    pthread_mutex_unlock(&g_rate_mutex);
                    last_packet_time = current_time;
                }
            }
        }
    }

    close(sockfd);
    return NULL;
}

void init_rate_monitor(unsigned char *gateway_mac, unsigned char *gateway_ipv6_ll) {
    memcpy(g_target_mac, gateway_mac, 6);
    g_has_ipv6 = (gateway_ipv6_ll != NULL);
    g_keep_running = 1;
    pthread_create(&g_monitor_thread, NULL, monitor_router_heartbeat, NULL);
}

float get_adaptive_interval(void) {
    float val;
    pthread_mutex_lock(&g_rate_mutex);
    val = g_adaptive_interval;
    pthread_mutex_unlock(&g_rate_mutex);
    return val;
}

void stop_rate_monitor(void) {
    g_keep_running = 0;
    // We don't join to avoid blocking if the thread is stuck in recv
    pthread_cancel(g_monitor_thread);
}
