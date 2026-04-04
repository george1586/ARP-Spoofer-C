#ifndef UTILS_RATE_H
#define UTILS_RATE_H

#include <pthread.h>

/**
 * Registers a callback to be executed when a router heartbeat is detected.
 * Used for triggering immediate poison bursts.
 */
void set_burst_callback(void (*callback)(void));

/**
 * Initializes the router heartbeat monitor thread.
 * 
 * @param gateway_mac The MAC address of the gateway to monitor.
 * @param gateway_ip The IPv4 address of the gateway.
 * @param gateway_ipv6_ll The IPv6 link-local address of the gateway.
 */
void init_rate_monitor(unsigned char *gateway_mac, unsigned char *gateway_ip, unsigned char *gateway_ipv6_ll);

/**
 * Returns the currently calculated adaptive interval in seconds.
 * 
 * @return The interval between poisoning rounds.
 */
float get_adaptive_interval(void);

/**
 * Stops the rate monitor thread.
 */
void stop_rate_monitor(void);

#endif
