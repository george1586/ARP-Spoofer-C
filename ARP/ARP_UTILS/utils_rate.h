#ifndef UTILS_RATE_H
#define UTILS_RATE_H

#include <pthread.h>

/**
 * Initializes the router heartbeat monitor thread.
 * 
 * @param gateway_mac The MAC address of the gateway to monitor.
 * @param gateway_ipv6_ll The IPv6 link-local address of the gateway.
 */
void init_rate_monitor(unsigned char *gateway_mac, unsigned char *gateway_ipv6_ll);

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
