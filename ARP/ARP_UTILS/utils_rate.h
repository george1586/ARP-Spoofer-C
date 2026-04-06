#ifndef UTILS_RATE_H
#define UTILS_RATE_H

#include <pthread.h>

void set_burst_callback(void (*callback)(void));

/**
 * Initialize the rate monitor. Now also takes our_mac for spoof failure detection (#10).
 */
void init_rate_monitor(unsigned char *gateway_mac, unsigned char *gateway_ip,
                       unsigned char *gateway_ipv6_ll, unsigned char *our_mac);

float get_adaptive_interval(void);
void stop_rate_monitor(void);

#endif
