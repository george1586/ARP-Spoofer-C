#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

unsigned char *get_own_mac(void)
{
    struct ifreq s;
    unsigned char *own_mac = malloc(6);
    if (!own_mac)
        return NULL;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
    {
        perror("socket");
        free(own_mac);
        return NULL;
    }
    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        memcpy(own_mac, s.ifr_hwaddr.sa_data, 6);
        close(fd);
        return own_mac;
    }

    return NULL;
}

unsigned char *get_own_ip(void)
{
    struct ifreq s;
    unsigned char *own_ip = malloc(4);
    if (!own_ip)
        return NULL;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
    {
        perror("ip");
        free(own_ip);
        return NULL;
    }
    strcpy(s.ifr_name, "eth0"); // changed to eth0 for pi
    if (0 == ioctl(fd, SIOCGIFADDR, &s))
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&s.ifr_addr;
        memcpy(own_ip, &addr->sin_addr, 4);
        close(fd);
        return own_ip;
    }
    return NULL;
}

unsigned char *get_netmask()
{
    struct ifreq s;
    unsigned char *netmask = malloc(4);
    if (!netmask)
        return NULL;
    int fd = socket(PF_INET, SOCK_DGRAM, AF_UNSPEC);
    if (fd < 0)
    {
        perror("netmask");
        free(netmask);
        return NULL;
    };
    memset(&s, 0, sizeof(s));
    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFNETMASK, &s))
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&s.ifr_netmask;
        memcpy(netmask, &addr->sin_addr, 4);
        close(fd);
        return netmask;
    }
    return NULL;
}

int enable_ip_forwarding() {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (f == NULL) {
        perror("Failed to open /proc/sys/net/ipv4/ip_forward");
        return -1;
    }
    fprintf(f, "1");
    fclose(f);
    return 0;
}

unsigned char *get_default_gateway_ip(void) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return NULL;
    
    char line[256];
    char iface[IFNAMSIZ];
    unsigned long dest, gw;
    
    // Skip the first header line
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return NULL;
    }
    
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %lx %lx", iface, &dest, &gw) == 3) {
            if (dest == 0) {
                unsigned char *gateway_ip = malloc(4);
                if (gateway_ip) {
                    // The gateway IP is heavily formatted in little-endian hex in /proc/net/route
                    // Using %lx reads it into an integer that natively matches the raw 4-byte IP structure
                    memcpy(gateway_ip, &gw, 4);
                }
                fclose(f);
                return gateway_ip;
            }
        }
    }
    
    fclose(f);
    return NULL;
}