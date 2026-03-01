# ARP-Spoofer-C

## I. High-level component architecture

1. **NetDiscovery**
   - Find MAC and IP addresses on the network (own, gateway, victims)
   - This is needed in order to forge the ARP
2. **ARP Poisoning Engine**
    -Maintains fake ARP entries for many clients at once
    -Refreshes them periodically ( ARP cache expires every 1-10 minutes depending on OS)
3. **Forwarding & Filtering Layer**
    - Forwards packets between client <-> router
    - Might have to setup iptables for VPN
    - Hooks in DNS Sinkhole, other DNS rules
4. **Control / Monitoring**
    - Simple UI (consider modified Technitium) so user can control on which devices the rules apply, what modes apply, etc. 

## II. Diagram in a gif 