#!/bin/bash
# System Validation Test for ARP-Spoofer-C
# Validates KPIs (Key Performance Indicators) for the spoofer's core mechanics.

echo "==========================================="
echo " ARP Spoofer System KPI Validation Suite"
echo "==========================================="

# Mock args were used in prototype, but now we test full Auto-Discovery
# The spoofer will now scan the network and find real targets

echo "[*] Compiling the project..."
make clean > /dev/null && make > /dev/null
if [ $? -ne 0 ]; then
    echo "[!] KPI FAILED: Build process failed."
    exit 1
fi
echo "[+] KPI PASSED: Build successful."

if ! ip link show eth0 > /dev/null 2>&1; then
    echo "[-] WARNING: 'eth0' interface not found on this system."
    echo "[-] The C engine strictly requires eth0 to bind raw sockets."
    echo "[-] Please run this script on the target Raspberry Pi for live validation."
    exit 0
fi

echo "[*] Launching ARP Spoofer in full auto-discovery background mode..."
sudo ./program > /tmp/spoofer_log.txt 2>&1 &
SPOOFER_PID=$!

# Give the C program time to resolve MACs, inject iptables, and start the loop
sleep 5
echo "--- SPOOFER LOG ---"
cat /tmp/spoofer_log.txt
echo "-------------------"

# KPI 1: Check Process State
if ps -p $SPOOFER_PID > /dev/null; then
    echo "[+] KPI PASSED: Spoofer process ($SPOOFER_PID) is actively running."
else
    echo "[!] KPI FAILED: Spoofer crashed or exited prematurely."
    exit 1
fi

# KPI 2: Check Kernel IP Forwarding
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FWD" -eq 1 ]; then
    echo "[+] KPI PASSED: Kernel IP Forwarding is actively enabled."
else
    echo "[!] KPI FAILED: IP Forwarding was NOT set to 1."
fi

# KPI 3: Check IPTables DNS Redirect hooks
if sudo iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    echo "[+] KPI PASSED: iptables DNS to Technitium redirect rule is active."
else
    echo "[!] KPI FAILED: iptables DNS redirect rule is missing!"
fi

# KPI 5: Check IPv6 Gateway Discovery (Warning if not found, but check if code tried)
if grep -q "Discovered IPv6 Gateway Address:" /tmp/spoofer_log.txt; then
    echo "[+] KPI PASSED: IPv6 Gateway link-local address discovered."
elif grep -q "Failed to discover IPv6 gateway" /tmp/spoofer_log.txt; then
    echo "[-] WARNING: IPv6 Discovery attempted but failed (Expected if network is IPv4-only)."
else
    echo "[!] KPI FAILED: IPv6 Gateway discovery log not found!"
fi

# KPI 6: Check IPv6 RA Blocking Transmission
if grep -q "IPv6 Blocking RA sent." /tmp/spoofer_log.txt; then
    echo "[+] KPI PASSED: ICMPv6 RA Blocking packets are being transmitted."
else
    echo "[!] KPI FAILED: No 'IPv6 Blocking RA sent' message found in logs!"
fi

echo "[*] Transmitting SIGINT (Graceful Shutdown) to the engine..."
sudo kill -SIGINT $SPOOFER_PID

# Give the C program time to broadcast the ARP Healing packets and delete iptables rules
sleep 2

# KPI 4: Check Graceful Teardown (IPTables Reverted)
if sudo iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    echo "[!] KPI FAILED: iptables DNS redirect rule was NOT cleaned up during shutdown!"
else
    echo "[+] KPI PASSED: iptables DNS redirect successfully purged (Healing successful)."
fi

echo "==========================================="
echo " System Validation KPIs Complete!"
echo "==========================================="
