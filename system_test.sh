#!/bin/bash
# System Validation Test for ARP-Spoofer-C
# Validates KPIs (Key Performance Indicators) for the spoofer's core mechanics.

echo "==========================================="
echo " ARP Spoofer System KPI Validation Suite"
echo "==========================================="

# Mock args for testing
VICTIM_IP="192.168.1.100"
GATEWAY_IP="192.168.1.1"

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

echo "[*] Launching ARP Spoofer in background..."
sudo ./program -t $VICTIM_IP -g $GATEWAY_IP > /tmp/spoofer_log.txt 2>&1 &
SPOOFER_PID=$!

# Give the C program time to resolve MACs, inject iptables, and start the loop
sleep 2

# KPI 1: Check Process State
if ps -p $SPOOFER_PID > /dev/null; then
    echo "[+] KPI PASSED: Spoofer process ($SPOOFER_PID) is actively running."
else
    echo "[!] KPI FAILED: Spoofer crashed or exited prematurely."
    echo "--- Spoofer Error Log ---"
    cat /tmp/spoofer_log.txt
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
