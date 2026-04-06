#!/bin/bash
# System Validation Test for ARP-Spoofer-C
# Validates KPIs (Key Performance Indicators) for the spoofer's core mechanics.

echo "==========================================="
echo " ARP Spoofer System KPI Validation Suite"
echo "==========================================="

PASS=0
FAIL=0
WARN=0
LOG="/tmp/spoofer_log.txt"
LOGFILE="/tmp/spoofer_session.log"

pass() { echo "[+] KPI PASSED: $1"; PASS=$((PASS+1)); }
fail() { echo "[!] KPI FAILED: $1"; FAIL=$((FAIL+1)); }
warn() { echo "[-] WARNING: $1"; WARN=$((WARN+1)); }

# ========================================
# KPI 1: Build Verification
# ========================================
echo ""
echo "[*] Compiling the project..."
make clean > /dev/null && make > /dev/null 2>&1
if [ $? -ne 0 ]; then
    fail "Build process failed."
    exit 1
fi
pass "Build successful (zero errors)."

# Check for compiler warnings
WARN_COUNT=$(make 2>&1 | grep -c "warning:")
if [ "$WARN_COUNT" -eq 0 ]; then
    pass "Build produced zero compiler warnings."
else
    warn "Build produced $WARN_COUNT compiler warnings."
fi

# ========================================
# KPI 2: Binary sanity checks
# ========================================
if [ -x ./program ]; then
    pass "Binary 'program' exists and is executable."
else
    fail "Binary 'program' not found or not executable."
    exit 1
fi

# KPI 2b: Help flag works without crashing
./program -h 2>&1 | grep -q "\-l"
if [ $? -eq 0 ]; then
    pass "Help text includes -l (logfile) flag."
else
    fail "Help text missing -l flag."
fi

./program -h 2>&1 | grep -q "\-w"
if [ $? -eq 0 ]; then
    pass "Help text includes -w (wide mode) flag."
else
    fail "Help text missing -w flag."
fi

# ========================================
# Interface check — bail early if no eth0
# ========================================
if ! ip link show eth0 > /dev/null 2>&1; then
    echo ""
    warn "'eth0' interface not found on this system."
    echo "[-] The C engine strictly requires eth0 to bind raw sockets."
    echo "[-] Please run this script on the target Raspberry Pi for live validation."
    echo ""
    echo "==========================================="
    printf " Results: %d PASSED, %d FAILED, %d WARNINGS\n" $PASS $FAIL $WARN
    echo "==========================================="
    exit 0
fi

# ========================================
# Pre-check Cleanup
# ========================================
echo ""
echo "[*] Cleaning up legacy rules before test..."
sudo iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null
sudo iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null
sudo arptables -F 2>/dev/null

# ========================================
# Launch spoofer with logging flag (#15)
# ========================================
echo "[*] Launching ARP Spoofer in auto-discovery mode with -l flag..."
sudo ./program -l "$LOGFILE" > "$LOG" 2>&1 &
SPOOFER_PID=$!

# Give time for discovery, iptables injection, and first poison cycle
sleep 10
echo "--- PRE-SHUTDOWN LOG (stdout) ---"
cat "$LOG"
echo "---------------------------------"

# ========================================
# KPI 3: Process State
# ========================================
if ps -p $SPOOFER_PID > /dev/null 2>&1; then
    pass "Spoofer process ($SPOOFER_PID) is actively running."
else
    fail "Spoofer crashed or exited prematurely."
    echo "--- CRASH LOG ---"
    cat "$LOG"
    echo "-----------------"
    exit 1
fi

# ========================================
# KPI 4: Kernel IP Forwarding
# ========================================
IP_FWD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FWD" -eq 1 ]; then
    pass "Kernel IP Forwarding is actively enabled."
else
    fail "IP Forwarding was NOT set to 1."
fi

# ========================================
# KPI 5: IPTables DNS Redirect (UDP + TCP) (#12)
# ========================================
if sudo iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    pass "iptables UDP/53 DNS redirect rule is active."
else
    fail "iptables UDP/53 DNS redirect rule is missing!"
fi

if sudo iptables -t nat -C PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    pass "iptables TCP/53 DNS redirect rule is active (new)."
else
    fail "iptables TCP/53 DNS redirect rule is missing!"
fi

# ========================================
# KPI 6: DoT (Port 853) Blocking
# ========================================
if sudo iptables -L FORWARD -n 2>/dev/null | grep -q "REJECT.*dpt:853"; then
    pass "DNS over TLS (Port 853) is being blocked."
else
    fail "DNS over TLS (Port 853) block rule not found!"
fi

# ========================================
# KPI 7: DoH Provider Blackholing
# ========================================
if sudo iptables -L FORWARD -n 2>/dev/null | grep -q "REJECT.*8.8.8.8"; then
    pass "Common DNS provider DoH endpoints are being blackholed."
else
    fail "DoH blackhole rules not found for common providers!"
fi

# ========================================
# KPI 8: ARP-Kill Firewall (OUTPUT only, not INPUT) (#3 fix)
# ========================================
if sudo arptables -L OUTPUT -n 2>/dev/null | grep -q "DROP"; then
    pass "arptables OUTPUT DROP rules are active (correct chain)."
else
    warn "No arptables OUTPUT DROP rules found (arptables may not be installed)."
fi

# Verify INPUT chain is clean (was the root cause of spoofing fade)
if sudo arptables -L INPUT -n 2>/dev/null | grep -q "DROP"; then
    fail "arptables INPUT has DROP rules — this blinds the heartbeat monitor!"
else
    pass "arptables INPUT chain is clean (heartbeat monitor unblinded)."
fi

# ========================================
# KPI 9: IPv6 Gateway Discovery
# ========================================
if grep -q "Discovered IPv6 Gateway Address:" "$LOG"; then
    pass "IPv6 Gateway link-local address discovered."
elif grep -q "Failed to discover IPv6 gateway" "$LOG"; then
    warn "IPv6 Discovery attempted but failed (expected on IPv4-only networks)."
else
    fail "IPv6 Gateway discovery log not found!"
fi

# ========================================
# KPI 10: Log file creation (#15)
# ========================================
if [ -f "$LOGFILE" ] && [ -s "$LOGFILE" ]; then
    pass "Log file created and contains data (-l flag working)."
else
    fail "Log file not created or empty — logging is broken!"
fi

# Verify log file has session header
if [ -f "$LOGFILE" ] && grep -q "ARP Spoofer Session Started" "$LOGFILE"; then
    pass "Log file contains session header with timestamp."
else
    fail "Log file missing session header."
fi

# ========================================
# KPI 11: Adaptive Rate Monitor Active
# ========================================
if grep -q "\[MONITOR\] Heartbeat sniffer active" "$LOG"; then
    pass "Adaptive rate monitor thread is active."
else
    fail "Adaptive rate monitor did not start!"
fi

# ========================================
# KPI 12: Poison loop producing output
# ========================================
if grep -q "Poison sent. Sleeping" "$LOG"; then
    pass "Poison loop is cycling and producing output."
else
    fail "No poison cycle output detected!"
fi

# ========================================
# KPI 13: Signal-safe shutdown (#13)
# ========================================
echo ""
echo "[*] Transmitting SIGINT (Graceful Shutdown) to the engine..."
sudo kill -SIGINT $SPOOFER_PID

# Healing takes ~2s (3 rounds * 0.5s sleep) + cleanup
sleep 5

# Verify process actually exited
if ps -p $SPOOFER_PID > /dev/null 2>&1; then
    fail "Process did NOT exit after SIGINT — signal handler may be broken!"
    sudo kill -9 $SPOOFER_PID 2>/dev/null
else
    pass "Process exited cleanly after SIGINT."
fi

# ========================================
# KPI 14: Graceful Teardown — IPTables Reverted
# ========================================
if sudo iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    fail "iptables UDP/53 redirect was NOT cleaned up during shutdown!"
else
    pass "iptables UDP/53 redirect successfully purged."
fi

if sudo iptables -t nat -C PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null; then
    fail "iptables TCP/53 redirect was NOT cleaned up during shutdown!"
else
    pass "iptables TCP/53 redirect successfully purged."
fi

# ========================================
# KPI 15: Graceful Teardown — Arptables Flushed
# ========================================
if sudo arptables -L OUTPUT -n 2>/dev/null | grep -q "DROP"; then
    fail "arptables ARP-Kill rules were NOT cleaned up during shutdown!"
else
    pass "arptables ARP-Kill rules successfully flushed."
fi

# ========================================
# KPI 16: ARP Healing Performed
# ========================================
# Re-read the log after shutdown
cat "$LOG" > /tmp/spoofer_log_final.txt
if grep -q "\[HEALING\] ARP Caches successfully restored" /tmp/spoofer_log_final.txt; then
    pass "ARP Healing broadcast confirmed in shutdown log."
else
    # Also check the log file
    if [ -f "$LOGFILE" ] && grep -q "\[HEALING\] ARP Caches successfully restored" "$LOGFILE"; then
        pass "ARP Healing broadcast confirmed in session log file."
    else
        fail "No ARP Healing confirmation found in logs!"
    fi
fi

# ========================================
# KPI 17: Shutdown cleanup message (#13)
# ========================================
if grep -q "\[SHUTDOWN\] Cleanup complete" /tmp/spoofer_log_final.txt || \
   ([ -f "$LOGFILE" ] && grep -q "\[SHUTDOWN\] Cleanup complete" "$LOGFILE"); then
    pass "Graceful shutdown cleanup completed (signal-safe handler working)."
else
    fail "Shutdown cleanup message not found — signal handler may not be signal-safe!"
fi

# ========================================
# KPI 18: Log file session end marker (#15)
# ========================================
if [ -f "$LOGFILE" ] && grep -q "Session Ended" "$LOGFILE"; then
    pass "Log file contains session end marker (log_close called)."
else
    fail "Log file missing session end marker."
fi

# ========================================
# Summary
# ========================================
echo ""
echo "--- POST-SHUTDOWN LOG (stdout) ---"
cat "$LOG"
echo "----------------------------------"

if [ -f "$LOGFILE" ]; then
    echo "--- SESSION LOG FILE ($LOGFILE) ---"
    cat "$LOGFILE"
    echo "----------------------------------"
fi

# Cleanup temp files
rm -f /tmp/spoofer_log_final.txt

echo ""
echo "==========================================="
printf " Results: %d PASSED, %d FAILED, %d WARNINGS\n" $PASS $FAIL $WARN
echo "==========================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
