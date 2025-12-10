#!/bin/bash
#==============================================================================
# Initial Enumeration Script
# Usage: ./enum.sh <target_ip> [output_dir]
# Author: Brad Turner
#==============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Arguments
TARGET=${1:?Usage: $0 <target_ip> [output_dir]}
OUTDIR=${2:-"./enum_$TARGET"}

# Create output directory
mkdir -p "$OUTDIR"/{nmap,web,smb,misc}

banner() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}[*] $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

info() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

#------------------------------------------------------------------------------
# NMAP SCANS
#------------------------------------------------------------------------------
banner "NMAP - Quick TCP Scan (Top 1000)"
nmap -sC -sV -oA "$OUTDIR/nmap/quick_tcp" "$TARGET" | tee "$OUTDIR/nmap/quick_tcp.txt"

banner "NMAP - Full TCP Scan (All Ports)"
nmap -p- -sC -sV -oA "$OUTDIR/nmap/full_tcp" "$TARGET" &
FULL_TCP_PID=$!
info "Full TCP scan running in background (PID: $FULL_TCP_PID)"

banner "NMAP - UDP Scan (Top 20)"
sudo nmap -sU --top-ports 20 -oA "$OUTDIR/nmap/udp_top20" "$TARGET" &
UDP_PID=$!
info "UDP scan running in background (PID: $UDP_PID)"

#------------------------------------------------------------------------------
# SERVICE-SPECIFIC ENUMERATION (based on quick scan results)
#------------------------------------------------------------------------------
# Extract open ports from quick scan
sleep 5  # Wait for quick scan to have some results
PORTS=$(grep -oP '\d+/open' "$OUTDIR/nmap/quick_tcp.gnmap" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')

if [ -z "$PORTS" ]; then
    warn "No open ports found yet, waiting for scan..."
    wait $FULL_TCP_PID
    PORTS=$(grep -oP '\d+/open' "$OUTDIR/nmap/full_tcp.gnmap" 2>/dev/null | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
fi

info "Open ports detected: $PORTS"

#------------------------------------------------------------------------------
# WEB ENUMERATION (80, 443, 8080, 8443)
#------------------------------------------------------------------------------
web_enum() {
    local port=$1
    local proto=$2
    
    banner "WEB ENUMERATION - Port $port ($proto)"
    
    # Whatweb fingerprint
    info "Running whatweb..."
    whatweb "$proto://$TARGET:$port" -v > "$OUTDIR/web/whatweb_$port.txt" 2>&1 || true
    
    # Gobuster directory scan
    info "Running gobuster..."
    gobuster dir -u "$proto://$TARGET:$port" \
        -w /usr/share/wordlists/dirb/common.txt \
        -t 50 \
        -o "$OUTDIR/web/gobuster_$port.txt" \
        -x php,html,txt,bak,old,asp,aspx \
        --no-error 2>/dev/null &
    
    # Nikto scan
    info "Running nikto..."
    nikto -h "$proto://$TARGET:$port" -o "$OUTDIR/web/nikto_$port.txt" 2>/dev/null &
    
    # Check for robots.txt and sitemap
    curl -sk "$proto://$TARGET:$port/robots.txt" > "$OUTDIR/web/robots_$port.txt" 2>/dev/null || true
    curl -sk "$proto://$TARGET:$port/sitemap.xml" > "$OUTDIR/web/sitemap_$port.txt" 2>/dev/null || true
}

# Run web enum for common web ports
for port in 80 443 8080 8443; do
    if echo "$PORTS" | grep -q "$port"; then
        if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
            web_enum $port "https"
        else
            web_enum $port "http"
        fi
    fi
done

#------------------------------------------------------------------------------
# SMB ENUMERATION (139, 445)
#------------------------------------------------------------------------------
if echo "$PORTS" | grep -qE '(139|445)'; then
    banner "SMB ENUMERATION"
    
    info "Running enum4linux-ng..."
    enum4linux-ng -A "$TARGET" > "$OUTDIR/smb/enum4linux.txt" 2>&1 &
    
    info "Running smbclient (list shares)..."
    smbclient -L "//$TARGET" -N > "$OUTDIR/smb/smbclient_list.txt" 2>&1 || true
    
    info "Running crackmapexec..."
    crackmapexec smb "$TARGET" --shares > "$OUTDIR/smb/cme_shares.txt" 2>&1 || true
    crackmapexec smb "$TARGET" --users > "$OUTDIR/smb/cme_users.txt" 2>&1 || true
    
    info "Running smbmap..."
    smbmap -H "$TARGET" > "$OUTDIR/smb/smbmap.txt" 2>&1 || true
    smbmap -H "$TARGET" -u null -p '' >> "$OUTDIR/smb/smbmap.txt" 2>&1 || true
    
    info "Checking for common vulns..."
    nmap --script smb-vuln* -p 139,445 "$TARGET" -oN "$OUTDIR/smb/nmap_smb_vulns.txt" 2>/dev/null &
fi

#------------------------------------------------------------------------------
# LDAP ENUMERATION (389, 636, 3268)
#------------------------------------------------------------------------------
if echo "$PORTS" | grep -qE '(389|636|3268)'; then
    banner "LDAP ENUMERATION (Active Directory Detected)"
    
    info "Running ldapsearch..."
    ldapsearch -x -H "ldap://$TARGET" -b '' -s base '(objectClass=*)' > "$OUTDIR/misc/ldap_rootdse.txt" 2>&1 || true
    
    # Extract domain from LDAP
    DOMAIN=$(grep -oP 'DC=\K[^,]+' "$OUTDIR/misc/ldap_rootdse.txt" 2>/dev/null | head -1)
    if [ -n "$DOMAIN" ]; then
        info "Domain detected: $DOMAIN"
        echo "$DOMAIN" > "$OUTDIR/misc/domain.txt"
    fi
    
    info "Running nmap ldap scripts..."
    nmap --script ldap-search,ldap-rootdse -p 389 "$TARGET" -oN "$OUTDIR/misc/nmap_ldap.txt" 2>/dev/null &
fi

#------------------------------------------------------------------------------
# RPC/NFS ENUMERATION
#------------------------------------------------------------------------------
if echo "$PORTS" | grep -qE '(111|2049)'; then
    banner "NFS ENUMERATION"
    
    info "Checking NFS exports..."
    showmount -e "$TARGET" > "$OUTDIR/misc/nfs_exports.txt" 2>&1 || true
fi

if echo "$PORTS" | grep -q "135"; then
    banner "RPC ENUMERATION (Windows)"
    
    info "Running rpcclient..."
    rpcclient -U "" -N "$TARGET" -c "enumdomusers" > "$OUTDIR/misc/rpc_users.txt" 2>&1 || true
fi

#------------------------------------------------------------------------------
# FTP ENUMERATION (21)
#------------------------------------------------------------------------------
if echo "$PORTS" | grep -q "21"; then
    banner "FTP ENUMERATION"
    
    info "Checking anonymous FTP..."
    echo -e "anonymous\nanonymous" | ftp -n "$TARGET" > "$OUTDIR/misc/ftp_anon.txt" 2>&1 << EOF || true
user anonymous anonymous
ls -la
bye
EOF
    
    nmap --script ftp-anon,ftp-vuln* -p 21 "$TARGET" -oN "$OUTDIR/misc/nmap_ftp.txt" 2>/dev/null &
fi

#------------------------------------------------------------------------------
# SSH ENUMERATION (22)
#------------------------------------------------------------------------------
if echo "$PORTS" | grep -q "22"; then
    banner "SSH ENUMERATION"
    
    info "SSH version detection..."
    nmap --script ssh2-enum-algos,ssh-auth-methods -p 22 "$TARGET" -oN "$OUTDIR/misc/nmap_ssh.txt" 2>/dev/null &
fi

#------------------------------------------------------------------------------
# SNMP ENUMERATION (UDP 161)
#------------------------------------------------------------------------------
banner "SNMP ENUMERATION (UDP 161)"
info "Running snmpwalk with common community strings..."
for community in public private manager; do
    snmpwalk -v2c -c "$community" "$TARGET" > "$OUTDIR/misc/snmp_${community}.txt" 2>&1 &
done

#------------------------------------------------------------------------------
# SUMMARY
#------------------------------------------------------------------------------
banner "ENUMERATION TASKS LAUNCHED"
info "Output directory: $OUTDIR"
info "Background jobs running: $(jobs -r | wc -l)"
info ""
info "Quick wins to check:"
info "  - Anonymous FTP access"
info "  - SMB null sessions"
info "  - Web directories (gobuster)"
info "  - Known service vulns (searchsploit)"
info ""
warn "Run 'jobs' to check background task status"
warn "Full TCP scan PID: $FULL_TCP_PID"
warn "UDP scan PID: $UDP_PID"

# Wait option
echo ""
read -p "Wait for all scans to complete? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    wait
    banner "ALL SCANS COMPLETE"
    info "Review results in: $OUTDIR"
fi

