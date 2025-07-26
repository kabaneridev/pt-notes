# Enumerating & Retrieving Password Policies

## 📋 Overview

Password policy enumeration is a critical reconnaissance step in Active Directory assessments. Understanding the domain's password requirements, lockout thresholds, and complexity rules helps determine the feasibility of password spraying attacks and guides credential attack strategies.

## 🎯 Why Password Policies Matter

### 🔍 **Assessment Value**
- **Password Spraying Planning**: Determines safe attack parameters
- **Lockout Avoidance**: Critical for maintaining stealth
- **Attack Vector Selection**: Influences credential attack methodology
- **Risk Assessment**: Weak policies indicate higher security risk

### ⚠️ **Key Policy Settings**
- **Minimum Password Length**: Affects password complexity
- **Lockout Threshold**: Maximum failed attempts before lockout
- **Lockout Duration**: How long accounts remain locked
- **Password Complexity**: Character requirements
- **Password History**: Prevents password reuse

---

## 🐧 Linux-Based Enumeration

### 🔑 Credentialed Enumeration

#### **CrackMapExec - Password Policy**
```bash
# Enumerate password policy with valid credentials
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

**Example Output:**
```
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Dumping password info for domain: INLANEFREIGHT
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password length: 8
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password history length: 24
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Maximum password age: Not Set
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Password Complexity Flags: 000001
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Refuse Password Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Store Cleartext: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Lockout Admins: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Clear Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password No Anon Change: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  	Domain Password Complex: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Minimum password age: 1 day 4 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Reset Account Lockout Counter: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Locked Account Duration: 30 minutes 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Account Lockout Threshold: 5
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Forced Log off Time: Not Set
```

---

### 🔓 SMB NULL Session Enumeration

#### **rpcclient - NULL Session**
```bash
# Connect with NULL session
rpcclient -U "" -N 172.16.5.5

# Query domain information
rpcclient $> querydominfo
Domain:		INLANEFREIGHT
Server:		
Comment:	
Total Users:	3650
Total Groups:	0
Total Aliases:	37
Sequence No:	1
Force Logoff:	-1
Domain Server State:	0x1
Server Role:	ROLE_DOMAIN_PDC
Unknown 3:	0x1

# Get password policy
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```

#### **enum4linux - Legacy Tool**
```bash
# Enumerate password policy
enum4linux -P 172.16.5.5
```

**Key Output:**
```
[+] Password Info for Domain: INLANEFREIGHT

	[+] Minimum password length: 8
	[+] Password history length: 24
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000001

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 1

	[+] Minimum password age: 1 day 4 minutes 
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: 5
	[+] Forced Log off Time: Not Set
```

#### **enum4linux-ng - Modern Rewrite**
```bash
# Enhanced enumeration with export options
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

**YAML/JSON Output:**
```yaml
domain_password_information:
  pw_history_length: 24
  min_pw_length: 8
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: true
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: 5
```

#### **Tool Port Usage**
| **Tool** | **Ports** |
|----------|-----------|
| nmblookup | 137/UDP |
| nbtstat | 137/UDP |
| net | 139/TCP, 135/TCP, 49152-65535 |
| rpcclient | 135/TCP |
| smbclient | 445/TCP |

---

### 🌐 LDAP Anonymous Bind

#### **ldapsearch - LDAP Query**
```bash
# Query password policy via LDAP
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

**Example Output:**
```
forceLogoff: -9223372036854775808
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 5
maxPwdAge: -9223372036854775808
minPwdAge: -864000000000
minPwdLength: 8
modifiedCountAtLastProm: 0
nextRid: 1002
pwdProperties: 1
pwdHistoryLength: 24
```

**Note**: In newer versions, use `-H ldap://IP` instead of `-h IP`

---

## 🪟 Windows-Based Enumeration

### 🔓 NULL Session from Windows

#### **net use Command**
```cmd
# Establish NULL session
net use \\DC01\ipc$ "" /u:""
The command completed successfully.

# Test with credentials
net use \\DC01\ipc$ "password" /u:guest
```

#### **Common Error Messages**
```cmd
# Account Disabled
System error 1331 has occurred.
This user can't sign in because this account is currently disabled.

# Incorrect Password
System error 1326 has occurred.
The user name or password is incorrect.

# Account Locked Out
System error 1909 has occurred.
The referenced account is currently locked out and may not be logged on to.
```

---

### 🔑 Credentialed Windows Enumeration

#### **net.exe - Built-in Tool**
```cmd
# Query account policy
net accounts
```

**Example Output:**
```
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

#### **PowerView - PowerShell Module**
```powershell
# Import and query domain policy
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

**Example Output:**
```powershell
Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
```

---

## 📊 Password Policy Analysis

### 🔍 **INLANEFREIGHT.LOCAL Analysis**

| **Setting** | **Value** | **Implication** |
|-------------|-----------|-----------------|
| **Minimum Length** | 8 characters | Allows weak passwords like `Welcome1` |
| **Lockout Threshold** | 5 attempts | Safe for 2-3 password spraying attempts |
| **Lockout Duration** | 30 minutes | Accounts auto-unlock (no admin required) |
| **Password Complexity** | Enabled | 3/4 character types required |
| **Password History** | 24 passwords | Prevents immediate reuse |
| **Maximum Age** | Unlimited | Passwords never expire |

### ⚠️ **Password Spraying Implications**
- **Safe Attempt Count**: 2-3 attempts per user
- **Wait Time**: 31+ minutes between spray rounds
- **Target Passwords**: `Welcome1`, `Password1`, `Company1`
- **Risk Level**: Low (auto-unlock, high threshold)

---

## 📋 Default Domain Password Policy

| **Policy** | **Default Value** |
|------------|-------------------|
| Enforce password history | 24 days |
| Maximum password age | 42 days |
| Minimum password age | 1 day |
| **Minimum password length** | **7** |
| Password complexity | Enabled |
| Store passwords using reversible encryption | Disabled |
| Account lockout duration | Not set |
| Account lockout threshold | 0 |
| Reset account lockout counter | Not set |

---

## 🎯 HTB Academy Lab Walkthrough

### 📝 Lab Questions

#### **Question 1**: *"What is the default Minimum password length when a new domain is created?"*
#### **Question 2**: *"What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain?"*

### 🚀 Step-by-Step Solution

#### 1️⃣ **Connect to Target**
```bash
# SSH to target system
ssh htb-student@TARGET_IP
# Password: HTB_@cademy_stdnt!
```

#### 2️⃣ **Method 1: enum4linux**
```bash
# Enumerate password policy
enum4linux -P 172.16.5.5
```

#### 3️⃣ **Method 2: rpcclient NULL Session**
```bash
# Connect with NULL session
rpcclient -U "" -N 172.16.5.5

# Query password policy
rpcclient $> getdompwinfo
min_password_length: 8
password_properties: 0x00000001
	DOMAIN_PASSWORD_COMPLEX
```

#### 4️⃣ **Method 3: ldapsearch**
```bash
# Query via LDAP
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep minPwdLength
minPwdLength: 8
```

#### 5️⃣ **Method 4: enum4linux-ng**
```bash
# Modern tool with structured output
enum4linux-ng -P 172.16.5.5 -oA ilfreight

# Check JSON output
cat ilfreight.json | grep -A5 "domain_password_information"
```

### ✅ **Answers**
1. **Default minimum password length**: `7`
2. **INLANEFREIGHT.LOCAL minPwdLength**: `8`

---

## 🛡️ Password Policy Best Practices

### ✅ **Strong Policy Recommendations**
- **Minimum Length**: 12-14 characters
- **Lockout Threshold**: 3-5 attempts
- **Lockout Duration**: 15-30 minutes
- **Complexity**: Enable but educate users
- **Password Age**: 90-180 days maximum

### 🚫 **Disable Legacy Features**
- **SMB NULL Sessions**: Prevent anonymous access
- **LDAP Anonymous Bind**: Require authentication
- **LM Hash Storage**: Use only NTLM/NTLMv2
- **Reversible Encryption**: Never enable

### 🔧 **Group Policy Hardening**
```
Computer Configuration → Windows Settings → Security Settings → Account Policies → Password Policy
- Minimum password length: 12
- Password complexity requirements: Enabled
- Minimum password age: 1 day
- Maximum password age: 90 days
- Password history: 24 passwords
```

---

## 🔍 Detection & Monitoring

### 📊 **Event IDs to Monitor**
- **4625**: Failed logon attempts
- **4740**: Account lockout events
- **4767**: Account unlock events
- **4724**: Password reset attempts

### 🚨 **Anomaly Detection**
- **Multiple failed authentications** from single source
- **Unusual authentication patterns** across multiple accounts
- **Service account lockouts** (often indicates spraying)
- **Authentication attempts** outside business hours

### 📈 **Baseline Metrics**
- Normal failed authentication rates
- Typical lockout frequencies
- Service account authentication patterns
- Geographic authentication patterns

---

## ⚡ Quick Reference Commands

### 🐧 **Linux Enumeration**
```bash
# CrackMapExec with credentials
crackmapexec smb TARGET -u USER -p PASS --pass-pol

# rpcclient NULL session
rpcclient -U "" -N TARGET
rpcclient $> getdompwinfo

# enum4linux-ng modern
enum4linux-ng -P TARGET -oA output

# LDAP anonymous bind
ldapsearch -h TARGET -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*" | grep -A10 -B10 pwdHistoryLength
```

### 🪟 **Windows Enumeration**
```cmd
REM Built-in Windows command
net accounts

REM NULL session test
net use \\DC\ipc$ "" /u:""
```

```powershell
# PowerView
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

---

## 🔑 Key Takeaways

### ✅ **Enumeration Success Factors**
- **Multiple Methods**: Try various approaches (SMB, LDAP, RPC)
- **Legacy Misconfigurations**: NULL sessions often work on older domains
- **Tool Redundancy**: Use both traditional and modern tools
- **Credential Context**: Some methods require authentication

### ⚠️ **Critical Considerations**
- **Lockout Avoidance**: Never exceed safe attempt thresholds
- **Stealth Operations**: Avoid generating excessive authentication logs
- **Policy Documentation**: Record all discovered settings for planning
- **Client Communication**: Confirm lockout policies when possible

### 🎯 **Next Steps**
1. **User Enumeration**: Gather target user lists
2. **Password List Creation**: Build spraying wordlists
3. **Attack Timing**: Plan spray intervals based on lockout policy
4. **Monitoring Setup**: Watch for defensive responses

---

*Understanding the password policy is fundamental to safe and effective credential attacks in Active Directory environments.* 