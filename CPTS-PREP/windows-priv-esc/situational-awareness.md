# Windows Privilege Escalation - Situational Awareness

## 🎯 Overview

**Situational awareness** is the first critical step in Windows privilege escalation. Before attempting any escalation techniques, we must understand:

- **Network topology** and dual-homed systems
- **Security protections** in place (AV, EDR, AppLocker)
- **System context** and current privileges
- **Network connectivity** and potential lateral movement paths

> **"We cannot function and react effectively without an understanding of our current surroundings"**

## 🌐 Network Information Gathering

### Interface and IP Address Enumeration

#### Basic Network Configuration
```cmd
# Complete network interface information
ipconfig /all

# Quick IP address overview
ipconfig

# DNS configuration
ipconfig /displaydns
```

#### Key Network Details to Note
```cmd
# Look for:
- Multiple network interfaces (dual-homed systems)
- DNS servers and domain information
- DHCP configuration
- IPv6 addresses and tunneling adapters
```

**Example Output Analysis:**
```cmd
# Dual-homed system identified
IPv4 Address: 10.129.43.8     # External/DMZ network
IPv4 Address: 192.168.20.56   # Internal network

# Domain information
Primary Dns Suffix: .htb
DNS Suffix Search List: .htb
```

### ARP Cache Analysis

```cmd
# View ARP cache for recent communications
arp -a

# Analyze per interface
arp -a -N [interface_ip]
```

**Strategic Value:**
- **Recent communications** - Shows hosts recently contacted
- **Network discovery** - Identifies active hosts on each network
- **Lateral movement targets** - Potential next hop systems
- **Administrative patterns** - RDP/WinRM connection evidence

### Routing Table Examination

```cmd
# Complete routing information
route print

# IPv4 routes only
route print -4

# IPv6 routes only
route print -6
```

**Analysis Points:**
```cmd
# Network segments accessible:
Network Destination    Netmask          Gateway       Interface
10.129.0.0            255.255.0.0      10.129.0.1    10.129.43.8  # External
192.168.20.0          255.255.255.0    192.168.20.1  192.168.20.56 # Internal

# Default routes - potential egress points
0.0.0.0               0.0.0.0          10.129.0.1    # Primary route
0.0.0.0               0.0.0.0          192.168.20.1  # Secondary route
```

### Advanced Network Discovery

```cmd
# Active TCP connections
netstat -an

# Processes and associated connections
netstat -anb

# Network statistics
netstat -s

# Network interfaces with statistics
netstat -i
```

```powershell
# PowerShell network cmdlets
Get-NetIPConfiguration
Get-NetRoute
Get-NetAdapter
Get-NetTCPConnection -State Established
```

## 🛡️ Security Protection Enumeration

### Windows Defender Status

```powershell
# Comprehensive Defender status
Get-MpComputerStatus

# Key status indicators
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled

# Threat detection settings
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring
```

**Critical Status Fields:**
- `AntivirusEnabled` - AV engine status
- `RealTimeProtectionEnabled` - Live scanning
- `BehaviorMonitorEnabled` - Behavioral analysis
- `OnAccessProtectionEnabled` - File access monitoring

### AppLocker Policy Assessment

```powershell
# Current effective AppLocker rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Local AppLocker policy only
Get-AppLockerPolicy -Local

# Domain AppLocker policy
Get-AppLockerPolicy -Domain

# Test specific executable against policy
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

**AppLocker Rule Types:**
- **Executable Rules** - Controls .exe, .com files
- **Windows Installer Rules** - Controls .msi, .msp files
- **Script Rules** - Controls .ps1, .bat, .cmd files
- **Packaged App Rules** - Controls Windows Store apps
- **DLL Rules** - Controls .dll files (rarely used)

#### AppLocker Bypass Indicators
```powershell
# Look for path-based rules that can be bypassed
PathConditions: {%PROGRAMFILES%\*}  # May allow unsigned executables in Program Files
PathConditions: {%WINDIR%\*}        # May allow execution from Windows directory
```

### Additional Security Services

```cmd
# Running services (potential EDR)
net start | findstr /i "carbon\|crowd\|cylinder\|defend\|fire\|malware\|secure"

# Process list for security tools
tasklist | findstr /i "carbon\|crowd\|cylinder\|defend\|fire\|malware\|secure"

# Windows Firewall status
netsh advfirewall show allprofiles
```

```powershell
# PowerShell security service enumeration
Get-Service | Where-Object {$_.Name -match "Defend|Malware|Antivirus|Carbon|Crowd|Fire"}

# Check for common EDR processes
Get-Process | Where-Object {$_.ProcessName -match "cb|crowd|fire|defend|malware"}
```

## 🔍 System Context Assessment

### Current User and Privileges

```cmd
# Current user information
whoami /all

# User privileges
whoami /priv

# Group memberships
whoami /groups

# Current user only
whoami
```

```powershell
# PowerShell user context
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Get-LocalUser | Where-Object {$_.Enabled -eq $true}
Get-LocalGroupMember -Group "Administrators"
```

### System Information

```cmd
# System details
systeminfo | findstr /i "system\|os\|service\|hotfix"

# OS version
ver

# Environment variables
set

# Installed software
wmic product get name,version
```

```powershell
# PowerShell system information
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory
Get-WmiObject -Class Win32_OperatingSystem
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10
```

## 📋 Situational Awareness Checklist

### Network Assessment
- [ ] **Multiple interfaces identified** - Check for dual-homed systems
- [ ] **Internal networks mapped** - Document accessible network segments  
- [ ] **ARP cache analyzed** - Note recent communication patterns
- [ ] **Routing table reviewed** - Understand network topology
- [ ] **Active connections listed** - Identify current network activity

### Security Posture
- [ ] **Windows Defender status** - Determine AV/EDR protection level
- [ ] **AppLocker rules assessed** - Understand execution restrictions
- [ ] **Firewall configuration** - Check for outbound restrictions
- [ ] **Security services identified** - Note EDR/monitoring tools
- [ ] **Admin privileges confirmed** - Verify current access level

### System Context
- [ ] **User privileges enumerated** - Document current user context
- [ ] **Group memberships verified** - Check for privileged groups
- [ ] **System version identified** - Note OS version and patch level
- [ ] **Installed software cataloged** - Identify potential attack vectors

## 🎯 HTB Academy Lab - Situational Awareness

### Lab Environment
- **Target**: Windows system accessible via RDP
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`
- **Objective**: Identify network configuration and security restrictions

### Lab Questions

#### Question 1: Network Interface Discovery
**Objective**: Find the IP address of the other NIC attached to the target host

```cmd
# Solution approach
ipconfig /all

# Look for multiple Ethernet adapters
# Identify IP addresses on different network segments
# Answer format: X.X.X.X (IP address of secondary interface)
```

#### Question 2: AppLocker Executable Restrictions  
**Objective**: Identify which executable (other than cmd.exe) is blocked by AppLocker

```powershell
# Solution approach
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test common executables
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\powershell.exe -User Everyone
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\net.exe -User Everyone

# Look for PolicyDecision: Denied
```

**Common Blocked Executables:**
- `powershell.exe` - PowerShell interpreter
- `cmd.exe` - Command prompt (mentioned as blocked)
- `net.exe` - Network configuration utility
- `wmic.exe` - Windows Management Instrumentation tool

### Expected Results
```cmd
# Network discovery result
Interface 1: 10.129.43.8    (External/HTB network)
Interface 2: 192.168.20.56  (Internal network)

# AppLocker restriction result
powershell.exe: DENIED
cmd.exe: DENIED  
net.exe: ALLOWED
```

## 💡 Key Takeaways

1. **Network topology understanding** - Dual-homed systems provide lateral movement opportunities
2. **Security awareness** - Early protection enumeration prevents detection
3. **Context establishment** - Know your current privileges before escalation attempts
4. **Tool restrictions** - AppLocker policies affect available attack vectors
5. **Systematic approach** - Complete situational awareness before technical exploitation

---

*This guide covers the essential first step in Windows privilege escalation - gathering comprehensive situational awareness to inform subsequent attack strategies.* 