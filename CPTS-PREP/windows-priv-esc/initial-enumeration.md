# Windows Initial Enumeration

## 🎯 Overview

**Initial enumeration** is crucial for identifying privilege escalation paths. After gaining low-privileged access, we must systematically gather information about the system, users, services, and configurations to find attack vectors.

## 🖥️ System Information

### Process Enumeration
```cmd
# Running processes with services
tasklist /svc

# Key processes to identify:
- System processes (smss.exe, csrss.exe, winlogon.exe, lsass.exe)
- Non-standard processes (FileZilla, custom services)
- Security tools (MsMpEng.exe = Windows Defender)
```

### Environment Variables
```cmd
# Display all environment variables
set

# Key variables to examine:
PATH       # Custom paths, DLL hijacking opportunities
HOMEDRIVE  # Network drives, file shares
USERPROFILE # User directory access
TEMP       # Temporary directories
```

**Critical PATH Analysis:**
- Custom applications in PATH (Python, Java)
- Writable directories in PATH (DLL injection)
- Order matters: left-to-right execution priority

### Detailed System Information
```cmd
# Complete system details
systeminfo

# Key information:
- OS Name & Version (exploit targeting)
- Hotfix(s) Installed (patch level)
- System Boot Time (last restart)
- Network Card(s) (dual-homed systems)
```

```powershell
# PowerShell alternative
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory
```

## 🔄 Patches and Updates

### Hotfix Enumeration
```cmd
# WMI hotfix query
wmic qfe

# Look for:
- Recent patch dates
- Missing critical updates
- KB numbers for exploit research
```

```powershell
# PowerShell hotfix enumeration
Get-HotFix | ft -AutoSize

# Sort by installation date
Get-HotFix | Sort-Object InstalledOn -Descending
```

## 📦 Installed Programs

### Software Discovery
```cmd
# WMI installed programs
wmic product get name
```

```powershell
# PowerShell software enumeration
Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# Alternative method
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion
```

**Target Applications:**
- **FileZilla/Putty** - Credential storage (LaZagne)
- **Java/Python** - Version vulnerabilities
- **Custom applications** - Privilege escalation vectors
- **Development tools** - Source code access

## 🌐 Network Services

### Active Connections
```cmd
# Active TCP/UDP connections
netstat -ano

# Identify:
- Local-only services (127.0.0.1)
- Non-standard ports
- Service-to-PID mapping
```

```powershell
# PowerShell network connections
Get-NetTCPConnection -State Listen
Get-NetTCPConnection -State Established
```

## 👥 User & Group Enumeration

### Current User Context
```cmd
# Current user
whoami
echo %USERNAME%

# User privileges
whoami /priv

# Group memberships
whoami /groups

# Complete user information
whoami /all
```

**Key Privileges to Look For:**
- `SeImpersonatePrivilege` - Juicy Potato attacks
- `SeAssignPrimaryTokenPrivilege` - Token manipulation
- `SeTakeOwnershipPrivilege` - File ownership changes
- `SeBackupPrivilege` - File access bypass

### User Discovery
```cmd
# All local users
net user

# Domain users (if domain-joined)
net user /domain

# Specific user details
net user [username]
```

### Group Analysis
```cmd
# Local groups
net localgroup

# Group members
net localgroup administrators
net localgroup "Backup Operators"
net localgroup "Remote Desktop Users"
```

**High-Value Groups:**
- **Administrators** - Local admin access
- **Backup Operators** - File access, backup rights
- **Server Operators** - Service control
- **Account Operators** - User/group management
- **Print Operators** - Load driver privilege

### Session Information
```cmd
# Logged-in users
query user

# Session details
query session
```

### Account Policies
```cmd
# Password policy and lockout settings
net accounts

# Key metrics:
- Password complexity requirements
- Lockout threshold
- Account lockout duration
```

## 🎯 HTB Academy Lab Solutions

### Lab Environment
- **Target**: `10.129.43.43` (ACADEMY-WINLPE-SRV01)
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`

### Question 1: Non-default User Privileges
**Command:**
```cmd
whoami /priv
```
**Answer**: `SeTakeOwnershipPrivilege`

### Question 2: Backup Operators Group Member
**Command:**
```cmd
net localgroup "Backup Operators"
```
**Answer**: `sarah`

### Question 3: Service on Port 8080
**Commands:**
```cmd
netstat -ano | findstr :8080
tasklist /svc /FI "PID eq [PID_FROM_NETSTAT]"
```
**Answer**: `tomcat8`

### Question 4: Logged-in User
**Command:**
```cmd
query user
```
**Answer**: `sccm_svc`

### Question 5: Session Type
**Command:**
```cmd
query user
# Look at SESSIONNAME column
```
**Answer**: `console`

## 📋 Essential Enumeration Checklist

### System Context
- [ ] **OS version and patches** (`systeminfo`)
- [ ] **Running processes** (`tasklist /svc`)
- [ ] **Environment variables** (`set`)
- [ ] **Installed software** (`wmic product get name`)
- [ ] **Network services** (`netstat -ano`)

### User Context
- [ ] **Current user privileges** (`whoami /priv`)
- [ ] **Group memberships** (`whoami /groups`)
- [ ] **All local users** (`net user`)
- [ ] **Local groups** (`net localgroup`)
- [ ] **Administrators group** (`net localgroup administrators`)
- [ ] **Logged-in users** (`query user`)
- [ ] **Password policy** (`net accounts`)

## ⚡ Quick Reference Commands

```cmd
# System enumeration one-liners
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
tasklist /svc | findstr /V /C:"N/A"
wmic qfe get Description,HotFixID,InstalledOn
wmic product get name,version,vendor
netstat -ano | findstr LISTENING

# User enumeration one-liners  
whoami /all
net user | findstr /V "command completed"
net localgroup | findstr /V "command completed"
net localgroup administrators
query user 2>nul || echo "Access denied"
```

## 💡 Key Takeaways

1. **Systematic approach** - Don't skip basic enumeration steps
2. **Privilege identification** - Special privileges = escalation paths
3. **Service analysis** - Non-standard services often vulnerable
4. **Group membership** - Powerful groups provide direct escalation
5. **Environment awareness** - PATH, shares, and custom configurations matter
6. **Session monitoring** - Other logged-in users = additional targets

---

*This enumeration phase sets the foundation for successful privilege escalation by providing comprehensive system and user context.* 