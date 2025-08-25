# Living Off the Land

## 📋 Overview

"Living Off the Land" refers to using only native Windows tools and commands for Active Directory enumeration and reconnaissance. This approach is essential when external tools cannot be uploaded, when operating in restricted environments, or when maintaining maximum stealth. By leveraging built-in Windows utilities, PowerShell cmdlets, and AD-integrated tools, we can perform comprehensive enumeration without introducing foreign binaries that might trigger security controls.

## 🎯 Strategic Context

### 🛡️ **When to Use Living Off the Land**
- **Restricted Environments**: No internet access or file upload capabilities
- **Stealth Operations**: Minimizing detection by avoiding external tool signatures
- **Managed Hosts**: Client-provided systems with restrictive policies
- **EDR Evasion**: Built-in tools are less likely to trigger alerts
- **Baseline Operations**: Understanding what's possible with native capabilities

### ⚠️ **Operational Considerations**
- **Logging Awareness**: Many commands generate logs in Event Viewer
- **PowerShell Monitoring**: Script Block Logging captures command history
- **EDR Detection**: Even native tools can trigger behavioral analysis
- **Version Dependencies**: Tool availability varies across Windows versions
- **Privilege Requirements**: Some commands require elevated privileges

---

## 🔧 Basic Environmental Reconnaissance

### 📊 **Host Information Gathering**

#### **Essential System Commands**
| **Command** | **Purpose** | **Output** |
|-------------|-------------|------------|
| `hostname` | Computer name | Host identifier |
| `[System.Environment]::OSVersion.Version` | OS version | Build and revision details |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Patch level | Security updates applied |
| `ipconfig /all` | Network configuration | Adapter settings and IPs |
| `set` | Environment variables | System and user variables |
| `echo %USERDOMAIN%` | Domain name | Current domain affiliation |
| `echo %logonserver%` | Domain controller | Authenticating DC |

#### **Comprehensive System Information**
```cmd
# Single command for complete system overview
systeminfo

# Key information retrieved:
# - Computer name and domain
# - OS version and build
# - Hardware details
# - Network configuration
# - Hotfix history
# - Time zone and boot time
```

**Example Output Analysis:**
```cmd
C:\htb> systeminfo

Host Name:                 ACADEMY-EA-MS01
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
Domain:                    INLANEFREIGHT.LOCAL
Logon Server:              \\ACADEMY-EA-DC01
Network Card(s):           2 NIC(s) Installed
                          [01]: Intel(R) 82574L Gigabit Network Connection
                                Connection Name: Ethernet
                                DHCP Enabled:    No
                                IP address(es)
                                [01]: 172.16.5.25
                                [02]: fe80::f98a:4f63:8384:d1d0
Hotfix(s):                 15 Hotfix(s) Installed
                          [01]: KB4580422
                          [02]: KB4512577
```

---

## ⚡ PowerShell Reconnaissance

### 🔍 **PowerShell Environment Analysis**
```powershell
# Check available modules
Get-Module

# Execution policy assessment
Get-ExecutionPolicy -List

# Environment variable enumeration
Get-ChildItem Env: | Format-Table Key,Value

# Command history discovery
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# Current user context
whoami
whoami /priv
whoami /groups
```

**Example PowerShell Environment Check:**
```powershell
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...}

PS C:\htb> Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    RemoteSigned

PS C:\htb> Get-ChildItem Env: | Format-Table Key,Value

Key                     Value
---                     -----
ALLUSERSPROFILE         C:\ProgramData
APPDATA                 C:\Windows\system32\config\systemprofile\AppData\Roaming
COMPUTERNAME            ACADEMY-EA-MS01
USERDOMAIN              INLANEFREIGHT
USERNAME                ACADEMY-EA-MS01$
USERPROFILE             C:\Windows\system32\config\systemprofile
```

### 🔄 **PowerShell Version Downgrade (Stealth Technique)**
```powershell
# Check current PowerShell version
Get-Host

# Downgrade to PowerShell v2.0 (bypasses Script Block Logging)
powershell.exe -version 2

# Verify downgrade success
Get-Host

# Note: PowerShell v2.0 lacks many modern logging capabilities
# This technique can evade Script Block Logging (PowerShell 3.0+)
```

**Example Downgrade Process:**
```powershell
PS C:\htb> Get-Host
Name             : ConsoleHost
Version          : 5.1.19041.1320
InstanceId       : 18ee9fb4-ac42-4dfe-85b2-61687291bbfc

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\htb> Get-Host
Name             : ConsoleHost
Version          : 2.0
InstanceId       : 121b807c-6daa-4691-85ef-998ac137e469

# Script Block Logging now bypassed!
```

---

## 🛡️ Security Controls Assessment

### 🔥 **Windows Firewall Enumeration**
```cmd
# Complete firewall profile analysis
netsh advfirewall show allprofiles

# Specific profile checks
netsh advfirewall show domainprofile
netsh advfirewall show privateprofile
netsh advfirewall show publicprofile

# Firewall rules enumeration
netsh advfirewall firewall show rule name=all
```

**Example Firewall Analysis:**
```cmd
PS C:\htb> netsh advfirewall show allprofiles

Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
```

### 🛡️ **Windows Defender Assessment**
```cmd
# Service status check
sc query windefend

# Detailed configuration analysis (PowerShell)
Get-MpComputerStatus

# Threat detection settings
Get-MpPreference

# Exclusion lists
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess
```

**Example Defender Analysis:**
```cmd
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

PS C:\htb> Get-MpComputerStatus

AMEngineVersion                  : 1.1.19000.8
AMProductVersion                 : 4.18.2202.4
AMRunningMode                    : Normal
AMServiceEnabled                 : True
AntispywareEnabled               : True
AntivirusEnabled                 : True
BehaviorMonitorEnabled           : True
IoavProtectionEnabled            : True
IsTamperProtected                : True
RealTimeProtectionEnabled        : True
```

### 👥 **Session and User Analysis**
```cmd
# Active sessions enumeration
qwinsta

# Logged on users
query user

# Current session details
query session

# User logon information
wmic computersystem get username
```

**Example Session Analysis:**
```cmd
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```

---

## 🌐 Network Intelligence Gathering

### 🔍 **Network Configuration Discovery**
```cmd
# ARP table analysis (known hosts)
arp -a

# Routing table enumeration
route print

# Network interfaces
ipconfig /all

# DNS configuration
ipconfig /displaydns

# Network statistics
netstat -an
netstat -rn
```

**Example Network Discovery:**
```cmd
PS C:\htb> arp -a

Interface: 172.16.5.25 --- 0x8
  Internet Address      Physical Address      Type
  172.16.5.5            00-50-56-b9-08-26     dynamic    # Domain Controller
  172.16.5.130          00-50-56-b9-f0-e1     dynamic    # File Server
  172.16.5.240          00-50-56-b9-9d-66     dynamic    # Mail Server

PS C:\htb> route print

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       172.16.5.1      172.16.5.25    261
       172.16.4.0    255.255.254.0         On-link       172.16.5.25    261
      172.16.5.25  255.255.255.255         On-link       172.16.5.25    261
     172.16.5.255  255.255.255.255         On-link       172.16.5.25    261
```

### 📊 **Network Intelligence Analysis**
- **ARP Entries**: Recently contacted hosts (potential targets)
- **Routing Table**: Known network segments (lateral movement opportunities)
- **DNS Cache**: Previously resolved domains and hosts
- **Active Connections**: Current network activity and services

---

## 🔍 WMI (Windows Management Instrumentation)

### 📝 **Core WMI Queries**

#### **System and Domain Information**
```cmd
# Patch and hotfix information
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Basic host information
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List

# Process enumeration
wmic process list /format:list

# Domain and trust information
wmic ntdomain list /format:list

# User account information
wmic useraccount list /format:list

# Local groups
wmic group list /format:list

# Service accounts
wmic sysaccount list /format:list
```

**Example WMI Domain Discovery:**
```cmd
PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

Caption          Description      DnsForestName           DomainControllerAddress  DomainName
ACADEMY-EA-MS01  ACADEMY-EA-MS01
INLANEFREIGHT    INLANEFREIGHT    INLANEFREIGHT.LOCAL     \\172.16.5.5             INLANEFREIGHT
LOGISTICS        LOGISTICS        INLANEFREIGHT.LOCAL     \\172.16.5.240           LOGISTICS
FREIGHTLOGISTIC  FREIGHTLOGISTIC  FREIGHTLOGISTICS.LOCAL  \\172.16.5.238           FREIGHTLOGISTIC
```

#### **Advanced WMI Techniques**
```cmd
# Remote system information
wmic /node:"TARGETHOST" computersystem get Name,Domain

# Service enumeration
wmic service get name,displayname,pathname,startmode

# Installed software
wmic product get name,version,vendor

# Startup programs
wmic startup get caption,command,location

# Share enumeration
wmic share list full
```

---

## 🌐 Net Commands

### 📊 **Essential Net Command Reference**

| **Command** | **Purpose** | **Example Usage** |
|-------------|-------------|-------------------|
| `net accounts` | Password policy | Local account settings |
| `net accounts /domain` | Domain password policy | Domain-wide policies |
| `net group /domain` | Domain groups | All domain security groups |
| `net group "Domain Admins" /domain` | Group membership | Privileged users |
| `net user /domain` | Domain users | All domain user accounts |
| `net user USERNAME /domain` | User details | Specific user information |
| `net localgroup` | Local groups | Host-specific groups |
| `net localgroup administrators` | Admin group | Local administrators |
| `net share` | Shared resources | Available network shares |
| `net view` | Network hosts | Visible domain computers |
| `net view /domain` | Domain computers | Domain-joined systems |

### 🔍 **Domain Enumeration Examples**
```cmd
# Domain groups discovery
net group /domain

# Domain Admins identification
net group "Domain Admins" /domain

# User account details
net user /domain wrouse

# Password policy analysis
net accounts /domain

# Local administrators
net localgroup administrators /domain

# Network shares
net view \\HOSTNAME /ALL

# Domain computers
net view /domain
```

**Example Domain Group Enumeration:**
```cmd
PS C:\htb> net group /domain

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

Group Accounts for \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
-------------------------------------------------------------------------------
*Accounting
*Backup Operators
*Billing
*CEO
*CFO
*Cloneable Domain Controllers
*Compliance Management
*Domain Admins
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*File Share G Drive
*File Share H Drive
*Help Desk Level 1
*VPN Users
```

**Example User Information:**
```cmd
PS C:\htb> net user /domain wrouse

User name                    wrouse
Full Name                    Christopher Davis
Comment
Account active               Yes
Account expires              Never
Password last set            10/27/2021 10:38:01 AM
Password expires             Never
Password changeable          10/28/2021 10:38:01 AM
Password required            Yes
User may change password     Yes
Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never
Logon hours allowed          All

Local Group Memberships
Global Group memberships     *File Share G Drive   *File Share H Drive
                             *Warehouse            *Printer Access
                             *Domain Users         *VPN Users
                             *Shared Calendar Read
```

### 🔄 **Net1 Stealth Technique**
```cmd
# Use net1 instead of net to avoid potential monitoring triggers
net1 group /domain
net1 user /domain
net1 localgroup administrators

# Functions identically to net commands but may evade basic string detection
```

---

## 🔍 Dsquery (Directory Services Query)

### 📝 **Overview**
Dsquery is a native Active Directory command-line tool for LDAP-based queries. It exists on all domain-joined systems and provides powerful search capabilities without requiring additional tools.

### 👥 **User and Computer Enumeration**
```cmd
# All domain users
dsquery user

# All domain computers
dsquery computer

# Specific organizational unit
dsquery user "OU=Finance,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"

# Wildcard searches
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

# Limited results
dsquery user -limit 10
```

**Example User Discovery:**
```cmd
PS C:\htb> dsquery user

"CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Htb Student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Annie Vazquez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Paul Falcon,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Walter Dillard,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

### 🔍 **Advanced LDAP Filtering**
```cmd
# Users with password not required flag
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Domain Controllers
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

# Service accounts (SPNs)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))" -attr sAMAccountName servicePrincipalName

# Administrative accounts
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(adminCount=1))" -attr sAMAccountName

# Disabled accounts
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr sAMAccountName description
```

### 🔧 **LDAP Filter Components**

#### **OID (Object Identifier) Rules**
| **OID** | **Function** | **Usage** |
|---------|--------------|-----------|
| `1.2.840.113556.1.4.803` | Bitwise AND | Exact bit match required |
| `1.2.840.113556.1.4.804` | Bitwise OR | Any matching bit |
| `1.2.840.113556.1.4.1941` | Distinguished Name | Membership/ownership chains |

#### **UserAccountControl Values**
| **Value** | **Flag** | **Description** |
|-----------|----------|-----------------|
| `1` | SCRIPT | Login script executed |
| `2` | ACCOUNTDISABLE | Account disabled |
| `8` | HOMEDIR_REQUIRED | Home directory required |
| `16` | LOCKOUT | Account locked out |
| `32` | PASSWD_NOTREQD | Password not required |
| `64` | PASSWD_CANT_CHANGE | Password cannot change |
| `128` | ENCRYPTED_TEXT_PWD_ALLOWED | Encrypted text password allowed |
| `512` | NORMAL_ACCOUNT | Normal user account |
| `8192` | SERVER_TRUST_ACCOUNT | Domain controller |
| `65536` | DONT_EXPIRE_PASSWORD | Password never expires |

#### **Logical Operators**
```cmd
# AND operator - all conditions must match
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))

# OR operator - any condition matches
(|(objectClass=user)(objectClass=computer))

# NOT operator - condition must not match
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))
```

---

## 🎯 HTB Academy Lab Solutions

### 📝 **Lab Questions & Solutions**

#### 🛡️ **Question 1: "Enumerate the host's security configuration information and provide its AMProductVersion."**

**Solution Process:**
```powershell
# Method 1: PowerShell Get-MpComputerStatus
Get-MpComputerStatus | Select-Object AMProductVersion

# Method 2: WMI Query
wmic /namespace:\\root\Microsoft\Windows\Defender path MSFT_MpComputerStatus get AMProductVersion

# Method 3: Registry query
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /s | findstr "AMProductVersion"

# Method 4: Detailed security enumeration
Get-MpComputerStatus | Format-List
```

**Expected Output:**
```powershell
PS C:\htb> Get-MpComputerStatus | Select-Object AMProductVersion

AMProductVersion
----------------
4.18.2202.4
```

**Expected Answer:** `4.18.2202.4`

#### 👥 **Question 2: "What domain user is explicitly listed as a member of the local Administrators group on the target host?"**

**Solution Process:**
```cmd
# Method 1: Net command
net localgroup administrators

# Method 2: WMI query
wmic group where name="Administrators" assoc:list

# Method 3: PowerShell
Get-LocalGroupMember -Group "Administrators"

# Method 4: Direct query
net localgroup administrators /domain
```

**Expected Output:**
```cmd
PS C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
INLANEFREIGHT\damundsen
INLANEFREIGHT\Domain Admins
The command completed successfully.
```

**Expected Answer:** `damundsen`

#### 🚩 **Question 3: "Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer."**

**Solution Process:**
```cmd
# Step 1: Find disabled users with administrative privileges
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1))" -attr sAMAccountName description

# Step 2: Alternative - Find disabled users and check descriptions
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr sAMAccountName description | findstr -i "flag\|htb\|{.*}"

# Step 3: PowerShell approach
Get-ADUser -Filter {(Enabled -eq $false) -and (adminCount -eq 1)} -Properties Description | Select-Object Name, Description

# Step 4: Net command verification (if specific user found)
net user [DISABLED_ADMIN_USER] /domain

# Step 5: WMI approach
wmic useraccount where "disabled=true" get name,description
```

**Expected Output:**
```cmd
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1))" -attr sAMAccountName description

  sAMAccountName description
  backup_svc     HTB{...}
```

**Expected Answer:** `HTB{...}`

---

## 🔧 Advanced Native Techniques

### 🔍 **PowerShell One-Liners**
```powershell
# Domain user enumeration with details
Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName, Enabled, LastLogonDate, AdminCount | Format-Table

# Group membership analysis
Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {Get-ADUser $_ -Properties LastLogonDate | Select-Object Name, LastLogonDate}

# Computer enumeration
Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | Sort-Object LastLogonDate

# Service Principal Name discovery
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | Select-Object Name, ServicePrincipalName

# Find user accounts with interesting flags
Get-ADUser -Filter * -Properties UserAccountControl | Where-Object {$_.UserAccountControl -band 0x10000} | Select-Object Name, UserAccountControl
```

### 🌐 **WMI Remote Enumeration**
```cmd
# Remote system information
wmic /node:"TARGET_HOST" /user:"DOMAIN\USER" /password:"PASSWORD" computersystem get Name,Domain

# Remote process enumeration
wmic /node:"TARGET_HOST" process list brief

# Remote service enumeration
wmic /node:"TARGET_HOST" service get name,state,startmode

# Remote group enumeration
wmic /node:"TARGET_HOST" group get name,description
```

### 🔍 **Registry-Based Discovery**
```cmd
# Domain information from registry
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" /s

# Cached logons
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount

# Auto-logon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword

# Installed software
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s | findstr "DisplayName"
```

---

## ⚡ Quick Reference Commands

### 🔧 **Essential Command Matrix**

| **Category** | **Command** | **Purpose** |
|--------------|-------------|-------------|
| **System Info** | `systeminfo` | Complete system overview |
| **Network** | `ipconfig /all` | Network configuration |
| **Network** | `arp -a` | Known hosts discovery |
| **Network** | `route print` | Network topology |
| **Security** | `netsh advfirewall show allprofiles` | Firewall status |
| **Security** | `Get-MpComputerStatus` | Defender configuration |
| **Sessions** | `qwinsta` | Active sessions |
| **Domain** | `net group /domain` | Domain groups |
| **Domain** | `net user /domain` | Domain users |
| **Domain** | `dsquery user` | LDAP user query |
| **Domain** | `dsquery computer` | LDAP computer query |
| **WMI** | `wmic ntdomain list /format:list` | Domain information |

### 🚀 **Rapid Enumeration Script**
```cmd
@echo off
echo === Basic Host Information ===
hostname
echo %USERDOMAIN%
echo %LOGONSERVER%

echo === Network Configuration ===
ipconfig /all | findstr /i "IP Address\|Subnet\|Gateway\|DNS"

echo === Domain Groups ===
net group /domain

echo === Local Administrators ===
net localgroup administrators

echo === Security Configuration ===
sc query windefend

echo === Active Sessions ===
qwinsta

echo === ARP Table ===
arp -a

echo === Domain Controllers ===
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName
```

---

## 🔑 Key Takeaways

### ✅ **Native Tool Advantages**
- **No File Transfer**: Built-in tools eliminate upload requirements
- **Reduced Detection**: Lower probability of triggering security controls
- **Legitimate Activity**: Commands blend with normal administrative tasks
- **Universal Availability**: Tools exist on all Windows domain systems

### 🎯 **Strategic Enumeration Priorities**
1. **System Context**: Understand host role and privilege level
2. **Security Posture**: Assess defensive capabilities and monitoring
3. **Network Topology**: Map accessible systems and network segments
4. **Domain Structure**: Identify users, groups, and trust relationships
5. **Attack Vectors**: Locate privilege escalation and lateral movement opportunities

### ⚠️ **Operational Security Considerations**
- **PowerShell Logging**: Script Block Logging captures command history
- **Event Generation**: Net commands and WMI queries create Event Log entries
- **Behavioral Analysis**: Unusual command patterns may trigger EDR alerts
- **Version Downgrade**: PowerShell v2.0 bypasses modern logging capabilities
- **Alternative Syntax**: Use `net1` instead of `net` to avoid string detection

### 🚀 **Escalation Pathways**
After native enumeration, typical next steps include:
- **Credential Harvesting**: Memory dumps, registry extraction, file hunting
- **Privilege Escalation**: Service misconfigurations, scheduled tasks, permissions
- **Lateral Movement**: PSRemoting, WMI execution, service account abuse
- **Persistence**: Registry modifications, service creation, scheduled tasks

---

*Living off the land demonstrates that comprehensive Active Directory enumeration is possible using only native Windows tools - proving that security through obscurity is insufficient and that proper access controls and monitoring are essential for domain protection.* 