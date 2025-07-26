# Credentialed Enumeration - from Windows

## 📋 Overview

After gaining valid domain credentials, enumeration from a Windows attack host provides access to powerful native tools and specialized AD enumeration frameworks. Windows-based enumeration offers deeper integration with AD infrastructure, access to PowerShell modules, and the ability to leverage tools that can provide comprehensive domain intelligence and attack path visualization.

## 🎯 Strategic Context

### 🎪 **Windows vs Linux Enumeration Advantages**
- **Native Integration**: Direct access to AD PowerShell modules and cmdlets
- **Stealth Operations**: Blend in with legitimate administrative activities
- **Comprehensive Data**: More detailed attribute and permission enumeration
- **Visual Analysis**: Advanced attack path visualization with BloodHound GUI

### 🛠️ **Key Tools & Techniques**
- **ActiveDirectory PowerShell Module**: Native Microsoft AD administration cmdlets
- **PowerView**: Advanced AD reconnaissance and analysis framework
- **SharpView**: .NET port of PowerView for modern environments
- **Snaffler**: Automated sensitive file discovery across domain shares
- **BloodHound**: Attack path visualization and relationship analysis

---

## 🔧 ActiveDirectory PowerShell Module

### 📝 **Overview**
The ActiveDirectory PowerShell module contains 147+ cmdlets for comprehensive AD administration and enumeration. When available on domain-joined hosts (especially admin workstations), it provides native, stealth-friendly enumeration capabilities.

### 🔍 **Module Discovery and Loading**
```powershell
# Check available modules
Get-Module

# Import ActiveDirectory module
Import-Module ActiveDirectory

# Verify module is loaded
Get-Module | Where-Object {$_.Name -eq "ActiveDirectory"}
```

**Example Discovery Output:**
```powershell
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption...}

PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption...}
```

### 🏰 **Domain Information Gathering**
```powershell
# Get comprehensive domain information
Get-ADDomain
```

**Key Information Retrieved:**
```powershell
PS C:\htb> Get-ADDomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {LOGISTICS.INLANEFREIGHT.LOCAL}
ComputersContainer                 : CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
DeletedObjectsContainer            : CN=Deleted Objects,DC=INLANEFREIGHT,DC=LOCAL
DistinguishedName                  : DC=INLANEFREIGHT,DC=LOCAL
DNSRoot                            : INLANEFREIGHT.LOCAL
DomainControllersContainer         : OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3842939050-3880317879-2865463114
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=INLANEFREIGHT,DC=LOCAL
Forest                             : INLANEFREIGHT.LOCAL
InfrastructureMaster               : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
PDCEmulator                        : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
RIDMaster                          : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
SubordinateReferences              : {DC=LOGISTICS,DC=INLANEFREIGHT,DC=LOCAL, 
                                     DC=ForestDnsZones,DC=INLANEFREIGHT,DC=LOCAL,
                                     DC=DomainDnsZones,DC=INLANEFREIGHT,DC=LOCAL}
```

### 👥 **User Enumeration**
```powershell
# Find users with Service Principal Names (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Get specific user details
Get-ADUser -Identity username -Properties *

# Find users with specific attributes
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount
```

**Example Kerberoastable User Output:**
```powershell
DistinguishedName    : CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Sharepoint
Name                 : adfs
ObjectClass          : user
ObjectGUID           : 49b53bea-4bc4-4a68-b694-b806d9809e95
SamAccountName       : adfs
ServicePrincipalName : {adfsconnect/azure01.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5244
Surname              : Admin
UserPrincipalName    :

DistinguishedName    : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
Enabled              : True
GivenName            : Jessica
Name                 : BACKUPAGENT
ObjectClass          : user
ObjectGUID           : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName       : backupagent
ServicePrincipalName : {backupjob/veam001.inlanefreight.local}
SID                  : S-1-5-21-3842939050-3880317879-2865463114-5220
```

### 🔗 **Trust Relationship Enumeration**
```powershell
# Enumerate all domain trusts
Get-ADTrust -Filter *
```

**Example Trust Output:**
```powershell
Direction               : BiDirectional
DisallowTransivity      : False
DistinguishedName       : CN=LOGISTICS.INLANEFREIGHT.LOCAL,CN=System,DC=INLANEFREIGHT,DC=LOCAL
ForestTransitive        : False
IntraForest             : True
IsTreeParent            : False
IsTreeRoot              : False
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
ObjectClass             : trustedDomain
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustAttributes         : 32
TrustType               : Uplevel

Direction               : BiDirectional
ForestTransitive        : True
IntraForest             : False
Name                    : FREIGHTLOGISTICS.LOCAL
TrustAttributes         : 8
TrustType               : Uplevel
```

### 🏷️ **Group Management**
```powershell
# Enumerate all groups
Get-ADGroup -Filter * | Select-Object name

# Get detailed group information
Get-ADGroup -Identity "Backup Operators"

# Get group membership
Get-ADGroupMember -Identity "Backup Operators"
```

**Example Group Analysis:**
```powershell
PS C:\htb> Get-ADGroup -Identity "Backup Operators"

DistinguishedName : CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Backup Operators
ObjectClass       : group
ObjectGUID        : 6276d85d-9c39-4b7c-8449-cad37e8abc38
SamAccountName    : Backup Operators
SID               : S-1-5-32-551

PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```

---

## ⚡ PowerView

### 📝 **Overview**
PowerView is an advanced PowerShell framework for AD reconnaissance and situational awareness. It provides comprehensive enumeration capabilities, relationship analysis, and attack path identification through extensive cmdlet collections.

### 📊 **Core PowerView Functions**

| **Category** | **Key Functions** | **Purpose** |
|--------------|-------------------|-------------|
| **Domain/LDAP** | Get-Domain, Get-DomainController, Get-DomainUser | Core domain enumeration |
| **Groups** | Get-DomainGroup, Get-DomainGroupMember | Group and membership analysis |
| **Computers** | Get-DomainComputer, Get-NetShare, Get-NetSession | Host and share enumeration |
| **GPO** | Get-DomainGPO, Get-DomainPolicy | Group Policy analysis |
| **ACL** | Find-InterestingDomainAcl | Permission and ACL enumeration |
| **Trust** | Get-DomainTrust, Get-ForestTrust | Trust relationship mapping |
| **Meta** | Find-DomainUserLocation, Find-LocalAdminAccess | Advanced discovery functions |

### 👤 **User Enumeration and Analysis**
```powershell
# Get detailed user information
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

**Example Detailed User Output:**
```powershell
name                 : Matthew Morgan
samaccountname       : mmorgan
description          :
memberof             : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                       CN=Shared Calendar Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                       CN=Printer Access,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL}
whencreated          : 10/27/2021 5:37:06 PM
pwdlastset           : 11/18/2021 10:02:57 AM
lastlogontimestamp   : 2/27/2022 6:34:25 PM
accountexpires       : NEVER
admincount           : 1
userprincipalname    : mmorgan@inlanefreight.local
serviceprincipalname :
useraccountcontrol   : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

### 🔄 **Recursive Group Membership Analysis**
```powershell
# Analyze nested group memberships
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

**Example Recursive Output:**
```powershell
GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : svc_qualys
MemberDistinguishedName : CN=svc_qualys,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-5613

GroupDomain             : INLANEFREIGHT.LOCAL
GroupName               : Secadmins
GroupDistinguishedName  : CN=Secadmins,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberDomain            : INLANEFREIGHT.LOCAL
MemberName              : spong1990
MemberDistinguishedName : CN=Maggie Jablonski,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
MemberObjectClass       : user
MemberSID               : S-1-5-21-3842939050-3880317879-2865463114-1965
```

### 🔗 **Trust Relationship Mapping**
```powershell
# Map all domain trusts
Get-DomainTrustMapping
```

**Example Trust Mapping:**
```powershell
SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 2/26/2022 11:55:55 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 2/27/2022 12:02:39 AM
```

### 🔐 **Administrative Access Testing**
```powershell
# Test local admin access on specific hosts
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# Find hosts where current user has local admin
Find-LocalAdminAccess
```

**Example Admin Access Output:**
```powershell
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True
```

### 🎫 **Kerberoastable Account Discovery**
```powershell
# Find users with SPNs set (Kerberoastable)
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

**Example SPN Output:**
```powershell
serviceprincipalname                          samaccountname
--------------------                          --------------
adfsconnect/azure01.inlanefreight.local       adfs
backupjob/veam001.inlanefreight.local         backupagent
d0wngrade/kerberoast.inlanefreight.local      d0wngrade
kadmin/changepw                               krbtgt
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 sqldev
MSSQLSvc/SPSJDB.inlanefreight.local:1433      sqlprod
MSSQLSvc/SQL-CL01-01inlanefreight.local:49351 sqlqa
sts/inlanefreight.local                       solarwindsmonitor
testspn/kerberoast.inlanefreight.local        testspn
testspn2/kerberoast.inlanefreight.local       testspn2
```

---

## 🔨 SharpView

### 📝 **Overview**
SharpView is a .NET port of PowerView, providing similar functionality while avoiding PowerShell detection mechanisms. It's particularly useful in environments with PowerShell restrictions or advanced monitoring.

### 🔍 **Basic Usage**
```cmd
# Get help for specific functions
.\SharpView.exe Get-DomainUser -Help

# Enumerate specific user
.\SharpView.exe Get-DomainUser -Identity forend
```

**Example SharpView Help Output:**
```cmd
PS C:\htb> .\SharpView.exe Get-DomainUser -Help

Get_DomainUser -Identity <String[]> -DistinguishedName <String[]> -SamAccountName <String[]> -Name <String[]> -MemberDistinguishedName <String[]> -MemberName <String[]> -SPN <Boolean> -AdminCount <Boolean> -AllowDelegation <Boolean> -DisallowDelegation <Boolean> -TrustedToAuth <Boolean> -PreauthNotRequired <Boolean> -KerberosPreauthNotRequired <Boolean> -NoPreauth <Boolean> -Domain <String> -LDAPFilter <String> -Filter <String> -Properties <String[]> -SearchBase <String> -ADSPath <String> -Server <String> -DomainController <String> -SearchScope <SearchScope> -ResultPageSize <Int32> -ServerTimeLimit <Nullable`1> -SecurityMasks <Nullable`1> -Tombstone <Boolean> -FindOne <Boolean> -ReturnOne <Boolean> -Credential <NetworkCredential> -Raw <Boolean> -UACFilter <UACEnum>
```

**Example User Enumeration:**
```cmd
PS C:\htb> .\SharpView.exe Get-DomainUser -Identity forend

[Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
[Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=forend)))
objectsid                      : {S-1-5-21-3842939050-3880317879-2865463114-5614}
samaccounttype                 : USER_OBJECT
objectguid                     : 53264142-082a-4cb8-8714-8158b4974f3b
useraccountcontrol             : NORMAL_ACCOUNT
accountexpires                 : 12/31/1600 4:00:00 PM
lastlogon                      : 4/18/2022 1:01:21 PM
lastlogontimestamp             : 4/9/2022 1:33:21 PM
pwdlastset                     : 2/28/2022 12:03:45 PM
name                           : forend
distinguishedname              : CN=forend,OU=IT Admins,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
samaccountname                 : forend
memberof                       : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, 
                                CN=Shared Calendar Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL}
```

---

## 📁 Snaffler

### 📝 **Overview**
Snaffler automates the discovery of sensitive files across domain shares by enumerating hosts, shares, and readable directories, then hunting for files that could enhance our position in the assessment.

### 🚀 **Basic Execution**
```cmd
# Basic Snaffler execution with output to console and log
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

**Command Breakdown:**
- `-s`: Print results to console
- `-d`: Specify domain to search
- `-o`: Write results to log file
- `-v data`: Verbosity level (data = only display results)

### 🔍 **Example Snaffler Output**
```cmd
PS C:\htb> .\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data

 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler

2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\ADMIN$)
2022-03-31 12:16:54 -07:00 [Share] {Black}(\\ACADEMY-EA-MS01.INLANEFREIGHT.LOCAL\C$)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-MX01.INLANEFREIGHT.LOCAL\address)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\User Shares)
2022-03-31 12:16:54 -07:00 [Share] {Green}(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\ZZZ_archive)
2022-03-31 12:17:18 -07:00 [Share] {Green}(\\ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL\CertEnroll)
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.kdb$|289B|3/31/2022 12:09:22 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\GroupBackup.kdb) .kdb
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|299B|3/31/2022 12:05:33 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ShowReset.key) .key
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|298B|3/31/2022 12:05:10 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ProtectStep.key) .key
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.ppk$|275B|3/31/2022 12:04:40 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\StopTrace.ppk) .ppk
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.sqldump$|312B|3/31/2022 12:05:30 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Development\DenyRedo.sqldump) .sqldump
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.keychain$|295B|3/31/2022 12:08:42 PM>(\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\SetStep.keychain) .keychain
```

### 🎯 **Sensitive File Categories**

| **Color Code** | **Risk Level** | **File Types** | **Examples** |
|----------------|----------------|----------------|--------------|
| **Red** | High | Keys, configs, dumps | .key, .config, .sqldump, .mdf |
| **Black** | Medium | Encrypted stores | .kdb, .kwallet, .ppk, .psafe3 |
| **Green** | Low | Shares discovered | Available network shares |

---

## 🩸 BloodHound

### 📝 **Overview**
BloodHound provides visual analysis of AD attack paths by mapping relationships between users, computers, groups, and permissions. The SharpHound collector gathers comprehensive data for upload to the BloodHound GUI.

### 🔧 **SharpHound Data Collection**
```cmd
# Basic collection with all methods
.\SharpHound.exe -c All --zipfilename ILFREIGHT

# Stealth collection (DCOnly when possible)
.\SharpHound.exe --stealth --zipfilename STEALTH_COLLECT

# Specific collection methods
.\SharpHound.exe -c Session,LoggedOn,Trusts,ACL --zipfilename TARGETED
```

**Example SharpHound Execution:**
```cmd
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT

2022-04-18T13:58:22.1163680-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:22.1163680-07:00|INFORMATION|Initializing SharpHound at 1:58 PM on 4/18/2022
2022-04-18T13:58:22.6788709-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-04-18T13:58:23.0851206-07:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2022-04-18T13:58:53.9132950-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 67 MB RAM
2022-04-18T13:59:15.7882419-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-04-18T13:59:45.8663528-07:00|INFORMATION|Status: 3809 objects finished (+16 46.45122)/s -- Using 110 MB RAM
2022-04-18T13:59:45.8663528-07:00|INFORMATION|Enumeration finished in 00:01:22.7919186
2022-04-18T13:59:46.3663660-07:00|INFORMATION|SharpHound Enumeration Completed at 1:59 PM on 4/18/2022! Happy Graphing
```

### 📊 **BloodHound GUI Analysis**
```bash
# Start BloodHound GUI (Windows)
bloodhound

# Default credentials if prompted:
# Username: neo4j
# Password: HTB_@cademy_stdnt!
```

### 🔍 **Key BloodHound Queries**

#### **🎯 High-Impact Pre-built Queries**
```cypher
-- Find Computers with Unsupported Operating Systems
MATCH (c:Computer) WHERE c.operatingsystem =~ "(?i).*(2000|2003|2008|xp|vista|7|me).*" RETURN c

-- Find Computers where Domain Users are Local Admin
MATCH p=(m:Group)-[:AdminTo]->(c:Computer) WHERE m.name =~ "DOMAIN USERS@.*" RETURN p

-- Find Shortest Paths to Domain Admins
MATCH (m:User) WHERE NOT m.name = "ANONYMOUS LOGON" AND NOT m.name ENDS WITH "$" 
MATCH (n:Group) WHERE n.name = "DOMAIN ADMINS@INLANEFREIGHT.LOCAL" 
MATCH p = shortestPath((m)-[*1..]->(n)) RETURN p

-- Find All Kerberoastable Users
MATCH (u:User) WHERE u.hasspn=true RETURN u
```

#### **💎 Advanced Custom Queries**
```cypher
-- Find users with DCSync rights
MATCH p=()-[:DCSync|AllExtendedRights|GenericAll]->(:Domain) RETURN p

-- Find computers with LAPS enabled
MATCH (c:Computer) WHERE c.haslaps = true RETURN c

-- Find sessions for high-value targets
MATCH p=(c:Computer)-[:HasSession]->(u:User) WHERE u.highvalue = true RETURN p

-- Find constrained delegation opportunities
MATCH p=(u:User)-[:AllowedToDelegate]->(c:Computer) RETURN p
```

---

## 🎯 HTB Academy Lab Solutions

### 📝 **Lab Questions & Solutions**

#### 🔍 **Question 1: "Using Bloodhound, determine how many Kerberoastable accounts exist within the INLANEFREIGHT domain. (Submit the number as the answer)"**

**Solution Process:**
```cypher
# Method 1: BloodHound Raw Query
MATCH (u:User) WHERE u.hasspn=true RETURN count(u)

# Method 2: Pre-built Query Analysis
# Go to Analysis tab -> "Find All Kerberoastable Users"
# Count the returned nodes

# Method 3: PowerView verification
Get-DomainUser -SPN | Measure-Object | Select-Object Count

# Method 4: ActiveDirectory module verification
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} | Measure-Object | Select-Object Count
```

**Expected Answer Format:** `[number]` (e.g., `13`)

#### ⚡ **Question 2: "What PowerView function allows us to test if a user has administrative access to a local or remote host?"**

**Solution:**
```powershell
# The function is: Test-AdminAccess
Test-AdminAccess -ComputerName HOSTNAME

# Alternative verification:
Get-Help Test-AdminAccess
```

**Expected Answer:** `Test-AdminAccess`

#### 📁 **Question 3: "Run Snaffler and hunt for a readable web config file. What is the name of the user in the connection string within the file?"**

**Solution Process:**
```cmd
# Step 1: Run Snaffler to find web.config files
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data | findstr -i "web.config"

# Step 2: Look for web.config files in the output
# Example output might show:
# [File] {Red}<KeepExtExactRed|R|^\.config$|1024B|...>(\\HOST\Share\path\web.config) .config

# Step 3: Access the file and examine connection strings
type "\\HOSTNAME\Share\path\web.config"

# Step 4: Look for connection string patterns like:
# <connectionStrings>
#   <add name="DefaultConnection" connectionString="Server=...;User ID=USERNAME;Password=..." />
# </connectionStrings>

# Step 5: Extract the username from the connection string
```

**Expected Answer Format:** `[username]` (e.g., `sqlservice`)

#### 🔐 **Question 4: "What is the password for the database user?"**

**Solution Process:**
```cmd
# Continue from Question 3 - examine the same web.config file
# Look for the password in the connection string:
# connectionString="Server=server;User ID=username;Password=PASSWORD_HERE;"

# Extract the password value from the connection string
```

**Expected Answer Format:** `[password]` (e.g., `MyV3ryStr0ngP@ssw0rd!`)

---

## 🔧 Advanced Enumeration Techniques

### 🎯 **Comprehensive User Analysis**
```powershell
# Find high-value user accounts
Get-DomainUser -Properties admincount,serviceprincipalname,memberof | Where-Object {$_.admincount -eq 1 -or $_.serviceprincipalname -ne $null}

# Analyze password policies and account settings
Get-DomainUser -Properties pwdlastset,lastlogontimestamp,useraccountcontrol | Where-Object {$_.useraccountcontrol -match "DONT_EXPIRE_PASSWORD"}

# Find users with constrained delegation
Get-DomainUser -TrustedToAuth -Properties trustedtodelegated,serviceprincipalname
```

### 🖥️ **Computer and Service Analysis**
```powershell
# Find computers with specific services
Get-DomainComputer -Properties operatingsystem,serviceprincipalname | Where-Object {$_.serviceprincipalname -match "MSSQL|HTTP|CIFS"}

# Identify file servers and shares
Get-DomainFileServer
Get-DomainDFSShare

# Find computers with sessions from high-value users
Find-DomainUserLocation -UserGroupIdentity "Domain Admins"
```

### 🔐 **Permission and ACL Analysis**
```powershell
# Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Find modifiable GPOs
Get-DomainGPO | Where-Object {$_.gpcfilesyspath -like "*SYSVOL*"}

# Analyze dangerous privileges
Get-DomainUser -AdminCount | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}
```

---

## ⚡ Quick Reference Commands

### 🔧 **Essential One-Liners**
```powershell
# Quick Kerberoastable account count
(Get-ADUser -Filter {ServicePrincipalName -ne "$null"}).Count

# Find Domain Admins with PowerView
Get-DomainGroupMember -Identity "Domain Admins" | Select-Object MemberName

# Quick admin access test
Test-AdminAccess -ComputerName (Get-Content hosts.txt)

# Fast SPN enumeration
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname

# Trust relationship summary
Get-DomainTrust | Select-Object SourceName,TargetName,TrustDirection,TrustType
```

### 🔍 **Data Analysis and Correlation**
```powershell
# Cross-reference users and groups
$users = Get-DomainUser -Properties memberof
$groups = Get-DomainGroup
$users | ForEach-Object { 
    $_.memberof | ForEach-Object { 
        if($_ -match "Domain Admins|Enterprise Admins|Backup Operators") { 
            Write-Host "High-value group membership: $($_.samaccountname) -> $_" 
        } 
    } 
}

# Correlate sessions with admin rights
$admins = Get-DomainGroupMember -Identity "Domain Admins"
$sessions = Get-NetSession
$admins | ForEach-Object { 
    $sessions | Where-Object {$_.UserName -eq $_.MemberName} 
}
```

---

## 🔑 Key Takeaways

### ✅ **Windows Enumeration Advantages**
- **Native Tool Integration**: Access to ActiveDirectory PowerShell module and built-in cmdlets
- **Stealth Operations**: Blend in with legitimate administrative activities
- **Comprehensive Analysis**: Deep attribute and relationship enumeration
- **Visual Intelligence**: BloodHound provides unmatched attack path visualization

### 🎯 **Strategic Priorities**
1. **Kerberoastable Accounts**: Identify service accounts with SPNs for credential extraction
2. **Administrative Rights**: Map local admin access across domain systems
3. **Sensitive File Discovery**: Use Snaffler to find configuration files and credentials
4. **Attack Path Analysis**: Leverage BloodHound for relationship mapping and privilege escalation paths
5. **Trust Relationships**: Understand cross-domain attack opportunities

### ⚠️ **Operational Considerations**
- **Tool Placement**: Document all tools transferred to domain systems
- **Artifact Cleanup**: Remove tools and logs at engagement conclusion
- **Stealth vs Speed**: Balance comprehensive enumeration with detection avoidance
- **Data Correlation**: Cross-reference findings from multiple tools for accuracy

### 🚀 **Next Steps After Enumeration**
- **Kerberoasting**: Extract and crack service account credentials
- **ASREPRoasting**: Target accounts without Kerberos pre-authentication
- **Privilege Escalation**: Exploit identified admin rights and permissions
- **Lateral Movement**: Use discovered credentials and access rights for network traversal

---

*Windows-based credentialed enumeration provides the deepest insight into Active Directory environments - leveraging native tools and comprehensive frameworks to map the entire domain landscape and identify critical attack paths.* 