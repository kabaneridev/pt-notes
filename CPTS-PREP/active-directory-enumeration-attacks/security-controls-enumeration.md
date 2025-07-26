# Enumerating Security Controls

## 📋 Overview

After gaining initial access to an Active Directory environment, understanding the defensive security controls in place is crucial for planning effective enumeration and attack strategies. Security controls can significantly impact tool selection, exploitation techniques, and post-exploitation activities. Organizations implement varying levels of protection, and these controls may not be applied uniformly across all systems.

## 🎯 Why Enumerate Security Controls?

### 🔍 **Strategic Planning**
- **Tool Selection**: Choose appropriate enumeration tools based on security restrictions
- **Attack Path Planning**: Identify potential bypasses and alternative techniques
- **Risk Assessment**: Understand detection capabilities and defensive posture
- **Stealth Operations**: Avoid triggering security controls during enumeration

### ⚠️ **Common Variations**
- **Inconsistent Policies**: Different protection levels across machine types
- **Legacy Systems**: Older systems may have fewer protections
- **Department Differences**: Varying security standards between business units
- **Administrative Oversight**: Gaps in security policy implementation

---

## 🛡️ Windows Defender Enumeration

### 📝 **Overview**
Windows Defender (Microsoft Defender) has significantly improved and by default blocks many penetration testing tools like PowerView. Understanding its current status helps inform tool selection and evasion strategies.

### 🔍 **Checking Defender Status**
```powershell
# Primary Defender status check
Get-MpComputerStatus

# Key parameters to focus on:
# - RealTimeProtectionEnabled: True/False
# - AMServiceEnabled: Antimalware service status  
# - BehaviorMonitorEnabled: Behavioral detection
# - OnAccessProtectionEnabled: File access monitoring
```

### 📊 **Example Output Analysis**
```powershell
PS C:\htb> Get-MpComputerStatus

AMEngineVersion                 : 1.1.17400.5
AMProductVersion                : 4.10.14393.0
AMServiceEnabled                : True
AMServiceVersion                : 4.10.14393.0
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 9/2/2020 11:31:50 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 1
AntivirusSignatureLastUpdated   : 9/2/2020 11:31:51 AM
AntivirusSignatureVersion       : 1.323.392.0
BehaviorMonitorEnabled          : False
ComputerID                      : 07D23A51-F83F-4651-B9ED-110FF2B83A9C
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : False
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
NISSignatureAge                 : 4294967295
NISSignatureLastUpdated         :
NISSignatureVersion             : 0.0.0.0
OnAccessProtectionEnabled       : False
QuickScanAge                    : 0
QuickScanEndTime                : 9/3/2020 12:50:45 AM
QuickScanStartTime              : 9/3/2020 12:49:49 AM
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
PSComputerName                  :
```

### 🎯 **Critical Parameters Interpretation**

| **Parameter** | **Value** | **Impact** | **Evasion Strategy** |
|---------------|-----------|------------|---------------------|
| **RealTimeProtectionEnabled** | True | High - Active scanning | Use obfuscated scripts, living-off-land techniques |
| **BehaviorMonitorEnabled** | False | Medium - Behavioral analysis disabled | Can use more aggressive techniques |
| **OnAccessProtectionEnabled** | False | Low - File access not monitored | Direct file manipulation possible |
| **AMServiceEnabled** | True | High - Core protection active | Require AV evasion techniques |

### 🔧 **Additional Defender Checks**
```powershell
# Check Defender exclusions (if accessible)
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess

# Check real-time protection status
(Get-MpComputerStatus).RealTimeProtectionEnabled

# Check if cloud protection is enabled
(Get-MpPreference).MAPSReporting

# Check submission settings
(Get-MpPreference).SubmitSamplesConsent
```

---

## 🔒 AppLocker Enumeration

### 📝 **Overview**
AppLocker is Microsoft's application whitelisting solution that controls which applications, scripts, and files users can execute. It provides granular control over executables, scripts, Windows Installer files, DLLs, packaged apps, and packed app installers.

### 🔍 **Enumerating AppLocker Policies**
```powershell
# Get effective AppLocker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Check specific rule types
Get-AppLockerPolicy -Effective -xml

# Alternative method using registry
Get-ChildItem "HKLM:SOFTWARE\Policies\Microsoft\Windows\SrpV2" -Recurse
```

### 📊 **Example AppLocker Policy Analysis**
```powershell
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# BLOCKED: PowerShell executable
PathConditions      : {%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 3d57af4a-6cf8-4e5b-acfc-c2c2956061fa
Name                : Block PowerShell
Description         : Blocks Domain Users from using PowerShell on workstations
UserOrGroupSid      : S-1-5-21-2974783224-3764228556-2640795941-513
Action              : Deny

# ALLOWED: Program Files
PathConditions      : {%PROGRAMFILES%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : 921cc481-6e17-4653-8f75-050b80acca20
Name                : (Default Rule) All files located in the Program Files folder
Description         : Allows members of the Everyone group to run applications that are located in the Program Files folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

# ALLOWED: Windows folder
PathConditions      : {%WINDIR%\*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : a61c8b2c-a319-4cd0-9690-d2177cad7b51
Name                : (Default Rule) All files located in the Windows folder
Description         : Allows members of the Everyone group to run applications that are located in the Windows folder.
UserOrGroupSid      : S-1-1-0
Action              : Allow

# ALLOWED: Administrators (all files)
PathConditions      : {*}
PathExceptions      : {}
PublisherExceptions : {}
HashExceptions      : {}
Id                  : fd686d83-a829-4351-8ff4-27c7de5755d2
Name                : (Default Rule) All files
Description         : Allows members of the local Administrators group to run all applications.
UserOrGroupSid      : S-1-5-32-544
Action              : Allow
```

### 🎯 **AppLocker Bypass Strategies**

#### 🚪 **Common PowerShell Bypass Locations**
```powershell
# If %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe is blocked:

# Try 32-bit PowerShell
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

# Try PowerShell ISE
%SystemRoot%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\PowerShell_ISE.exe

# Try other PowerShell variants
powershell_ise.exe
pwsh.exe  # PowerShell Core
```

#### 📂 **Writable Directory Identification**
```powershell
# Common writable directories that might not be blocked:
C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\Tasks_Migrated\
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System\
C:\Windows\Tasks\
```

#### 🔧 **AppLocker Analysis Script**
```powershell
# Comprehensive AppLocker enumeration script
function Analyze-AppLocker {
    Write-Host "[*] Analyzing AppLocker Configuration" -ForegroundColor Cyan
    
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $rules = $policy.RuleCollections
        
        Write-Host "[+] AppLocker is configured" -ForegroundColor Green
        
        foreach ($collection in $rules) {
            Write-Host "`n[*] Rule Collection: $($collection.Name)" -ForegroundColor Yellow
            
            foreach ($rule in $collection) {
                Write-Host "  Rule: $($rule.Name)" -ForegroundColor White
                Write-Host "  Action: $($rule.Action)" -ForegroundColor $(if($rule.Action -eq "Allow"){"Green"}else{"Red"})
                Write-Host "  Paths: $($rule.PathConditions.Path -join ', ')" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "[-] AppLocker not configured or accessible" -ForegroundColor Red
    }
}

Analyze-AppLocker
```

---

## 🔐 PowerShell Constrained Language Mode

### 📝 **Overview**
PowerShell Constrained Language Mode restricts many PowerShell features needed for effective post-exploitation, including COM objects, approved .NET types only, XAML-based workflows, PowerShell classes, and advanced scripting capabilities.

### 🔍 **Checking Language Mode**
```powershell
# Quick language mode check
$ExecutionContext.SessionState.LanguageMode

# Possible values:
# - FullLanguage: No restrictions
# - ConstrainedLanguage: Limited functionality
# - RestrictedLanguage: Severely limited
# - NoLanguage: PowerShell disabled
```

### 📊 **Language Mode Impact Analysis**

| **Mode** | **Capabilities** | **Restrictions** | **Bypass Difficulty** |
|----------|------------------|------------------|----------------------|
| **FullLanguage** | Complete PowerShell functionality | None | N/A |
| **ConstrainedLanguage** | Basic cmdlets, limited .NET | No COM, limited types, no Add-Type | Medium |
| **RestrictedLanguage** | Very basic functionality | Most features blocked | High |
| **NoLanguage** | PowerShell completely disabled | Everything blocked | Very High |

### 🎯 **Constrained Language Mode Detection**
```powershell
# Comprehensive language mode analysis
function Test-LanguageRestrictions {
    $mode = $ExecutionContext.SessionState.LanguageMode
    Write-Host "[*] Current Language Mode: $mode" -ForegroundColor Cyan
    
    switch ($mode) {
        "FullLanguage" {
            Write-Host "[+] Full PowerShell access available" -ForegroundColor Green
        }
        "ConstrainedLanguage" {
            Write-Host "[!] Constrained Language Mode detected" -ForegroundColor Yellow
            Write-Host "    - COM objects blocked" -ForegroundColor Red
            Write-Host "    - Limited .NET types" -ForegroundColor Red
            Write-Host "    - Add-Type blocked" -ForegroundColor Red
        }
        "RestrictedLanguage" {
            Write-Host "[-] Severely restricted PowerShell" -ForegroundColor Red
        }
        "NoLanguage" {
            Write-Host "[-] PowerShell functionality disabled" -ForegroundColor Red
        }
    }
}

Test-LanguageRestrictions
```

### 🔧 **Testing Specific Restrictions**
```powershell
# Test COM object access
try {
    $wmi = New-Object -ComObject "WbemScripting.SWbemLocator"
    Write-Host "[+] COM objects accessible" -ForegroundColor Green
}
catch {
    Write-Host "[-] COM objects blocked" -ForegroundColor Red
}

# Test Add-Type capability
try {
    Add-Type -TypeDefinition "public class Test { }"
    Write-Host "[+] Add-Type accessible" -ForegroundColor Green
}
catch {
    Write-Host "[-] Add-Type blocked" -ForegroundColor Red
}

# Test .NET reflection
try {
    [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")
    Write-Host "[+] .NET reflection accessible" -ForegroundColor Green
}
catch {
    Write-Host "[-] .NET reflection blocked" -ForegroundColor Red
}
```

---

## 🔑 LAPS (Local Administrator Password Solution)

### 📝 **Overview**
Microsoft LAPS randomizes and rotates local administrator passwords on Windows hosts to prevent lateral movement using shared local admin credentials. Understanding LAPS deployment helps identify potential privilege escalation paths and lateral movement opportunities.

### 🛠️ **LAPS Enumeration Tools**
```powershell
# Import LAPSToolkit (if available)
Import-Module .\LAPSToolkit.ps1

# Alternative: Manual LDAP queries
# LAPS stores passwords in ms-MCS-AdmPwd attribute
```

### 🔍 **Finding LAPS Delegated Groups**
```powershell
# Enumerate groups with LAPS password read permissions
Find-LAPSDelegatedGroups

# Example output interpretation:
OrgUnit                                             Delegated Groups
-------                                             ----------------
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\Domain Admins
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\LAPS Admins
OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL           INLANEFREIGHT\Domain Admins
OU=Workstations,DC=INLANEFREIGHT,DC=LOCAL           INLANEFREIGHT\LAPS Admins
```

### 🎯 **LAPS Extended Rights Enumeration**
```powershell
# Find users/groups with extended rights (including LAPS password read)
Find-AdmPwdExtendedRights

# Example output:
ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\Domain Admins Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\LAPS Admins   Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\Domain Admins Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\LAPS Admins   Delegated
```

### 💎 **Retrieving LAPS Passwords**
```powershell
# Attempt to read LAPS passwords (requires appropriate permissions)
Get-LAPSComputers

# Example output with sensitive data:
ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

### 🔧 **Manual LAPS Enumeration (Without LAPSToolkit)**
```powershell
# Check if LAPS is installed on current machine
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}" -ErrorAction SilentlyContinue

# Query LDAP for LAPS-enabled computers
$Searcher = New-Object System.DirectoryServices.DirectorySearcher
$Searcher.Filter = "(&(objectCategory=computer)(ms-MCS-AdmPwd=*))"
$Searcher.PropertiesToLoad.Add("ms-MCS-AdmPwd") | Out-Null
$Searcher.PropertiesToLoad.Add("ms-MCS-AdmPwdExpirationTime") | Out-Null
$Searcher.PropertiesToLoad.Add("cn") | Out-Null

try {
    $Results = $Searcher.FindAll()
    foreach ($Computer in $Results) {
        $ComputerName = $Computer.Properties["cn"][0]
        $Password = $Computer.Properties["ms-MCS-AdmPwd"][0]
        $Expiration = $Computer.Properties["ms-MCS-AdmPwdExpirationTime"][0]
        
        Write-Host "Computer: $ComputerName" -ForegroundColor Green
        Write-Host "Password: $Password" -ForegroundColor Yellow
        Write-Host "Expires: $([DateTime]::FromFileTime($Expiration))" -ForegroundColor Cyan
        Write-Host "---"
    }
}
catch {
    Write-Host "[-] No LAPS access or LAPS not deployed" -ForegroundColor Red
}
```

### 🎯 **LAPS Attack Strategies**

#### 🔍 **Targeting LAPS Admins**
```powershell
# 1. Identify LAPS admin groups
Find-LAPSDelegatedGroups | Select-Object "Delegated Groups" -Unique

# 2. Enumerate members of LAPS admin groups
net group "LAPS Admins" /domain

# 3. Target LAPS admin accounts for compromise
# (password spraying, kerberoasting, etc.)
```

#### 🎪 **Computer Account Hijacking**
```powershell
# If you have GenericAll/WriteOwner on computer accounts
# The account that joined the computer has "All Extended Rights"
# This includes the ability to read LAPS passwords

# 1. Find computer accounts you can modify
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -eq "YourUser"}

# 2. Check if LAPS is enabled on those computers
Get-LAPSComputers -ComputerName "TARGET-COMPUTER"
```

---

## 🔧 Additional Security Controls

### 🛡️ **Windows Firewall**
```powershell
# Check Windows Firewall status
Get-NetFirewallProfile

# Get firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq "True"} | Select-Object DisplayName, Direction, Action

# Check for specific blocked ports
Test-NetConnection -ComputerName 127.0.0.1 -Port 445
```

### 🕵️ **Event Log Monitoring**
```powershell
# Check if PowerShell logging is enabled
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue

# Check Sysmon installation
Get-Service | Where-Object {$_.Name -eq "Sysmon64" -or $_.Name -eq "Sysmon"}
```

### 🔒 **BitLocker**
```powershell
# Check BitLocker status
Get-BitLockerVolume

# Check recovery key access
Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -Properties *
```

---

## 📊 Complete Security Controls Assessment Script

### 🚀 **Comprehensive Enumeration Script**
```powershell
function Invoke-SecurityControlsEnum {
    Write-Host "`n=== SECURITY CONTROLS ENUMERATION ===" -ForegroundColor Cyan
    Write-Host "Starting comprehensive security assessment...`n" -ForegroundColor Yellow
    
    # Windows Defender
    Write-Host "[*] Checking Windows Defender..." -ForegroundColor Green
    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop
        Write-Host "  [+] Windows Defender Status:" -ForegroundColor White
        Write-Host "      Real-time Protection: $($defender.RealTimeProtectionEnabled)" -ForegroundColor $(if($defender.RealTimeProtectionEnabled){"Red"}else{"Green"})
        Write-Host "      Behavior Monitor: $($defender.BehaviorMonitorEnabled)" -ForegroundColor $(if($defender.BehaviorMonitorEnabled){"Red"}else{"Green"})
        Write-Host "      On-Access Protection: $($defender.OnAccessProtectionEnabled)" -ForegroundColor $(if($defender.OnAccessProtectionEnabled){"Red"}else{"Green"})
    }
    catch {
        Write-Host "  [-] Cannot access Windows Defender status" -ForegroundColor Red
    }
    
    # AppLocker
    Write-Host "`n[*] Checking AppLocker..." -ForegroundColor Green
    try {
        $applocker = Get-AppLockerPolicy -Effective -ErrorAction Stop
        if ($applocker) {
            Write-Host "  [+] AppLocker is configured" -ForegroundColor Red
            $rules = $applocker.RuleCollections
            foreach ($collection in $rules) {
                $denyRules = $collection | Where-Object {$_.Action -eq "Deny"}
                if ($denyRules) {
                    Write-Host "      Blocked: $($denyRules.Name -join ', ')" -ForegroundColor Red
                }
            }
        }
    }
    catch {
        Write-Host "  [+] AppLocker not configured" -ForegroundColor Green
    }
    
    # PowerShell Language Mode
    Write-Host "`n[*] Checking PowerShell Language Mode..." -ForegroundColor Green
    $langMode = $ExecutionContext.SessionState.LanguageMode
    Write-Host "  Language Mode: $langMode" -ForegroundColor $(if($langMode -eq "FullLanguage"){"Green"}else{"Red"})
    
    # LAPS
    Write-Host "`n[*] Checking LAPS..." -ForegroundColor Green
    try {
        if (Get-Command Find-LAPSDelegatedGroups -ErrorAction SilentlyContinue) {
            $lapsGroups = Find-LAPSDelegatedGroups
            if ($lapsGroups) {
                Write-Host "  [+] LAPS is deployed" -ForegroundColor Yellow
                Write-Host "      Delegated groups found: $($lapsGroups.Count)" -ForegroundColor White
            }
        } else {
            Write-Host "  [!] LAPSToolkit not available for detailed enumeration" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [-] LAPS enumeration failed" -ForegroundColor Red
    }
    
    # Additional checks
    Write-Host "`n[*] Additional Security Checks..." -ForegroundColor Green
    
    # Check UAC
    $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    Write-Host "  UAC Enabled: $($uac.EnableLUA -eq 1)" -ForegroundColor $(if($uac.EnableLUA -eq 1){"Red"}else{"Green"})
    
    # Check Windows Firewall
    try {
        $firewall = Get-NetFirewallProfile -ErrorAction Stop
        $enabled = $firewall | Where-Object {$_.Enabled -eq $true}
        Write-Host "  Windows Firewall Profiles Enabled: $($enabled.Count)/3" -ForegroundColor $(if($enabled.Count -gt 0){"Red"}else{"Green"})
    }
    catch {
        Write-Host "  Windows Firewall: Cannot determine status" -ForegroundColor Yellow
    }
    
    Write-Host "`n=== ASSESSMENT COMPLETE ===`n" -ForegroundColor Cyan
}

# Execute the assessment
Invoke-SecurityControlsEnum
```

---

## 🎯 Key Attack Implications

### 📋 **Security Control Impact Matrix**

| **Control** | **High Impact** | **Medium Impact** | **Low Impact** |
|-------------|-----------------|-------------------|----------------|
| **Windows Defender** | Real-time scanning active | Behavior monitoring enabled | On-access protection disabled |
| **AppLocker** | PowerShell/cmd blocked | Script execution restricted | Default rules only |
| **Constrained Language** | NoLanguage/Restricted | ConstrainedLanguage | FullLanguage |
| **LAPS** | Fully deployed | Partial deployment | Not deployed |

### 🚀 **Adaptation Strategies**

#### 🛡️ **High Security Environment**
```powershell
# When multiple controls are active:
- Use living-off-the-land techniques
- Leverage built-in Windows tools
- Focus on abuse of legitimate functionality
- Employ memory-only payloads
- Use signed binaries and DLL hijacking
```

#### 🔧 **Medium Security Environment**
```powershell
# When some controls are present:
- Test specific bypass techniques
- Use alternative execution methods
- Leverage trusted directories/binaries
- Employ obfuscation techniques
```

#### 🎯 **Low Security Environment**
```powershell
# When few controls are active:
- Standard PowerShell tools available
- Direct tool execution possible
- Minimal evasion required
- Focus on speed and efficiency
```

---

## ⚡ Quick Reference Commands

### 🔍 **Rapid Assessment**
```powershell
# One-liner security assessment
Write-Host "Defender: $((Get-MpComputerStatus).RealTimeProtectionEnabled) | Language: $($ExecutionContext.SessionState.LanguageMode) | AppLocker: $(if(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue){'Enabled'}else{'Disabled'})"

# Test common restrictions
Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ErrorAction SilentlyContinue
$ExecutionContext.SessionState.LanguageMode
(Get-MpComputerStatus).RealTimeProtectionEnabled
```

### 🛠️ **Bypass Testing**
```powershell
# PowerShell alternative locations
%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
%SystemRoot%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe

# Test COM access in Constrained Language
try { New-Object -ComObject Excel.Application } catch { "COM Blocked" }

# Test .NET reflection
try { [System.IO.File]::ReadAllText("C:\Windows\System32\drivers\etc\hosts") } catch { ".NET Restricted" }
```

---

## 🔑 Key Takeaways

### ✅ **Essential Enumeration Points**
- **Always check security controls** before deploying tools or techniques
- **Understand the defensive landscape** to plan effective attack paths
- **Look for inconsistencies** in security policy implementation
- **Test bypass techniques** systematically when restrictions are found

### ⚠️ **Critical Considerations**
- **Not all systems are equal** - security controls may vary by host type
- **Legacy systems** often have fewer protections than modern workstations
- **Administrative workstations** typically have stronger controls
- **Server systems** may have different security postures than endpoints

### 🎯 **Strategic Planning**
1. **Enumerate all security controls** on initial access
2. **Identify gaps and inconsistencies** in defensive coverage
3. **Adapt tool selection** based on control presence
4. **Plan alternative techniques** for restricted environments
5. **Document findings** for reporting and future reference

---

*Understanding security controls is essential for effective Active Directory enumeration - know your restrictions before you engage, and always have a plan B when controls block your primary approach.* 