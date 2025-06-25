# Windows Enumeration

Proper enumeration is the foundation of successful privilege escalation on Windows systems. This document outlines key areas to examine and commands to use when enumerating a Windows machine.

## System Information

```powershell
# Basic system information
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Hotfixes and patches
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Environment variables
set
Get-ChildItem Env: | Format-Table -AutoSize

# Connected drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | Where-Object {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}

# Network information
ipconfig /all
route print
arp -a
```

## User Information

```powershell
# Current user
whoami
whoami /all

# Local users
net user
Get-LocalUser | Format-Table Name,Enabled,LastLogon

# Local administrators
net localgroup administrators
Get-LocalGroupMember -Group "Administrators" | Format-Table Name,PrincipalSource

# User privileges
whoami /priv
```

## Network Information

```powershell
# Open ports and connections
netstat -ano
Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Format-Table LocalAddress,LocalPort,RemoteAddress,RemotePort,State

# Firewall configuration
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all

# Network shares
net share
Get-SmbShare
```

## Running Processes and Services

```powershell
# List running processes
tasklist /v
Get-Process | Format-Table Name,Id,Path,Company

# List services
net start
wmic service list brief
Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table -Property Name,DisplayName,Status

# Query specific service
sc qc <service_name>
Get-Service <service_name> | Select-Object *
```

## Scheduled Tasks

```powershell
# List scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName,TaskPath,State
```

## File System Information

```powershell
# Search for writable directories in Program Files
Get-ChildItem "C:\Program Files" -Recurse | Get-Acl | Where-Object {$_.AccessToString -match "Everyone\sAllow\s\sModify"}
Get-ChildItem "C:\Program Files (x86)" -Recurse | Get-Acl | Where-Object {$_.AccessToString -match "Everyone\sAllow\s\sModify"}

# Search for unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch "`"" -and $_.PathName -notmatch "C:\\Windows"} | Select-Object Name,PathName,StartMode

# Search for files with specific permissions
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

# Search for config files containing password
Get-ChildItem -Path C:\ -Include *.xml,*.ini,*.txt,*.config -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 100KB } | Select-String -Pattern "password" | Format-List
```

## Registry Settings

```powershell
# Check for AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Check auto-logon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /v DefaultPassword

# Search for stored credentials in registry
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

## Installed Applications

```powershell
# List installed applications
wmic product get name, version, vendor
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
```

## Antivirus and Security Products

```powershell
# Check Windows Defender status
Get-MpComputerStatus

# Check for common security products
wmic /namespace:\\root\securitycenter2 path antivirusproduct GET displayName,productState,pathToSignedProductExe
```

## Interesting Directories and Files

```powershell
# Search for common sensitive files
Get-ChildItem -Path C:\ -Include *pass*.txt,*pass*.xml,*pass*.ini,*pass*.xlsx,*cred*,*vnc*,*.config*,*.conf,*id_rsa*,*.key -File -Recurse -ErrorAction SilentlyContinue

# Search for web configuration files
Get-ChildItem -Path C:\ -Include web.config,applicationHost.config,php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue

# Search for recent files
Get-ChildItem -Path C:\Users -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object FullName,LastWriteTime -First 50
```

## Automated Enumeration Tools

For more thorough enumeration, consider using specialized tools if you can upload them to the target system:

```powershell
# Windows Privilege Escalation Awesome Script (WinPEAS)
.\winPEAS.exe

# PowerUp (Privilege escalation checks)
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# SharpUp (C# port of PowerUp)
.\SharpUp.exe

# PrivescCheck
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck
```

## Combining PowerShell Commands

Create custom PowerShell scripts to perform multiple checks:

```powershell
$ErrorActionPreference = "SilentlyContinue"

# System info
Write-Host "[+] System Information" -ForegroundColor Green
systeminfo | Select-String "OS Name", "OS Version", "System Type"

# User information
Write-Host "[+] Current User and Privileges" -ForegroundColor Green
whoami /all

# Service information
Write-Host "[+] Non-standard Services" -ForegroundColor Green
Get-WmiObject win32_service | Where-Object {$_.PathName -notmatch "C:\\Windows"} | Select-Object Name, PathName, StartMode

# Scheduled tasks
Write-Host "[+] Interesting Scheduled Tasks" -ForegroundColor Green
Get-ScheduledTask | Where-Object {$_.TaskPath -notmatch "\\Microsoft\\"} | Format-Table TaskName,TaskPath,State

# Network information
Write-Host "[+] Network Connections" -ForegroundColor Green
netstat -ano | findstr "LISTENING"
```

## Remember

- Always check what commands are available and usable in your specific context.
- Take notes of findings for later analysis.
- Look for unusual or non-standard configurations.
- Correlate information between different sources to identify privilege escalation vectors.
- Be methodical and thorough in your enumeration process.

This enumeration process will help identify potential privilege escalation vectors. After completing enumeration, analyze your findings to determine the most promising attack paths.

## Identifying Suspicious Processes

Analyzing running processes is critical for identifying potential security issues or opportunities for privilege escalation. Non-standard processes can indicate compromise or misconfigurations that you can exploit.

### Listing and Analyzing Processes

```cmd
# Basic process listing
tasklist

# Verbose process listing
tasklist /v

# List processes with service information
tasklist /svc

# More detailed process information with PowerShell
Get-Process | Select-Object Name, Id, Path, Company

# Find processes running as SYSTEM
tasklist /v | findstr "SYSTEM"

# Find processes with unusual paths
wmic process get name,executablepath | findstr /i /v "C:\\Windows\\system32"
```

### Suspicious Process Characteristics

When analyzing processes, look for:

1. **Unusual locations**: Processes running from temp directories, user directories, or non-standard program paths
2. **Uncommon names**: Processes with misspelled names (e.g., svch0st.exe instead of svchost.exe)
3. **High privileges**: Processes running as SYSTEM or Administrator unnecessarily
4. **Missing descriptions**: Legitimate Windows processes typically have proper descriptions
5. **Unusual parent-child relationships**: Use Process Explorer to identify abnormal process hierarchies

### Suspicious Process Examples

These processes might indicate potential compromise or misconfiguration:

- **seatbelt.exe**: Part of the GhostPack toolkit, used for security assessments; presence may indicate ongoing penetration testing or compromise
- **nc.exe/netcat**: Network utility commonly used for creating backdoors or reverse shells
- **psexec.exe**: Legitimate SysInternals tool, but often abused for lateral movement
- **mimikatz.exe**: Credential dumping tool
- **powershell.exe** with unusual parent processes or command line parameters
- **cmd.exe** running as SYSTEM or with unusual parent processes
- **wmic.exe** used for remote execution or suspicious queries

### Detailed Analysis with Seatbelt

Ironically, Seatbelt itself is a powerful enumeration tool used by penetration testers. If you find it installed, you might be able to use it for your own enumeration:

```cmd
# If available, run basic checks
Seatbelt.exe -group=system

# Run all checks
Seatbelt.exe all

# Specific checks for processes
Seatbelt.exe NonstandardProcesses
```

### Process Analysis with PowerShell

```powershell
# Get detailed information about suspicious processes
Get-WmiObject Win32_Process | Where-Object {$_.ExecutablePath -notlike "C:\Windows*"} | Select-Object Name, ExecutablePath, CommandLine

# Check for unusual parent-child relationships
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath

# Identify processes with open network connections
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name ProcessName -Value (Get-Process -Id $_.OwningProcess).Name -PassThru }
```

### Investigating Process Command Lines

Command line parameters can reveal suspicious behavior:

```cmd
# Using wmic (works on older Windows versions)
wmic process get name,commandline

# Using PowerShell (more modern)
Get-WmiObject Win32_Process | Select-Object Name, CommandLine

# Look for suspicious flags in PowerShell commands
Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*-enc*" -or $_.CommandLine -like "*-exec*bypass*"} | Select-Object Name, CommandLine
```

### Exploiting Weak Process Permissions

If you find a process running with high privileges but with weak file permissions:

```cmd
# Check file permissions of the executable
icacls "C:\path\to\suspicious\process.exe"

# If writable, you might be able to replace it with a malicious version
copy C:\path\to\malicious.exe C:\path\to\suspicious\process.exe

# Or if service, check service configuration
sc qc "SuspiciousService"
```

## Service Enumeration

```powershell
# List services
net start
wmic service list brief
Get-Service | Where-Object {$_.Status -eq "Running"} | Format-Table -Property Name,DisplayName,Status

# Query specific service
sc qc <service_name>
Get-Service <service_name> | Select-Object *
``` 