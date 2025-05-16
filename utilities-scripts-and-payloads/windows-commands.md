# Windows Commands Cheatsheet

This cheatsheet contains essential Windows commands useful for penetration testing, system enumeration, and privilege escalation.

## Basic System Commands

```cmd
# Display Windows version information
ver

# System information
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Host name
hostname

# Current user
whoami
echo %username%

# Get user privileges
whoami /priv

# Get all user information
whoami /all

# Display environment variables
set

# Display network configuration
ipconfig /all

# Show running processes
tasklist
tasklist /v  # verbose

# Show service details
sc query

# Display date and time
date /t
time /t
```

## File Navigation and Management

```cmd
# Display current directory
cd
# or 
echo %cd%

# Change directory
cd path\to\directory
cd C:\Users\Administrator\Desktop
cd ..   # Move up one directory
cd \    # Move to root of current drive

# List directory contents
dir
dir /a   # Show hidden files
dir /s   # List recursively
dir /b   # Brief format (filenames only)
dir /q   # Show owners
dir /r   # Show alternate data streams

# Find files (recursively)
dir /s /b C:\filename.txt
dir /s /b C:\*.txt

# Create directory
mkdir NewFolder

# Delete files
del file.txt
del /f /q file.txt  # Force delete, quiet mode

# Delete directory
rmdir FolderName
rmdir /s /q FolderName  # Delete folder and its contents

# Copy files
copy source.txt destination.txt
copy file.txt C:\Destination\
xcopy /s /e /h /i source_dir destination_dir  # Copy directories recursively

# Move files
move source.txt destination.txt

# Rename files
ren oldname.txt newname.txt

# View file contents
type file.txt

# Search file contents
findstr "search_string" file.txt
findstr /s /i "password" *.txt *.ini *.config
```

## User and Permission Management

```cmd
# List users
net user

# User details
net user username

# List groups
net localgroup

# List members of a group
net localgroup Administrators

# Add user
net user newuser password /add

# Add user to group
net localgroup Administrators username /add

# Check file permissions
icacls "C:\path\to\file.txt"

# Grant full permissions
icacls "C:\path\to\file.txt" /grant username:F

# Take ownership of file
takeown /f "C:\path\to\file.txt"

# Run command as another user
runas /user:domain\username "command"
```

## Network Commands

```cmd
# Show network connections
netstat -ano
netstat -ano | findstr "ESTABLISHED"
netstat -ano | findstr "LISTENING"

# Show routing table
route print

# ARP table
arp -a

# Trace route
tracert example.com

# DNS lookup
nslookup example.com

# Test connectivity
ping example.com
ping -n 3 example.com  # 3 pings only

# Download file (PowerShell)
powershell -c "Invoke-WebRequest -Uri 'http://example.com/file.txt' -OutFile 'file.txt'"
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://example.com/file.txt', 'file.txt')"

# SMB shares
net share
net use Z: \\server\share
```

## Scheduled Tasks

```cmd
# List scheduled tasks
schtasks

# Detailed task information
schtasks /query /fo LIST /v

# Query specific task
schtasks /query /tn TaskName /fo list /v

# Run task
schtasks /run /tn TaskName

# Create task
schtasks /create /tn TaskName /tr C:\path\to\executable.exe /sc DAILY /st 12:00
```

## Services

```cmd
# List all services
sc query
net start

# Query specific service
sc qc ServiceName
sc query ServiceName

# Start/stop service
net start ServiceName
net stop ServiceName
sc start ServiceName
sc stop ServiceName

# Get service details
sc qc ServiceName

# List services with spaces in path (unquoted service paths)
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

## Registry

```cmd
# Query registry key
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

# Query specific value
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName

# Add registry value
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestApp /t REG_SZ /d "C:\path\to\app.exe" /f

# Delete registry value
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestApp /f

# Registry search
reg query HKLM /f "password" /t REG_SZ /s
```

## PowerShell Commands

```powershell
# Run PowerShell commands from CMD
powershell -c "Get-Process"

# Running PowerShell script
powershell -ExecutionPolicy Bypass -File script.ps1

# Get command history
(Get-PSReadlineOption).HistorySavePath
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# List files recursively
Get-ChildItem -Path C:\ -Include *.txt -File -Recurse -ErrorAction SilentlyContinue

# Get file contents
Get-Content file.txt
Get-Content -Path C:\file.txt

# Find in files
Get-ChildItem -Path C:\ -Recurse | Select-String -Pattern "password"

# Get process details
Get-Process | Where-Object {$_.ProcessName -eq "notepad"}

# Get service details
Get-Service | Where-Object {$_.Status -eq "Running"}

# Download file 
Invoke-WebRequest -Uri "http://example.com/file.txt" -OutFile "file.txt"
```

## Finding and Searching

```cmd
# Find files with specific name
where /r C:\ filename.txt

# Find files by wildcard
dir /s /b C:\*.txt

# Search for string in files
findstr /s /i "password" C:\*.txt

# Search for specific text in current directory
findstr /s /i "confidential" *.*

# Find files modified in the last 7 days
forfiles /P C:\ /S /D +7 /C "cmd /c echo @path @fdate"

# Find large files
forfiles /S /M *.* /C "cmd /c if @fsize GEQ 1000000 echo @path @fsize"

# Alternate data streams
dir /r | find ":$DATA"

# Find all executable files in a directory
dir /s /b C:\*.exe
```

## System and Security

```cmd
# Check patches/hotfixes installed
wmic qfe list brief

# List installed software
wmic product get name,version

# Check startup programs
wmic startup list brief

# Firewall status
netsh firewall show state
netsh advfirewall show allprofiles

# Check Windows Defender status
sc query windefend

# Manage firewall rules
netsh advfirewall firewall show rule name=all
netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80

# Event log
wevtutil qe Security /c:5 /f:text
```

## Other Useful Commands

```cmd
# Run command and redirect output to file
command > output.txt
ipconfig > network_info.txt

# Append to file
command >> output.txt

# Redirect stderr
command 2> errors.txt

# Redirect stdout and stderr
command > output.txt 2>&1

# Pipe commands
command1 | command2
ipconfig | findstr "IPv4"

# Command separator
command1 & command2

# Execute second command if first succeeds
command1 && command2

# Execute second command if first fails
command1 || command2

# Background process
start command

# Output formatting
more
find
findstr
```

## Remote Execution

```cmd
# PSExec (if available)
psexec \\remote-computer -u username -p password cmd

# WMI remote execution
wmic /node:remote-computer process call create "cmd.exe /c command"

# PowerShell remote execution
powershell -c "Invoke-Command -ComputerName remote-computer -ScriptBlock {command}"
```

## File Transfer Methods

```cmd
# Using certutil
certutil -urlcache -split -f "http://example.com/file.txt" file.txt

# Using BITSAdmin
bitsadmin /transfer myJob /download /priority high http://example.com/file.txt C:\path\to\file.txt

# Using FTP (interactive)
ftp -s:script.txt server

# PowerShell Base64 encode/decode
powershell -c "[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('string to encode'))"
powershell -c "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('base64string'))"
```

## Command History and Help

```cmd
# View command history (if doskey is used)
doskey /history

# Get help for a command
help command
command /?

# Clear screen
cls

# Exit command prompt
exit
```

Remember that some commands may require administrative privileges to run successfully. Use `runas` or launch CMD/PowerShell as administrator when necessary. 