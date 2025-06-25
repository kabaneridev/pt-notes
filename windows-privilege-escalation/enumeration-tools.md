# Windows Enumeration Tools

Automated enumeration tools can significantly speed up the privilege escalation discovery process. While manual enumeration is essential for understanding systems thoroughly, these tools can help identify potential vectors quickly during time-constrained assessments like the OSCP exam.

## WinPEAS

WinPEAS (Windows Privilege Escalation Awesome Script) is a comprehensive enumeration script that checks for common privilege escalation vectors.

> **Note:** A detailed documentation of WinPEAS is available in the [tools/winpeas.md](../tools/winpeas.md) file. This section provides only a brief overview for completeness.

### Key Features Overview

- Comprehensive system enumeration 
- Checks for credentials, misconfigurations, and vulnerabilities
- Available as executable (.exe), batch script (.bat), and PowerShell script (.ps1)
- Color-coded output highlighting critical findings in red
- Modular command structure for targeted enumeration

### Quick Reference

```cmd
# Basic usage
winpeas.exe > winpeas_output.txt

# Targeted commands
winpeas.exe quiet cmd servicesinfo
winpeas.exe quiet cmd windowscreds

# Efficient OSCP usage
winpeas.exe quiet fast
winpeas.exe quiet searchfast
```

## PrivescCheck

PrivescCheck is a PowerShell script that performs similar checks to WinPEAS but doesn't require executing a binary file (helpful for bypassing AV).

### Installation and Usage

Download from: [https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck)

```powershell
# Bypass execution policy if needed
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force

# Import and run the script
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck

# Output to file
PS C:\> Invoke-PrivescCheck -Extended -Report "PrivescCheck_Report"
```

### Features

PrivescCheck examines:
- User privileges and groups
- Services with weak permissions
- DLL hijacking opportunities
- Credential exposure
- Registry-based vulnerabilities
- AlwaysInstallElevated settings
- And more

### OSCP Tips

- The `-Extended` flag provides more comprehensive checks
- The `-Report` parameter generates HTML and CSV reports

## PowerUp

PowerUp is a PowerShell script from the PowerSploit framework specifically designed to identify common Windows privilege escalation vectors.

### Installation and Usage

Download from: [https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)

```powershell
# Import the script
. .\PowerUp.ps1

# Run all checks
Invoke-AllChecks

# Save results to a file
Invoke-AllChecks | Out-File -FilePath PowerUp_Results.txt
```

### Key Features

PowerUp focuses on common Windows misconfigurations:
- Service issues (unquoted paths, weak permissions)
- Registry autoruns with weak permissions
- Modifiable registry entries
- DLL hijacking opportunities
- Writeable service directories
- AlwaysInstallElevated registry settings
- Credential exposure in common locations

### Specific Checks

```powershell
# Check for service issues only
Get-ServiceUnquoted
Get-ModifiableServiceFile
Get-ModifiableService

# Check for AlwaysInstallElevated
Get-RegistryAlwaysInstallElevated

# Check writeable paths
Get-ModifiablePath
```

### OSCP Tips

- PowerUp is lightweight and less likely to trigger antivirus compared to compiled executables
- It excels at finding service-related vulnerabilities
- The output is structured and easier to read than many other tools

## SharpUp

SharpUp is a C# port of PowerUp that can run on Windows systems as a compiled executable, making it useful when PowerShell is restricted.

### Installation and Usage

Download from: [https://github.com/GhostPack/SharpUp](https://github.com/GhostPack/SharpUp)

```cmd
# Run all checks
SharpUp.exe

# Run with specific check
SharpUp.exe audit
```

### Key Features

SharpUp checks for:
- AlwaysInstallElevated registry keys
- Unquoted service paths
- Modifiable service binaries
- Modifiable service directories
- High integrity processes
- Token privileges that can be abused
- Registry autoruns

### OSCP Tips

- Use SharpUp when PowerShell execution is restricted
- The binary can be compiled with different .NET Framework versions for compatibility
- Smaller and more focused than WinPEAS, so can be less noisy

## Seatbelt

Seatbelt is a comprehensive C# enumeration tool that performs detailed system reconnaissance.

### Installation and Usage

Download from: [https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)

```cmd
# Run all checks
Seatbelt.exe -all

# Run specific checks
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe WindowsDefender

# Output to file
Seatbelt.exe -all -output=OutputFile.txt
```

### Key Features

Seatbelt performs comprehensive system enumeration:
- Detailed system information
- User information and environment
- Security products installed
- Installed applications
- COM objects and registry settings
- File searches and local group policies
- Network configuration and connections
- Process details and token privileges
- Scheduled tasks and services

### OSCP Tips

- Seatbelt produces extremely detailed output - use specific group checks to focus your enumeration
- The `-group=user` and `-group=system` flags are most useful for privilege escalation
- Many results require manual analysis to identify exploitable conditions

## Accesschk.exe

Accesschk.exe is a Microsoft Sysinternals tool designed to check access permissions on files, directories, registry keys, and Windows services.

### Installation and Usage

Download from: [https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)

```cmd
# Check service permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Check directory permissions
accesschk.exe -uwdqs Users c:\ /accepteula

# Check registry permissions
accesschk.exe -uwkqs Users hklm\Software /accepteula

# Check for weak service permissions
accesschk.exe -uwcqv * /accepteula
```

### Key Features

Accesschk.exe is particularly useful for:
- Identifying services that can be modified by non-administrators
- Finding directories where regular users have write permissions
- Discovering registry keys with weak permissions
- Checking file permissions in system directories
- Verifying if a user has specific rights on objects

### OSCP Tips

- Always use the `/accepteula` flag to avoid interactive prompts
- Focus on checking services (`-c`), directories (`-d`), files (`-f`), and registry keys (`-k`)
- The `-u` flag shows only resources with some level of access
- The `-w` flag specifically checks for write access, which is most relevant for privilege escalation

## WES-NG (Windows Exploit Suggester - Next Generation)

WES-NG runs on your attack machine rather than the target, making it useful when you want to avoid triggering antivirus alerts.

### Installation and Usage

Download from: [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

```bash
# Update the database
python3 wes.py --update

# On the target, capture system info
systeminfo > systeminfo.txt

# Transfer the file to your attack machine, then run:
python3 wes.py systeminfo.txt

# Filter for exploits with Metasploit modules
python3 wes.py systeminfo.txt -i 'Metasploit'
```

### Features

- Identifies missing patches
- Suggests potential exploits
- Checks against a database of vulnerabilities
- Works offline (doesn't require execution on the target)

### OSCP Tips

- Always run with the most up-to-date database
- Look for exploits marked as "Appears Vulnerable"
- Prioritize exploits that have publicly available PoCs

## Comparison of Tools

| Tool | Language | AV Detection Risk | Speed | Detail Level | Special Features |
|------|----------|------------------|-------|--------------|------------------|
| WinPEAS | C#/Batch | Medium-High | Fast | Very High | Most comprehensive, color-coded output |
| PrivescCheck | PowerShell | Medium | Fast | High | Good balance of detail and readability |
| PowerUp | PowerShell | Medium | Fast | Medium | Excellent for service issues |
| SharpUp | C# | Medium | Fast | Medium | Works when PowerShell is restricted |
| Seatbelt | C# | Medium | Slow | Extremely High | Most detailed system info |
| Accesschk | Native | Low | Fast | Low | Focused permission checks |
| WES-NG | Python | N/A (runs on attacker) | Fast | Medium | Missing patch identification |

## Best Practices for OSCP

1. **Start with PowerUp or SharpUp** - They're fast and focused on common issues
2. **Use accesschk.exe for targeted permission checks** - After identifying suspicious services/files
3. **Run WinPEAS if initial tools don't find anything** - For more comprehensive enumeration
4. **Use Seatbelt selectively** - When you need very detailed information about specific system components
5. **Always redirect output to files** - These tools produce extensive information that's easier to analyze offline

## Additional Tools and Techniques

### Metasploit's Local Exploit Suggester

If you already have a Meterpreter session, you can use:

```
use post/multi/recon/local_exploit_suggester
set SESSION [session_id]
run
```

Remember that manual verification of the issues found by these tools is essential - automated tools can produce false positives or miss context-specific vulnerabilities. 