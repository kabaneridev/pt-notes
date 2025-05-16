# Windows Enumeration Tools

Automated enumeration tools can significantly speed up the privilege escalation discovery process. While manual enumeration is essential for understanding systems thoroughly, these tools can help identify potential vectors quickly during time-constrained assessments like the OSCP exam.

## WinPEAS

WinPEAS (Windows Privilege Escalation Awesome Script) is a comprehensive enumeration script that checks for common privilege escalation vectors.

### Installation and Usage

Download from: [https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

Available as both executable (.exe) and batch script (.bat):

```cmd
# Running the executable
C:\> winpeas.exe > winpeas_output.txt

# Running with specific checks
C:\> winpeas.exe quiet servicesinfo
```

### Features

WinPEAS checks for:
- System information and configuration issues
- Credentials in files, registry, and history
- Kernel vulnerabilities
- Service misconfigurations
- Unquoted service paths
- Scheduled tasks
- Startup applications
- Installed applications
- Writeable directories
- Network information
- And much more

### OSCP Tips

- Use the `quiet` parameter to reduce output verbosity
- Focus on specific checks when you have a suspicion about a potential vector
- Always redirect output to a file for easier analysis

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

## PowerUp

PowerUp is part of PowerSploit and focuses specifically on Windows privilege escalation vectors.

### Installation and Usage

Download from: [https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

```powershell
# Import and run
PS C:\> . .\PowerUp.ps1
PS C:\> Invoke-AllChecks

# Output to file
PS C:\> Invoke-AllChecks | Out-File -FilePath PowerUp_Output.txt
```

### Features

PowerUp is especially effective at finding:
- Service issues (unquoted paths, binary permissions)
- Registry AutoRuns
- Modifiable registry entries
- Writeable service directories
- Path DLL hijacking

### OSCP Tips

- PowerUp may find different issues than WinPEAS/PrivescCheck, so running multiple tools is recommended
- Pay special attention to the "Service Issues" section

## Additional Tools

### Metasploit's Local Exploit Suggester

If you already have a Meterpreter session, you can use:

```
use post/multi/recon/local_exploit_suggester
set SESSION [session_id]
run
```

### Windows-Exploit-Suggester (Original)

An older alternative to WES-NG:
[https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

### Seatbelt

A C# project that performs detailed system reconnaissance:
[https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)

## Best Practices for Tool Usage

1. **Don't Rely Solely on Tools**: Automated tools can miss privilege escalation vectors. Use them as a starting point, not the end of your enumeration.

2. **Run Multiple Tools**: Each tool has its strengths and may find different issues.

3. **Parse Output Carefully**: These tools generate large amounts of information. Develop the skill to quickly identify potential vectors.

4. **Understand the Underlying Techniques**: Know what each tool is checking for so you can verify findings manually.

5. **AV Evasion**: Be prepared with PowerShell options if executables are detected by antivirus.

## OSCP Exam Considerations

For the OSCP exam:

1. Have these tools readily available in your arsenal
2. Practice using them in lab environments
3. Know how to transfer them to target machines
4. Understand how to interpret their results
5. Be ready to manually verify and exploit any findings

Remember that automated tools assist but don't replace manual enumeration skills. Often, the privilege escalation vector that leads to success will be one that requires manual inspection and creative thinking. 