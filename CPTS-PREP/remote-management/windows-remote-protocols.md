# Windows Remote Management Protocols

## Overview
Windows systems utilize various remote management protocols for system administration, monitoring, and control. These protocols enable IT administrators to manage Windows machines remotely and provide various levels of access and functionality.

## RDP (Remote Desktop Protocol)

### Overview
RDP (Remote Desktop Protocol) is a proprietary protocol developed by Microsoft that allows for remote connections to Windows systems. It provides full desktop access with graphical user interface over network connections.

**Key Characteristics:**
- **Port 3389**: Default RDP port
- **Authentication**: Network Level Authentication (NLA), password-based
- **Encryption**: TLS encryption for secure connections
- **Functionality**: Full desktop remote access
- **Clients**: Windows Remote Desktop, mstsc, rdesktop, xfreerdp

### RDP Features
- **Desktop Sharing**: Full graphical desktop access
- **Multi-Session**: Multiple simultaneous connections
- **RemoteApp**: Application-specific remote access
- **Clipboard Integration**: Copy/paste between local and remote systems
- **Drive Redirection**: Access to local drives from remote session

### RDP Configuration
```bash
# Enable RDP via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Enable RDP via PowerShell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Configure RDP authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 1 /f
```

### RDP Enumeration
```bash
# Nmap RDP detection
nmap -p3389 -sV -sC target

# RDP security enumeration
nmap -p3389 --script rdp-enum-encryption target
nmap -p3389 --script rdp-ntlm-info target

# RDP vulnerability scanning
nmap -p3389 --script rdp-vuln* target
```

### RDP Security Issues
1. **Weak Authentication**: Default or weak passwords
2. **Version Vulnerabilities**: Outdated RDP versions
3. **Encryption Issues**: Weak encryption protocols
4. **Brute Force**: Password guessing attacks
5. **Network Exposure**: RDP accessible from internet

## WinRM (Windows Remote Management)

### Overview
WinRM (Windows Remote Management) is Microsoft's implementation of the WS-Management Protocol, providing remote management capabilities for Windows systems. It enables remote execution of commands and scripts.

**Key Characteristics:**
- **Port 5985**: HTTP (unencrypted)
- **Port 5986**: HTTPS (encrypted)
- **Authentication**: Kerberos, NTLM, Basic, Certificate
- **Protocol**: SOAP over HTTP/HTTPS
- **Functionality**: Remote command execution, PowerShell remoting

### WinRM Features
- **PowerShell Remoting**: Remote PowerShell sessions
- **Command Execution**: Execute commands on remote systems
- **Event Forwarding**: Forward Windows events
- **Configuration Management**: Remote system configuration
- **Scalability**: Manage multiple systems simultaneously

### WinRM Configuration
```bash
# Enable WinRM
winrm quickconfig

# Configure WinRM listeners
winrm create winrm/config/listener?Address=*+Transport=HTTP

# Set authentication methods
winrm set winrm/config/service/auth @{Basic="true"}
winrm set winrm/config/service/auth @{Kerberos="true"}

# Configure trusted hosts
winrm set winrm/config/client @{TrustedHosts="*"}
```

### WinRM Enumeration
```bash
# Nmap WinRM detection
nmap -p5985,5986 -sV -sC target

# WinRM service enumeration
nmap -p5985,5986 --script http-enum target
nmap -p5985,5986 --script http-headers target

# WinRM authentication testing
nmap -p5985 --script http-auth target
```

### WinRM Security Issues
1. **Weak Authentication**: Basic authentication over HTTP
2. **Configuration**: Overly permissive settings
3. **Encryption**: Unencrypted HTTP transport
4. **Access Control**: Insufficient access restrictions
5. **Credential Exposure**: Credentials in scripts and configurations

## WMI (Windows Management Instrumentation)

### Overview
WMI (Windows Management Instrumentation) is Microsoft's implementation of Web-Based Enterprise Management (WBEM) and Common Information Model (CIM). It provides a standardized way to access management information in an enterprise environment.

**Key Characteristics:**
- **Port 135**: RPC endpoint mapper
- **Dynamic Ports**: Random high ports for actual communication
- **Authentication**: Windows authentication (NTLM, Kerberos)
- **Functionality**: System information, configuration, monitoring
- **Access**: Local and remote management

### WMI Components
- **WMI Service**: Core service providing WMI functionality
- **WMI Repository**: Database storing WMI class definitions
- **WMI Providers**: Components that provide management data
- **WMI Classes**: Object-oriented representation of manageable resources
- **WQL**: WMI Query Language for data retrieval

### WMI Configuration
```bash
# Enable WMI through firewall
netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes

# Configure WMI authentication
dcomcnfg.exe
# Navigate to Component Services > Computers > My Computer > DCOM Config > Windows Management Instrumentation
```

### WMI Enumeration
```bash
# Nmap WMI detection
nmap -p135 -sV -sC target

# WMI service enumeration
nmap -p135 --script rpc-grind target
nmap -p135 --script ms-sql-info target
```

### WMI Security Issues
1. **Authentication**: Windows authentication bypass
2. **Access Control**: Insufficient WMI permissions
3. **Information Disclosure**: Sensitive system information
4. **Privilege Escalation**: WMI-based escalation techniques
5. **Persistence**: WMI event subscriptions for persistence

## Advanced Enumeration Techniques

### RDP Advanced Enumeration
```bash
# RDP certificate analysis
nmap -p3389 --script ssl-cert target

# RDP encryption enumeration
nmap -p3389 --script rdp-enum-encryption target

# RDP brute force
hydra -l administrator -P passwords.txt rdp://target
ncrack -u administrator -P passwords.txt rdp://target
```

### WinRM Advanced Enumeration
```bash
# WinRM service detection
crackmapexec winrm target -u username -p password

# WinRM command execution
evil-winrm -i target -u username -p password

# WinRM PowerShell remoting
Enter-PSSession -ComputerName target -Credential (Get-Credential)
```

### WMI Advanced Enumeration
```bash
# WMI remote queries
wmic /node:target /user:domain\username /password:password computersystem get name

# WMI information gathering
wmic /node:target os get caption,version,installdate
wmic /node:target service get name,startmode,state
wmic /node:target process get name,processid,commandline
```

## Practical Examples

### HTB Academy Style RDP Enumeration
```bash
# Step 1: Service detection
nmap -p3389 -sV -sC target

# Step 2: Certificate analysis
nmap -p3389 --script ssl-cert target

# Step 3: Encryption enumeration
nmap -p3389 --script rdp-enum-encryption target

# Step 4: Authentication testing
xfreerdp /u:administrator /p:password /v:target
rdesktop -u administrator -p password target
```

### HTB Academy Style WinRM Enumeration
```bash
# Step 1: Service detection
nmap -p5985,5986 -sV -sC target

# Step 2: Authentication testing
crackmapexec winrm target -u username -p password

# Step 3: Command execution
evil-winrm -i target -u username -p password

# Step 4: PowerShell remoting
pwsh
Enter-PSSession -ComputerName target -Credential username
```

### HTB Academy Lab Questions Examples
```bash
# Question 1: "What version of RDP is running on the target?"
nmap -p3389 -sV target
# Look for: Microsoft Terminal Services (RDP version)
# Answer: RDP version number

# Question 2: "Is WinRM enabled on the target?"
nmap -p5985,5986 target
# Look for: open ports
# Answer: Yes/No

# Question 3: "What authentication methods are supported by WinRM?"
nmap -p5985 --script http-auth target
# Look for: Basic, Negotiate, NTLM
# Answer: Authentication methods

# Question 4: "Execute a command via WinRM and submit the result"
evil-winrm -i target -u username -p password
*Evil-WinRM* PS C:\Users\username> whoami
# Answer: Command output
```

## Security Assessment

### RDP Security Assessment
```bash
# RDP vulnerability scanning
nmap -p3389 --script rdp-vuln* target

# RDP brute force protection testing
hydra -l administrator -P passwords.txt rdp://target

# RDP encryption analysis
nmap -p3389 --script rdp-enum-encryption target
```

### WinRM Security Assessment
```bash
# WinRM configuration analysis
crackmapexec winrm target -u username -p password

# WinRM authentication testing
evil-winrm -i target -u username -p password

# WinRM command execution testing
winrs -r:target -u:username -p:password cmd
```

### WMI Security Assessment
```bash
# WMI access testing
wmic /node:target /user:username /password:password computersystem get name

# WMI information gathering
wmic /node:target service get name,startmode,state
wmic /node:target process get name,processid
```

## Enumeration Checklist

### RDP Enumeration
- [ ] Port scan for RDP (3389/tcp)
- [ ] Version detection and banner grabbing
- [ ] Certificate analysis
- [ ] Encryption enumeration
- [ ] Authentication testing
- [ ] Vulnerability scanning
- [ ] Brute force protection testing

### WinRM Enumeration
- [ ] Port scan for WinRM (5985,5986/tcp)
- [ ] Service detection and version identification
- [ ] Authentication method enumeration
- [ ] HTTP/HTTPS configuration analysis
- [ ] Command execution testing
- [ ] PowerShell remoting testing
- [ ] Configuration analysis

### WMI Enumeration
- [ ] Port scan for RPC (135/tcp)
- [ ] Service detection and enumeration
- [ ] Authentication testing
- [ ] Information gathering via WMI queries
- [ ] Access control testing
- [ ] Privilege assessment
- [ ] Persistence mechanism analysis

## Attack Vectors

### RDP Attack Vectors
```bash
# RDP brute force
hydra -l administrator -P passwords.txt rdp://target

# RDP vulnerability exploitation
# BlueKeep (CVE-2019-0708)
# DejaBlue (CVE-2019-1181, CVE-2019-1182)

# RDP credential harvesting
# Keyloggers in RDP sessions
# Clipboard monitoring
```

### WinRM Attack Vectors
```bash
# WinRM command execution
evil-winrm -i target -u username -p password

# WinRM PowerShell exploitation
Enter-PSSession -ComputerName target -Credential username
Invoke-Command -ComputerName target -ScriptBlock {whoami}

# WinRM persistence
# Event subscriptions via WMI
# Scheduled tasks
```

### WMI Attack Vectors
```bash
# WMI command execution
wmic /node:target process call create "cmd.exe /c command"

# WMI persistence
# Event subscriptions
# MOF files
# WMI classes

# WMI lateral movement
# Remote process creation
# Service manipulation
```

## Common Vulnerabilities

### RDP Vulnerabilities
- **CVE-2019-0708**: BlueKeep RCE vulnerability
- **CVE-2019-1181**: DejaBlue RCE vulnerability
- **CVE-2019-1182**: DejaBlue RCE vulnerability
- **CVE-2012-0002**: RDP denial of service
- **CVE-2018-0886**: CredSSP authentication bypass

### WinRM Vulnerabilities
- **Configuration Issues**: Weak authentication settings
- **Network Exposure**: WinRM accessible from untrusted networks
- **Authentication Bypass**: Weak authentication mechanisms
- **Privilege Escalation**: WinRM-based escalation techniques

### WMI Vulnerabilities
- **WMI Event Subscriptions**: Persistence mechanisms
- **WMI Query Injection**: Malicious WQL queries
- **Access Control**: Insufficient WMI permissions
- **Information Disclosure**: Sensitive system information

## Tools and Techniques

### RDP Tools
```bash
# RDP clients
mstsc                # Windows Remote Desktop
rdesktop             # Linux RDP client
xfreerdp             # Cross-platform RDP client
freerdp              # Free RDP implementation

# RDP security tools
nmap                 # Network scanning
hydra                # Brute force
ncrack               # Network authentication cracker
```

### WinRM Tools
```bash
# WinRM clients
winrs                # Windows Remote Shell
evil-winrm           # WinRM pentesting tool
pwsh                 # PowerShell Core

# WinRM testing tools
crackmapexec         # Network authentication testing
nmap                 # Service detection
```

### WMI Tools
```bash
# WMI clients
wmic                 # Windows WMI command-line
powershell           # PowerShell WMI cmdlets
wmios                # WMI object browser

# WMI testing tools
wmiexec              # WMI command execution
wmipersist           # WMI persistence toolkit
```

## Defensive Measures

### RDP Hardening
```bash
# Change default RDP port
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 3390 /f

# Enable Network Level Authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f

# Restrict RDP access
# Use Group Policy to limit RDP access
# Configure firewall rules
```

### WinRM Security
```bash
# Disable WinRM if not needed
Stop-Service winrm
Set-Service winrm -StartupType Disabled

# Configure WinRM securely
winrm set winrm/config/service/auth @{Basic="false"}
winrm set winrm/config/service @{AllowUnencrypted="false"}

# Restrict WinRM access
# Use Group Policy to configure WinRM
# Configure firewall rules
```

### WMI Security
```bash
# Configure WMI security
# Use Group Policy to configure WMI settings
# Set appropriate DCOM permissions
# Monitor WMI activity

# Disable WMI if not needed
Stop-Service winmgmt
Set-Service winmgmt -StartupType Disabled
```

## Best Practices

### RDP Best Practices
1. **Change default port**: Use non-standard ports
2. **Enable NLA**: Require Network Level Authentication
3. **Use strong passwords**: Implement password policies
4. **Limit access**: Restrict RDP access to authorized users
5. **Monitor connections**: Log and monitor RDP sessions
6. **Keep updated**: Apply security patches regularly

### WinRM Best Practices
1. **Use HTTPS**: Enable SSL/TLS encryption
2. **Restrict authentication**: Disable basic authentication
3. **Limit access**: Configure trusted hosts carefully
4. **Monitor activity**: Log WinRM connections and commands
5. **Network security**: Use firewall rules and VPNs
6. **Regular audits**: Review WinRM configuration regularly

### WMI Best Practices
1. **Access control**: Set appropriate WMI permissions
2. **Monitor activity**: Log WMI queries and changes
3. **Disable if unused**: Turn off WMI if not needed
4. **Regular audits**: Review WMI configuration and usage
5. **Network security**: Restrict WMI network access
6. **Update regularly**: Keep WMI components updated

## Detection and Monitoring

### RDP Monitoring
```bash
# Monitor RDP connections
# Windows Event Logs: Security, TerminalServices-LocalSessionManager
# Event IDs: 4624, 4625, 1149

# RDP connection logging
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### WinRM Monitoring
```bash
# Monitor WinRM activity
# Windows Event Logs: Microsoft-Windows-WinRM
# PowerShell logging: Module, ScriptBlock, Transcription

# WinRM logging configuration
winrm set winrm/config/service @{EnableCompatibilityHttpListener="true"}
```

### WMI Monitoring
```bash
# Monitor WMI activity
# Windows Event Logs: Microsoft-Windows-WMI-Activity
# Event IDs: 5857, 5858, 5859, 5860, 5861

# WMI logging configuration
# Enable WMI-Activity logging via Group Policy
``` 