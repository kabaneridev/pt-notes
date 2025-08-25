# Windows Process Communication Analysis

## 🎯 Overview

**Process communication** analysis focuses on identifying privilege escalation opportunities through running services and inter-process communication. Processes running with elevated privileges, especially those accessible via network services or named pipes, can provide direct escalation paths.

## 🔑 Access Tokens

### Concept
- **Access tokens** describe the security context of processes/threads
- Contain user identity and privilege information  
- **Token presentation** occurs with every process interaction
- **Token inheritance** from parent processes

**Key Token Privileges:**
- `SeImpersonatePrivilege` - Rogue/Juicy/Lonely Potato attacks
- `SeAssignPrimaryTokenPrivilege` - Token manipulation
- `SeDebugPrivilege` - Process debugging and memory access

## 🌐 Network Service Enumeration

### Active Connections Analysis
```cmd
# Display all active connections with PIDs
netstat -ano

# Filter for listening services only
netstat -ano | findstr LISTENING

# PowerShell alternative
Get-NetTCPConnection -State Listen
```

### Target Service Categories

**🎯 High-Value Services:**
- **Port 21** - FTP (FileZilla Server)
- **Port 80/8080** - Web servers (IIS, XAMPP, Tomcat)
- **Port 3389** - RDP
- **Port 5985/5986** - WinRM
- **Port 1433** - MSSQL

**🔍 Localhost-Only Services:**
```cmd
# Look for services bound to loopback addresses
netstat -ano | findstr 127.0.0.1
netstat -ano | findstr ::1

# These services often lack security controls
# Example: FileZilla admin interface on 127.0.0.1:14147
```

### Service-to-Process Mapping
```cmd
# Find process by PID from netstat
tasklist | findstr "[PID]"

# Example workflow:
netstat -ano | findstr :8080  # Find PID listening on 8080
tasklist | findstr "5044"     # Identify process name
```

## 🔄 Named Pipes

### Concept
- **Named pipes** enable inter-process communication via shared memory
- **Client-server model** - creator is server, communicator is client
- **Communication types**:
  - **Half-duplex** - One-way (client → server)
  - **Full-duplex** - Two-way communication

### Named Pipe Enumeration

#### Using Pipelist (Sysinternals)
```cmd
# List all named pipes
pipelist.exe /accepteula

# Key pipes to analyze:
- lsass        # Local Security Authority
- spoolss      # Print Spooler
- eventlog     # Event Log service  
- Custom pipes # Application-specific
```

#### Using PowerShell
```powershell
# List named pipes with Get-ChildItem
Get-ChildItem \\.\pipe\

# Alternative syntax
gci \\.\pipe\
```

### Named Pipe Security Analysis

#### Permission Enumeration with AccessChk
```cmd
# Check specific pipe permissions
accesschk.exe /accepteula \\.\Pipe\[PIPE_NAME] -v

# Find writable pipes (privilege escalation opportunities)
accesschk.exe -w \pipe\* -v

# Look for Everyone group with excessive permissions
```

#### Dangerous Permission Patterns
```cmd
# Dangerous combinations:
RW Everyone - FILE_ALL_ACCESS      # Complete control
RW Everyone - FILE_WRITE_DATA      # Data modification
RW Everyone - WRITE_DAC            # Permission modification
```

## 🚨 Common Attack Vectors

### Web Server Exploitation
**Scenario**: IIS/XAMPP running as privileged user
```cmd
# 1. Identify web server process
netstat -ano | findstr :80
tasklist | findstr "[PID]"

# 2. Deploy web shell (if write access exists)
# 3. Execute commands as web server user
# 4. Leverage SeImpersonatePrivilege for SYSTEM
```

### FileZilla Server Attack
**Scenario**: Admin interface on localhost:14147
```cmd
# 1. Identify FileZilla admin port
netstat -ano | findstr 127.0.0.1:14147

# 2. Connect to admin interface (no authentication)  
# 3. Extract FTP credentials
# 4. Create FTP share at C:\ with elevated privileges
```

### Splunk Universal Forwarder
**Scenario**: Default configuration without authentication
- **Default behavior**: Runs as SYSTEM
- **Attack method**: Deploy malicious applications
- **Impact**: Direct SYSTEM-level code execution

### Named Pipe Privilege Escalation
**Example**: WindscribeService vulnerability
```cmd
# 1. Find vulnerable pipe
accesschk.exe -w \pipe\* -v | findstr "Everyone"

# 2. Confirm excessive permissions
accesschk.exe -accepteula -w \pipe\WindscribeService -v
# Result: RW Everyone FILE_ALL_ACCESS

# 3. Exploit pipe communication for privilege escalation
```

## 🎯 HTB Academy Lab Solutions

### Lab Environment
- **Target**: `10.129.43.43` (ACADEMY-WINLPE-SRV01)
- **Credentials**: `htb-student:HTB_@cademy_stdnt!`
- **Tools**: `C:\Tools\AccessChk\`

### Question 1: Service on Port 21
**Objective**: Identify service listening on 0.0.0.0:21

**Solution Steps:**
```cmd
# 1. Connect via RDP
xfreerdp /v:10.129.43.43 /u:htb-student /p:HTB_@cademy_stdnt!

# 2. Find PID listening on port 21
netstat -ano | findstr :21
# Result shows PID (e.g., 2156)

# 3. Identify process by PID
tasklist | findstr "2156"
# Output: FileZilla Server.exe
```

**Answer**: `filezilla server`

### Question 2: WRITE_DAC Privileges on Named Pipe
**Objective**: Find account with WRITE_DAC over `\pipe\SQLLocal\SQLEXPRESS01`

**Solution Steps:**
```cmd
# 1. Navigate to AccessChk directory
cd C:\Tools\AccessChk

# 2. Check named pipe permissions
accesschk.exe -accepteula -w \pipe\SQLLocal\SQLEXPRESS01 -v

# 3. Analyze output for WRITE_DAC privilege
# Result shows: NT SERVICE\MSSQL$SQLEXPRESS01 with WRITE_DAC
```

**Answer**: `NT Service\MSSQL$SQLEXPRESS01`

## 🔍 Attack Pattern Recognition

### Network Service Indicators
```cmd
# Identify potential targets:
Port 8080     # Tomcat, development servers
Port 9090     # Administrative interfaces  
Port 10000+   # Custom applications
Localhost-only # Insecure by design assumption
```

### Named Pipe Red Flags
```cmd
# Dangerous permission combinations:
Everyone group      # Overly permissive
FILE_ALL_ACCESS    # Complete control
WRITE_DAC          # Permission modification
Custom pipe names  # Application vulnerabilities
```

### Service Context Analysis
```cmd
# High-privilege service users:
SYSTEM                    # Highest privileges
NT AUTHORITY\SYSTEM      # System-level access
Administrator            # Admin privileges
Service accounts         # Often over-privileged
```

## 📋 Process Communication Checklist

### Network Services
- [ ] **Active connections** (`netstat -ano`)
- [ ] **Localhost services** (127.0.0.1 binding)
- [ ] **Process identification** (`tasklist`)
- [ ] **Service context** (user running service)
- [ ] **Web server detection** (port 80, 8080, 8443)
- [ ] **Administrative interfaces** (non-standard ports)

### Named Pipes
- [ ] **Pipe enumeration** (`pipelist.exe` or `gci \\.\pipe\`)
- [ ] **Permission analysis** (`accesschk.exe -w \pipe\*`)
- [ ] **Everyone group access** (overly permissive pipes)
- [ ] **Custom application pipes** (non-standard names)
- [ ] **WRITE_DAC privileges** (permission modification)

### Attack Surface Assessment
- [ ] **SeImpersonatePrivilege** detection
- [ ] **Vulnerable service versions** 
- [ ] **Default configurations** (Splunk, FileZilla)
- [ ] **File upload capabilities** (web servers)
- [ ] **Administrative access** (localhost services)

## 💡 Key Takeaways

1. **Network services** running as privileged users provide direct escalation paths
2. **Localhost-only services** often lack security controls
3. **Named pipes** with excessive permissions enable privilege escalation
4. **Web servers** with SeImpersonatePrivilege lead to SYSTEM access
5. **Default configurations** frequently contain security weaknesses
6. **Service context matters** - identify which user runs each service

---

*Process communication analysis reveals privilege escalation opportunities through network services and inter-process communication vulnerabilities.* 