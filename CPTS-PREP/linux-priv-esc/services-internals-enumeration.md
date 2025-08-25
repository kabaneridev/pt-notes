# 🔧 Linux Services & Internals Enumeration

## 🎯 Overview

Deep enumeration of running services, internal processes, user activities, and system internals to identify privilege escalation vectors and attack opportunities.

## 🌐 Network Internals

### Network Interfaces & Connectivity
```bash
# Network interfaces (pivot opportunities)
ip a
ifconfig -a

# Hosts file analysis
cat /etc/hosts

# Check for internal networks and additional interfaces
```

## 👥 User Activity Analysis

### Login History & Current Users
```bash
# User login history
lastlog

# Currently logged users
w
who

# Recent user activity
last
```

**Look for:**
- Active admin users
- Login patterns and timing
- Remote connections (SSH sessions)
- Shared accounts

### Command History Investigation
```bash
# Current user history
history

# All user history files
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null

# Bash history files
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
```

**Search for Sensitive Commands:**
```bash
history | grep -i "pass\|key\|secret\|sudo\|su\|mysql\|ssh"
```

## ⏰ Scheduled Tasks & Automation

### Cron Job Enumeration
```bash
# System cron jobs
ls -la /etc/cron*
cat /etc/crontab

# User cron jobs
crontab -l
ls -la /var/spool/cron/crontabs/

# Systemd timers
systemctl list-timers
```

**Analysis Points:**
- Scripts running as root
- Writable paths in cron jobs
- File permission issues
- Backup scripts with credentials

## 📦 Installed Software & Packages

### Package Analysis
```bash
# Installed packages
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee installed_pkgs.list

# Sudo version (vulnerability check)
sudo -V

# Available binaries
ls -l /bin /usr/bin/ /usr/sbin/
```

### GTFObins Cross-Reference
```bash
# Check for GTFObins binaries
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```

## 🔍 Process & Service Analysis

### Running Processes
```bash
# All running processes
ps aux

# Processes by user
ps aux | grep root
ps aux | grep www-data

# Process tree
pstree -p

# Services and sockets
systemctl list-units --type=service
systemctl list-sockets
ss -tulpn
```

### Process Investigation
```bash
# Trace system calls (detailed analysis)
strace ping -c1 target_ip

# Process command lines
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

# Memory maps
cat /proc/*/maps 2>/dev/null | grep -E "(rwx|rw-)" | head
```

## 📁 Configuration & Script Discovery

### Configuration Files
```bash
# Find all config files
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null

# Database configs
find / -name "*sql*" -type f 2>/dev/null
find / -name "*db*" -type f 2>/dev/null

# Web application configs
find /var/www -name "*.conf" -o -name "config.*" 2>/dev/null
find /etc -name "*apache*" -o -name "*nginx*" 2>/dev/null
```

### Script Discovery
```bash
# All shell scripts
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

# Recently modified scripts
find / -name "*.sh" -mtime -7 2>/dev/null

# Writable scripts
find / -type f -name "*.sh" -writable 2>/dev/null
```

## 🔍 System Internals

### /proc Filesystem Analysis
```bash
# System information from /proc
cat /proc/version
cat /proc/cpuinfo
cat /proc/meminfo

# Network information
cat /proc/net/tcp
cat /proc/net/udp
cat /proc/net/route

# Module information
lsmod
cat /proc/modules
```

### File System Details
```bash
# Recently modified files
find / -type f -mtime -1 2>/dev/null | head -20

# Large files (potential data stores)
find / -type f -size +10M 2>/dev/null

# Files modified in last 24 hours
find / -type f -mtime 0 2>/dev/null
```

## 🛠️ Available Tools Assessment

### Development Tools
```bash
# Compilers and interpreters
which gcc g++ python python3 perl ruby node java
dpkg -l | grep -E "(python|perl|ruby|gcc|java)"

# Network tools
which netcat nc nmap curl wget socat telnet

# System tools  
which strace ltrace gdb
```

### Useful Binaries for Privesc
```bash
# SUID/SGID binaries
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

# Writable directories in PATH
echo $PATH | tr ':' '\n' | xargs ls -ld 2>/dev/null

# World-writable files
find / -type f -perm -002 2>/dev/null | head -20
```

## 📊 Quick Enumeration Script

```bash
#!/bin/bash
echo "=== LINUX SERVICES & INTERNALS ENUMERATION ==="

echo "[+] Network Interfaces:"
ip a | grep -E "(inet|ens|eth|lo)"

echo "[+] Currently Logged Users:"
w

echo "[+] Running Services (root):"
ps aux | grep root | head -10

echo "[+] Cron Jobs:"
ls -la /etc/cron* 2>/dev/null

echo "[+] SUID Binaries:"
find / -type f -perm -4000 2>/dev/null | head -10

echo "[+] Recent Files:"
find / -type f -mtime -1 2>/dev/null | head -10

echo "[+] Available Tools:"
which python python3 gcc netcat nc curl wget 2>/dev/null

echo "[+] Sudo Version:"
sudo -V 2>/dev/null | head -1
```

## 🎯 Key Targets to Identify

### High-Value Information
- **Active admin sessions** - Target for credential stealing
- **Vulnerable services** - Running as root with known CVEs  
- **Scheduled tasks** - Cron jobs with misconfigurations
- **Config files** - Containing passwords or sensitive data
- **Development tools** - Compilers for exploit compilation
- **Network tools** - For lateral movement and pivoting

### Attack Vector Prioritization
1. **SUID/SGID binaries** with GTFObins entries
2. **Root processes** with configuration vulnerabilities
3. **Writable cron jobs** or scripts executed by root
4. **Readable config files** with embedded credentials
5. **Development environments** with compilation capabilities

---

*Services and internals enumeration reveals the operational heartbeat of the system - identifying running processes, user activities, and system configurations that can be leveraged for privilege escalation.* 