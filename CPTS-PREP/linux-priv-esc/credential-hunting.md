# 🔍 Credential Hunting

## 🎯 Overview

Systematic search for stored credentials across the Linux file system. Credentials may be found in configuration files, scripts, history files, backups, databases, and various application-specific locations.

## 📁 Common Credential Locations

### Configuration Files
```bash
# All config files
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

# Database configs
find / -name "*.conf" -exec grep -l "password\|pass\|pwd" {} \; 2>/dev/null

# Web application configs
find /var/www -name "wp-config.php" 2>/dev/null
find /var/www -name "config.php" 2>/dev/null
find /etc -name "*sql*" -o -name "*db*" 2>/dev/null
```

### WordPress Database Credentials
```bash find / -name "flag4.txt" -exec cat {} \; 2>/dev/null
# WordPress config files
find / -name "wp-config.php" -exec cat {} \; 2>/dev/null

# Extract DB credentials
grep 'DB_USER\|DB_PASSWORD\|DB_HOST' /var/www/*/wp-config.php
```

## 🔑 SSH Key Discovery

### SSH Key Locations
```bash
# Current user SSH keys
ls -la ~/.ssh/

# All user SSH directories
find /home -name ".ssh" -type d 2>/dev/null

# SSH private keys system-wide
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null

# SSH config files
find / -name "ssh_config" -o -name "sshd_config" 2>/dev/null
```

### SSH Key Analysis
```bash
# Check known_hosts for lateral movement targets
cat ~/.ssh/known_hosts
cat /home/*/.ssh/known_hosts 2>/dev/null

# Read private keys (if accessible)
find /home -name "id_*" -not -name "*.pub" -exec cat {} \; 2>/dev/null
```

## 📝 History & Log Files

### Command History Files
```bash
# Bash history files
cat ~/.bash_history
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null

# Other history files
find / -type f \( -name "*_hist" -o -name "*_history" \) 2>/dev/null

# Search for passwords in history
history | grep -i "pass\|pwd\|key\|secret"
```

### Log File Investigation
```bash
# System logs
grep -r "password\|secret\|key" /var/log/ 2>/dev/null

# Application logs
find /var/log -type f -exec grep -l "password\|credential" {} \; 2>/dev/null

# Web server logs
grep -E "(password|login|auth)" /var/log/apache2/* 2>/dev/null
grep -E "(password|login|auth)" /var/log/nginx/* 2>/dev/null
```

## 🗃️ Backup & Archive Files

### Backup File Discovery
```bash
# Common backup extensions
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null

# Compressed archives
find / -name "*.tar*" -o -name "*.zip" -o -name "*.gz" 2>/dev/null

# Database backups
find / -name "*.sql" -o -name "*.db" -o -name "*.sqlite*" 2>/dev/null
```

## 💾 Database & Application Files

### Database Credential Hunting
```bash
# MySQL/MariaDB
find / -name "*.cnf" -exec grep -l "password" {} \; 2>/dev/null
cat /etc/mysql/my.cnf 2>/dev/null

# PostgreSQL
find / -name "pg_hba.conf" -o -name "postgresql.conf" 2>/dev/null

# SQLite databases
find / -name "*.sqlite*" -o -name "*.db" 2>/dev/null | head -10
```

### Web Application Files
```bash
# PHP application configs
find /var/www -name "*.php" -exec grep -l "password\|mysql\|database" {} \; 2>/dev/null

# Python application configs
find / -name "settings.py" -o -name "config.py" 2>/dev/null

# Configuration directories
ls -la /opt/*/config/ 2>/dev/null
ls -la /etc/*/conf.d/ 2>/dev/null
```

## 📧 Mail & Spool Directories

### Mail System Investigation
```bash
# Mail directories
ls -la /var/mail/ 2>/dev/null
ls -la /var/spool/mail/ 2>/dev/null

# Cron spool
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# Print spool
ls -la /var/spool/cups/ 2>/dev/null
```

## 🔍 Comprehensive Credential Search

### File Content Search
```bash
# Search for password patterns
grep -r -i "password\|passwd" /etc/ 2>/dev/null | head -20
grep -r -i "user.*pass\|pass.*user" /var/ 2>/dev/null | head -10

# Search for specific keywords
grep -r -E "(password|passwd|pwd|secret|key|token|credential)" /home/ 2>/dev/null

# Database connection strings
grep -r -E "(mysql://|postgres://|mongodb://)" / 2>/dev/null
```

### Specific Application Hunting
```bash
# WordPress
find / -name "wp-config.php" -exec grep -H "DB_" {} \; 2>/dev/null

# Drupal
find / -name "settings.php" -exec grep -H "database\|password" {} \; 2>/dev/null

# Joomla
find / -name "configuration.php" -exec grep -H "password\|user" {} \; 2>/dev/null

# Apache/Nginx configs
grep -r "auth\|password" /etc/apache2/ /etc/nginx/ 2>/dev/null
```

## 🔐 Advanced Credential Discovery

### Environment Variables & Memory
```bash
# Check environment for secrets
env | grep -i "pass\|key\|secret\|token"

# Process environment variables
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret"

# Command line arguments
cat /proc/*/cmdline 2>/dev/null | tr '\0' '\n' | grep -i "pass\|key\|secret"
```

### Hidden & Dot Files
```bash
# Hidden files in user directories
find /home -name ".*" -type f -exec grep -l "password\|key" {} \; 2>/dev/null

# Dot files system-wide
find / -name ".*" -type f -size +0c 2>/dev/null | grep -E "(config|rc|profile)"

# Recently modified files (might contain fresh credentials)
find / -type f -mtime -7 -exec grep -l "password" {} \; 2>/dev/null | head -10
```

## 🚀 Quick Credential Hunt Script

```bash
#!/bin/bash
echo "=== CREDENTIAL HUNTING ==="

echo "[+] WordPress configs:"
find / -name "wp-config.php" -exec grep -H "DB_" {} \; 2>/dev/null

echo "[+] SSH keys:"
find /home -name "id_*" 2>/dev/null | grep -v ".pub"

echo "[+] Config files with passwords:"
grep -r "password" /etc/ 2>/dev/null | head -5

echo "[+] History files:"
find / -name "*history*" -type f 2>/dev/null

echo "[+] Backup files:"
find / -name "*.bak" -o -name "*.backup" 2>/dev/null | head -10

echo "[+] Database files:"
find / -name "*.db" -o -name "*.sql" 2>/dev/null | head -10

echo "[+] Environment variables:"
env | grep -i "pass\|key\|secret" | head -5
```

## 🎯 High-Value Target Files

### Priority File Types
```bash
# Web configs
*.php (wp-config.php, config.php)
*.xml (configuration.xml, web.xml)
*.properties (application.properties)

# Database files
*.cnf (my.cnf)
*.conf (postgresql.conf)
*.db, *.sqlite

# Backup files
*.bak, *.backup, *.old
*.tar, *.gz, *.zip

# Application configs
settings.py, config.py
.env, .properties
```

### Common Credential Patterns
```bash
# Database credentials
"username=", "password=", "passwd="
"DB_USER", "DB_PASSWORD", "DATABASE_URL"

# API keys
"api_key=", "secret_key=", "access_token="
"API_SECRET", "SECRET_KEY"

# Service credentials
"admin_user", "admin_pass"
"service_user", "service_password"
```

## 🔑 Password Validation

### Test Discovered Credentials
```bash
# Test against local users
su - username  # Use discovered password

# SSH to localhost/other hosts
ssh user@localhost
ssh user@discovered_host

# Database connections
mysql -u user -p'password'
psql -U user -h localhost
```

## ⚠️ Credential Security

### What to Look For
- **Plaintext passwords** in config files
- **Connection strings** with embedded credentials
- **SSH private keys** without passphrases
- **Database credentials** for privilege escalation
- **Service account passwords** for lateral movement

### Common Mistakes
- WordPress `wp-config.php` with default credentials
- Backup files containing production passwords
- Development configs deployed to production
- SSH keys in world-readable locations
- Passwords in bash history or scripts

---

*Credential hunting transforms file system enumeration into actionable intelligence - discovering stored secrets that enable privilege escalation and lateral movement throughout the target environment.* 