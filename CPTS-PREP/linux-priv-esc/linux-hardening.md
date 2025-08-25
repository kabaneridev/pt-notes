# 🛡️ Linux Hardening

## 🎯 Overview

Comprehensive Linux hardening eliminates most privilege escalation opportunities through systematic security configuration, regular updates, and proper access controls.

## 🔄 Updates and Patching

### Critical Update Practices
```bash
# Ubuntu/Debian automatic updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# RHEL/CentOS automatic updates
sudo yum install yum-cron
sudo systemctl enable yum-cron

# Check for available updates
apt list --upgradable
dnf check-update
```

### Kernel Security Updates
```bash
# Prioritize kernel updates (eliminates kernel exploits)
apt list --upgradable | grep linux-image
sudo apt update && sudo apt upgrade linux-image-generic

# Check current vs available kernel
uname -r
apt list --installed | grep linux-image
```

## 🔧 Configuration Management

### File System Hardening
```bash
# Audit SUID/SGID binaries
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null > suid_audit.txt
find / -type f -perm -2000 -exec ls -la {} \; 2>/dev/null > sgid_audit.txt

# Remove unnecessary SUID bits
sudo chmod u-s /path/to/unnecessary/suid/binary

# Find world-writable files
find / -type f -perm -002 2>/dev/null

# Find world-writable directories
find / -type d -perm -002 2>/dev/null
```

### Service Configuration
```bash
# Use absolute paths in scripts and cron jobs
# BAD:  tar czf backup.tar.gz *
# GOOD: /bin/tar czf backup.tar.gz *

# Secure cron permissions
chmod 600 /etc/crontab
chown root:root /etc/cron.d/*

# Remove unnecessary services
systemctl list-units --state=enabled
sudo systemctl disable unnecessary_service
```

### Credential Security
```bash
# Remove cleartext credentials
grep -r "password\|secret" /etc/ /opt/ /var/ 2>/dev/null

# Secure bash history
export HISTCONTROL=ignoreboth
export HISTSIZE=0

# Clean sensitive files
shred -vfz -n 3 sensitive_file
```

## 👥 User Management

### Account Hardening
```bash
# Limit user accounts
grep "/bin/bash\|/bin/sh" /etc/passwd

# Strong password policy
sudo apt install libpam-pwquality
# Edit /etc/security/pwquality.conf

# Password aging
sudo chage -M 90 username  # 90-day expiration
sudo chage -l username     # Check settings

# Lock unused accounts
sudo usermod -L unused_user
sudo usermod -s /sbin/nologin service_account
```

### Group Management
```bash
# Audit dangerous groups
getent group lxd docker disk adm shadow

# Remove users from dangerous groups
sudo deluser username docker
sudo deluser username lxd

# Review sudo permissions
sudo visudo
# Remove wildcards, use absolute paths
```

## 🔍 Security Controls

### Enable Security Features
```bash
# SELinux (RHEL/CentOS)
sudo setenforce 1
getenforce

# AppArmor (Ubuntu/Debian)
sudo systemctl enable apparmor
sudo aa-status

# Firewall
sudo ufw enable
sudo ufw default deny incoming
```

### Logging and Monitoring
```bash
# Enable audit logging
sudo systemctl enable auditd
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /bin/su -p x -k privilege_escalation

# Monitor SUID executions
sudo auditctl -a always,exit -F arch=b64 -S execve -C uid!=euid -k suid_exec

# Log sudo usage
sudo visudo
# Add: Defaults logfile="/var/log/sudo.log"
```

## 🔬 Security Auditing

### Lynis Security Scanner
```bash
# Download and run Lynis
git clone https://github.com/CISOfy/lynis.git
cd lynis

# Run security audit
sudo ./lynis audit system

# Review results
# Hardening index: 60-100 [############        ]
# Tests performed: 256
# Warnings and suggestions provided
```

### Custom Hardening Check
```bash
#!/bin/bash
echo "=== LINUX HARDENING AUDIT ==="

echo "[+] Kernel version and updates:"
uname -r
apt list --upgradable 2>/dev/null | grep linux-image | head -3

echo "[+] SUID binaries count:"
find / -type f -perm -4000 2>/dev/null | wc -l

echo "[+] World-writable files:"
find / -type f -perm -002 2>/dev/null | head -5

echo "[+] Dangerous group memberships:"
for group in lxd docker disk adm; do
    members=$(getent group $group 2>/dev/null | cut -d: -f4)
    if [ ! -z "$members" ]; then
        echo "  $group: $members"
    fi
done

echo "[+] Services running as root:"
ps aux | grep "^root" | grep -v "^\[" | wc -l

echo "[+] Password policy:"
grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS" /etc/login.defs 2>/dev/null

echo "[+] Sudo configuration issues:"
sudo -l 2>/dev/null | grep -E "NOPASSWD|\*|ALL"
```

## 🔑 Hardening Checklist

### Critical Actions
- [ ] **Update kernel** - Eliminate kernel exploits
- [ ] **Remove unnecessary SUID** - Audit and remove dangerous SUID bits
- [ ] **Fix sudo configurations** - Use absolute paths, remove wildcards
- [ ] **Clean dangerous groups** - Remove users from lxd, docker, disk
- [ ] **Secure cron jobs** - Absolute paths, proper permissions
- [ ] **Clear credentials** - Remove plaintext passwords from files
- [ ] **Enable logging** - Audit privilege escalation attempts

### Advanced Hardening
- [ ] **SELinux/AppArmor** - Mandatory access controls
- [ ] **Regular audits** - Lynis, custom scripts, compliance checks
- [ ] **Service minimization** - Remove unnecessary packages/services
- [ ] **Network segmentation** - Limit lateral movement
- [ ] **Monitoring** - Real-time privilege escalation detection

## 📊 Compliance Frameworks

### Standards to Consider
- **DISA STIGs** - Security Technical Implementation Guides
- **CIS Benchmarks** - Center for Internet Security
- **ISO 27001** - Information security management
- **PCI-DSS** - Payment card industry standards
- **HIPAA** - Healthcare information protection

## 🔧 Automation Tools

### Configuration Management
```bash
# Puppet - Configuration automation
# SaltStack - Infrastructure management  
# Ansible - IT automation
# Chef - Infrastructure as code
```

### Monitoring Integration
```bash
# Zabbix - Network and server monitoring
# Nagios - IT infrastructure monitoring
# Slack/Email - Alert integration
# SIEM - Security event correlation
```

---

*Proper Linux hardening eliminates the vast majority of privilege escalation vectors - systematic application of security controls, regular updates, and continuous monitoring create robust defenses against privilege escalation attacks.* 