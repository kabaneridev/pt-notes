# Prevention & Hardening - HTB Academy Guide

## Overview

Comprehensive security measures to prevent file inclusion vulnerabilities and harden systems against LFI/RFI attacks.

---

## Secure Coding Practices

### Input Validation and Sanitization

**Whitelist Approach:**
```php
<?php
// Secure file inclusion with whitelist
$allowed_files = ['home', 'about', 'contact', 'products'];
$page = $_GET['page'] ?? 'home';

if (in_array($page, $allowed_files)) {
    include($page . '.php');
} else {
    include('error.php');
}
?>
```

**Using basename() Function:**
```php
<?php
// Strip directory traversal attempts
$file = basename($_GET['file']);
$file = './templates/' . $file . '.php';

if (file_exists($file)) {
    include($file);
}
?>
```

---

## Web Server Configuration Hardening

### PHP Configuration (php.ini)

**Essential Security Settings:**
```ini
# Disable dangerous functions
allow_url_fopen = Off
allow_url_include = Off

# Restrict file access
open_basedir = /var/www/html

# Disable dangerous functions
disable_functions = system,exec,shell_exec,passthru,popen,proc_open

# Hide PHP version
expose_php = Off

# Limit file uploads
file_uploads = Off
upload_max_filesize = 1M
```

**HTB Academy Prevention Lab:**
```bash
# Find php.ini location
sudo find / -name php.ini 2>/dev/null
# Result: /etc/php/7.4/apache2/php.ini

# Edit disable_functions (line 312)
sudo nano /etc/php/7.4/apache2/php.ini
disable_functions = system,exec,shell_exec,passthru

# Restart Apache
sudo service apache2 restart

# Test result shows: "system() has been disabled for security reasons"
```

---

## Apache/Nginx Hardening

### Apache Security Configuration

**Security Headers:**
```apache
# Hide server information
ServerTokens Prod
ServerSignature Off

# Directory listing protection
Options -Indexes

# File access restrictions
<FilesMatch "\.(php|phtml|php3|php4|php5|php7)$">
    Order Deny,Allow
    Deny from all
    Allow from 127.0.0.1
</FilesMatch>
```

---

## Web Application Firewall (WAF) Protection

### ModSecurity Rules

**LFI Detection Rules:**
```apache
# Block common LFI patterns
SecRule ARGS "@detectXSS" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'LFI Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Block directory traversal
SecRule ARGS "@contains ../" \
    "id:1002,\
    phase:2,\
    block,\
    msg:'Directory Traversal Detected'"

# Block PHP wrappers
SecRule ARGS "@rx (?:php|data|expect|input)://" \
    "id:1003,\
    phase:2,\
    block,\
    msg:'PHP Wrapper Detected'"
```

---

## Container Security & Isolation

### Docker Implementation

**Secure Dockerfile Example:**
```dockerfile
FROM php:7.4-apache

# Create non-root user
RUN useradd -m -s /bin/bash webuser

# Set secure php.ini
COPY secure-php.ini /usr/local/etc/php/php.ini

# Copy application with restricted permissions
COPY --chown=webuser:webuser ./app /var/www/html

# Run as non-root
USER webuser

EXPOSE 80
```

---

## Monitoring and Logging

### Log Analysis for LFI Detection

**Detection Patterns:**
```bash
# Monitor for LFI attempts
tail -f /var/log/apache2/access.log | grep -E "\.\./|php://|data://|expect://"

# Automated detection script
grep -E "(\.\.\/|php:\/\/|data:\/\/)" /var/log/apache2/access.log | \
awk '{print $1, $7}' | sort | uniq -c | sort -nr
```

---

## Continuous Security Testing

### Automated Vulnerability Scanning

**Regular Security Assessments:**
```bash
# Automated LFI scanning
nikto -h http://localhost -Tuning 5

# Custom security testing script
./test_lfi_protection.sh http://localhost
```

---

*[Content continues with SIEM integration and incident response...]*

*This guide covers prevention and hardening techniques from HTB Academy's File Inclusion module.* 