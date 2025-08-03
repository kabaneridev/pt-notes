# Preventing File Upload Vulnerabilities

> **🛡️ Defense-in-Depth:** Implementing comprehensive security measures against file upload attacks

## Overview

Throughout this module, we have discussed various methods of exploiting different file upload vulnerabilities. In any penetration test or bug bounty exercise we take part in, we must be able to report action points to be taken to rectify the identified vulnerabilities.

This section will discuss what we can do to ensure that our file upload functions are securely coded and safe against exploitation and what action points we can recommend for each type of file upload vulnerability.

---

## Extension Validation

> **📋 Best Practice:** Use both whitelist and blacklist approaches for comprehensive protection

### Dual Validation Approach

**The Problem:** File extensions play an important role in how files and scripts are executed, as most web servers and web applications tend to use file extensions to set their execution properties.

**The Solution:** While whitelisting extensions is always more secure, it is recommended to use both by whitelisting the allowed extensions and blacklisting dangerous extensions. This way, the blacklist will prevent uploading malicious scripts if the whitelist is ever bypassed (e.g., `shell.php.jpg`).

### Secure Implementation Example

**PHP Implementation:**
```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// Blacklist test
if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// Whitelist test
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

**Key Differences:**
- **Blacklist:** Checks if the extension exists **anywhere** within the file name
- **Whitelist:** Checks if the file name **ends** with the allowed extension

### Frontend + Backend Validation

**Defense Strategy:**
- Apply both **back-end** and **front-end** file validation
- Even if front-end validation can be easily bypassed, it reduces the chances of users uploading unintended files
- Prevents accidental triggering of defense mechanisms and false alerts

---

## Content Validation

> **🔍 Deep Inspection:** Validate both extension and file content to prevent bypass attacks

### Why Content Validation Matters

**Critical Principle:** Extension validation is not enough. We should also validate the file content. We cannot validate one without the other and must always validate both the file extension and its content.

**Key Requirement:** Always ensure that the file extension matches the file's content.

### Comprehensive Validation Example

**Multi-Layer PHP Validation:**
```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// Whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// Content test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only PNG images are allowed";
        die();
    }
}
```

### Validation Layers

1. **File Extension** - Basic filename validation
2. **HTTP Content-Type Header** - Client-provided content type
3. **File Signature/Magic Bytes** - Actual file content analysis
4. **Cross-Validation** - Ensure all three match expected file type

---

## Upload Disclosure Prevention

> **🚫 Access Control:** Hide upload directories and control file access through secure download mechanisms

### Directory Access Restrictions

**Security Principle:** Avoid disclosing the uploads directory or providing direct access to the uploaded file.

**Best Practice:** Hide the uploads directory from end-users and only allow them to download uploaded files through a controlled download page.

### Secure Download Implementation

**Download Script Approach:**
```php
// download.php - Controlled file access
function secureDownload($fileId, $userId) {
    // 1. Validate user authorization
    if (!isAuthorized($userId, $fileId)) {
        http_response_code(403);
        die("Access denied");
    }
    
    // 2. Fetch file info from database
    $fileInfo = getFileInfo($fileId);
    if (!$fileInfo) {
        http_response_code(404);
        die("File not found");
    }
    
    // 3. Validate file path
    $filePath = validatePath($fileInfo['stored_name']);
    if (!$filePath || !file_exists($filePath)) {
        http_response_code(404);
        die("File not found");
    }
    
    // 4. Set security headers
    header('Content-Disposition: attachment; filename="' . $fileInfo['original_name'] . '"');
    header('Content-Type: ' . $fileInfo['mime_type']);
    header('X-Content-Type-Options: nosniff');
    
    // 5. Serve file
    readfile($filePath);
}
```

### Security Headers

**Essential Headers for File Downloads:**

1. **Content-Disposition: attachment**
   - Instructs browser to download rather than render inline
   - Prevents execution in browser context

2. **Content-Type: [appropriate-mime-type]**
   - Specifies correct MIME type
   - Ensures proper browser handling

3. **X-Content-Type-Options: nosniff**
   - Prevents browser MIME-type sniffing
   - Enforces strict adherence to specified Content-Type

### Authorization and Path Security

**Strict Authorization Checks:**
- Verify requested file is owned by authenticated user
- Prevent Insecure Direct Object Reference (IDOR) vulnerabilities

**Path Validation:**
- Avoid unvalidated user input in file paths
- Enforce strict allowlist of accessible files and directories
- Defend against Local File Inclusion (LFI) attacks

### File Storage Security

**Directory Protection:**
```apache
# .htaccess in uploads directory
<Files "*">
    Order Deny,Allow
    Deny from All
</Files>
```

**File Naming Strategy:**
1. **Randomize stored filenames** - Prevent direct access guessing
2. **Store original names in database** - Maintain user-friendly names
3. **Sanitize original names** - Prevent injection attacks
4. **Use UUID/hash for storage** - Ensure uniqueness and security

**Example Implementation:**
```php
// Generate secure storage name
$storedName = generateUUID() . '.dat';
$originalName = sanitizeFilename($_FILES['upload']['name']);

// Store in database
$stmt = $pdo->prepare("INSERT INTO files (user_id, original_name, stored_name, mime_type) VALUES (?, ?, ?, ?)");
$stmt->execute([$userId, $originalName, $storedName, $mimeType]);

// Move file with secured name
move_uploaded_file($_FILES['upload']['tmp_name'], $uploadDir . $storedName);
```

---

## Further Security Measures

> **🔐 Defense-in-Depth:** Additional hardening techniques for comprehensive protection

### System Function Restrictions

**Disable Dangerous Functions (PHP):**
```ini
; php.ini configuration
disable_functions = exec,shell_exec,system,passthru,popen,proc_open,file_get_contents,file_put_contents,fwrite,include,require
```

**Common Dangerous Functions to Disable:**
- `exec()` - Execute external programs
- `shell_exec()` - Execute shell commands
- `system()` - Execute system commands
- `passthru()` - Execute external programs and display output
- `popen()` - Open process file pointer
- `proc_open()` - Execute command and open file pointers

### Error Handling Security

**Secure Error Management:**
```php
// Bad - Exposes sensitive information
if (!move_uploaded_file($tmpName, $destination)) {
    die("Failed to move file from $tmpName to $destination");
}

// Good - Generic error message
if (!move_uploaded_file($tmpName, $destination)) {
    error_log("File upload failed: $tmpName -> $destination");
    die("File upload failed. Please try again.");
}
```

**Error Handling Principles:**
1. **Never expose system paths** in error messages
2. **Log detailed errors** server-side for debugging
3. **Display generic messages** to users
4. **Disable error display** in production environments

### Web Server Configuration

**Apache Configuration:**
```apache
# Disable PHP execution in uploads directory
<Directory "/var/www/uploads">
    php_flag engine off
    AddType text/plain .php .php3 .phtml .pht
    RemoveHandler .php .phtml .php3 .php4 .php5
</Directory>

# Restrict file access
<Files "*.php">
    Order Allow,Deny
    Deny from all
</Files>
```

**Nginx Configuration:**
```nginx
# Disable PHP execution in uploads
location /uploads {
    location ~ \.php$ {
        deny all;
        return 403;
    }
}
```

### Container and Infrastructure Security

**Isolation Strategies:**
1. **Separate Upload Server** - Isolate uploads from main application
2. **Containerized Processing** - Use Docker/containers for file processing
3. **Network Segmentation** - Restrict upload server network access
4. **Chroot Jails** - Limit file system access

**PHP Open Base Directory:**
```ini
; Restrict PHP file access
open_basedir = /var/www/html/:/tmp/:/var/tmp/
```

---

## Additional Security Checklist

> **✅ Comprehensive Protection:** Complete checklist for secure file upload implementation

### File Processing Security

**1. File Size Limits**
```php
// Set reasonable file size limits
if ($_FILES['upload']['size'] > 5000000) { // 5MB limit
    die("File too large");
}
```

**2. Malware Scanning**
```bash
# ClamAV integration example
clamscan --quiet --infected $uploaded_file
if [ $? -eq 1 ]; then
    echo "Malware detected"
    rm $uploaded_file
    exit 1
fi
```

**3. Library Updates**
- Keep all file processing libraries updated
- Monitor security advisories for image processing libraries
- Use latest versions of ImageMagick, GD, etc.

### Web Application Firewall (WAF)

**WAF Rules for Upload Protection:**
```apache
# ModSecurity rules example
SecRule FILES "@detectSQLi" \
    "id:1001,phase:2,block,msg:'SQL Injection in file'"

SecRule FILES "@detectXSS" \
    "id:1002,phase:2,block,msg:'XSS in file'"

SecRule ARGS:filename "@contains .." \
    "id:1003,phase:2,block,msg:'Directory traversal attempt'"
```

### Content Sanitization

**Image Reprocessing:**
```php
// Strip metadata and reprocess image
function sanitizeImage($inputPath, $outputPath) {
    $image = imagecreatefromjpeg($inputPath);
    if ($image === false) {
        return false;
    }
    
    // Create clean image without metadata
    $result = imagejpeg($image, $outputPath, 90);
    imagedestroy($image);
    
    return $result;
}
```

**Document Sanitization:**
- Use libraries that strip macros from documents
- Convert documents to safe formats (e.g., PDF to image)
- Validate document structure before processing

### Monitoring and Logging

**Security Event Logging:**
```php
function logSecurityEvent($event, $details) {
    $logEntry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'],
        'event' => $event,
        'details' => $details
    ];
    
    error_log(json_encode($logEntry), 3, '/var/log/security.log');
}

// Usage
if (detectMaliciousUpload($file)) {
    logSecurityEvent('malicious_upload_attempt', [
        'filename' => $file['name'],
        'size' => $file['size'],
        'type' => $file['type']
    ]);
}
```

### Rate Limiting

**Upload Rate Limiting:**
```php
// Simple rate limiting implementation
function checkUploadRate($userId) {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);
    
    $key = "upload_rate:$userId";
    $current = $redis->get($key) ?: 0;
    
    if ($current >= 10) { // 10 uploads per hour
        return false;
    }
    
    $redis->incr($key);
    $redis->expire($key, 3600); // 1 hour
    
    return true;
}
```

---

## Penetration Testing Checklist

> **🎯 Assessment Guide:** Checklist for evaluating upload security during pentests

### Security Assessment Points

**1. Extension Validation**
- [ ] Whitelist implementation present
- [ ] Blacklist implementation present
- [ ] Both frontend and backend validation
- [ ] Case sensitivity handling
- [ ] Double extension protection

**2. Content Validation**
- [ ] MIME type checking implemented
- [ ] File signature verification
- [ ] Content-Type header validation
- [ ] Cross-validation between extension and content

**3. Access Control**
- [ ] Upload directory hidden from direct access
- [ ] Controlled download mechanism
- [ ] Proper authorization checks
- [ ] File ownership validation

**4. System Hardening**
- [ ] Dangerous functions disabled
- [ ] Error messages sanitized
- [ ] File size limits enforced
- [ ] Upload rate limiting

**5. Infrastructure Security**
- [ ] WAF protection active
- [ ] Antivirus scanning enabled
- [ ] Proper file permissions
- [ ] Network segmentation

### Recommended Mitigations

When performing web penetration tests, use these points as a checklist and provide any missing ones to developers:

1. **Implement dual validation** (whitelist + blacklist)
2. **Add content validation** alongside extension checks
3. **Hide upload directories** and use controlled access
4. **Disable dangerous system functions**
5. **Implement comprehensive logging** and monitoring
6. **Add file size and rate limiting**
7. **Deploy WAF protection** as secondary defense
8. **Regular security updates** for all libraries
9. **Malware scanning** for all uploads
10. **Proper error handling** without information disclosure

Once all security measures are implemented, the web application should be relatively secure and not vulnerable to common file upload threats. 