# 🟠 Joomla Discovery & Enumeration

> **🎯 Objective:** Master the identification, enumeration, and intelligence gathering techniques for Joomla installations to build comprehensive attack profiles for the second most popular CMS platform.

## Overview

Joomla powers approximately 3% of all websites on the internet, making it the second most prevalent CMS after WordPress. Released in 2005, Joomla is a PHP-based CMS using MySQL backend, enhanced with over 7,000 extensions and 1,000+ templates. Understanding Joomla architecture and enumeration techniques is crucial for comprehensive web application assessments.

**Key Statistics:**
- **3.5% CMS market share** - Second largest after WordPress
- **2.7+ million installations** worldwide (via public API data)
- **7,000+ extensions** and **1,000+ templates** available
- **Notable users:** eBay, Yamaha, Harvard University, UK government
- **"Jumla" means "all together"** in Swahili

---

## Joomla Architecture & Components

### Core Directory Structure
```
/administrator/          # Administrative backend
/bin/                   # Command-line scripts
/cache/                 # Temporary cache files
/cli/                   # Command-line interface
/components/            # Core and third-party components
/images/                # Media files and uploads
/includes/              # Core include files
/installation/          # Installation scripts (should be removed)
/language/              # Language files
/layouts/               # Layout files
/libraries/             # Core libraries
/logs/                  # Error and access logs
/modules/               # Site modules
/plugins/               # System plugins
/templates/             # Site templates/themes
/tmp/                   # Temporary files
configuration.php       # Main configuration file
index.php              # Main entry point
README.txt             # Version information
robots.txt             # Search engine directives
```

### User Role Hierarchy
```
Super Administrator → Full system access + core configuration
Administrator      → Site management + user administration  
Manager           → Content management + some admin functions
Publisher         → Publish and edit all articles
Editor            → Edit all articles (cannot publish)
Author            → Create and edit own articles
Registered        → Basic user access + profile editing
```

---

## Discovery & Fingerprinting

### Initial Identification Techniques

#### Method 1: HTML Meta Generator Tag
```bash
# Search for Joomla generator tag in page source
curl -s http://target.com | grep -i joomla

# Example output:
<meta name="generator" content="Joomla! - Open Source Content Management" />
```

#### Method 2: robots.txt Analysis
```bash
# Check robots.txt for Joomla-specific directories
curl -s http://target.com/robots.txt

# Typical Joomla robots.txt indicators:
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

#### Method 3: Favicon Detection
```bash
# Check for default Joomla favicon
curl -I http://target.com/favicon.ico

# Joomla sites often use distinctive favicon
# Compare hash with known Joomla favicon hashes
```

#### Method 4: Directory Structure Probing
```bash
# Test for Joomla-specific directories
curl -I http://target.com/administrator/
curl -I http://target.com/components/
curl -I http://target.com/modules/
curl -I http://target.com/plugins/
curl -I http://target.com/templates/

# Look for 200/403 responses indicating directory existence
```

---

## Version Detection Strategies

### Core Version Identification

#### Method 1: README.txt File
```bash
# Extract version from README.txt
curl -s http://target.com/README.txt | head -n 10

# Example output shows version info:
1- What is this?
* This is a Joomla! installation/upgrade package to version 3.x
* Joomla! Official site: https://www.joomla.org
* Joomla! 3.9 version history - https://docs.joomla.org/...
```

#### Method 2: XML Manifest Files
```bash
# Check administrator manifest for precise version
curl -s http://target.com/administrator/manifests/files/joomla.xml | xmllint --format -

# Extract version from XML:
curl -s http://target.com/administrator/manifests/files/joomla.xml | grep -oP '<version>\K[^<]+'

# Example output: 3.9.4
```

#### Method 3: Cache XML Version
```bash
# Alternative version detection via cache plugin
curl -s http://target.com/plugins/system/cache/cache.xml | grep version

# Output contains approximate version information
```

#### Method 4: JavaScript File Analysis
```bash
# Check media directory for version-specific JS files
curl -s http://target.com/media/system/js/ | grep -oP 'core-\K[0-9.]+'

# Look for version indicators in script filenames
```

### Language and Locale Detection
```bash
# Identify site language configuration
curl -s http://target.com/language/en-GB/en-GB.xml | head -n 5

# Check for multiple language support
ls -la /language/
```

---

## Manual Enumeration Techniques

### Template Discovery & Analysis

#### Active Template Identification
```bash
# Extract template information from page source
curl -s http://target.com/ | grep -i template

# Look for template-specific CSS/JS files:
# /templates/[TEMPLATE_NAME]/css/
# /templates/[TEMPLATE_NAME]/js/
```

#### Template Directory Enumeration
```bash
# List available templates
curl -s http://target.com/templates/

# Common default templates:
# - beez3
# - protostar (Joomla 3.x default)
# - cassiopeia (Joomla 4.x default)
```

### Component & Extension Discovery

#### Core Component Enumeration
```bash
# Test for common Joomla components
components=(
    "com_content"
    "com_users" 
    "com_contact"
    "com_newsfeeds"
    "com_search"
    "com_weblinks"
    "com_banners"
    "com_media"
)

for comp in "${components[@]}"; do
    curl -I "http://target.com/index.php?option=$comp"
done
```

#### Plugin Directory Analysis
```bash
# Enumerate plugin directories
curl -s http://target.com/plugins/

# Common plugin categories:
# - authentication
# - content
# - editors
# - search
# - system
# - user
```

#### Module Discovery
```bash
# Check for exposed module directories
curl -s http://target.com/modules/

# Look for custom modules and configurations
find /modules -name "*.xml" -type f
```

### Configuration File Analysis

#### Database Configuration
```bash
# Attempt to access configuration file (usually protected)
curl -s http://target.com/configuration.php

# If accessible, contains database credentials:
# public $host = 'localhost';
# public $user = 'db_user';
# public $password = 'db_password';
# public $db = 'joomla_db';
```

### Admin Panel Discovery

#### Administrative Access Points
```bash
# Standard admin login locations
curl -I http://target.com/administrator/
curl -I http://target.com/administrator/index.php

# Alternative admin paths (less common)
curl -I http://target.com/admin/
curl -I http://target.com/backend/
```

---

## Automated Enumeration Tools

### DroopeScan - Multi-CMS Scanner

#### Installation & Setup
```bash
# Install via pip
sudo pip3 install droopescan

# Verify installation
droopescan -h

# Alternative: Manual installation
git clone https://github.com/droope/droopescan.git
cd droopescan
pip install -r requirements.txt
```

#### Basic Joomla Scanning
```bash
# Comprehensive Joomla scan
droopescan scan joomla --url http://target.com

# Example output interpretation:
[+] Possible version(s):
    3.8.10
    3.8.11
    3.8.12
    3.8.13

[+] Possible interesting urls found:
    Detailed version information. - http://target.com/administrator/manifests/files/joomla.xml
    Login page. - http://target.com/administrator/
    License file. - http://target.com/LICENSE.txt
```

#### Advanced DroopeScan Options
```bash
# Scan with threads and timeout control
droopescan scan joomla --url http://target.com --threads 10 --timeout 30

# Enumerate specific components
droopescan scan joomla --url http://target.com --enumerate p  # plugins
droopescan scan joomla --url http://target.com --enumerate t  # themes

# Output to file
droopescan scan joomla --url http://target.com --output json > joomla_scan.json
```

### JoomlaScan - Legacy Python Tool

#### Installation & Dependencies
```bash
# Download JoomlaScan
git clone https://github.com/drego85/JoomlaScan.git
cd JoomlaScan

# Install Python 2.7 dependencies (tool requirement)
sudo python2.7 -m pip install urllib3
sudo python2.7 -m pip install certifi  
sudo python2.7 -m pip install bs4
sudo python2.7 -m pip install requests
```

#### JoomlaScan Execution
```bash
# Basic scan with component enumeration
python2.7 joomlascan.py -u http://target.com

# Example findings:
Component found: com_actionlogs
Component found: com_admin  
Component found: com_banners
Explorable Directory > http://target.com/components/com_ajax/
LICENSE file found > http://target.com/administrator/components/com_admin/admin.xml
```

### Custom Enumeration Scripts

#### Component Brute Force Script
```bash
#!/bin/bash
# joomla-component-enum.sh

target="$1"
components_file="joomla_components.txt"

# Common Joomla components wordlist
cat > $components_file << EOF
com_content
com_users
com_contact
com_newsfeeds
com_search
com_weblinks
com_banners
com_media
com_menus
com_modules
com_plugins
com_templates
EOF

echo "[+] Enumerating Joomla components on $target"

while IFS= read -r component; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$target/index.php?option=$component")
    if [ "$response" = "200" ]; then
        echo "[+] Found: $component"
    fi
done < "$components_file"
```

---

## Version-Specific Intelligence

### Joomla 3.x Series Analysis
```bash
# Joomla 3.x specific features and files
curl -s http://target.com/templates/protostar/  # Default 3.x template
curl -s http://target.com/media/jui/            # jQuery UI integration

# Common 3.x vulnerabilities to research:
# - SQL injection in various components
# - Directory traversal vulnerabilities
# - Authentication bypasses
```

### Joomla 4.x Series Analysis  
```bash
# Joomla 4.x specific indicators
curl -s http://target.com/templates/cassiopeia/ # Default 4.x template
curl -s http://target.com/api/                  # New API endpoints

# Modern framework indicators
curl -s http://target.com/ | grep -i "bootstrap"
curl -s http://target.com/ | grep -i "vue"
```

### Legacy Version Detection
```bash
# Joomla 1.5/2.5 legacy indicators (rarely seen)
curl -s http://target.com/templates/beez/       # Legacy template
curl -s http://target.com/libraries/joomla/     # Legacy library structure
```

---

## Authentication & Brute Force Attacks

### User Enumeration Limitations

#### Login Error Analysis
```bash
# Joomla returns generic error messages
curl -X POST http://target.com/administrator/index.php \
  -d "username=admin&passwd=wrongpass&task=login"

# Generic response:
"Warning: Username and password do not match or you do not have an account yet."

# No username enumeration via error messages (unlike WordPress)
```

### Brute Force Attack Strategies

#### Default Credential Testing
```bash
# Common default credentials to test
admin:admin
admin:password
admin:123456
administrator:admin
root:root
```

#### Custom Brute Force Script
```bash
#!/bin/bash
# joomla-brute.py equivalent in bash

target="$1"
userlist="$2"
passlist="$3"

while IFS= read -r username; do
    while IFS= read -r password; do
        response=$(curl -s -X POST "$target/administrator/index.php" \
            -d "username=$username&passwd=$password&task=login" \
            -c cookies.txt)
        
        if [[ $response != *"Username and password do not match"* ]]; then
            echo "[+] Success: $username:$password"
            exit 0
        fi
    done < "$passlist"
done < "$userlist"
```

#### Metasploit Brute Force Module
```bash
# Using Metasploit for Joomla brute force
msfconsole
use auxiliary/scanner/http/joomla_bruteforce_login
set RHOSTS target.com
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

---

## Joomla-Specific Vulnerability Patterns

### Common Security Issues

#### Installation Directory Exposure
```bash
# Check if installation directory exists (should be removed)
curl -I http://target.com/installation/

# If accessible, may reveal:
# - Database configuration
# - System information
# - Installation logs
```

#### Configuration Backup Files
```bash
# Look for configuration backups
curl -I http://target.com/configuration.php.bak
curl -I http://target.com/configuration.php.old
curl -I http://target.com/configuration.php~
```

#### Directory Listing Vulnerabilities
```bash
# Test for directory listing on key folders
directories=(
    "/administrator/components/"
    "/components/"
    "/modules/"
    "/plugins/"
    "/templates/"
    "/images/"
    "/media/"
)

for dir in "${directories[@]}"; do
    curl -s "http://target.com$dir" | grep -q "Index of" && echo "Directory listing: $dir"
done
```

#### Component-Specific Vulnerabilities
```bash
# Research component versions for CVEs
curl -s http://target.com/administrator/components/com_admin/admin.xml | grep version
curl -s http://target.com/components/com_content/ | grep -i version

# Cross-reference with CVE databases
# - JVN (Japan Vulnerability Notes)
# - CVE Details
# - Exploit-DB
```

---

## Intelligence Gathering Workflow

### Comprehensive Enumeration Checklist

#### Phase 1: Initial Discovery
- [ ] **Joomla Confirmation** - Meta tags, robots.txt, directory structure
- [ ] **Version Detection** - README.txt, XML manifests, cache files
- [ ] **Directory Listing** - Check for exposed directories
- [ ] **Admin Panel Location** - Confirm administrator access

#### Phase 2: Component Analysis
- [ ] **Active Template** - Identification and version detection
- [ ] **Component Discovery** - Enumerate installed components
- [ ] **Plugin Enumeration** - System and content plugins
- [ ] **Module Analysis** - Site and administrative modules

#### Phase 3: Vulnerability Research
- [ ] **CVE Mapping** - Map versions to known vulnerabilities
- [ ] **Configuration Review** - Default settings and misconfigurations
- [ ] **Extension Security** - Third-party component vulnerabilities

#### Phase 4: Authentication Assessment
- [ ] **Default Credentials** - Test common username/password combinations
- [ ] **Brute Force Viability** - Assess account lockout policies
- [ ] **Admin Access Methods** - Alternative authentication mechanisms

---

## Global Joomla Statistics API

### Version Distribution Analysis
```bash
# Query Joomla public statistics API
curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool

# Analyze version distribution for targeting
curl -s https://developer.joomla.org/stats/cms_version | jq '.data.cms_version'

# Example output showing 2.7M+ installations:
{
    "data": {
        "cms_version": {
            "3.5": 13,
            "3.6": 24.29,
            "3.8": 18.84,
            "3.9": 30.28,
            "4.0": 1.52
        },
        "total": 2776276
    }
}
```

### Geographic and Technology Statistics
```bash
# Additional API endpoints for intelligence
curl -s https://developer.joomla.org/stats/php_version | jq .
curl -s https://developer.joomla.org/stats/db_type | jq .
curl -s https://developer.joomla.org/stats/server_os | jq .
```

---

## HTB Academy Lab Solutions

### Lab 1: Version Fingerprinting
**Question:** "Fingerprint the Joomla version in use on http://app.inlanefreight.local (Format: x.x.x)"

**Solution Methodology:**
```bash
# Method 1: XML Manifest (Most Accurate)
curl -s http://app.inlanefreight.local/administrator/manifests/files/joomla.xml | grep -oP '<version>\K[^<]+'

# Method 2: README.txt Analysis
curl -s http://app.inlanefreight.local/README.txt | head -n 10 | grep -i version

# Method 3: Cache XML File
curl -s http://app.inlanefreight.local/plugins/system/cache/cache.xml | grep -oP 'version="[^"]*"'

# Method 4: DroopeScan Verification
droopescan scan joomla --url http://app.inlanefreight.local

# Expected format: 3.9.4 (or similar version number)
```

### Lab 2: Admin Password Discovery
**Question:** "Find the password for the admin user on http://app.inlanefreight.local"

**Solution Methodology:**
```bash
# Method 1: Default Credentials Testing
curl -X POST http://app.inlanefreight.local/administrator/index.php \
  -d "username=admin&passwd=admin&task=login" \
  -v

# Method 2: Common Password List
passwords=(
    "admin"
    "password" 
    "123456"
    "password123"
    "admin123"
)

for pass in "${passwords[@]}"; do
    response=$(curl -s -X POST "http://app.inlanefreight.local/administrator/index.php" \
        -d "username=admin&passwd=$pass&task=login")
    
    if [[ $response != *"Username and password do not match"* ]]; then
        echo "Found password: $pass"
        break
    fi
done

# Method 3: Custom Brute Force Script
python3 joomla-brute.py -u http://app.inlanefreight.local \
  -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
  -usr admin

# Expected answer: admin (weak default configuration)
```

---

## Professional Documentation

### Enumeration Findings Template
```
=== Joomla Discovery Report ===

Target: [URL]
Discovery Date: [DATE]

== Core Information ==
Joomla Version: [VERSION]
Template: [TEMPLATE NAME] v[VERSION]
Admin Panel: [URL/administrator/]

== Installed Components ==
[COMPONENT NAME] - [DISCOVERY METHOD]

== System Modules ==
[MODULE NAME] - [STATUS/VERSION]

== Security Findings ==
[HIGH/MEDIUM/LOW] - [VULNERABILITY DESCRIPTION]
Evidence: [SCREENSHOT/REQUEST-RESPONSE]
CVE: [IF APPLICABLE]

== Recommended Actions ==
1. [IMMEDIATE SECURITY UPDATES]
2. [CONFIGURATION IMPROVEMENTS]
3. [MONITORING RECOMMENDATIONS]
```

---

## Defensive Considerations

### Security Hardening Recommendations
```bash
# Essential Joomla security steps
1. Remove /installation/ directory after setup
2. Rename /administrator/ directory to custom path
3. Enable two-factor authentication
4. Implement strong passwords and account policies
5. Regular core and extension updates
6. File permission hardening (644 for files, 755 for directories)
```

### Monitoring and Detection
```bash
# Log locations to monitor
/logs/error.php          # Error logs
/administrator/logs/     # Admin activity logs

# File integrity monitoring
find /administrator -name "*.php" -type f -exec md5sum {} \; > joomla_hashes.txt
```

---

## Next Steps

After Joomla enumeration, proceed to:
1. **[Joomla Attacks & Exploitation](joomla-attacks.md)** - Weaponizing discovered vulnerabilities
2. **[Component-Specific Attacks](joomla-component-attacks.md)** - Extension exploitation techniques
3. **[Privilege Escalation](joomla-privilege-escalation.md)** - Administrative access and persistence

**💡 Key Takeaway:** Joomla enumeration requires systematic analysis of version indicators, component discovery, and security configuration assessment. While less common than WordPress, Joomla installations often contain unique vulnerabilities in custom components and configurations that reward thorough enumeration efforts. 