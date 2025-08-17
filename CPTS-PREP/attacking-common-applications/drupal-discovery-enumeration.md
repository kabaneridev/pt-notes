# 🅳 Drupal Discovery & Enumeration

> **🎯 Objective:** Master the identification, enumeration, and intelligence gathering techniques for Drupal installations to complete comprehensive CMS security assessment capabilities across the three major content management platforms.

## Overview

Drupal, launched in **2001**, represents the third pillar of the **CMS Trinity** alongside WordPress and Joomla. While holding a smaller market share (**2.4% of CMS market**), Drupal powers critical infrastructure including **56% of government websites globally** and **33 Fortune 500 companies**. Its enterprise focus and robust architecture make it a high-value target requiring specialized enumeration techniques.

**Key Drupal Statistics:**
- **1.5% of internet sites** (over 1.1 million installations)
- **5% of top 1 million websites** worldwide
- **7% of top 10,000 sites** (enterprise concentration)
- **950,000+ active instances** (Update Status module data)
- **Available in 100 languages** with global deployment
- **Major users:** Tesla, Warner Bros Records, government agencies

---

## Drupal Architecture & Fundamentals

### Core Concepts & Structure

#### Content Management via Nodes
```
Node System Architecture:
/node/1     → Blog post
/node/2     → Article  
/node/3     → Page content
/node/4     → Poll/Survey
/node/[ID]  → Any content type

Node = Universal content container in Drupal
```

#### User Role Hierarchy
```
Administrator      → Complete system control and configuration
Authenticated User → Login access with role-based permissions
Anonymous         → Public visitors (read-only by default)

Custom Roles:
Editor            → Content editing permissions
Moderator         → Comment and user management
Content Manager   → Specific content type management
```

#### Directory Structure Analysis
```
/core/               # Drupal 8+ core files
/modules/            # Contributed and custom modules
/themes/             # Site themes and templates
/sites/              # Multi-site configurations
/profiles/           # Installation profiles
/vendor/             # Third-party libraries (Composer)
/libraries/          # External libraries (Drupal 7)

Configuration Files:
sites/default/settings.php      # Database and site configuration
.htaccess                      # Apache configuration
robots.txt                     # Search engine directives
```

---

## Discovery & Fingerprinting Techniques

### Initial Identification Methods

#### Method 1: Generator Meta Tag Detection
```bash
# Search for Drupal generator meta tag
curl -s http://target.com | grep -i drupal

# Example outputs:
<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
<meta name="generator" content="Drupal 7 (http://drupal.org)" />
```

#### Method 2: Powered by Footer Analysis
```bash
# Look for Drupal attribution in page footer
curl -s http://target.com | grep -i "powered by"

# Typical findings:
<span>Powered by <a href="https://www.drupal.org">Drupal</a></span>
```

#### Method 3: Node-Based URL Pattern Recognition
```bash
# Test for node-based URL structure
curl -I http://target.com/node/1
curl -I http://target.com/node/2
curl -I http://target.com/?q=node/1

# Drupal-specific URL patterns:
/node/[number]          # Content nodes
/admin                  # Administrative interface
/user                   # User management
/user/login            # Login page
/?q=node/[number]      # Clean URLs disabled
```

#### Method 4: Standard File Detection
```bash
# Check for Drupal-specific files
curl -I http://target.com/CHANGELOG.txt
curl -I http://target.com/README.txt
curl -I http://target.com/INSTALL.txt
curl -I http://target.com/LICENSE.txt
curl -I http://target.com/MAINTAINERS.txt

# Look for robots.txt Drupal indicators
curl -s http://target.com/robots.txt | grep -E "(node|admin|user)"

# Example robots.txt content:
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
```

#### Method 5: CSS/JavaScript Fingerprinting
```bash
# Search for Drupal-specific assets
curl -s http://target.com | grep -E "(drupal|misc/|sites/)"

# Common asset patterns:
/misc/drupal.css               # Drupal 6/7
/core/misc/drupal.css          # Drupal 8+
/sites/default/files/          # File uploads
/modules/system/system.css     # System styles
/themes/[theme]/css/          # Theme assets
```

---

## Version Detection Strategies

### Core Version Identification

#### Method 1: CHANGELOG.txt Analysis (Primary)
```bash
# Extract version from CHANGELOG.txt (most reliable)
curl -s http://target.com/CHANGELOG.txt | head -n 3

# Example outputs:
Drupal 7.57, 2018-02-21
Drupal 8.9.1, 2020-06-17
Drupal 9.3.6, 2022-02-16

# Automated version extraction
curl -s http://target.com/CHANGELOG.txt | grep -m1 "^Drupal" | awk '{print $2}' | tr -d ','

# Check if CHANGELOG.txt is blocked
curl -I http://target.com/CHANGELOG.txt
# HTTP/1.1 404 Not Found (indicates newer/hardened installation)
```

#### Method 2: Generator Meta Tag Version
```bash
# Extract version from HTML meta generator
curl -s http://target.com | grep -oP 'content="Drupal \K[0-9.]+'

# Example extraction:
curl -s http://target.com | grep generator | grep -oP 'Drupal \K[0-9.]+'
```

#### Method 3: Core JavaScript File Analysis
```bash
# Drupal 7 version detection via jQuery
curl -s http://target.com/misc/jquery.js | head -n 5

# Drupal 8+ version detection
curl -s http://target.com/core/misc/drupal.js | head -n 10

# Search for version strings in assets
curl -s http://target.com | grep -oP '/core/misc/drupal\.js\?v=\K[0-9.]+'
```

#### Method 4: CSS Timestamp Analysis
```bash
# Check CSS files for version indicators
curl -s http://target.com | grep -oP 'system\.css\?[a-z0-9]+'

# Extract modification timestamps
curl -s http://target.com/modules/system/system.css | head -n 3
```

#### Method 5: Update Status Module Detection
```bash
# Check for update.php (indicates version)
curl -I http://target.com/update.php

# Version information in installation profile
curl -s http://target.com/profiles/standard/standard.info
```

### Version-Specific Indicators

#### Drupal 6 Characteristics
```bash
# Directory structure indicators
curl -I http://target.com/misc/drupal.js
curl -I http://target.com/includes/
curl -I http://target.com/modules/system/
curl -I http://target.com/themes/garland/    # Default theme

# jQuery version (typically 1.2.x)
curl -s http://target.com/misc/jquery.js | grep -oP 'jQuery \K[0-9.]+'
```

#### Drupal 7 Characteristics  
```bash
# Drupal 7 specific files and paths
curl -I http://target.com/misc/            # Misc directory
curl -I http://target.com/sites/all/       # All sites directory
curl -I http://target.com/themes/bartik/   # Default Bartik theme

# jQuery version (typically 1.4.x)
curl -s http://target.com/misc/jquery.js | head -n 3
```

#### Drupal 8+ Characteristics
```bash
# Drupal 8+ modern structure
curl -I http://target.com/core/            # Core directory
curl -I http://target.com/vendor/          # Composer dependencies
curl -I http://target.com/themes/classy/   # Classy base theme

# Symfony integration detection
curl -s http://target.com | grep -i symfony

# Twig template engine indicators
curl -s http://target.com | grep -E "\.html\.twig"
```

---

## Manual Enumeration Techniques

### Content Discovery via Node Enumeration

#### Sequential Node Discovery
```bash
# Enumerate content nodes systematically
for i in {1..100}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/node/$i")
    if [ "$response" = "200" ]; then
        echo "[+] Found node: $i"
        curl -s "http://target.com/node/$i" | grep -oP '<title>\K[^<]+' | head -n 1
    fi
done

# Alternative with clean URLs disabled
for i in {1..50}; do
    curl -s -o /dev/null -w "Node $i: %{http_code}\n" "http://target.com/?q=node/$i"
done
```

#### Content Type Analysis
```bash
# Identify content types from node URLs
curl -s http://target.com/node/1 | grep -oP 'content-type-\K[a-z-]+'

# Common Drupal content types:
# - article (blog posts, news)
# - page (static pages)
# - webform (contact forms)
# - product (e-commerce)
# - event (calendar entries)
```

### Administrative Interface Discovery

#### Admin Panel Enumeration
```bash
# Standard administrative paths
curl -I http://target.com/admin
curl -I http://target.com/admin/config
curl -I http://target.com/admin/content
curl -I http://target.com/admin/structure
curl -I http://target.com/admin/appearance
curl -I http://target.com/admin/modules
curl -I http://target.com/admin/people

# Check admin response codes
admin_paths=(
    "/admin"
    "/admin/config" 
    "/admin/content"
    "/admin/structure"
    "/admin/appearance"
    "/admin/modules"
    "/admin/people"
    "/admin/reports"
)

for path in "${admin_paths[@]}"; do
    echo "Checking: $path"
    curl -s -o /dev/null -w "%{http_code}" "http://target.com$path"
done
```

#### User Management Interface
```bash
# User-related paths
curl -I http://target.com/user
curl -I http://target.com/user/login
curl -I http://target.com/user/register
curl -I http://target.com/user/password

# User profile enumeration (if accessible)
for i in {1..10}; do
    curl -s -o /dev/null -w "User $i: %{http_code}\n" "http://target.com/user/$i"
done
```

### Module & Theme Discovery

#### Active Module Enumeration
```bash
# Common module paths to test
modules=(
    "admin_menu"
    "block"
    "comment"
    "contact"
    "field"
    "file"
    "filter"
    "forum"
    "image"
    "menu"
    "node"
    "path"
    "search"
    "system"
    "taxonomy"
    "user"
    "views"
    "webform"
)

echo "[+] Enumerating Drupal modules:"
for module in "${modules[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/modules/$module/")
    if [ "$response" != "404" ]; then
        echo "[+] Module found: $module (HTTP $response)"
    fi
done
```

#### Theme Discovery & Analysis
```bash
# Enumerate active themes
curl -s http://target.com | grep -oP '/themes/[^/]+/' | sort -u

# Common Drupal themes to test
themes=(
    "bartik"        # Drupal 7 default
    "garland"       # Drupal 6 default  
    "seven"         # Admin theme
    "stark"         # Minimal theme
    "classy"        # Drupal 8 base
    "stable"        # Drupal 8 base
    "olivero"       # Drupal 9 default
    "claro"         # Drupal 9 admin
)

for theme in "${themes[@]}"; do
    curl -s -o /dev/null -w "Theme $theme: %{http_code}\n" "http://target.com/themes/$theme/"
done
```

#### Custom Module Discovery
```bash
# Look for custom modules in sites directory
curl -s http://target.com/sites/all/modules/ | grep -oP 'href="[^"]*"' | cut -d'"' -f2

# Check for development modules (dangerous if enabled)
dev_modules=(
    "devel"
    "stage_file_proxy"
    "reroute_email"
    "field_ui"
    "views_ui"
)

for module in "${dev_modules[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com/admin/modules")
    echo "Checking dev module: $module"
done
```

---

## Automated Enumeration Tools

### DroopeScan - Advanced Drupal Scanner

#### Installation & Setup
```bash
# Install via pip (recommended)
sudo pip3 install droopescan

# Verify installation
droopescan --help

# Alternative: Manual installation
git clone https://github.com/droope/droopescan.git
cd droopescan
pip3 install -r requirements.txt
python3 droopescan -h
```

#### Basic Drupal Scanning
```bash
# Comprehensive Drupal enumeration
droopescan scan drupal -u http://target.com

# Example output interpretation:
[+] Plugins found:
    php http://target.com/modules/php/
    views http://target.com/modules/views/

[+] Themes found:
    bartik http://target.com/themes/bartik/

[+] Possible version(s):
    7.56
    7.57
    7.58

[+] Possible interesting urls found:
    Default admin - http://target.com/user/login
```

#### Advanced DroopeScan Options
```bash
# Enumerate specific components
droopescan scan drupal -u http://target.com --enumerate p    # plugins only
droopescan scan drupal -u http://target.com --enumerate t    # themes only
droopescan scan drupal -u http://target.com --enumerate v    # version only

# Control scan intensity
droopescan scan drupal -u http://target.com --threads 10 --timeout 30

# Scan multiple targets
droopescan scan drupal --url-file targets.txt

# Output to file
droopescan scan drupal -u http://target.com --output json > drupal_scan.json
```

#### DroopeScan Output Analysis
```bash
# Parse JSON output for specific information
cat drupal_scan.json | jq '.plugins[].name'
cat drupal_scan.json | jq '.themes[].name'  
cat drupal_scan.json | jq '.version[]'

# Filter high-confidence results
cat drupal_scan.json | jq '.plugins[] | select(.confidence > 75)'
```

### Custom Drupal Enumeration Scripts

#### Comprehensive Module Brute Force
```bash
#!/bin/bash
# drupal-module-enum.sh

target="$1"
wordlist="/usr/share/seclists/Discovery/Web-Content/CMS/drupal_modules.txt"

if [ ! -f "$wordlist" ]; then
    echo "[!] Wordlist not found. Creating basic module list..."
    cat > drupal_modules.txt << 'EOF'
admin_menu
backup_migrate
captcha
cck
ctools
date
devel
entity
features
field_group
google_analytics
imageapi
imagefield
imce
jquery_ui
libraries
link
location
menu_block
module_filter
panels
pathauto
recaptcha
rules
token
transliteration
views
webform
wysiwyg
EOF
    wordlist="drupal_modules.txt"
fi

echo "[+] Enumerating Drupal modules on $target"
echo "[+] Using wordlist: $wordlist"

while IFS= read -r module; do
    # Check both Drupal 7 and 8+ paths
    for path in "/sites/all/modules/$module" "/modules/$module" "/modules/contrib/$module"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$target$path/")
        if [ "$response" = "200" ] || [ "$response" = "403" ]; then
            echo "[+] Found module: $module ($path) - HTTP $response"
            
            # Try to get module info
            info_response=$(curl -s "$target$path/${module}.info")
            if [ -n "$info_response" ]; then
                version=$(echo "$info_response" | grep -oP 'version = "\K[^"]+')
                description=$(echo "$info_response" | grep -oP 'description = "\K[^"]+')
                echo "    Version: $version"
                echo "    Description: $description"
            fi
        fi
    done
done < "$wordlist"
```

#### Node Content Discovery Script
```bash
#!/bin/bash
# drupal-node-discovery.sh

target="$1"
max_nodes="${2:-100}"

echo "[+] Discovering Drupal content nodes on $target"
echo "[+] Testing up to $max_nodes nodes..."

found_nodes=()

for i in $(seq 1 $max_nodes); do
    # Test both clean URLs and query parameters
    for url_format in "/node/$i" "/?q=node/$i"; do
        response=$(curl -s -o /dev/null -w "%{http_code}" "$target$url_format")
        if [ "$response" = "200" ]; then
            echo "[+] Node $i: $target$url_format"
            found_nodes+=("$i")
            
            # Extract title and content type
            content=$(curl -s "$target$url_format")
            title=$(echo "$content" | grep -oP '<title>\K[^<]+' | head -n 1)
            content_type=$(echo "$content" | grep -oP 'content-type-\K[a-z-]+' | head -n 1)
            
            echo "    Title: $title"
            echo "    Type: $content_type"
            break
        fi
    done
done

echo "[+] Summary: Found ${#found_nodes[@]} accessible nodes"
printf '%s\n' "${found_nodes[@]}"
```

---

## Configuration & Security Analysis

### Settings.php Analysis

#### Database Configuration Discovery
```bash
# Attempt to access settings.php (usually protected)
curl -s http://target.com/sites/default/settings.php

# Common settings.php locations
settings_paths=(
    "/sites/default/settings.php"
    "/sites/all/settings.php"
    "/sites/example.com/settings.php"
)

# Look for backup/development files
backup_configs=(
    "/sites/default/settings.php.bak"
    "/sites/default/settings.php.old" 
    "/sites/default/settings.php~"
    "/sites/default/settings.local.php"
    "/sites/default/development.settings.php"
)

for config in "${backup_configs[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com$config")
    if [ "$response" = "200" ]; then
        echo "[!] Accessible config found: $config"
        curl -s "http://target.com$config" | grep -E "(database|password|host)"
    fi
done
```

#### Multi-site Configuration Detection
```bash
# Check for multi-site setup
curl -s http://target.com/sites/ | grep -oP 'href="[^"]*"' | grep -v '\.\.'

# Common multi-site indicators
curl -I http://target.com/sites/sites.php
curl -I http://target.com/sites/example.sites.php

# Domain-specific configurations
curl -I http://target.com/sites/example.com/
curl -I http://target.com/sites/www.example.com/
```

### Update Status & Security Headers

#### Update Status Analysis
```bash
# Check for update.php access
curl -I http://target.com/update.php

# Look for update status information
curl -s http://target.com/admin/reports/updates 2>/dev/null | grep -i "security update"

# Available updates endpoint (if accessible)
curl -s http://target.com/admin/modules/update
```

#### Security Header Analysis
```bash
# Analyze Drupal security headers
curl -I http://target.com

# Key headers to examine:
# X-Drupal-Cache: HIT/MISS (caching status)
# X-Generator: Drupal (version info)
# Set-Cookie: SESS* (session management)
# X-Frame-Options: (clickjacking protection)
# Content-Security-Policy: (XSS protection)
```

---

## HTB Academy Lab Solutions

### Lab: Drupal Version Detection
**Question:** "Identify the Drupal version number in use on http://drupal-qa.inlanefreight.local"

**Solution Methodology:**

#### Step 1: Environment Setup
```bash
# Add VHost entry to /etc/hosts
echo "STMIP drupal-qa.inlanefreight.local" >> /etc/hosts

# Verify connectivity
curl -I http://drupal-qa.inlanefreight.local/
```

#### Step 2: Primary Version Detection Method
```bash
# Method 1: CHANGELOG.txt (Most Reliable)
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | head -n 5

# Extract first version entry
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m1 "^Drupal"

# Expected output format:
Drupal 7.30, 2014-07-24

# Clean version extraction:
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m1 "Drupal" | awk '{print $2}' | tr -d ','
```

#### Step 3: Alternative Detection Methods
```bash
# Method 2: Generator Meta Tag
curl -s http://drupal-qa.inlanefreight.local/ | grep -i generator

# Method 3: README.txt Analysis
curl -s http://drupal-qa.inlanefreight.local/README.txt | head -n 10

# Method 4: DroopeScan Verification
droopescan scan drupal -u http://drupal-qa.inlanefreight.local

# Method 5: Manual CSS/JS Analysis
curl -s http://drupal-qa.inlanefreight.local/misc/jquery.js | head -n 3
```

#### Step 4: Verify Answer Format
```bash
# HTB Lab Answer: 7.30
# Full version from CHANGELOG: Drupal 7.30, 2014-07-24
# Submit format: 7.30 (version number only)

# Verification command:
curl -s http://drupal-qa.inlanefreight.local/CHANGELOG.txt | grep -m1 "Drupal" | awk '{print $2}' | tr -d ','
# Output: 7.30
```

### Expected Lab Answers

**Target:** `http://drupal-qa.inlanefreight.local`  
**Answer:** `7.30`  
**Method:** CHANGELOG.txt analysis  
**Full Version String:** `Drupal 7.30, 2014-07-24`

---

## Version-Specific Vulnerability Research

### Drupal 7 Security Landscape

#### Common Drupal 7 Vulnerabilities
```bash
# Research known vulnerabilities for identified version
searchsploit "drupal 7"
searchsploit "drupal 7.30"

# Key vulnerability classes:
# - SQL Injection (Drupalgeddon)
# - Remote Code Execution
# - Cross-Site Scripting
# - Authentication Bypass
# - Privilege Escalation
```

#### Drupalgeddon Vulnerability Series
```bash
# CVE-2014-3704 (Drupalgeddon 1) - SQL Injection
# Affects: Drupal 7.0 - 7.31
# Impact: Remote Code Execution

# CVE-2018-7600 (Drupalgeddon 2) - Remote Code Execution  
# Affects: Drupal 6.x, 7.x, 8.x
# Impact: Complete system compromise

# CVE-2018-7602 (Drupalgeddon 3) - Remote Code Execution
# Affects: Drupal 7.x, 8.x (partial fix bypass)
# Impact: Authentication bypass to RCE
```

### Module-Specific Security Research

#### High-Risk Module Categories
```bash
# File upload modules (arbitrary file upload)
- imagefield
- filefield  
- media
- imce

# User input modules (injection vulnerabilities)
- webform
- contact
- comment
- forum

# Development modules (information disclosure)
- devel
- stage_file_proxy
- field_ui
- views_ui

# Third-party integrations (authentication bypass)
- ldap
- saml
- oauth
```

#### Module Vulnerability Research
```bash
# Research specific module vulnerabilities
module="webform"
version="7.x-3.20"

# Search exploit databases
searchsploit "drupal $module"
searchsploit "$module $version"

# Check Drupal security advisories
curl -s "https://www.drupal.org/security" | grep -i "$module"

# CVE database search
curl -s "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=drupal+$module"
```

---

## Intelligence Gathering Workflow

### Comprehensive Enumeration Checklist

#### Phase 1: Initial Discovery
- [ ] **Drupal Confirmation** - Generator meta tag, powered by footer, node URLs
- [ ] **Version Detection** - CHANGELOG.txt, README.txt, meta tags, assets
- [ ] **Architecture Analysis** - Directory structure, clean URLs, multi-site
- [ ] **Admin Interface Discovery** - Login page, admin paths accessibility

#### Phase 2: Content Analysis  
- [ ] **Node Enumeration** - Sequential content discovery and type analysis
- [ ] **User Interface Discovery** - Registration, password reset, profile access
- [ ] **Content Type Mapping** - Articles, pages, custom types identification
- [ ] **URL Structure Analysis** - Clean URLs vs query parameters

#### Phase 3: Module & Theme Discovery
- [ ] **Active Module Enumeration** - Core and contributed modules identification
- [ ] **Theme Discovery** - Active and available themes analysis
- [ ] **Custom Code Detection** - Site-specific modules and modifications
- [ ] **Development Module Check** - Dangerous dev modules exposure

#### Phase 4: Configuration & Security Assessment
- [ ] **Configuration File Analysis** - Settings.php accessibility and backups
- [ ] **Multi-site Configuration** - Additional site discovery
- [ ] **Update Status Review** - Security updates and patch levels
- [ ] **Security Header Analysis** - Protection mechanisms evaluation

---

## Defensive Considerations

### Security Hardening Recommendations

#### Core Security Measures
```bash
# Essential Drupal security steps:
1. Remove/rename update.php after updates
2. Disable PHP module in production
3. Remove development modules (devel, field_ui, views_ui)
4. Block access to CHANGELOG.txt and README.txt
5. Implement proper file permissions (644 files, 755 directories)
6. Enable security updates and monitoring
```

#### File System Hardening
```bash
# Recommended file permissions
find /var/www/drupal/ -type f -exec chmod 644 {} \;
find /var/www/drupal/ -type d -exec chmod 755 {} \;
chmod 444 /var/www/drupal/sites/default/settings.php

# Block access to sensitive files via .htaccess
<Files "*.info">
  Order deny,allow
  Deny from all
</Files>
```

### Monitoring and Detection

#### Attack Pattern Recognition
```bash
# Monitor for common attack patterns:
# - CHANGELOG.txt access attempts
# - Node enumeration (sequential /node/X requests)
# - Admin path brute forcing
# - Module directory enumeration
# - Settings.php access attempts

# Log analysis for Drupal attacks
tail -f /var/log/apache2/access.log | grep -E "(CHANGELOG|node/[0-9]+|admin|settings\.php)"
```

#### Security Monitoring Setup
```bash
# File integrity monitoring for key files
find /var/www/drupal/ -name "*.php" -type f -exec md5sum {} \; > drupal_hashes.txt

# Monitor configuration changes
inotifywait -m -r -e modify /var/www/drupal/sites/default/settings.php
```

---

## Cross-Module Integration

### Drupal in Multi-CMS Environments

#### CMS Fingerprinting Automation
```bash
#!/bin/bash
# cms-identify.sh

target="$1"

echo "[+] CMS Identification for $target"

# WordPress detection
if curl -s "$target/wp-admin/" | grep -q "WordPress"; then
    echo "[+] WordPress detected"
fi

# Joomla detection  
if curl -s "$target/" | grep -qi "joomla"; then
    echo "[+] Joomla detected"
fi

# Drupal detection
if curl -s "$target/" | grep -qi "drupal"; then
    echo "[+] Drupal detected"
    version=$(curl -s "$target/CHANGELOG.txt" | grep -m1 "Drupal" 2>/dev/null)
    echo "    Version: $version"
fi
```

#### Integration with Other Modules
- **[File Upload Attacks](../file-upload-attacks/)** - Drupal media module vulnerabilities
- **[Command Injection](../command-injection/)** - Drupal module command execution
- **[SQL Injection](../databases/)** - Drupalgeddon and database attacks
- **[XSS Attacks](../xss-cross-site-scripting.md)** - Drupal input filtering bypasses

---

## Next Steps

After Drupal enumeration, proceed to:
1. **[Drupal Attacks & Exploitation](drupal-attacks.md)** - Drupalgeddon and module vulnerabilities
2. **[Servlet Containers](tomcat-enumeration.md)** - Java application attacks  
3. **[Development Tools](jenkins-enumeration.md)** - CI/CD and build system attacks

**💡 Key Takeaway:** Drupal enumeration requires understanding of the **node-based content system**, **version-specific file locations**, and **module architecture**. While less common than WordPress, Drupal installations often power **critical enterprise and government infrastructure**, making thorough enumeration essential for comprehensive security assessments. 