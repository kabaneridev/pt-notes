# 🌐 WordPress Discovery & Enumeration

> **🎯 Objective:** Master the identification, enumeration, and intelligence gathering techniques for WordPress installations to build comprehensive attack profiles.

## Overview

WordPress powers approximately 32.5% of all websites on the internet, making it the most prevalent CMS we'll encounter during penetration testing. Understanding WordPress architecture, enumeration techniques, and vulnerability patterns is essential for successful web application assessments.

**Key Statistics:**
- **50,000+ plugins** and **4,100+ themes** available
- **54% of vulnerabilities** originate from plugins
- **31.5% from WordPress core**, **14.5% from themes**
- **8% of compromises** due to weak passwords
- **60% due to outdated versions**

---

## WordPress Architecture & Components

### Core Directory Structure
```
/wp-admin/          # Administrative backend
/wp-content/        # Themes, plugins, uploads
  /plugins/         # Third-party plugins
  /themes/          # WordPress themes
  /uploads/         # User-uploaded content
/wp-includes/       # Core WordPress files
wp-config.php       # Configuration file
wp-login.php        # Login page
xmlrpc.php          # XML-RPC interface
readme.html         # Version information
robots.txt          # Search engine directives
```

### User Role Hierarchy
```
Administrator  → Full administrative access + code execution potential
Editor        → Publish/manage all posts + plugin access
Author        → Publish/manage own posts
Contributor   → Write/manage posts (cannot publish)
Subscriber    → Browse posts + edit profile
```

---

## Discovery & Fingerprinting

### Initial Identification Techniques

#### Method 1: robots.txt Analysis
```bash
# Check robots.txt for WordPress indicators
curl -s http://target.com/robots.txt

# Typical WordPress robots.txt:
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/
Sitemap: https://target.com/wp-sitemap.xml
```

#### Method 2: HTML Meta Generator Tag
```bash
# Search for WordPress version in page source
curl -s http://target.com | grep -i wordpress

# Example output:
<meta name="generator" content="WordPress 5.8" />
```

#### Method 3: Directory Detection
```bash
# Test for common WordPress directories
curl -I http://target.com/wp-admin/
curl -I http://target.com/wp-content/
curl -I http://target.com/wp-login.php

# Look for redirects to wp-login.php (indicates WordPress)
```

#### Method 4: File Signature Detection
```bash
# Check for WordPress-specific files
curl -I http://target.com/readme.html
curl -I http://target.com/wp-config.php
curl -I http://target.com/xmlrpc.php
```

---

## Manual Enumeration Techniques

### Theme Identification & Analysis

#### Discovering Active Theme
```bash
# Extract theme information from page source
curl -s http://target.com/ | grep themes

# Example output shows Business Gravity theme:
<link rel='stylesheet' href='http://target.com/wp-content/themes/business-gravity/assets/css/bootstrap.min.css' />
```

#### Theme Version Detection
```bash
# Check theme directory for version files
curl -s http://target.com/wp-content/themes/business-gravity/readme.txt
curl -s http://target.com/wp-content/themes/business-gravity/style.css | grep Version
```

### Plugin Discovery & Enumeration

#### Source Code Analysis
```bash
# Search for plugin references in page source
curl -s http://target.com/ | grep plugins

# Example findings:
<link rel='stylesheet' href='/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' />
<script src='/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.8'></script>
```

#### Direct Plugin Testing
```bash
# Test for common plugins
curl -I http://target.com/wp-content/plugins/wp-super-cache/
curl -I http://target.com/wp-content/plugins/yoast-seo/
curl -I http://target.com/wp-content/plugins/contact-form-7/
```

#### Plugin Version Detection
```bash
# Check plugin readme files for version information
curl -s http://target.com/wp-content/plugins/mail-masta/readme.txt

# Look for version indicators in plugin files
curl -s http://target.com/wp-content/plugins/plugin-name/ | grep -i version
```

### Directory Listing Exploitation

#### Checking for Exposed Directories
```bash
# Test common WordPress directories for listing
curl -s http://target.com/wp-content/plugins/
curl -s http://target.com/wp-content/themes/
curl -s http://target.com/wp-content/uploads/

# Look for directory indexes that reveal file structure
```

### XML-RPC Discovery
```bash
# Test XML-RPC availability
curl -X POST http://target.com/xmlrpc.php

# XML-RPC can be used for:
# - Brute force attacks
# - DDoS amplification
# - Information disclosure
```

---

## User Enumeration Techniques

### Login Error Message Analysis

#### Username Enumeration via Login Form
```bash
# Test valid username with invalid password
curl -X POST http://target.com/wp-login.php \
  -d "log=admin&pwd=wrongpassword" \
  -v

# Response: "The password for username admin is incorrect."

# Test invalid username
curl -X POST http://target.com/wp-login.php \
  -d "log=nonexistent&pwd=password" \
  -v

# Response: "The username nonexistent is not registered on this site."
```

#### Author ID Enumeration
```bash
# Enumerate users via author parameter
for i in {1..10}; do
  curl -s "http://target.com/?author=$i" | grep -i "author"
done

# Look for redirects or author page content
```

#### REST API User Enumeration
```bash
# WordPress REST API user endpoint
curl -s http://target.com/wp-json/wp/v2/users | jq .

# Extract usernames from JSON response
curl -s http://target.com/wp-json/wp/v2/users | jq '.[].slug'
```

---

## Automated Enumeration with WPScan

### Installation & Setup
```bash
# Install WPScan
sudo gem install wpscan

# Get WPVulnDB API token (75 requests/day free)
# Register at https://wpvulndb.com/
```

### Basic Enumeration Scan
```bash
# Comprehensive WordPress enumeration
wpscan --url http://target.com --enumerate --api-token YOUR_API_TOKEN

# Specific enumeration options:
# ap = All plugins
# at = All themes  
# u  = Users
# m  = Media files
# cb = Config backups
```

### Advanced WPScan Usage

#### Plugin-Focused Enumeration
```bash
# Enumerate all plugins (including inactive)
wpscan --url http://target.com --enumerate ap --api-token YOUR_API_TOKEN

# Aggressive plugin detection
wpscan --url http://target.com --enumerate ap --plugins-detection aggressive
```

#### User Enumeration & Brute Force
```bash
# Enumerate users only
wpscan --url http://target.com --enumerate u

# Brute force discovered users
wpscan --url http://target.com --usernames admin,john --passwords passwords.txt
```

#### Custom Wordlists
```bash
# Use custom plugin/theme wordlists
wpscan --url http://target.com --enumerate ap --plugins-list custom_plugins.txt
```

### WPScan Output Analysis

#### Vulnerability Assessment
```bash
# Example WPScan output interpretation:
[!] Title: WordPress 5.4 to 5.8 - Data Exposure via REST API
    Fixed in: 5.8.1
    References:
     - https://wpvulndb.com/vulnerabilities/38dd7e87-9a22-48e2-bab1-dc79448ecdfb
     - CVE-2021-39200

[!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
    Fixed in: N/A
    References:
     - https://wpvulndb.com/vulnerabilities/f0f1a868-4462-4def-b4e7-1f1c5c534247
```

---

## Version Detection Strategies

### Core WordPress Version
```bash
# Multiple methods for version detection:

# 1. Meta generator tag
curl -s http://target.com | grep generator

# 2. RSS feed generator
curl -s http://target.com/?feed=rss2 | grep generator

# 3. readme.html file
curl -s http://target.com/readme.html | grep Version

# 4. Version parameter in scripts/styles
curl -s http://target.com | grep -oP 'ver=\K[0-9.]+'
```

### Plugin/Theme Versioning
```bash
# Version detection methods:

# 1. readme.txt files
curl -s http://target.com/wp-content/plugins/PLUGIN/readme.txt | grep "Stable tag"

# 2. CSS/JS version parameters  
curl -s http://target.com | grep -oP 'plugin-name.*?ver=\K[0-9.]+'

# 3. Plugin headers in PHP files
curl -s http://target.com/wp-content/plugins/PLUGIN/plugin-file.php | grep "Version:"
```

---

## Intelligence Gathering Workflow

### Comprehensive Enumeration Checklist

#### Phase 1: Initial Discovery
- [ ] **WordPress Confirmation** - robots.txt, directory structure, meta tags
- [ ] **Version Detection** - Core version identification
- [ ] **Directory Listing** - Check for exposed directories
- [ ] **XML-RPC Status** - Test availability and functionality

#### Phase 2: Component Analysis  
- [ ] **Active Theme** - Identification and version detection
- [ ] **Plugin Discovery** - Enumerate installed plugins
- [ ] **Plugin Versions** - Specific version identification
- [ ] **User Enumeration** - Valid username discovery

#### Phase 3: Vulnerability Mapping
- [ ] **CVE Research** - Map versions to known vulnerabilities
- [ ] **Configuration Issues** - Default credentials, exposed files
- [ ] **Custom Code Review** - Theme/plugin custom functionality

#### Phase 4: Attack Surface Assessment
- [ ] **Entry Points** - Login forms, comment sections, contact forms
- [ ] **File Upload** - Media upload functionality
- [ ] **Administrative Access** - wp-admin accessibility
- [ ] **API Endpoints** - REST API and XML-RPC availability

---

## Common Vulnerability Patterns

### High-Priority Findings

#### Outdated Core Installation
```bash
# Impact: Multiple CVEs affecting core functionality
# Detection: Version comparison with latest releases
# Risk: High - Core vulnerabilities often lead to RCE
```

#### Vulnerable Plugins
```bash
# Most Common: 
# - Contact Form 7 (various versions)
# - wpDiscuz (RCE vulnerabilities)
# - mail-masta (LFI vulnerabilities)
# - File Manager plugins (arbitrary file access)

# Detection Strategy:
# 1. Enumerate all plugins
# 2. Identify exact versions
# 3. Cross-reference with vulnerability databases
```

#### Default/Weak Credentials
```bash
# Common credentials to test:
admin:admin
admin:password
admin:123456
wordpress:wordpress

# Test against wp-login.php and wp-admin access
```

#### Directory Listing Enabled
```bash
# Check critical directories:
/wp-content/plugins/     # Plugin source code exposure
/wp-content/uploads/     # Uploaded file enumeration  
/wp-content/themes/      # Theme file access
```

---

## Example Discovery Session

### Target: blog.inlanefreight.local

#### Step 1: Initial Fingerprinting
```bash
# Confirm WordPress installation
curl -s http://blog.inlanefreight.local/robots.txt
# Output shows /wp-admin/ and /wp-content/ directories

# Check version
curl -s http://blog.inlanefreight.local | grep generator
# Output: <meta name="generator" content="WordPress 5.8" />
```

#### Step 2: Theme & Plugin Discovery
```bash
# Identify theme
curl -s http://blog.inlanefreight.local/ | grep themes
# Output: /wp-content/themes/business-gravity/

# Find plugins
curl -s http://blog.inlanefreight.local/ | grep plugins
# Output: contact-form-7, mail-masta, wpDiscuz plugins detected
```

#### Step 3: User Enumeration
```bash
# Test login error messages
curl -X POST http://blog.inlanefreight.local/wp-login.php -d "log=admin&pwd=test"
# Output: "The password for username admin is incorrect."
# Confirms 'admin' is a valid user
```

#### Step 4: Automated Validation
```bash
# WPScan confirmation
wpscan --url http://blog.inlanefreight.local --enumerate --api-token TOKEN
# Confirms findings and identifies additional vulnerabilities
```

---

## Professional Documentation

### Enumeration Findings Template
```
=== WordPress Discovery Report ===

Target: [URL]
Discovery Date: [DATE]

== Core Information ==
WordPress Version: [VERSION]
Theme: [THEME NAME] v[VERSION]
XML-RPC Status: [ENABLED/DISABLED]

== User Accounts ==
[USERNAME] - [ROLE] - [DISCOVERY METHOD]

== Installed Plugins ==
[PLUGIN NAME] v[VERSION] - [VULNERABILITY STATUS]

== Security Findings ==
[HIGH/MEDIUM/LOW] - [VULNERABILITY DESCRIPTION]
Evidence: [SCREENSHOT/REQUEST-RESPONSE]
CVE: [IF APPLICABLE]

== Recommended Actions ==
1. [IMMEDIATE ACTIONS]
2. [SECURITY IMPROVEMENTS]
3. [MONITORING RECOMMENDATIONS]
```

---

## HTB Academy Lab Solutions

### Lab Questions

#### Q1: Find flag.txt in accessible directory
**Solution Methodology:**
```bash
# Test directory listing on common paths
curl -s http://blog.inlanefreight.local/wp-content/uploads/
curl -s http://blog.inlanefreight.local/wp-content/plugins/
curl -s http://blog.inlanefreight.local/wp-content/themes/

# Look for exposed files in plugin directories
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/
# Check for flag.txt in exposed directories
```

#### Q2: Discover additional plugin (manual enumeration)
**Solution Methodology:**
```bash
# Analyze different pages for plugin references
curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
curl -s http://blog.inlanefreight.local/category/news/ | grep plugins

# Check page source on multiple URLs:
# - Homepage
# - Individual posts (?p=1, ?p=2)
# - Category pages
# - Archive pages

# Look for plugin CSS/JS files not found in initial scan
```

#### Q3: Find plugin version number
**Solution Methodology:**
```bash
# Check plugin directory for version files
curl -s http://blog.inlanefreight.local/wp-content/plugins/[PLUGIN]/readme.txt
curl -s http://blog.inlanefreight.local/wp-content/plugins/[PLUGIN]/style.css | grep Version
curl -s http://blog.inlanefreight.local/wp-content/plugins/[PLUGIN]/ | grep -i version

# Look for version in plugin CSS/JS URLs
curl -s http://blog.inlanefreight.local/?p=1 | grep -oP 'plugin-name.*?ver=\K[0-9.]+'
```

---

## Next Steps

After completing enumeration, proceed to:
1. **[WordPress Attacks & Exploitation](wordpress-attacks.md)** - Weaponizing discovered vulnerabilities
2. **[Privilege Escalation](wordpress-privilege-escalation.md)** - Gaining administrative access
3. **[Post-Exploitation](wordpress-post-exploitation.md)** - Maintaining access and lateral movement

**💡 Key Takeaway:** Thorough enumeration is critical for WordPress assessments. Manual techniques often discover vulnerabilities missed by automated scanners, while automated tools validate and expand manual findings. 