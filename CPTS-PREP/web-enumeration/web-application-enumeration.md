# 🔧 Web Application Enumeration

## **Overview**

Web Application Enumeration focuses on identifying technologies, frameworks, hidden content, and potential vulnerabilities in web applications. This phase builds upon subdomain discovery to analyze the actual web services and applications running on discovered hosts.

**Key Objectives:**
- Identify web technologies and frameworks
- Discover hidden directories and files
- Enumerate parameters and API endpoints
- Analyze security headers and configurations
- Identify CMS-specific vulnerabilities
- Discover virtual hosts and applications

---

## **Technology Stack Identification**

### **whatweb - Command Line Technology Detection**
```bash
# Basic scan
whatweb https://example.com

# Aggressive scan with all plugins
whatweb -a 3 https://example.com

# Output to JSON format
whatweb --log-json=results.json https://example.com

# Scan multiple URLs from file
whatweb -i urls.txt

# Scan with specific user agent
whatweb --user-agent "Mozilla/5.0..." https://example.com
```

### **Wappalyzer (Browser Extension)**
- Automatically identifies technologies on visited pages
- Shows: CMS, frameworks, libraries, servers, databases
- Real-time analysis during browsing

### **Nmap HTTP Scripts for Technology Detection**
```bash
# HTTP technology detection
nmap -sV --script=http-enum,http-headers,http-methods,http-robots.txt example.com -p 80,443

# Comprehensive HTTP enumeration
nmap --script "http-*" example.com -p 80,443

# CMS detection
nmap --script http-wordpress-enum,http-joomla-brute,http-drupal-enum example.com -p 80,443
```

### **Manual Header Analysis**
```bash
# Curl header analysis
curl -I https://example.com

# Check for technology-specific headers
curl -H "User-Agent: Mozilla/5.0..." -I https://example.com | grep -E "(Server|X-Powered-By|X-Generator|X-Framework)"

# Check security headers
curl -I https://example.com | grep -E "(X-Frame-Options|Content-Security-Policy|X-XSS-Protection)"
```

---

## **Directory & File Enumeration**

### **Gobuster - Directory Brute Forcing**
```bash
# Basic directory enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# With extensions
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js

# With specific status codes
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -s 200,204,301,302,307,403

# With custom headers
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -H "Authorization: Bearer token"

# Recursive enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -r

# Output to file
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -o results.txt
```

### **ffuf - Fast Web Fuzzer**
```bash
# Directory fuzzing
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# File extension fuzzing
ffuf -u https://example.com/indexFUZZ -w extensions.txt

# Filter by response size
ffuf -u https://example.com/FUZZ -w wordlist.txt -fs 1234

# Filter by response codes
ffuf -u https://example.com/FUZZ -w wordlist.txt -fc 404,400

# POST data fuzzing
ffuf -u https://example.com/login -d "username=admin&password=FUZZ" -w passwords.txt -X POST
```

### **dirb - Recursive Directory Scanner**
```bash
# Basic scan
dirb https://example.com

# With custom wordlist
dirb https://example.com /usr/share/wordlists/dirb/big.txt

# With specific extensions
dirb https://example.com -X .php,.txt,.html

# With authentication
dirb https://example.com -u username:password

# Ignore specific response codes
dirb https://example.com -N 404,403
```

---

## **Virtual Host Discovery**

### **ffuf Virtual Host Fuzzing**
```bash
# Basic virtual host discovery
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Filter by response size
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fs 1234

# Filter by response codes
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fc 404,400

# Custom IP with virtual hosts
ffuf -u https://192.168.1.100 -H "Host: FUZZ.example.com" -w subdomains.txt
```

### **gobuster vhost mode**
```bash
# Virtual host enumeration
gobuster vhost -u https://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# With custom domain
gobuster vhost -u https://192.168.1.100 -w subdomains.txt --domain example.com

# Custom user agent
gobuster vhost -u https://example.com -w subdomains.txt -a "Mozilla/5.0..."
```

---

## **Parameter Discovery**

### **ffuf Parameter Fuzzing**
```bash
# GET parameter discovery
ffuf -u https://example.com/page?FUZZ=value -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt

# POST parameter discovery
ffuf -u https://example.com/login -d "FUZZ=value" -w parameters.txt -X POST

# Hidden parameter discovery
ffuf -u https://example.com/api/user?FUZZ=1 -w parameters.txt -fs 1234

# JSON parameter fuzzing
ffuf -u https://example.com/api/user -d '{"FUZZ":"value"}' -w parameters.txt -X POST -H "Content-Type: application/json"
```

### **Arjun - Parameter Discovery Tool**
```bash
# Basic parameter discovery
arjun -u https://example.com/page

# POST method parameter discovery
arjun -u https://example.com/login -m POST

# Custom headers
arjun -u https://example.com/page -h "Authorization: Bearer token"

# Custom delay
arjun -u https://example.com/page -d 2

# Output to file
arjun -u https://example.com/page -o parameters.txt

# Threaded scanning
arjun -u https://example.com/page -t 20
```

### **paramspider - Parameter Mining**
```bash
# Extract parameters from Wayback Machine
paramspider --domain example.com

# Output to file
paramspider --domain example.com --output params.txt

# Level of depth
paramspider --domain example.com --level high

# Custom wordlist
paramspider --domain example.com --wordlist custom_params.txt
```

---

## **API Enumeration**

### **Common API Endpoints**
```bash
# Standard API paths to test
/api/
/api/v1/
/api/v2/
/rest/
/graphql
/swagger
/openapi.json
/api-docs
/docs/
/v1/
/v2/
/admin/api/
/internal/api/

# Test with curl
curl -X GET https://example.com/api/
curl -X GET https://example.com/api/users
curl -X GET https://example.com/api/v1/users

# API documentation endpoints
curl https://example.com/swagger-ui.html
curl https://example.com/api/docs
curl https://example.com/openapi.json
```

### **API Fuzzing with ffuf**
```bash
# API endpoint discovery
ffuf -u https://example.com/api/FUZZ -w api-endpoints.txt

# API version discovery
ffuf -u https://example.com/api/FUZZ/users -w versions.txt

# HTTP method testing
ffuf -u https://example.com/api/users -X FUZZ -w methods.txt

# API parameter fuzzing
ffuf -u https://example.com/api/users?FUZZ=1 -w parameters.txt
```

### **GraphQL Enumeration**
```bash
# GraphQL introspection
curl -X POST https://example.com/graphql -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}'

# GraphQL schema discovery
curl -X POST https://example.com/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}'
```

---

## **Web Crawling & Spidering**

### **hakrawler - Fast Web Crawler**
```bash
# Basic crawling
echo "https://example.com" | hakrawler

# Include subdomains
echo "https://example.com" | hakrawler -subs

# Custom depth
echo "https://example.com" | hakrawler -depth 3

# Output URLs only
echo "https://example.com" | hakrawler -plain

# Include JavaScript files
echo "https://example.com" | hakrawler -js
```

### **wget Recursive Download**
```bash
# Mirror website structure
wget --recursive --no-clobber --page-requisites --html-extension --convert-links --domains example.com https://example.com

# Limited depth crawling
wget -r -l 3 https://example.com

# Follow robots.txt
wget -r --respect-robots=on https://example.com

# Download specific file types
wget -r -A "*.pdf,*.doc,*.xls" https://example.com
```

### **Burp Suite Spider**
```bash
# Configure Burp proxy (127.0.0.1:8080)
# Navigate to Target > Site map
# Right-click target > Spider this host
# Monitor crawling progress in Spider tab
```

---

## **JavaScript Analysis**

### **LinkFinder - Extract Endpoints from JS**
```bash
# Extract endpoints from JavaScript files
python3 linkfinder.py -i https://example.com -o cli

# Analyze downloaded JS files
python3 linkfinder.py -i /path/to/script.js -o cli

# Extract from all JS files on domain
python3 linkfinder.py -i https://example.com -d -o cli

# Output to file
python3 linkfinder.py -i https://example.com -d -o cli > endpoints.txt
```

### **JSFScan.sh - JavaScript File Scanner**
```bash
# Scan for JavaScript files and extract information
./JSFScan.sh -u https://example.com

# Custom output directory
./JSFScan.sh -u https://example.com -o /tmp/jsfiles

# Analyze specific JavaScript file
./JSFScan.sh -f /path/to/script.js
```

### **Manual JavaScript Analysis**
```bash
# Download all JavaScript files
wget -r -A "*.js" https://example.com

# Search for sensitive information
grep -r -i "password\|api_key\|secret\|token" *.js

# Look for API endpoints
grep -r -o "\/[a-zA-Z0-9_\/\-\.]*" *.js | grep -E "(api|endpoint|route)"

# Find comments
grep -r "\/\*\|\/\/" *.js

# Extract URLs
grep -r -o "https\?://[^\"']*" *.js

# Find hardcoded credentials
grep -r -i "username\|password\|token" *.js
```

---

## **CMS-Specific Enumeration**

### **WordPress**
```bash
# WPScan - comprehensive WordPress scanner
wpscan --url https://example.com

# Enumerate users
wpscan --url https://example.com --enumerate u

# Enumerate plugins
wpscan --url https://example.com --enumerate p

# Enumerate themes
wpscan --url https://example.com --enumerate t

# Aggressive scan
wpscan --url https://example.com --enumerate ap,at,cb,dbe

# With API token for vulnerability data
wpscan --url https://example.com --api-token YOUR_API_TOKEN

# Password brute force
wpscan --url https://example.com --usernames admin --passwords passwords.txt
```

### **Joomla**
```bash
# JoomScan
joomscan -u https://example.com

# Droopescan for Joomla
droopescan scan joomla -u https://example.com

# Manual enumeration
curl https://example.com/administrator/manifests/files/joomla.xml
curl https://example.com/language/en-GB/en-GB.xml
```

### **Drupal**
```bash
# Droopescan for Drupal
droopescan scan drupal -u https://example.com

# CMSmap
cmsmap -t https://example.com

# Manual enumeration
curl https://example.com/CHANGELOG.txt
curl https://example.com/README.txt
curl https://example.com/core/CHANGELOG.txt
```

---

## **Security Headers Analysis**

### **Security Headers Check**
```bash
# Check security headers
curl -I https://example.com | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security)"

# Comprehensive security headers analysis
curl -I https://example.com | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|X-Permitted-Cross-Domain-Policies|Referrer-Policy)"
```

### **SSL/TLS Analysis**
```bash
# SSL certificate information
openssl s_client -connect example.com:443 -showcerts

# SSL Labs API (command line)
ssllabs-scan example.com

# testssl.sh comprehensive SSL testing
./testssl.sh https://example.com

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 example.com
```

---

## **HTTP Methods Testing**

### **Method Enumeration**
```bash
# Check allowed HTTP methods
curl -X OPTIONS https://example.com -i

# Test dangerous methods
curl -X PUT https://example.com/test.txt -d "test content"
curl -X DELETE https://example.com/test.txt
curl -X TRACE https://example.com
curl -X PATCH https://example.com/api/user/1 -d '{"name":"modified"}'

# Nmap HTTP methods script
nmap --script http-methods --script-args http-methods.url-path=/admin example.com -p 80,443
```

---

## **robots.txt and Sitemap Analysis**

### **robots.txt Enumeration**
```bash
# Check robots.txt
curl https://example.com/robots.txt

# Find disallowed directories
curl https://example.com/robots.txt | grep -i disallow

# Extract interesting paths
curl https://example.com/robots.txt | grep -E "(admin|login|config|backup|private)"

# Check multiple robots.txt locations
curl https://example.com/robots.txt
curl https://example.com/admin/robots.txt
curl https://example.com/api/robots.txt
```

### **Sitemap Discovery**
```bash
# Check for sitemaps
curl https://example.com/sitemap.xml
curl https://example.com/sitemap_index.xml
curl https://example.com/sitemap1.xml

# Google sitemap format
curl https://example.com/sitemap.txt

# Common sitemap locations
curl https://example.com/sitemap.xml.gz
curl https://example.com/sitemaps/sitemap.xml
```

---

## **WAF Detection and Bypass**

### **WAF Detection**
```bash
# wafw00f - WAF detection
wafw00f https://example.com

# Manual detection through headers
curl -I https://example.com | grep -E "(cloudflare|incapsula|barracuda|f5|imperva)"

# Test with malicious payload
curl "https://example.com/?test=<script>alert(1)</script>"

# Check for rate limiting
for i in {1..10}; do curl -I https://example.com; done
```

### **Basic WAF Bypass Techniques**
```bash
# URL encoding
curl "https://example.com/?test=%3Cscript%3Ealert(1)%3C/script%3E"

# Mixed case
curl "https://example.com/?test=<ScRiPt>alert(1)</ScRiPt>"

# Double encoding
curl "https://example.com/?test=%253Cscript%253Ealert(1)%253C/script%253E"

# Using different HTTP methods
curl -X POST https://example.com/search -d "query=<script>alert(1)</script>"

# Custom headers
curl -H "X-Forwarded-For: 127.0.0.1" https://example.com
```

---

## **HTB Academy Lab Examples**

### **Lab 1: Technology Stack Identification**
```bash
# Identify the web server and version
whatweb http://94.237.49.166:58026

# Expected output analysis:
# - HTTP Server version
# - Scripting language (PHP, ASP.NET, etc.)
# - Framework identification
# - CMS detection
```

### **Lab 2: Directory Discovery**
```bash
# Discover hidden directories and files
gobuster dir -u http://94.237.49.166:58026 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# Focus on administrative interfaces
gobuster dir -u http://94.237.49.166:58026 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/wp-plugins.txt

# Look for backup files
gobuster dir -u http://94.237.49.166:58026 -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,orig
```

### **Lab 3: Virtual Host Discovery**
```bash
# Discover virtual hosts
ffuf -u http://94.237.49.166:58026 -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fs 10918

# Test discovered virtual hosts
curl -H "Host: admin.inlanefreight.htb" http://94.237.49.166:58026
curl -H "Host: api.inlanefreight.htb" http://94.237.49.166:58026
```

---

## **Security Assessment**

### **Vulnerability Indicators**
1. **Exposed admin interfaces** - /admin, /wp-admin, /administrator
2. **Default credentials** - admin:admin, admin:password
3. **Information disclosure** - Error messages, debug information
4. **Weak authentication** - No rate limiting, weak passwords
5. **Missing security headers** - XSS protection, CSRF tokens
6. **Outdated software** - Old CMS versions, known vulnerabilities

### **Common Misconfigurations**
1. **Directory listing enabled** - Apache/Nginx misconfiguration
2. **Backup files accessible** - .bak, .old, .backup files
3. **Source code exposure** - .git directories, .svn folders
4. **Configuration files** - .env, config.php, web.config
5. **Temporary files** - Editors' backup files (~, .swp)

---

## **Defensive Measures**

### **Web Application Hardening**
1. **Remove server banners** - Hide version information
2. **Implement security headers** - CSP, HSTS, X-Frame-Options
3. **Disable directory listing** - Prevent folder browsing
4. **Remove default files** - Default pages, documentation
5. **Secure configuration** - Error handling, debug modes off

### **Monitoring and Detection**
1. **WAF implementation** - Block malicious requests
2. **Access logging** - Monitor enumeration attempts
3. **Rate limiting** - Prevent brute force attacks
4. **Anomaly detection** - Unusual request patterns
5. **Regular security assessments** - Automated vulnerability scanning

---

## **Tools Summary**

| Tool | Purpose | Best Use Case |
|------|---------|--------------|
| **whatweb** | Technology detection | Initial reconnaissance |
| **gobuster** | Directory/file discovery | Finding hidden content |
| **ffuf** | Web fuzzing | Parameter/vhost discovery |
| **wpscan** | WordPress security | CMS-specific testing |
| **burp suite** | Web application testing | Manual analysis |
| **arjun** | Parameter discovery | Finding hidden parameters |
| **wafw00f** | WAF detection | Security control identification |
| **hakrawler** | Web crawling | Content discovery |
| **linkfinder** | JavaScript analysis | Endpoint extraction |

---

## **Key Takeaways**

1. **Technology identification** guides subsequent testing approaches
2. **Directory enumeration** reveals hidden functionality and files
3. **Parameter discovery** uncovers additional attack surface
4. **JavaScript analysis** exposes client-side vulnerabilities
5. **Virtual hosts** may contain additional applications
6. **Security headers** indicate the security posture
7. **CMS enumeration** requires specialized tools and techniques
8. **WAF detection** is crucial for bypass strategy
9. **API enumeration** focuses on modern application architectures
10. **Comprehensive methodology** combines multiple tools and techniques

---

## **References**

- HTB Academy: Information Gathering - Web Edition
- OWASP Web Security Testing Guide
- SecLists: https://github.com/danielmiessler/SecLists
- Burp Suite Documentation
- FFUF Documentation: https://github.com/ffuf/ffuf 