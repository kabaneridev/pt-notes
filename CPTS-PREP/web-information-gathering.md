# 🕷️ Web Application Information Gathering

## **Overview**

Web Application Information Gathering is a specialized phase of reconnaissance that focuses specifically on web applications and their underlying technologies. Unlike infrastructure enumeration, this phase targets the application layer to identify technologies, frameworks, hidden files, parameters, and potential attack vectors.

---

## **WHOIS Information Gathering**

### **Basic WHOIS Lookup**
```bash
# Basic WHOIS query
whois example.com

# WHOIS with specific server
whois -h whois.internic.net example.com

# Multiple domain lookup
for domain in example.com google.com; do echo "=== $domain ==="; whois $domain; done
```

### **Key Information to Extract**
```bash
# Domain registration details
whois example.com | grep -E "(Registrar|Creation Date|Registry Expiry|Updated Date)"

# Name servers
whois example.com | grep -i "name server"

# Contact information
whois example.com | grep -E "(Registrant|Admin|Tech)" -A 5

# DNSSEC status
whois example.com | grep -i dnssec
```

### **WHOIS Data Analysis**
```bash
# Extract email addresses
whois example.com | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Extract phone numbers
whois example.com | grep -oE '\+?[0-9]{1,4}?[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'

# Extract organization names
whois example.com | grep -i "organization\|registrant"

# Check domain age
whois example.com | grep -i "creation date"
```

### **Privacy Protection Detection**
```bash
# Common privacy services
whois example.com | grep -iE "(whoisguard|privacy|proxy|domains by proxy|perfect privacy)"

# Registrar privacy indication
whois example.com | grep -i "redacted\|privacy\|proxy"
```

### **Historical WHOIS Data**
```bash
# Using online tools (manual process)
# Visit: https://whois.domaintools.com/
# Visit: https://who.is/whois-history/

# Check for domain transfers
whois example.com | grep -i "registrar\|updated date"
```

### **Subdomain WHOIS Analysis**
```bash
# Check WHOIS for discovered subdomains
for sub in mail admin ftp api; do
  echo "=== $sub.example.com ==="
  whois $sub.example.com 2>/dev/null || echo "No WHOIS data"
done

# IP-based WHOIS for subdomains
dig +short api.example.com | head -1 | xargs whois
```

### **Practical WHOIS Intelligence**
```bash
# Find related domains by registrant email
whois example.com | grep -i "registrant.*email" | cut -d: -f2 | tr -d ' '

# Check registrar patterns
whois example.com | grep -i registrar

# Domain expiration monitoring
whois example.com | grep -i "expiry\|expires"
```

---

## **DNS Enumeration & Analysis**

### **DNS Tools Overview**

| Tool | Key Features | Use Cases |
|------|-------------|-----------|
| **dig** | Versatile DNS lookup tool supporting various query types (A, MX, NS, TXT, etc.) with detailed output | Manual DNS queries, zone transfers, troubleshooting DNS issues, in-depth analysis |
| **nslookup** | Simpler DNS lookup tool, primarily for A, AAAA, and MX records | Basic DNS queries, quick domain resolution checks |
| **host** | Streamlined DNS lookup tool with concise output | Quick checks of A, AAAA, and MX records |
| **dnsenum** | Automated DNS enumeration with dictionary attacks, brute-forcing, zone transfers | Discovering subdomains and gathering DNS information efficiently |
| **fierce** | DNS reconnaissance and subdomain enumeration with recursive search and wildcard detection | User-friendly DNS reconnaissance, identifying subdomains and targets |
| **dnsrecon** | Combines multiple DNS reconnaissance techniques with various output formats | Comprehensive DNS enumeration, subdomain discovery, record gathering |
| **theHarvester** | OSINT tool gathering information from various sources, including DNS records | Collecting email addresses, employee information, domain-associated data |
| **Online DNS Services** | User-friendly web interfaces for DNS lookups | Quick DNS lookups when command-line tools unavailable |

### **The Domain Information Groper (dig)**

The `dig` command is the most versatile and powerful utility for querying DNS servers. Its flexibility and detailed output make it the go-to choice for DNS reconnaissance.

#### **Common dig Commands**

| Command | Description |
|---------|-------------|
| `dig domain.com` | Performs default A record lookup for the domain |
| `dig domain.com A` | Retrieves IPv4 address (A record) associated with domain |
| `dig domain.com AAAA` | Retrieves IPv6 address (AAAA record) associated with domain |
| `dig domain.com MX` | Finds mail servers (MX records) responsible for domain |
| `dig domain.com NS` | Identifies authoritative name servers for domain |
| `dig domain.com TXT` | Retrieves TXT records associated with domain |
| `dig domain.com CNAME` | Retrieves canonical name (CNAME) record for domain |
| `dig domain.com SOA` | Retrieves start of authority (SOA) record for domain |
| `dig @1.1.1.1 domain.com` | Specifies specific name server to query (1.1.1.1) |
| `dig +trace domain.com` | Shows full path of DNS resolution |
| `dig -x 192.168.1.1` | Performs reverse lookup on IP to find hostname |
| `dig +short domain.com` | Provides short, concise answer to query |
| `dig +noall +answer domain.com` | Displays only answer section of query output |
| `dig domain.com ANY` | Retrieves all available DNS records (many servers ignore this) |

### **Basic DNS Queries**
```bash
# A records
dig example.com A

# All records
dig example.com ANY

# MX records (mail servers)
dig example.com MX

# NS records (name servers)
dig example.com NS

# TXT records (SPF, DKIM, DMARC)
dig example.com TXT

# SOA record
dig example.com SOA
```

### **Understanding dig Output**
```bash
# Example dig output for google.com
kabaneridev@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

#### **Output Breakdown:**

**Header Section:**
- `opcode: QUERY, status: NOERROR, id: 16449` - Query type, success status, unique identifier
- `flags: qr rd ad` - Query Response, Recursion Desired, Authentic Data flags
- `QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0` - Number of entries in each section

**Question Section:**
- `google.com. IN A` - Query: "What is the IPv4 address (A record) for google.com?"

**Answer Section:**
- `google.com. 0 IN A 142.251.47.142` - IP address is 142.251.47.142, TTL is 0

**Footer:**
- `Query time: 0 msec` - Processing time
- `SERVER: 172.23.176.1#53` - DNS server that provided the answer
- `WHEN:` - Timestamp of query
- `MSG SIZE rcvd: 54` - Size of DNS message received

### **Quick DNS Queries**
```bash
# Short output only
dig +short hackthebox.com
# Output: 104.18.20.126
#         104.18.21.126

# Answer section only
dig +noall +answer google.com

# Specific query types
dig +short google.com MX
dig +short google.com NS
dig +short google.com TXT
```

### **Advanced dig Techniques**
```bash
# Trace full DNS resolution path
dig +trace google.com

# Query specific DNS server
dig @8.8.8.8 google.com A
dig @1.1.1.1 google.com MX

# Multiple query types in one command
dig google.com A MX NS TXT

# Check DNSSEC validation
dig +dnssec google.com

# TCP instead of UDP (for large responses)
dig +tcp google.com TXT

# No recursion (direct authoritative query)
dig +norecurse @ns1.google.com google.com
```

### **Practical DNS Enumeration Examples**
```bash
# Complete domain reconnaissance
domain="example.com"

echo "=== Basic Records ==="
dig +short $domain A
dig +short $domain AAAA
dig +short $domain MX
dig +short $domain NS

echo "=== TXT Records Analysis ==="
dig +short $domain TXT | grep -E "(spf|dkim|dmarc)"

echo "=== Mail Server Analysis ==="
for mx in $(dig +short $domain MX | awk '{print $2}'); do
  echo "Mail server: $mx"
  dig +short $mx A
done

echo "=== Name Server Analysis ==="
for ns in $(dig +short $domain NS); do
  echo "Name server: $ns"
  dig +short $ns A
done
```

### **DNS Zone Transfer Attempts**
```bash
# Find name servers
dig example.com NS

# Attempt zone transfer
dig @ns1.example.com example.com AXFR
dig @ns2.example.com example.com AXFR

# Try all discovered name servers
for ns in $(dig +short example.com NS); do
  echo "Trying zone transfer with $ns"
  dig @$ns example.com AXFR
done
```

### **DNS Security Considerations**
```bash
# Check DNSSEC implementation
dig +dnssec example.com

# Verify DNSSEC chain
dig +trace +dnssec example.com

# Check for DNS over HTTPS (DoH)
curl -H "Accept: application/dns-json" "https://1.1.1.1/dns-query?name=example.com&type=A"
```

⚠️ **Important Security Note:**
- Some DNS servers can detect and block excessive queries
- Always respect rate limits and use reasonable delays
- Obtain proper authorization before extensive DNS reconnaissance
- Consider using multiple DNS servers to distribute queries
- Be aware that extensive querying may trigger security alerts

### **Reverse DNS Lookups**
```bash
# Reverse lookup for IP
dig -x 1.2.3.4

# Reverse lookup for IP range
for i in {1..254}; do
  dig -x 192.168.1.$i +short
done | grep -v "^$"
```

### **DNS Cache Snooping**
```bash
# Check if domain is cached
dig @8.8.8.8 example.com +norecurse

# Try different DNS servers
for dns in 8.8.8.8 1.1.1.1 208.67.222.222; do
  echo "Testing $dns"
  dig @$dns example.com +short
done
```

### **Automated DNS Enumeration Tools**

#### **dnsenum - Comprehensive DNS Enumeration**
```bash
# Basic enumeration
dnsenum example.com

# With specific wordlist
dnsenum --dnsserver 8.8.8.8 --enum example.com

# Brute force subdomains
dnsenum --subfile /usr/share/wordlists/dnsmap.txt example.com

# Zone transfer attempts
dnsenum --noreverse example.com

# Output to file
dnsenum -o dns_results.txt example.com
```

#### **dnsrecon - Advanced DNS Reconnaissance**
```bash
# Standard enumeration
dnsrecon -d example.com

# Brute force with custom wordlist
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Zone transfer
dnsrecon -d example.com -t axfr

# Reverse lookup on IP range
dnsrecon -r 192.168.1.0/24

# Google enumeration
dnsrecon -d example.com -t goo
```

#### **fierce - Subdomain Scanner**
```bash
# Basic subdomain enumeration
fierce --domain example.com

# Custom wordlist
fierce --domain example.com --wordlist custom_subdomains.txt

# Specific DNS server
fierce --domain example.com --dns-servers 8.8.8.8

# Output to file
fierce --domain example.com > fierce_results.txt
```

#### **theHarvester - OSINT DNS Gathering**
```bash
# Search multiple sources
theHarvester -d example.com -l 500 -b all

# Specific sources
theHarvester -d example.com -l 200 -b google,bing,yahoo

# DNS brute force
theHarvester -d example.com -c

# Output formats
theHarvester -d example.com -l 100 -b google -f results.xml
```

---

## **Technology Stack Identification**

### **Wappalyzer (Browser Extension)**
```bash
# Install browser extension
# Automatically identifies technologies on visited pages
# Shows: CMS, frameworks, libraries, servers, databases
```

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
```

### **ffuf - Fast Web Fuzzer**
```bash
# Directory fuzzing
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# File extension fuzzing
ffuf -u https://example.com/indexFUZZ -w extensions.txt

# Virtual host discovery
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w subdomains.txt

# Parameter discovery
ffuf -u https://example.com/page?FUZZ=value -w parameters.txt

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
```

---

## **Subdomain Discovery (Web-Focused)**

### **Certificate Transparency for Web Apps**
```bash
# Web-specific subdomain discovery
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Filter for web-related subdomains
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq -r '.[].name_value' | grep -E "(www|web|app|api|admin|portal|dashboard)"
```

### **Subfinder - Passive Subdomain Discovery**
```bash
# Basic subdomain discovery
subfinder -d example.com

# With specific sources
subfinder -d example.com -sources crtsh,hackertarget,virustotal

# Output to file
subfinder -d example.com -o subdomains.txt

# Resolve subdomains
subfinder -d example.com -resolve
```

### **Assetfinder - Quick Subdomain Enumeration**
```bash
# Fast subdomain discovery
assetfinder example.com

# Find only subdomains
assetfinder --subs-only example.com
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
```

### **gobuster vhost mode**
```bash
# Virtual host enumeration
gobuster vhost -u https://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# With custom domain
gobuster vhost -u https://192.168.1.100 -w subdomains.txt --domain example.com
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
```

### **paramspider - Parameter Mining**
```bash
# Extract parameters from Wayback Machine
paramspider --domain example.com

# Output to file
paramspider --domain example.com --output params.txt

# Level of depth
paramspider --domain example.com --level high
```

---

## **API Enumeration**

### **Common API Endpoints**
```bash
# Standard API paths
/api/
/api/v1/
/api/v2/
/rest/
/graphql
/swagger
/openapi.json
/api-docs
/docs/

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
ffuf -u https://example.com/api/users -X GET,POST,PUT,DELETE
```

---

## **Web Crawling & Spidering**

### **Burp Suite Spider**
```bash
# Configure Burp proxy (127.0.0.1:8080)
# Navigate to Target > Site map
# Right-click target > Spider this host
# Monitor crawling progress in Spider tab
```

### **wget Recursive Download**
```bash
# Mirror website structure
wget --recursive --no-clobber --page-requisites --html-extension --convert-links --domains example.com https://example.com

# Limited depth crawling
wget -r -l 3 https://example.com

# Follow robots.txt
wget -r --respect-robots=on https://example.com
```

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
```

### **JSFScan.sh - JavaScript File Scanner**
```bash
# Scan for JavaScript files and extract information
./JSFScan.sh -u https://example.com

# Custom output directory
./JSFScan.sh -u https://example.com -o /tmp/jsfiles
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
```

---

## **CMS-Specific Enumeration**

### **WordPress**
```bash
# WPScan
wpscan --url https://example.com

# Enumerate users
wpscan --url https://example.com --enumerate u

# Enumerate plugins
wpscan --url https://example.com --enumerate p

# Enumerate themes
wpscan --url https://example.com --enumerate t

# Aggressive scan
wpscan --url https://example.com --enumerate ap,at,cb,dbe
```

### **Joomla**
```bash
# JoomScan
joomscan -u https://example.com

# Droopescan for Joomla
droopescan scan joomla -u https://example.com
```

### **Drupal**
```bash
# Droopescan for Drupal
droopescan scan drupal -u https://example.com

# CMSmap
cmsmap -t https://example.com
```

---

## **Security Headers Analysis**

### **Security Headers Check**
```bash
# Check security headers
curl -I https://example.com | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security)"

# Security headers scanner
python3 shcheck.py https://example.com

# Online tool analysis
# Visit: https://securityheaders.com/
```

### **SSL/TLS Analysis**
```bash
# SSL certificate information
openssl s_client -connect example.com:443 -showcerts

# SSL Labs API (command line)
ssllabs-scan example.com

# testssl.sh comprehensive SSL testing
./testssl.sh https://example.com
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
```

### **Sitemap Discovery**
```bash
# Check for sitemaps
curl https://example.com/sitemap.xml
curl https://example.com/sitemap_index.xml
curl https://example.com/sitemap1.xml

# Google sitemap format
curl https://example.com/sitemap.txt
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
```

---

## **Practical HTB Academy Lab Examples**

### **Lab 1: WHOIS and DNS Analysis**
```bash
# Domain intelligence gathering
whois inlanefreight.htb

# Basic DNS enumeration with dig
dig inlanefreight.htb A
dig inlanefreight.htb MX
dig inlanefreight.htb NS
dig inlanefreight.htb TXT

# Detailed dig analysis
dig +trace inlanefreight.htb
dig +short inlanefreight.htb MX

# Zone transfer attempts
for ns in $(dig +short inlanefreight.htb NS); do
  echo "Attempting zone transfer with $ns"
  dig @$ns inlanefreight.htb AXFR
done

# Automated enumeration
dnsenum inlanefreight.htb
dnsrecon -d inlanefreight.htb

# OSINT gathering
theHarvester -d inlanefreight.htb -l 100 -b google

# Expected analysis:
# - Registration details and contact information
# - Name server configuration and vulnerabilities
# - Mail server identification and security
# - TXT records for SPF/DKIM/DMARC policies
# - Subdomain discovery and enumeration
# - Email addresses and employee information
```

### **Lab 2: Technology Stack Identification**
```bash
# Identify the web server and version
whatweb http://94.237.49.166:58026

# Expected output analysis:
# - HTTP Server version
# - Scripting language (PHP, ASP.NET, etc.)
# - Framework identification
# - CMS detection

# Follow-up enumeration based on identified technology
```

### **Lab 3: Directory Discovery**
```bash
# Discover hidden directories and files
gobuster dir -u http://94.237.49.166:58026 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# Focus on administrative interfaces
gobuster dir -u http://94.237.49.166:58026 -w admin-panels.txt

# Look for backup files
gobuster dir -u http://94.237.49.166:58026 -w backup-files.txt -x bak,backup,old,orig
```

### **Lab 4: Virtual Host Discovery**
```bash
# Discover virtual hosts
ffuf -u http://94.237.49.166:58026 -H "Host: FUZZ.inlanefreight.htb" -w subdomains.txt -fs 10918

# Test discovered virtual hosts
curl -H "Host: admin.inlanefreight.htb" http://94.237.49.166:58026
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
| **whois** | Domain registration info | Initial domain intelligence |
| **dig** | DNS enumeration | Zone transfers, record analysis |
| **dnsenum** | Automated DNS enumeration | Comprehensive subdomain discovery |
| **dnsrecon** | Advanced DNS reconnaissance | Multi-technique DNS enumeration |
| **fierce** | Subdomain scanner | User-friendly subdomain discovery |
| **theHarvester** | OSINT gathering | Email addresses, employee info |
| **whatweb** | Technology detection | Initial reconnaissance |
| **gobuster** | Directory/file discovery | Finding hidden content |
| **ffuf** | Web fuzzing | Parameter/vhost discovery |
| **subfinder** | Subdomain enumeration | Passive reconnaissance |
| **wpscan** | WordPress security | CMS-specific testing |
| **burp suite** | Web application testing | Manual analysis |
| **arjun** | Parameter discovery | Finding hidden parameters |
| **wafw00f** | WAF detection | Security control identification |

---

## **Key Takeaways**

1. **WHOIS data provides** fundamental domain intelligence and contact information
2. **DNS enumeration** reveals infrastructure and potential zone transfer vulnerabilities  
3. **dig command** is the most versatile tool for manual DNS analysis and troubleshooting
4. **Automated DNS tools** (dnsenum, dnsrecon, fierce) accelerate subdomain discovery
5. **Rate limiting awareness** is crucial to avoid detection and blocking
6. **Web reconnaissance is different** from infrastructure enumeration
7. **Technology identification** guides subsequent testing approaches
8. **Directory enumeration** reveals hidden functionality and files
9. **Parameter discovery** uncovers additional attack surface
10. **JavaScript analysis** exposes client-side vulnerabilities
11. **Virtual hosts** may contain additional applications
12. **Security headers** indicate the security posture
13. **CMS enumeration** requires specialized tools and techniques

---

## **References**

- HTB Academy: Information Gathering - Web Edition
- OWASP Web Security Testing Guide
- SecLists: https://github.com/danielmiessler/SecLists
- Burp Suite Documentation
- FFUF Documentation: https://github.com/ffuf/ffuf 