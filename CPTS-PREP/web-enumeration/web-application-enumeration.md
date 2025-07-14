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

### **BuiltWith - Web Technology Profiler**
```bash
# Online service: https://builtwith.com/
# Provides detailed technology stack reports
# Features:
# - Technology stack identification
# - Historical technology usage
# - Contact information discovery
# - Competitive analysis

# Free plan: Basic technology detection
# Pro plan: Advanced analytics and historical data
```

### **Netcraft - Web Security Services**
```bash
# Online service: https://www.netcraft.com/
# Comprehensive web security reporting
# Features:
# - Website technology fingerprinting
# - Security posture assessment
# - SSL/TLS configuration analysis
# - Hosting provider identification
# - Uptime monitoring

# Site report: https://www.netcraft.com/tools/
# Search for: site:example.com
```

### **Nikto - Web Server Scanner**
```bash
# Installation
sudo apt update && sudo apt install -y perl
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl

# Basic website scan
nikto -h https://example.com

# Fingerprinting only (Software Identification)
nikto -h https://example.com -Tuning b

# Comprehensive scan
nikto -h https://example.com -Display V

# Output to file
nikto -h https://example.com -o nikto-results.txt

# Scan with specific plugins
nikto -h https://example.com -Plugins tests

# Test specific port
nikto -h https://example.com -p 8080

# Use proxy
nikto -h https://example.com -useproxy http://proxy:8080

# Tuning options:
# -Tuning 1: Interesting files
# -Tuning 2: Configuration issues
# -Tuning 3: Information disclosure
# -Tuning b: Software identification
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

### **Understanding Virtual Hosts**

Virtual hosting allows web servers to host multiple websites or applications on a single server by leveraging the **HTTP Host header**. This is crucial for discovering hidden applications and services that might not be publicly listed in DNS.

#### **How Virtual Hosts Work**

**Key Concepts:**
- **Subdomains**: Extensions of main domain (e.g., `blog.example.com`) with DNS records
- **Virtual Hosts (VHosts)**: Server configurations that can host multiple sites on same IP
- **Host Header**: HTTP header that tells the server which website is being requested

**Process Flow:**
1. **Browser Request**: Sends HTTP request to server IP with Host header
2. **Host Header**: Contains domain name (e.g., `Host: www.example.com`)
3. **Server Processing**: Web server examines Host header and consults virtual host config
4. **Content Serving**: Server serves appropriate content based on matched virtual host

#### **Types of Virtual Hosting**

| Type | Description | Advantages | Disadvantages |
|------|-------------|------------|---------------|
| **Name-Based** | Uses HTTP Host header to distinguish sites | Cost-effective, flexible, no multiple IPs needed | Requires Host header support, SSL/TLS limitations |
| **IP-Based** | Assigns unique IP to each website | Protocol independent, better isolation | Expensive, requires multiple IPs |
| **Port-Based** | Different ports for different websites | Useful when IPs limited | Not user-friendly, requires port in URL |

#### **Example Apache Configuration**
```apache
# Name-based virtual host configuration
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org  
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName dev.example1.com
    DocumentRoot /var/www/example1-dev
</VirtualHost>
```

**Key Point**: Even without DNS records, virtual hosts can be accessed by modifying local `/etc/hosts` file or fuzzing Host headers directly.

---

### **gobuster - Virtual Host Enumeration**

**gobuster** is highly effective for virtual host discovery with its dedicated `vhost` mode:

#### **Basic gobuster vhost Usage**
```bash
# HTB Academy example - comprehensive vhost enumeration
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

# Basic virtual host enumeration
gobuster vhost -u http://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# Target specific IP with domain
gobuster vhost -u http://192.168.1.100 -w subdomains.txt --append-domain --domain example.com
```

#### **Important gobuster Flags**
```bash
# --append-domain flag (REQUIRED in newer versions)
# Appends base domain to each wordlist entry
gobuster vhost -u http://target.com -w wordlist.txt --append-domain

# Performance optimization
gobuster vhost -u http://example.com -w wordlist.txt --append-domain -t 50 -k

# Output to file
gobuster vhost -u http://example.com -w wordlist.txt --append-domain -o vhost_results.txt

# Custom user agent and headers
gobuster vhost -u http://example.com -w wordlist.txt --append-domain -a "Mozilla/5.0..." -H "X-Forwarded-For: 127.0.0.1"
```

#### **gobuster vhost Example Output**
```bash
kabaneridev@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://inlanefreight.htb:81
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.inlanefreight.htb:81 Status: 200 [Size: 100]
Found: admin.inlanefreight.htb:81 Status: 200 [Size: 1500]
Found: dev.inlanefreight.htb:81 Status: 403 [Size: 500]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

### **ffuf - Fast Virtual Host Fuzzing**

**ffuf** provides flexible and fast virtual host discovery with powerful filtering:

#### **Basic ffuf Virtual Host Discovery**
```bash
# Basic virtual host discovery
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# HTB Academy style with IP target
ffuf -u http://94.237.49.166:58026 -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Filter by response size (critical for avoiding false positives)
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fs 10918

# Filter by response codes
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fc 404,400,403

# Custom IP with virtual hosts
ffuf -u http://192.168.1.100 -H "Host: FUZZ.example.com" -w subdomains.txt -fs 1234
```

#### **Advanced ffuf Filtering**
```bash
# Multiple filtering criteria
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt -fs 1234,5678 -fc 404,403

# Filter by response time
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt -ft 1000

# Match specific patterns
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt -mr "Welcome"

# Output formatting
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt -o results.json -of json
```

### **feroxbuster - Rust-Based Virtual Host Discovery**
```bash
# Basic virtual host discovery
feroxbuster -u http://example.com -w wordlist.txt -H "Host: FUZZ.example.com" --filter-status 404

# Advanced filtering
feroxbuster -u http://target.com -w wordlist.txt -H "Host: FUZZ.target.com" --filter-size 1234 --filter-status 404,403

# Recursive virtual host discovery
feroxbuster -u http://target.com -w wordlist.txt -H "Host: FUZZ.target.com" --recurse-depth 2
```

---

### **Virtual Host Discovery Strategies**

#### **1. Preparation Phase**
```bash
# Target identification
nslookup example.com
dig example.com A

# Wordlist selection
ls /usr/share/seclists/Discovery/DNS/
# Common choices:
# - subdomains-top1million-5000.txt (fast)
# - subdomains-top1million-110000.txt (comprehensive)
# - subdomains-top1million-20000.txt (balanced)
```

#### **2. Initial Discovery**
```bash
# Quick scan with small wordlist
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# Identify baseline response
curl -H "Host: nonexistent.target.com" http://target-ip
curl -H "Host: target.com" http://target-ip
```

#### **3. Filtering Setup**
```bash
# Determine filter criteria based on baseline
# Note response sizes, status codes, response times

# Example: If default response is 1234 bytes
ffuf -u http://target-ip -H "Host: FUZZ.target.com" -w wordlist.txt -fs 1234
```

#### **4. Comprehensive Enumeration**
```bash
# Large wordlist with proper filtering
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -t 50

# Custom wordlists for specific targets
# Create custom wordlist based on:
# - Company name variations
# - Common IT terms
# - Technology stack keywords
```

### **Manual Virtual Host Testing**
```bash
# Test discovered virtual hosts
curl -H "Host: admin.example.com" http://target-ip
curl -H "Host: dev.example.com" http://target-ip  
curl -H "Host: api.example.com" http://target-ip

# Check for different responses
curl -I -H "Host: admin.example.com" http://target-ip
curl -I -H "Host: www.example.com" http://target-ip

# Test with different methods
curl -X POST -H "Host: admin.example.com" http://target-ip
curl -X PUT -H "Host: api.example.com" http://target-ip
```

### **Local Testing with /etc/hosts**
```bash
# Add discovered virtual hosts to local hosts file
echo "192.168.1.100 admin.example.com" >> /etc/hosts
echo "192.168.1.100 dev.example.com" >> /etc/hosts

# Test in browser
firefox http://admin.example.com
firefox http://dev.example.com

# Remove entries when done
sed -i '/example.com/d' /etc/hosts
```

---

### **HTB Academy Lab Examples**

#### **Lab: Virtual Host Discovery**
```bash
# Target: inlanefreight.htb (add to /etc/hosts first)
echo "TARGET_IP inlanefreight.htb" >> /etc/hosts

# Comprehensive virtual host enumeration
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

# Expected discoveries based on HTB Academy questions:
# - web*.inlanefreight.htb
# - vm*.inlanefreight.htb  
# - br*.inlanefreight.htb
# - a*.inlanefreight.htb
# - su*.inlanefreight.htb

# Test discovered virtual hosts
curl -H "Host: web.inlanefreight.htb" http://TARGET_IP:81
curl -H "Host: admin.inlanefreight.htb" http://TARGET_IP:81

# Alternative with ffuf
ffuf -u http://TARGET_IP:81 -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs DEFAULT_SIZE
```

#### **Analysis Process**
```bash
# 1. Establish baseline
curl -I -H "Host: nonexistent.inlanefreight.htb" http://TARGET_IP:81

# 2. Note default response characteristics
# - Status code
# - Response size  
# - Response time
# - Headers

# 3. Run enumeration with proper filtering
# 4. Verify discovered virtual hosts
# 5. Document findings and access patterns
```

---

### **Security Considerations**

#### **Detection Avoidance**
```bash
# Rate limiting
gobuster vhost -u http://target.com -w wordlist.txt --append-domain -t 10 --delay 100ms

# Random user agents
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w wordlist.txt -H "User-Agent: Mozilla/5.0 (Random)"

# Distributed scanning
# Use multiple source IPs if available
# Rotate through different DNS servers
```

#### **Traffic Analysis**
- Virtual host discovery generates significant HTTP traffic
- Monitor for IDS/WAF detection
- Use proper authorization before testing
- Document all discovered virtual hosts

#### **False Positive Management**
```bash
# Common false positive patterns:
# - Wildcard DNS responses
# - Load balancer default pages
# - CDN default responses
# - Error pages with dynamic content

# Mitigation strategies:
# - Use multiple filter criteria (-fs, -fc, -fw)
# - Manual verification of results
# - Compare response content, not just size
```

---

### **Defensive Measures**

#### **Server Hardening**
```apache
# Disable default virtual host
<VirtualHost *:80>
    ServerName default
    DocumentRoot /var/www/html/default
    # Return 403 for undefined hosts
    <Location />
        Require all denied
    </Location>
</VirtualHost>

# Specific virtual host configuration
<VirtualHost *:80>
    ServerName www.example.com
    DocumentRoot /var/www/example
    # Only respond to specific Host headers
</VirtualHost>
```

#### **Monitoring**
```bash
# Monitor for virtual host enumeration
tail -f /var/log/apache2/access.log | grep -E "Host:.*\.(target\.com|example\.com)"

# Detect unusual Host header patterns
awk '{print $1, $7}' /var/log/apache2/access.log | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /"
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

### **Popular Web Crawlers Overview**

**Professional Tools:**
- **Burp Suite Spider** - Active crawler for web application mapping and vulnerability discovery
- **OWASP ZAP** - Free, open-source web application security scanner with spider component
- **Scrapy** - Versatile Python framework for building custom web crawlers
- **Apache Nutch** - Highly extensible and scalable open-source web crawler

### **ReconSpider - HTB Academy Custom Spider**
```bash
# Installation
pip3 install scrapy

# Download ReconSpider
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip

# Usage
python3 ReconSpider.py http://inlanefreight.com

# Alternative installation location
python3 /opt/tools/ReconSpider.py http://inlanefreight.com
```

#### **ReconSpider Results Analysis**
ReconSpider saves data in `results.json` with the following structure:

```json
{
    "emails": [
        "lily.floid@inlanefreight.com",
        "cvs@inlanefreight.com"
    ],
    "links": [
        "https://www.themeansar.com",
        "https://www.inlanefreight.com/index.php/offices/"
    ],
    "external_files": [
        "https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf"
    ],
    "js_files": [
        "https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2"
    ],
    "form_fields": [],
    "images": [
        "https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png"
    ],
    "videos": [],
    "audio": [],
    "comments": [
        "<!-- #masthead -->"
    ]
}
```

**JSON Key Analysis:**
| Key | Description | Security Relevance |
|-----|-------------|-------------------|
| `emails` | Email addresses found on domain | User enumeration, social engineering |
| `links` | URLs of links within domain | Site mapping, hidden pages |
| `external_files` | External files (PDFs, docs) | Information disclosure |
| `js_files` | JavaScript files | Endpoint discovery, sensitive data |
| `form_fields` | Form fields discovered | Parameter discovery, injection points |
| `images` | Image URLs | Metadata extraction |
| `videos` | Video URLs | Content analysis |
| `audio` | Audio file URLs | Content analysis |
| `comments` | HTML comments | Information disclosure |

#### **ReconSpider Data Mining**
```bash
# Extract specific data types
cat results.json | jq '.emails[]'
cat results.json | jq '.external_files[]'
cat results.json | jq '.js_files[]'

# Find potential cloud storage
cat results.json | jq '.external_files[]' | grep -E "(s3\.|amazonaws|blob\.core|storage\.googleapis)"

# Extract email domains
cat results.json | jq '.emails[]' | cut -d'@' -f2 | sort -u

# Look for interesting file extensions
cat results.json | jq '.external_files[]' | grep -E "\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|conf|config|bak)$"
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

### **OWASP ZAP Spider**
```bash
# Command line scanning
zap-cli quick-scan --spider http://example.com

# GUI mode
# Tools > Spider
# Enter target URL
# Configure scope and options
# Start spider
```

### **Scrapy Custom Spider**
```python
# Create custom spider (basic example)
import scrapy

class ReconSpider(scrapy.Spider):
    name = 'recon'
    
    def __init__(self, url=None, *args, **kwargs):
        super(ReconSpider, self).__init__(*args, **kwargs)
        self.start_urls = [url]
        
    def parse(self, response):
        # Extract emails
        emails = response.css('a[href*="mailto:"]::attr(href)').getall()
        
        # Extract links
        links = response.css('a::attr(href)').getall()
        
        # Extract comments
        comments = response.xpath('//comment()').getall()
        
        yield {
            'url': response.url,
            'emails': emails,
            'links': links,
            'comments': comments
        }
        
        # Follow links
        for link in links:
            yield response.follow(link, self.parse)

# Run spider
# scrapy crawl recon -a url=http://example.com -o results.json
```

### **Ethical Crawling Practices**

#### **Critical Guidelines**
1. **Always obtain permission** before crawling a website
2. **Respect robots.txt** and website terms of service
3. **Be mindful of server resources** - avoid excessive requests
4. **Implement delays** between requests to prevent server overload
5. **Use appropriate scope** - don't crawl beyond authorized targets
6. **Monitor impact** - watch for 429 (rate limit) responses

#### **Responsible Crawling Configuration**
```bash
# Scrapy settings for ethical crawling
DOWNLOAD_DELAY = 1                    # 1 second delay between requests
RANDOMIZE_DOWNLOAD_DELAY = 0.5        # 0.5 * to 1.5 * DOWNLOAD_DELAY
CONCURRENT_REQUESTS = 1               # Limit concurrent requests
ROBOTSTXT_OBEY = True                 # Respect robots.txt
USER_AGENT = 'responsible-crawler'    # Identify your crawler

# Example respectful crawling
scrapy crawl spider -s DOWNLOAD_DELAY=2 -s CONCURRENT_REQUESTS=1
```

#### **Legal Considerations**
- **Penetration Testing Authorization** - Ensure proper scope documentation
- **Rate Limiting Compliance** - Don't bypass intentional restrictions
- **Data Protection** - Handle discovered data responsibly
- **Service Availability** - Don't impact legitimate users
- **Disclosure** - Report findings through proper channels

---

## **Search Engine Discovery (OSINT)**

### **Overview**

Search Engine Discovery, also known as OSINT (Open Source Intelligence) gathering, leverages search engines as powerful reconnaissance tools to uncover information about target websites, organizations, and individuals. This technique uses specialized search operators to extract data that may not be readily visible on websites.

**Why Search Engine Discovery Matters:**
- **Open Source** - Information is publicly accessible, making it legal and ethical
- **Breadth of Information** - Search engines index vast portions of the web
- **Ease of Use** - User-friendly and requires no specialized technical skills
- **Cost-Effective** - Free and readily available resource for information gathering

**Applications:**
- **Security Assessment** - Identifying vulnerabilities, exposed data, and potential attack vectors
- **Competitive Intelligence** - Gathering information about competitors' products and services
- **Threat Intelligence** - Identifying emerging threats and tracking malicious actors
- **Investigative Research** - Uncovering hidden connections and financial transactions

### **Search Operators**

Search operators are specialized commands that unlock precise control over search results, allowing you to pinpoint specific types of information.

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `site:` | Limits results to specific website/domain | `site:example.com` | Find all publicly accessible pages |
| `inurl:` | Finds pages with specific term in URL | `inurl:login` | Search for login pages |
| `filetype:` | Searches for files of particular type | `filetype:pdf` | Find downloadable PDF documents |
| `intitle:` | Finds pages with specific term in title | `intitle:"confidential report"` | Look for confidential documents |
| `intext:` | Searches for term within body text | `intext:"password reset"` | Identify password reset pages |
| `cache:` | Displays cached version of webpage | `cache:example.com` | View previous content |
| `link:` | Finds pages linking to specific webpage | `link:example.com` | Identify websites linking to target |
| `related:` | Finds websites related to specific webpage | `related:example.com` | Discover similar websites |
| `info:` | Provides summary information about webpage | `info:example.com` | Get basic details about target |
| `define:` | Provides definitions of word/phrase | `define:phishing` | Get definitions from various sources |
| `numrange:` | Searches for numbers within specific range | `site:example.com numrange:1000-2000` | Find pages with numbers in range |
| `allintext:` | Finds pages containing all specified words in body | `allintext:admin password reset` | Search for multiple terms in body |
| `allinurl:` | Finds pages containing all specified words in URL | `allinurl:admin panel` | Look for multiple terms in URL |
| `allintitle:` | Finds pages containing all specified words in title | `allintitle:confidential report 2023` | Search for multiple terms in title |

### **Advanced Search Operators**

| Operator | Description | Example | Use Case |
|----------|-------------|---------|----------|
| `AND` | Requires all terms to be present | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages |
| `OR` | Includes pages with any of the terms | `"linux" OR "ubuntu" OR "debian"` | Search for any Linux distribution |
| `NOT` | Excludes results containing specified term | `site:bank.com NOT inurl:login` | Exclude login pages |
| `*` | Wildcard - represents any character/word | `site:company.com filetype:pdf user* manual` | Find user manuals (user guide, etc.) |
| `..` | Range search for numerical values | `site:ecommerce.com "price" 100..500` | Products priced between 100-500 |
| `" "` | Searches for exact phrases | `"information security policy"` | Find exact phrase matches |
| `-` | Excludes terms from search results | `site:news.com -inurl:sports` | Exclude sports content |

### **Google Dorking Examples**

#### **Finding Login Pages**
```bash
# Basic login page discovery
site:example.com inurl:login
site:example.com inurl:admin
site:example.com (inurl:login OR inurl:admin)

# Comprehensive admin interface discovery
site:example.com inurl:admin
site:example.com intitle:"admin panel"
site:example.com inurl:administrator
site:example.com "admin login"
```

#### **Identifying Exposed Files**
```bash
# Document discovery
site:example.com filetype:pdf
site:example.com (filetype:xls OR filetype:docx)
site:example.com filetype:pptx
site:example.com (filetype:doc OR filetype:docx OR filetype:pdf)

# Sensitive file types
site:example.com filetype:sql
site:example.com filetype:txt
site:example.com filetype:log
site:example.com filetype:bak
```

#### **Uncovering Configuration Files**
```bash
# Configuration file discovery
site:example.com inurl:config.php
site:example.com (ext:conf OR ext:cnf)
site:example.com (ext:ini OR ext:cfg)
site:example.com "wp-config.php"
```

#### **Locating Database Backups**
```bash
# Database backup discovery
site:example.com inurl:backup
site:example.com filetype:sql
site:example.com inurl:db
site:example.com (inurl:backup OR inurl:db OR filetype:sql)
```

#### **Finding Sensitive Information**
```bash
# Credential discovery
site:example.com "password"
site:example.com "username" AND "password"
site:example.com intext:"password" filetype:txt
site:example.com "login credentials"

# API key discovery
site:example.com "api_key"
site:example.com "API key"
site:example.com intext:"secret_key"
site:example.com "access_token"
```

#### **Directory Listings**
```bash
# Open directory discovery
site:example.com intitle:"index of"
site:example.com intitle:"directory listing"
site:example.com inurl:"/uploads/"
site:example.com inurl:"/files/"
```

#### **Error Pages and Debug Information**
```bash
# Error page discovery
site:example.com intext:"error"
site:example.com intitle:"error" OR intitle:"exception"
site:example.com "stack trace"
site:example.com "debug" OR "debugging"
```

### **Specialized Google Dorks**

#### **WordPress-Specific Dorks**
```bash
# WordPress discovery
site:example.com inurl:wp-admin
site:example.com inurl:wp-login.php
site:example.com inurl:wp-content
site:example.com "wp-config.php"
site:example.com inurl:wp-includes
```

#### **Database-Specific Dorks**
```bash
# Database interface discovery
site:example.com inurl:phpmyadmin
site:example.com "phpMyAdmin"
site:example.com inurl:adminer
site:example.com "database admin"
```

#### **Version Control Systems**
```bash
# Git repository discovery
site:example.com inurl:".git"
site:example.com filetype:git
site:example.com inurl:".svn"
site:example.com inurl:".hg"
```

### **OSINT Tools and Resources**

#### **Google Hacking Database**
```bash
# Access comprehensive dork database
# Visit: https://www.exploit-db.com/google-hacking-database
# Categories:
# - Footholds
# - Files containing usernames
# - Sensitive directories
# - Web server detection
# - Vulnerable files
# - Vulnerable servers
# - Error messages
# - Files containing passwords
# - Sensitive online shopping info
```

#### **Automated Google Dorking Tools**
```bash
# Pagodo - Automated Google Dorking
git clone https://github.com/opsdisk/pagodo.git
cd pagodo
python3 pagodo.py -d example.com -g dorks.txt -l 100 -s

# Dork-cli - Command line Google dorking
npm install -g dork-cli
dork -s "site:example.com" -c 100

# GooDork - Google dorking tool
go get github.com/dwisiswant0/goodork
goodork -q "site:example.com" -p 2
```

### **Search Engine Alternatives**

#### **Bing Search Operators**
```bash
# Bing-specific operators
site:example.com
url:example.com
domain:example.com
filetype:pdf site:example.com
inbody:"sensitive information"
```

#### **DuckDuckGo Search**
```bash
# DuckDuckGo operators
site:example.com
filetype:pdf
inurl:admin
intitle:"login"
```

#### **Yandex Search**
```bash
# Yandex operators
site:example.com
mime:pdf
inurl:admin
title:"confidential"
```

### **Practical OSINT Workflow**

#### **Phase 1: Initial Discovery**
```bash
# Basic reconnaissance
site:example.com
site:example.com inurl:login
site:example.com filetype:pdf
site:example.com intitle:"confidential"
```

#### **Phase 2: Deep Enumeration**
```bash
# Comprehensive file discovery
site:example.com (filetype:pdf OR filetype:doc OR filetype:xls)
site:example.com (inurl:admin OR inurl:login OR inurl:dashboard)
site:example.com (intext:"password" OR intext:"credential")
```

#### **Phase 3: Vulnerability Discovery**
```bash
# Security-focused searches
site:example.com inurl:".git"
site:example.com "index of"
site:example.com intext:"error" OR intext:"exception"
site:example.com inurl:config
```

#### **Phase 4: Intelligence Analysis**
```bash
# Organizational intelligence
site:example.com filetype:pdf "internal"
site:example.com "employee" OR "staff"
site:example.com intext:"@example.com"
```

### **Legal and Ethical Considerations**

#### **Best Practices**
1. **Stay within legal boundaries** - Only search publicly indexed information
2. **Respect robots.txt** - Understand website crawling policies
3. **Avoid automation abuse** - Don't overload search engines with requests
4. **Document findings responsibly** - Handle discovered information ethically
5. **Report vulnerabilities** - Follow responsible disclosure practices

#### **Limitations**
- **Not all information is indexed** - Some data may be hidden or protected
- **Information may be outdated** - Search engine caches may not reflect current state
- **False positives** - Search results may include irrelevant information
- **Rate limiting** - Search engines may limit query frequency

---

## **Web Archives (Wayback Machine)**

### **Overview**

Web Archives provide access to historical snapshots of websites, allowing reconnaissance professionals to explore how websites appeared and functioned in the past. The Internet Archive's Wayback Machine is the most prominent web archive, containing billions of web pages captured since 1996.

**What is the Wayback Machine?**
The Wayback Machine is a digital archive of the World Wide Web operated by the Internet Archive, a non-profit organization. It allows users to "go back in time" and view snapshots of websites as they appeared at various points in their history.

### **How the Wayback Machine Works**

The Wayback Machine operates through a three-step process:

1. **Crawling** - Automated web crawlers browse the internet systematically, following links and downloading webpage copies
2. **Archiving** - Downloaded webpages and resources are stored with specific timestamps, creating historical snapshots
3. **Accessing** - Users can view archived snapshots through the web interface by entering URLs and selecting dates

**Archive Frequency:**
- Popular websites: Multiple captures per day
- Regular websites: Weekly or monthly captures
- Less popular sites: Few snapshots over years
- Factors: Website popularity, update frequency, available resources

### **Why Web Archives Matter for Reconnaissance**

#### **Critical Applications:**
1. **Uncovering Hidden Assets** - Discover old pages, directories, files, or subdomains no longer accessible
2. **Vulnerability Discovery** - Find exposed sensitive information or security flaws from past versions
3. **Change Tracking** - Observe website evolution, technology changes, and structural modifications
4. **Intelligence Gathering** - Extract historical OSINT about target's activities, employees, strategies
5. **Stealthy Reconnaissance** - Passive activity that doesn't interact with target infrastructure

### **Wayback Machine Usage**

#### **Basic Web Interface**
```bash
# Access Wayback Machine
https://web.archive.org/

# Search specific website
https://web.archive.org/web/*/example.com

# View specific date capture
https://web.archive.org/web/20200101000000*/example.com

# Timeline view
https://web.archive.org/web/20200101*/example.com
```

#### **URL Format Structure**
```bash
# Standard format
https://web.archive.org/web/[timestamp]/[original-url]

# Timestamp format: YYYYMMDDhhmmss
# Example: 20200315143022 = March 15, 2020, 14:30:22

# Wildcard searches
https://web.archive.org/web/2020*/example.com
https://web.archive.org/web/*/example.com/admin
```

### **Advanced Wayback Machine Techniques**

#### **Subdomain Discovery**
```bash
# Search for subdomains in archived content
https://web.archive.org/web/*/subdomain.example.com
https://web.archive.org/web/*/admin.example.com
https://web.archive.org/web/*/api.example.com
https://web.archive.org/web/*/dev.example.com

# Use site search with wildcards
https://web.archive.org/web/*/*.example.com
```

#### **Directory and File Discovery**
```bash
# Look for historical directories
https://web.archive.org/web/*/example.com/admin/
https://web.archive.org/web/*/example.com/backup/
https://web.archive.org/web/*/example.com/config/
https://web.archive.org/web/*/example.com/uploads/

# Search for specific file types
https://web.archive.org/web/*/example.com/*.pdf
https://web.archive.org/web/*/example.com/*.sql
https://web.archive.org/web/*/example.com/*.txt
```

#### **Technology Evolution Tracking**
```bash
# Compare technology changes over time
# 2015: Basic HTML site
https://web.archive.org/web/20150101/example.com

# 2018: WordPress migration
https://web.archive.org/web/20180101/example.com

# 2023: Modern framework
https://web.archive.org/web/20230101/example.com
```

### **Automated Wayback Machine Tools**

#### **waybackurls - URL Extraction**
```bash
# Install waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Extract all URLs for domain
echo "example.com" | waybackurls

# Extract URLs from specific timeframe
echo "example.com" | waybackurls | grep "2020"

# Find specific file types
echo "example.com" | waybackurls | grep -E "\.(pdf|sql|txt|bak)$"

# Find admin/login pages
echo "example.com" | waybackurls | grep -E "(admin|login|dashboard)"
```

#### **gau (GetAllURLs)**
```bash
# Install gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Get all URLs from multiple sources including Wayback
gau example.com

# Output to file
gau example.com > urls.txt

# Filter by status codes
gau example.com | grep "200"

# Find specific paths
gau example.com | grep "/api/"
```

#### **Wayback Machine Downloader**
```bash
# Install wayback machine downloader
gem install wayback_machine_downloader

# Download entire archived website
wayback_machine_downloader http://example.com

# Download specific time range
wayback_machine_downloader http://example.com -from 20180101 -to 20181231

# Download only specific file types
wayback_machine_downloader http://example.com -only_filter "\.pdf$"

# Download from specific timestamp
wayback_machine_downloader http://example.com -timestamp 20200315
```

### **Historical Intelligence Gathering**

#### **Employee and Contact Discovery**
```bash
# Look for historical team/about pages
https://web.archive.org/web/*/example.com/team
https://web.archive.org/web/*/example.com/about
https://web.archive.org/web/*/example.com/contact
https://web.archive.org/web/*/example.com/staff

# Search for email patterns in archived content
waybackurls example.com | xargs curl -s | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
```

#### **Technology Stack Evolution**
```bash
# Track technology changes
# Compare HTML source between years
https://web.archive.org/web/20150101/example.com (view source)
https://web.archive.org/web/20200101/example.com (view source)

# Look for framework/CMS changes
# WordPress indicators: wp-content, wp-includes
# Drupal indicators: sites/default, drupal.js
# Custom frameworks: unique JavaScript/CSS patterns
```

#### **Sensitive Information Discovery**
```bash
# Look for accidentally exposed files
waybackurls example.com | grep -E "\.(sql|bak|old|config|env)$"

# Search for development/staging environments
waybackurls example.com | grep -E "(dev|staging|test|demo)\."

# Find configuration files
waybackurls example.com | grep -E "(config|settings|wp-config)"

# Look for debug/error pages
waybackurls example.com | grep -E "(error|debug|exception)"
```

### **Manual Investigation Techniques**

#### **Timeline Analysis**
```bash
# Create investigation timeline
1. Identify key dates (launch, major updates, security incidents)
2. Compare snapshots before/after major changes
3. Look for temporary exposures during transitions
4. Track technology migration periods
5. Identify patterns in content/structure changes
```

#### **Content Comparison**
```bash
# Compare different time periods
# Use browser developer tools to:
# 1. View page source differences
# 2. Check JavaScript/CSS file changes
# 3. Analyze HTML comments
# 4. Look for hidden form fields
# 5. Extract metadata changes
```

### **HTB Academy Lab Examples**

#### **Lab 6: Wayback Machine Investigation**
```bash
# HackTheBox historical analysis
# Access archived HTB versions
https://web.archive.org/web/20170610/hackthebox.eu

# Questions from HTB Academy:
# 1. Pen Testing Labs count on August 8, 2018
https://web.archive.org/web/20180808/hackthebox.eu

# 2. Member count on June 10, 2017
https://web.archive.org/web/20170610/hackthebox.eu

# Historical domain redirects
# 3. Facebook.com redirect in March 2002
https://web.archive.org/web/20020301/facebook.com

# Product evolution tracking
# 4. PayPal "beam money" product in October 1999
https://web.archive.org/web/19991001/paypal.com

# Technology prototypes
# 5. Google Search Engine Prototype in November 1998
https://web.archive.org/web/19981101/google.com

# Administrative information
# 6. IANA last update date in March 2000
https://web.archive.org/web/20000301/www.iana.org

# Content metrics
# 7. Wikipedia page count in March 2001
https://web.archive.org/web/20010301/wikipedia.com
```

#### **Practical Investigation Workflow**
```bash
# Step 1: Initial timeline exploration
waybackurls target.com | head -20

# Step 2: Identify key time periods
# Look for major gaps or changes in archive frequency

# Step 3: Manual investigation of critical periods
# Focus on transitions, launches, incidents

# Step 4: Automated URL extraction
echo "target.com" | waybackurls | grep -E "(admin|config|backup|dev)"

# Step 5: Content analysis
# Download and analyze specific snapshots
```

### **Alternative Web Archives**

#### **Archive.today**
```bash
# Access archive.today (also archive.is, archive.ph)
https://archive.today/

# Search specific domain
https://archive.today/https://example.com

# Manual snapshots - user-submitted
# Good for recent captures and specific pages
```

#### **Common Crawl**
```bash
# Access Common Crawl data
# Large-scale web crawl data available for research
# More technical, requires processing tools
# Useful for large-scale analysis
```

#### **Library and Government Archives**
```bash
# UK Web Archive: https://www.webarchive.org.uk/
# End of Term Archive: http://eotarchive.cdlib.org/
# Portuguese Web Archive: http://arquivo.pt/
# National archives often contain region-specific content
```

### **Limitations and Considerations**

#### **Technical Limitations**
1. **Not all content archived** - Dynamic content, JavaScript-heavy sites may not work
2. **Incomplete captures** - Some resources (images, CSS) may be missing
3. **No interaction** - Forms, logins, and dynamic features don't work
4. **robots.txt respect** - Some content excluded by website owners
5. **Legal restrictions** - Some content removed due to legal requests

#### **Investigation Challenges**
1. **Content authenticity** - Verify information with other sources
2. **Timestamp accuracy** - Archive dates may not reflect actual publication dates
3. **Context missing** - Surrounding events and circumstances
4. **Selective preservation** - Popular sites better archived than obscure ones

### **Legal and Ethical Guidelines**

#### **Best Practices**
1. **Respect copyright** - Archived content still subject to intellectual property laws
2. **Privacy considerations** - Personal information in archives should be handled responsibly
3. **Purpose limitation** - Use archived data only for legitimate security research
4. **Disclosure responsibility** - Report significant findings through proper channels
5. **Documentation** - Maintain records of research methodology and sources

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

### **Lab 1: Fingerprinting inlanefreight.com**

#### **Banner Grabbing with curl**
```bash
# Basic HTTP headers
curl -I inlanefreight.com

# Expected output:
# HTTP/1.1 301 Moved Permanently
# Date: Fri, 31 May 2024 12:07:44 GMT
# Server: Apache/2.4.41 (Ubuntu)
# Location: https://inlanefreight.com/
# Content-Type: text/html; charset=iso-8859-1

# Follow redirects to HTTPS
curl -I https://inlanefreight.com

# Shows WordPress redirection:
# HTTP/1.1 301 Moved Permanently
# Server: Apache/2.4.41 (Ubuntu)
# X-Redirect-By: WordPress
# Location: https://www.inlanefreight.com/

# Final destination
curl -I https://www.inlanefreight.com

# Shows WordPress-specific headers:
# HTTP/1.1 200 OK
# Server: Apache/2.4.41 (Ubuntu)
# Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
# Link: <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"
```

#### **WAF Detection with wafw00f**
```bash
# Install wafw00f
pip3 install git+https://github.com/EnableSecurity/wafw00f

# Detect WAF
wafw00f inlanefreight.com

# Expected output:
# [*] Checking https://inlanefreight.com
# [+] The site https://inlanefreight.com is behind Wordfence (Defiant) WAF.
# [~] Number of requests: 2
```

#### **Comprehensive Scanning with Nikto**
```bash
# Fingerprinting-only scan
nikto -h inlanefreight.com -Tuning b

# Expected findings:
# + Target IP: 134.209.24.248
# + Target Hostname: www.inlanefreight.com
# + SSL Info: Subject: /CN=inlanefreight.com
# + Server: Apache/2.4.41 (Ubuntu)
# + /index.php?: Uncommon header 'x-redirect-by' found, with contents: WordPress
# + Apache/2.4.41 appears to be outdated (current is at least 2.4.59)
# + /license.txt: License file found may identify site software
# + /: A Wordpress installation was found
# + /wp-login.php: Wordpress login found
```

#### **Technology Stack Analysis**
```bash
# Comprehensive technology detection
whatweb https://www.inlanefreight.com

# Manual analysis reveals:
# - Web Server: Apache/2.4.41 (Ubuntu)
# - CMS: WordPress
# - SSL/TLS: Let's Encrypt certificate
# - Security: Wordfence WAF protection
# - IPv6: Dual-stack configuration
# - API: WordPress REST API exposed
```

### **Lab 2: Virtual Host Discovery**
```bash
# Discover virtual hosts for target system
ffuf -u http://target-ip -H "Host: FUZZ.inlanefreight.local" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fs 10918

# Test discovered virtual hosts
curl -H "Host: app.inlanefreight.local" http://target-ip
curl -H "Host: dev.inlanefreight.local" http://target-ip

# Analyze responses for different technologies
curl -I -H "Host: app.inlanefreight.local" http://target-ip
curl -I -H "Host: dev.inlanefreight.local" http://target-ip
```

### **Lab 3: Directory Discovery**
```bash
# Comprehensive directory enumeration
gobuster dir -u http://target-ip -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# WordPress-specific enumeration
gobuster dir -u http://target-ip -w /usr/share/wordlists/SecLists/Discovery/Web-Content/CMS/wp-plugins.txt

# Look for sensitive files
gobuster dir -u http://target-ip -w /usr/share/wordlists/dirb/common.txt -x bak,backup,old,orig,license
```

### **Lab 4: ReconSpider Web Crawling**
```bash
# Install and run ReconSpider
pip3 install scrapy
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip

# Spider the target
python3 ReconSpider.py http://inlanefreight.com

# Alternative tool location
python3 /opt/tools/ReconSpider.py http://inlanefreight.com

# Analyze results for cloud storage
cat results.json | jq '.external_files[]' | grep -E "(s3\.|amazonaws|blob\.core|storage\.googleapis)"

# Expected finding from HTB Academy lab:
# inlanefreight-comp133.s3.amazonaws.htb
# This indicates AWS S3 bucket for future reports storage
```

#### **ReconSpider Results Analysis**
```bash
# Extract email addresses
cat results.json | jq '.emails[]'
# Output: lily.floid@inlanefreight.com, cvs@inlanefreight.com

# Find external files
cat results.json | jq '.external_files[]' | head -5
# Output: PDFs, documents, potential sensitive files

# Extract JavaScript files for endpoint discovery
cat results.json | jq '.js_files[]' | grep -v ".min.js" | head -3
# Output: Non-minified JS files for analysis

# Look for HTML comments
cat results.json | jq '.comments[]' | head -5
# Output: HTML comments that might contain sensitive information
```

### **Lab 5: Search Engine Discovery (OSINT)**
```bash
# Basic reconnaissance using Google dorking
site:inlanefreight.com
site:inlanefreight.com inurl:login
site:inlanefreight.com filetype:pdf

# Document discovery
site:inlanefreight.com (filetype:pdf OR filetype:doc OR filetype:xls)
site:inlanefreight.com "confidential" OR "internal"
site:inlanefreight.com intitle:"report" filetype:pdf

# Login interface discovery
site:inlanefreight.com inurl:admin
site:inlanefreight.com inurl:login
site:inlanefreight.com intitle:"admin panel"

# Configuration file discovery
site:inlanefreight.com inurl:config
site:inlanefreight.com "wp-config.php"
site:inlanefreight.com ext:conf OR ext:cnf

# Error page discovery
site:inlanefreight.com intext:"error"
site:inlanefreight.com "stack trace"
site:inlanefreight.com "debug"

# Version control exposure
site:inlanefreight.com inurl:".git"
site:inlanefreight.com inurl:".svn"

# Directory listing discovery
site:inlanefreight.com intitle:"index of"
site:inlanefreight.com inurl:"/uploads/"
```

#### **OSINT Intelligence Analysis**
```bash
# Employee enumeration
site:inlanefreight.com "employee" OR "staff"
site:inlanefreight.com intext:"@inlanefreight.com"
site:inlanefreight.com "team" OR "about us"

# Technology stack identification
site:inlanefreight.com "powered by"
site:inlanefreight.com "built with"
site:inlanefreight.com "framework"

# Credential discovery
site:inlanefreight.com "password"
site:inlanefreight.com "username" AND "password"
site:inlanefreight.com intext:"api_key"

# Backup file discovery
site:inlanefreight.com inurl:backup
site:inlanefreight.com filetype:sql
site:inlanefreight.com filetype:bak
```

---

## **Automated Reconnaissance Frameworks**

### **Overview**

While manual reconnaissance can be effective, it can also be time-consuming and prone to human error. Automating web reconnaissance tasks significantly enhances efficiency and accuracy, allowing you to gather information at scale and identify potential vulnerabilities more rapidly.

**Why Automate Reconnaissance?**

**Key Advantages:**
- **Efficiency** - Automated tools perform repetitive tasks much faster than humans
- **Scalability** - Scale reconnaissance efforts across large numbers of targets
- **Consistency** - Follow predefined rules ensuring reproducible results
- **Comprehensive Coverage** - Perform wide range of tasks: DNS, subdomains, crawling, port scanning
- **Integration** - Easy integration with other tools creating seamless workflows

### **Reconnaissance Frameworks**

#### **FinalRecon - All-in-One Python Framework**
```bash
# Installation
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py

# Basic usage
./finalrecon.py --help
```

**FinalRecon Features:**
- **Header Information** - Server details, technologies, security misconfigurations
- **Whois Lookup** - Domain registration details, registrant information
- **SSL Certificate Information** - Certificate validity, issuer, security details
- **Web Crawler** - HTML/CSS/JavaScript analysis, internal/external links
- **DNS Enumeration** - 40+ DNS record types including DMARC
- **Subdomain Enumeration** - Multiple sources (crt.sh, AnubisDB, ThreatMiner, etc.)
- **Directory Enumeration** - Custom wordlists and file extensions
- **Wayback Machine** - URLs from last 5 years
- **Port Scanning** - Fast port enumeration

#### **FinalRecon Command Options**
| Option | Argument | Description |
|--------|----------|-------------|
| `--url` | URL | Specify target URL |
| `--headers` | - | Retrieve header information |
| `--sslinfo` | - | Get SSL certificate information |
| `--whois` | - | Perform Whois lookup |
| `--crawl` | - | Crawl target website |
| `--dns` | - | Perform DNS enumeration |
| `--sub` | - | Enumerate subdomains |
| `--dir` | - | Search for directories |
| `--wayback` | - | Retrieve Wayback URLs |
| `--ps` | - | Fast port scan |
| `--full` | - | Full reconnaissance scan |

#### **FinalRecon Advanced Options**
| Option | Default | Description |
|--------|---------|-------------|
| `-dt` | 30 | Number of threads for directory enum |
| `-pt` | 50 | Number of threads for port scan |
| `-T` | 30.0 | Request timeout |
| `-w` | dirb_common.txt | Path to wordlist |
| `-r` | False | Allow redirect |
| `-s` | True | Toggle SSL verification |
| `-d` | 1.1.1.1 | Custom DNS servers |
| `-e` | - | File extensions (txt,xml,php) |
| `-o` | txt | Export format |
| `-k` | - | Add API key (shodan@key) |

#### **FinalRecon Practical Examples**
```bash
# Basic header and whois analysis
./finalrecon.py --headers --whois --url http://inlanefreight.com

# Full reconnaissance scan
./finalrecon.py --full --url http://example.com

# Specific modules combination
./finalrecon.py --dns --sub --dir --url http://example.com

# Custom directory enumeration
./finalrecon.py --dir --url http://example.com -w /usr/share/wordlists/dirb/big.txt -e php,txt,html

# SSL and header analysis
./finalrecon.py --sslinfo --headers --url https://example.com

# Subdomain enumeration with API keys
./finalrecon.py --sub --url example.com -k shodan@your_api_key
```

### **Other Reconnaissance Frameworks**

#### **Recon-ng - Modular Framework**
```bash
# Installation
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip3 install -r REQUIREMENTS

# Basic usage
./recon-ng
[recon-ng][default] > marketplace search
[recon-ng][default] > marketplace install all
[recon-ng][default] > modules load recon/domains-hosts/brute_hosts
[recon-ng][default][brute_hosts] > options set SOURCE example.com
[recon-ng][default][brute_hosts] > run
```

**Recon-ng Features:**
- **Modular Structure** - Various modules for different tasks
- **Database Integration** - Store and manage reconnaissance data
- **API Integration** - Multiple third-party services
- **Report Generation** - HTML, XML, CSV output formats
- **Extensible** - Custom module development

#### **theHarvester - OSINT Data Gathering**
```bash
# Installation
pip3 install theHarvester

# Basic usage
theHarvester -d example.com -l 500 -b all

# Specific sources
theHarvester -d example.com -l 200 -b google,bing,yahoo

# DNS brute force
theHarvester -d example.com -c

# Save results
theHarvester -d example.com -l 100 -b google -f results.xml
```

**theHarvester Features:**
- **Email Address Discovery** - Multiple search engines and sources
- **Subdomain Enumeration** - Various databases and APIs
- **Employee Name Discovery** - Social media and public records
- **Host Discovery** - Active and passive techniques
- **Port Scanning** - Basic port enumeration
- **Banner Grabbing** - Service identification

#### **SpiderFoot - OSINT Automation**
```bash
# Installation
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt

# Web interface
python3 sf.py -l 127.0.0.1:5001

# Command line
python3 sfcli.py -s example.com
```

**SpiderFoot Features:**
- **100+ Modules** - Comprehensive data source integration
- **Web Interface** - User-friendly dashboard
- **API Support** - RESTful API for automation
- **Real-time Analysis** - Live data correlation
- **Threat Intelligence** - Malware, blacklist checking
- **Social Media** - Profile and relationship discovery

#### **OSINT Framework - Tool Collection**
```bash
# Access online
https://osintframework.com/

# Categories:
# - Username
# - Email Address
# - Domain Name
# - IP Address
# - Documents
# - Business Records
# - Phone Numbers
# - Social Networks
```

### **Automation Workflow Design**

#### **Phase 1: Initial Reconnaissance**
```bash
# FinalRecon full scan
./finalrecon.py --full --url http://target.com

# theHarvester data gathering
theHarvester -d target.com -l 500 -b all

# Basic subdomain enumeration
subfinder -d target.com
```

#### **Phase 2: Deep Enumeration**
```bash
# Recon-ng comprehensive scan
# Load multiple modules for thorough coverage

# SpiderFoot automated investigation
# 100+ modules for extensive data correlation

# Custom script automation
# Combine multiple tools in pipeline
```

#### **Phase 3: Data Analysis**
```bash
# Consolidate results from multiple tools
# Remove duplicates and false positives
# Prioritize high-value targets
# Generate comprehensive reports
```

### **Custom Automation Scripts**

#### **Bash Automation Example**
```bash
#!/bin/bash
# Auto-recon script

TARGET=$1
echo "[+] Starting automated reconnaissance for $TARGET"

# Phase 1: Basic enumeration
echo "[+] Running subfinder..."
subfinder -d $TARGET -o subdomains.txt

echo "[+] Running theHarvester..."
theHarvester -d $TARGET -l 500 -b all -f harvester_results.xml

# Phase 2: Web enumeration  
echo "[+] Running FinalRecon..."
./finalrecon.py --full --url http://$TARGET

# Phase 3: Archive analysis
echo "[+] Running waybackurls..."
echo $TARGET | waybackurls > wayback_urls.txt

# Phase 4: Technology identification
echo "[+] Running whatweb..."
whatweb $TARGET

echo "[+] Reconnaissance completed for $TARGET"
```

#### **Python Automation Example**
```python
#!/usr/bin/env python3
import subprocess
import sys
import json

def run_subfinder(domain):
    """Run subfinder and return results"""
    cmd = f"subfinder -d {domain} -silent"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout.strip().split('\n')

def run_waybackurls(domain):
    """Run waybackurls and return results"""
    cmd = f"echo {domain} | waybackurls"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip().split('\n')

def run_whatweb(domain):
    """Run whatweb and return results"""
    cmd = f"whatweb {domain} --log-json=-"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 auto_recon.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    results = {}
    
    print(f"[+] Starting automated reconnaissance for {domain}")
    
    # Subdomain enumeration
    print("[+] Running subdomain enumeration...")
    results['subdomains'] = run_subfinder(domain)
    
    # Wayback Machine URLs
    print("[+] Gathering historical URLs...")
    results['wayback_urls'] = run_waybackurls(domain)
    
    # Technology identification
    print("[+] Identifying technologies...")
    results['technologies'] = run_whatweb(domain)
    
    # Save results
    with open(f"{domain}_recon_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to {domain}_recon_results.json")

if __name__ == "__main__":
    main()
```

### **Tool Integration Strategies**

#### **API-Based Integration**
```bash
# Shodan API integration
shodan host $target_ip

# VirusTotal API
curl -H "x-apikey: YOUR_API_KEY" \
  "https://www.virustotal.com/vtapi/v2/domain/report?domain=example.com"

# SecurityTrails API
curl -H "APIKEY: YOUR_API_KEY" \
  "https://api.securitytrails.com/v1/domain/example.com/subdomains"
```

#### **Output Standardization**
```bash
# JSON output for parsing
tool --output json target.com | jq '.'

# CSV for spreadsheet analysis
tool --output csv target.com

# XML for detailed processing
tool --output xml target.com
```

### **Best Practices for Automation**

#### **Performance Optimization**
1. **Parallel Execution** - Run multiple tools simultaneously
2. **Rate Limiting** - Respect target server resources
3. **Caching** - Store results to avoid duplicate work
4. **Threading** - Use appropriate thread counts
5. **Resource Management** - Monitor CPU and memory usage

#### **Error Handling**
1. **Graceful Failures** - Continue execution if one tool fails
2. **Retry Logic** - Implement retry mechanisms for network issues
3. **Logging** - Comprehensive logging for debugging
4. **Validation** - Verify tool outputs and results
5. **Backup Plans** - Alternative tools for critical functions

#### **Security Considerations**
1. **API Key Management** - Secure storage of credentials
2. **Network Isolation** - Run in controlled environments
3. **Output Sanitization** - Clean and validate results
4. **Access Controls** - Restrict tool usage and access
5. **Audit Trails** - Maintain records of automation activities

### **HTB Academy Lab Examples**

#### **Lab 7: FinalRecon Automation**
```bash
# Install FinalRecon
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py

# Run header and whois analysis
./finalrecon.py --headers --whois --url http://inlanefreight.com

# Expected output analysis:
# Headers: Server: Apache/2.4.41 (Ubuntu)
# Whois: Domain registration details, AWS name servers
# Export: Results saved to ~/.local/share/finalrecon/dumps/
```

#### **Automation Workflow Example**
```bash
# Step 1: Quick reconnaissance
./finalrecon.py --headers --whois --dns --url http://target.com

# Step 2: Comprehensive scan
./finalrecon.py --full --url http://target.com

# Step 3: Targeted enumeration
./finalrecon.py --sub --dir --wayback --url http://target.com

# Step 4: Analysis and reporting
# Review exported results in JSON/TXT format
# Correlate findings with manual analysis
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
| **nikto** | Web server scanning | Comprehensive security assessment |
| **builtwith** | Technology profiling | Detailed technology stack analysis |
| **netcraft** | Web security services | Security posture assessment |
| **gobuster** | Directory/file discovery | Finding hidden content |
| **ffuf** | Web fuzzing | Parameter/vhost discovery |
| **wpscan** | WordPress security | CMS-specific testing |
| **burp suite** | Web application testing | Manual analysis |
| **arjun** | Parameter discovery | Finding hidden parameters |
| **wafw00f** | WAF detection | Security control identification |
| **reconspider** | Custom web crawling | HTB Academy reconnaissance |
| **hakrawler** | Web crawling | Content discovery |
| **burp spider** | Professional crawling | Web application mapping |
| **owasp zap** | Security scanning | Vulnerability discovery |
| **scrapy** | Custom crawling | Python framework |
| **google dorking** | OSINT reconnaissance | Search engine discovery |
| **pagodo** | Automated dorking | Google hacking database |
| **wayback machine** | Web archives | Historical website analysis |
| **waybackurls** | Archive URL extraction | Historical endpoint discovery |
| **gau** | URL aggregation | Multiple source URL collection |
| **finalrecon** | Automated framework | All-in-one Python reconnaissance |
| **recon-ng** | Modular framework | Database-driven reconnaissance |
| **theharvester** | OSINT gathering | Email, subdomain, employee discovery |
| **spiderfoot** | OSINT automation | 100+ module automation platform |
| **linkfinder** | JavaScript analysis | Endpoint extraction |

---

## **Key Takeaways**

1. **Technology identification** guides subsequent testing approaches
2. **Directory enumeration** reveals hidden functionality and files
3. **Parameter discovery** uncovers additional attack surface
4. **Web crawling** provides comprehensive content discovery
5. **Search engine discovery** exposes publicly indexed sensitive information
6. **Web archives** reveal historical assets and vulnerabilities
7. **JavaScript analysis** exposes client-side vulnerabilities
8. **Virtual hosts** may contain additional applications
9. **Security headers** indicate the security posture
10. **CMS enumeration** requires specialized tools and techniques
11. **WAF detection** is crucial for bypass strategy
12. **API enumeration** focuses on modern application architectures
13. **OSINT techniques** reveal organizational intelligence
14. **Automated frameworks** significantly enhance reconnaissance efficiency
15. **Comprehensive methodology** combines multiple tools and techniques

---

## **References**

- HTB Academy: Information Gathering - Web Edition
- OWASP Web Security Testing Guide
- SecLists: https://github.com/danielmiessler/SecLists
- Burp Suite Documentation
- FFUF Documentation: https://github.com/ffuf/ffuf
- Google Hacking Database: https://www.exploit-db.com/google-hacking-database
- Pagodo: https://github.com/opsdisk/pagodo
- ReconSpider: https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
- Wayback Machine: https://web.archive.org/
- waybackurls: https://github.com/tomnomnom/waybackurls
- gau (GetAllURLs): https://github.com/lc/gau
- Wayback Machine Downloader: https://github.com/hartator/wayback-machine-downloader
- FinalRecon: https://github.com/thewhiteh4t/FinalRecon
- Recon-ng: https://github.com/lanmaster53/recon-ng
- theHarvester: https://github.com/laramies/theHarvester
- SpiderFoot: https://github.com/smicallef/spiderfoot
- OSINT Framework: https://osintframework.com/ 