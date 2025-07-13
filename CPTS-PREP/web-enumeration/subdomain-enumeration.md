# 🌐 Subdomain Enumeration & DNS Discovery

## **Overview**

Subdomain enumeration is a critical phase of web reconnaissance that focuses on discovering subdomains and DNS infrastructure. This process reveals the attack surface by identifying additional hosts, services, and potential entry points that might not be immediately visible.

**Key Objectives:**
- Discover hidden subdomains and services
- Map DNS infrastructure and name servers
- Identify cloud resources and third-party services
- Analyze DNS security configurations
- Enumerate zone transfers and DNS vulnerabilities

---

## **DNS Tools Overview**

| Tool | Key Features | Best Use Case |
|------|-------------|---------------|
| **dig** | Versatile DNS lookup tool supporting all record types with detailed output | Manual DNS queries, zone transfers, troubleshooting |
| **dnsenum** | Comprehensive DNS enumeration with zone transfers, brute-forcing, WHOIS | All-in-one automated DNS reconnaissance |
| **fierce** | DNS reconnaissance with recursive search and wildcard detection | User-friendly subdomain discovery |
| **dnsrecon** | Multi-technique DNS reconnaissance with custom output formats | Comprehensive enumeration with various methods |
| **amass** | Advanced subdomain discovery with 30+ data sources | Maximum subdomain coverage (passive + active) |
| **assetfinder** | Simple subdomain discovery using various techniques | Quick lightweight scans |
| **subfinder** | Passive subdomain enumeration from public sources | Stealth reconnaissance |
| **puredns** | High-performance DNS brute-forcer with wildcard filtering | Massive wordlist handling |
| **theHarvester** | OSINT tool gathering subdomains from search engines | Email addresses + subdomain discovery |

---

## **Manual DNS Enumeration**

### **The Domain Information Groper (dig)**

The `dig` command is the most versatile DNS enumeration tool, essential for manual analysis:

#### **Common dig Commands**
```bash
# Basic record queries
dig domain.com A          # IPv4 addresses
dig domain.com AAAA       # IPv6 addresses  
dig domain.com MX         # Mail servers
dig domain.com NS         # Name servers
dig domain.com TXT        # Text records
dig domain.com SOA        # Start of authority

# Query specific DNS server
dig @1.1.1.1 domain.com A

# Trace full DNS resolution path
dig +trace domain.com

# Short output only
dig +short domain.com

# Reverse DNS lookup
dig -x 192.168.1.1
```

#### **Zone Transfer Attempts**
```bash
# Discover name servers
dig domain.com NS

# Attempt zone transfers
dig @ns1.domain.com domain.com AXFR
dig @ns2.domain.com domain.com AXFR

# Test all name servers
for ns in $(dig +short domain.com NS); do
  echo "Testing $ns for zone transfer"
  dig @$ns domain.com AXFR
done
```

#### **Advanced dig Techniques**
```bash
# DNS server version detection
dig @dns-server version.bind CH TXT

# Check DNSSEC implementation
dig +dnssec domain.com

# TCP queries (for large responses)
dig +tcp domain.com TXT

# No recursion (direct authoritative query)
dig +norecurse @ns1.domain.com domain.com
```

---

## **Automated DNS Enumeration**

### **dnsenum - Comprehensive DNS Enumeration**

**dnsenum** is a versatile Perl-based tool providing comprehensive DNS reconnaissance:

**Key Features:**
- DNS Record Enumeration (A, AAAA, NS, MX, TXT)
- Automatic zone transfer attempts
- Subdomain brute-forcing with wordlists
- Google scraping for additional subdomains
- Reverse lookups and WHOIS integration

```bash
# Basic enumeration with HTB Academy example
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Complete enumeration with recursion
dnsenum --enum example.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r

# Custom DNS server
dnsenum --dnsserver 8.8.8.8 --enum example.com

# Without reverse lookups (faster)
dnsenum --noreverse example.com

# Advanced options
dnsenum --enum example.com \
    -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    --dnsserver 1.1.1.1 \
    --timeout 10 \
    --threads 5 \
    -r
```

### **fierce - User-Friendly Subdomain Scanner**
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

### **dnsrecon - Advanced DNS Reconnaissance**
```bash
# Standard enumeration
dnsrecon -d example.com

# Brute force with custom wordlist
dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t brt

# Zone transfer attempts
dnsrecon -d example.com -t axfr

# Reverse lookup on IP range
dnsrecon -r 192.168.1.0/24

# Google enumeration
dnsrecon -d example.com -t goo
```

---

## **Advanced Subdomain Discovery**

### **amass - Comprehensive Subdomain Discovery**

**amass** is the most powerful subdomain discovery tool with extensive data sources:

**Key Features:**
- 30+ external data sources for passive enumeration
- Active DNS brute-forcing and permutation
- Integration with APIs and other tools
- Network mapping and visualization
- Continuous monitoring capabilities

```bash
# Basic subdomain enumeration
amass enum -d example.com

# Passive enumeration only (stealth)
amass enum -passive -d example.com

# Active enumeration with brute-forcing
amass enum -active -d example.com -brute

# Multiple domains
amass enum -d example.com,target.com,company.com

# Use all available data sources
amass enum -d example.com -src

# Output to file
amass enum -d example.com -o subdomains.txt

# JSON output for parsing
amass enum -d example.com -json subdomain_data.json

# Use specific resolvers
amass enum -d example.com -rf resolvers.txt

# Rate limiting
amass enum -d example.com -rps 10

# Advanced configuration
amass enum -d example.com -config /path/to/config.yaml
```

**Configuration Example:**
```yaml
# ~/.config/amass/config.yaml
scope:
  domains:
    - example.com
  blacklist:
    - test.example.com
    - dev.example.com

brute_forcing:
  enabled: true
  recursive: true
  min_for_recursive: 1

data_sources:
  - name: CertSpotter
    apikey: your-api-key
  - name: Shodan
    apikey: your-api-key
```

### **puredns - High-Performance DNS Brute-Forcer**

**puredns** excels at high-performance brute-forcing with smart filtering:

**Key Features:**
- Handles massive wordlists efficiently
- Wildcard detection and filtering
- Custom DNS resolver configuration
- Rate limiting to prevent server overload
- Trusted domain validation

```bash
# Basic brute-forcing
puredns bruteforce wordlist.txt example.com

# Use custom resolvers
puredns bruteforce wordlist.txt example.com --resolvers resolvers.txt

# Rate limiting (queries per second)
puredns bruteforce wordlist.txt example.com --rate-limit 1000

# Wildcard detection and filtering
puredns bruteforce wordlist.txt example.com --wildcard-tests 3

# Advanced filtering
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt example.com \
    --resolvers resolvers.txt \
    --rate-limit 500 \
    --wildcard-tests 5 \
    --write results.txt \
    --write-wildcards wildcards.txt \
    --progress

# Resolve existing subdomain list
puredns resolve subdomains.txt --resolvers resolvers.txt --write resolved.txt
```

---

## **Passive Subdomain Discovery**

### **Certificate Transparency**
```bash
# Basic crt.sh search
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq -r '.[].name_value' | sort -u

# Filter for web-related subdomains
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq -r '.[].name_value' | grep -E "(www|web|app|api|admin|portal|dashboard)"
```

### **subfinder - Passive Subdomain Discovery**
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

### **assetfinder - Quick Subdomain Enumeration**
```bash
# Fast subdomain discovery
assetfinder example.com

# Find only subdomains
assetfinder --subs-only example.com
```

### **theHarvester - OSINT DNS Gathering**
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

## **Tool Selection Guide**

### **When to Use What**

| Scenario | Recommended Tool | Reason |
|----------|------------------|--------|
| **Quick manual DNS queries** | **dig** | Most versatile, detailed output |
| **Comprehensive automated scan** | **dnsenum** | All-in-one: zone transfers, brute-force, WHOIS |
| **Passive reconnaissance only** | **amass** (passive) | 30+ data sources, stealth |
| **Maximum subdomain coverage** | **amass** (active) | Passive + active brute-forcing |
| **High-performance brute-forcing** | **puredns** | Massive wordlists, wildcard filtering |
| **User-friendly quick scan** | **fierce** | Simple interface, wildcard detection |
| **Multi-technique approach** | **dnsrecon** | Various techniques, custom outputs |
| **Quick lightweight scan** | **assetfinder** | Fast, simple discovery |

### **Performance Comparison**

| Tool | Speed | Accuracy | Stealth | Wordlist Size | Resource Usage |
|------|-------|----------|---------|---------------|----------------|
| **dig** | Manual | High | High | Manual | Low |
| **dnsenum** | Medium | High | Medium | Medium | Medium |
| **amass** | Medium-Fast | Very High | High (passive) | Large | High |
| **puredns** | Very Fast | High | Medium | Very Large | Medium |
| **fierce** | Fast | High | Medium | Medium | Low |
| **dnsrecon** | Medium | High | Medium | Medium | Medium |
| **assetfinder** | Fast | Medium | High | N/A | Low |
| **subfinder** | Fast | High | High | N/A | Low |

---

## **Recommended Workflow**

### **Phase 1: Quick Discovery**
```bash
# Fast initial enumeration
assetfinder example.com
subfinder -d example.com

# Certificate transparency
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq -r '.[].name_value' | sort -u
```

### **Phase 2: Passive Enumeration**
```bash
# Comprehensive passive discovery
amass enum -passive -d example.com

# OSINT gathering
theHarvester -d example.com -l 200 -b google,bing
```

### **Phase 3: Active Enumeration**
```bash
# Comprehensive active enumeration
amass enum -active -d example.com -brute

# Automated comprehensive scan
dnsenum --enum example.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### **Phase 4: High-Performance Brute-Forcing**
```bash
# Massive wordlist brute-forcing
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt example.com --rate-limit 1000

# Validation and cleanup
puredns resolve all_subdomains.txt --write validated_subdomains.txt
```

---

## **HTB Academy Lab Examples**

### **Lab 1: DNS Analysis**
```bash
# Basic DNS enumeration
dig inlanefreight.htb A
dig inlanefreight.htb MX  
dig inlanefreight.htb NS
dig inlanefreight.htb TXT

# Zone transfer attempts
for ns in $(dig +short inlanefreight.htb NS); do
  echo "Attempting zone transfer with $ns"
  dig @$ns inlanefreight.htb AXFR
done

# Automated enumeration
dnsenum --enum inlanefreight.htb -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
dnsrecon -d inlanefreight.htb

# Advanced subdomain discovery
amass enum -passive -d inlanefreight.htb
amass enum -active -d inlanefreight.htb -brute

# High-performance brute-forcing
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb --rate-limit 1000
```

---

## **Security Considerations**

### **Rate Limiting**
```bash
# Avoid detection with delays
for sub in $(cat wordlist.txt); do
  dig $sub.example.com
  sleep 1
done

# Use multiple DNS servers
dns_servers=(8.8.8.8 1.1.1.1 9.9.9.9)
for server in "${dns_servers[@]}"; do
  dig @$server example.com
done
```

### **Stealth Techniques**
```bash
# Passive enumeration only
amass enum -passive -d example.com
subfinder -d example.com

# Certificate transparency (no DNS queries)
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq -r '.[].name_value'
```

---

## **Defensive Measures**

### **DNS Server Hardening**
```bash
# Restrict zone transfers
allow-transfer { trusted-servers; };

# Disable recursion for external queries
allow-recursion { internal-networks; };

# Hide DNS version
version "Not disclosed";

# Rate limiting
rate-limit {
    responses-per-second 5;
    window 5;
};
```

### **Monitoring and Detection**
```bash
# Monitor DNS queries
tail -f /var/log/named/queries.log

# Detect enumeration attempts
grep -E "(axfr|version.bind)" /var/log/named/queries.log
```

---

## **Key Takeaways**

1. **dig is essential** for manual DNS analysis and troubleshooting
2. **dnsenum provides** comprehensive automated enumeration
3. **amass offers** maximum subdomain coverage with 30+ sources
4. **puredns excels** at high-performance brute-forcing
5. **Passive enumeration** (amass passive, subfinder) avoids detection
6. **Rate limiting** is crucial to prevent blocking
7. **Zone transfers** should be tested on all name servers
8. **Certificate transparency** provides valuable subdomain data
9. **Tool combination** yields better results than single tools
10. **DNS security** can be assessed through enumeration attempts

---

## **References**

- HTB Academy: Information Gathering - Web Edition
- RFC 1034, 1035: Domain Names - Concepts and Facilities
- OWASP Testing Guide: Information Gathering
- SecLists: https://github.com/danielmiessler/SecLists
- Amass Documentation: https://github.com/OWASP/Amass 