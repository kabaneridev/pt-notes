# 🔍 Footprinting - CPTS

## **Overview**

Footprinting is the first phase of penetration testing that involves gathering information about the target organization without direct interaction. This phase is crucial for understanding the target's infrastructure, technologies, and potential attack vectors.

## **Core Principles**

1. **What we see** - Visible services and information
2. **What we don't see** - Hidden infrastructure and services
3. **Developer's perspective** - Understanding technical requirements

## **Domain Information Gathering**

### **1. Certificate Transparency**

**Why Certificate Transparency works:**
- SSL certificates often include multiple domains/subdomains
- Certificate logs are publicly accessible
- Provides historical data about domains

**crt.sh - Certificate Transparency Search:**
```bash
# Basic search in browser
https://crt.sh/?q=example.com

# JSON output for parsing
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq .

# Extract unique subdomains
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

**Example Output:**
```
account.ttn.example.com
blog.example.com
bots.example.com
console.ttn.example.com
ct.example.com
data.ttn.example.com
*.example.com
example.com
integrations.ttn.example.com
iot.example.com
mails.example.com
marina.example.com
matomo.example.com
```

### **2. Company Hosted vs Third-Party**

**Identify directly accessible hosts:**
```bash
# Create subdomain list
curl -s https://crt.sh/\?q\=example.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u > subdomainlist

# Find hosts with direct IP addresses
for i in $(cat subdomainlist);do host $i | grep "has address" | grep example.com | cut -d" " -f1,4;done

# Extract IP addresses only
for i in $(cat subdomainlist);do host $i | grep "has address" | grep example.com | cut -d" " -f4 >> ip-addresses.txt;done
```

### **3. Shodan Intelligence**

**Why Shodan is valuable:**
- Shows open ports and services
- Reveals technology stack
- Provides geolocation data
- Historical scanning data

**Shodan Usage:**
```bash
# Scan individual IPs
shodan host 10.129.24.93

# Bulk scan from IP list
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

**Example Shodan Output Analysis:**
```
10.129.27.22
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-09-01T15:39:55.446281
Number of open ports:    8

Ports:
     25/tcp  SMTP
     53/tcp  DNS
     53/udp  DNS  
     80/tcp  Apache httpd 
     81/tcp  Apache httpd 
    110/tcp  POP3
    111/tcp  RPCbind
    443/tcp  Apache httpd 
    444/tcp  Unknown
```

**Key Information Extracted:**
- **Multiple web servers** (ports 80, 81, 443, 444)
- **Mail services** (SMTP on 25, POP3 on 110)
- **DNS services** (port 53 TCP/UDP)
- **RPC services** (port 111)

## **DNS Enumeration**

### Overview
Domain Name System (DNS) is an integral part of the Internet infrastructure that translates domain names into IP addresses. DNS operates without a central database - information is distributed across thousands of name servers globally. For penetration testing, DNS enumeration is crucial for discovering subdomains, mail servers, and internal infrastructure.

**Key DNS Components:**
- **DNS Root Servers**: Responsible for top-level domains (TLD), managed by ICANN
- **Authoritative Name Servers**: Hold authority for specific zones, provide binding information
- **Non-authoritative Name Servers**: Collect information through recursive/iterative queries
- **Caching DNS Servers**: Cache information from other servers for specified periods
- **Forwarding Servers**: Forward DNS queries to other DNS servers
- **Resolvers**: Perform local name resolution

### DNS Record Types

| Record Type | Description |
|-------------|-------------|
| **A** | Returns IPv4 address of requested domain |
| **AAAA** | Returns IPv6 address of requested domain |
| **MX** | Returns responsible mail servers |
| **NS** | Returns DNS servers (nameservers) of domain |
| **TXT** | Contains various information (SPF, DMARC, verification records) |
| **CNAME** | Alias record pointing to another domain name |
| **PTR** | Reverse lookup - converts IP addresses to domain names |
| **SOA** | Start of Authority - provides zone information and admin contact |

### DNS Configuration Analysis

#### BIND9 Configuration Files
```bash
# Main configuration locations
/etc/bind/named.conf.local    # Local zone definitions
/etc/bind/named.conf.options  # Global options
/etc/bind/named.conf.log      # Logging configuration
```

#### Zone File Structure
```bash
# Example zone file structure
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com. hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh (6 hours)
                    3600       ; retry (1 hour)
                    604800     ; expire (1 week)
                    86400 )    ; minimum TTL (1 day)

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.
      IN     MX     10 mx.domain.com.
      IN     A      10.129.14.5

server1      IN     A       10.129.14.5
www          IN     CNAME   server1
```

### Dangerous DNS Configurations

⚠️ **High-Risk Settings:**

| Option | Risk Level | Description |
|--------|------------|-------------|
| `allow-query` | Medium | Defines which hosts can send requests |
| `allow-recursion` | High | Defines which hosts can send recursive requests |
| `allow-transfer` | Critical | Defines which hosts can perform zone transfers |
| `zone-statistics` | Medium | Collects statistical data (information disclosure) |

### DNS Enumeration Techniques

#### 1. Basic DNS Queries
```bash
# Query specific record types
dig A domain.com
dig AAAA domain.com
dig MX domain.com
dig NS domain.com
dig TXT domain.com
dig SOA domain.com

# Query specific DNS server
dig @dns-server domain.com

# Query all available records
dig ANY domain.com @dns-server
```

#### 2. Name Server Discovery
```bash
# Discover name servers for domain
dig NS inlanefreight.htb @10.129.14.128

# Query multiple name servers
dig @ns1.domain.com domain.com
dig @ns2.domain.com domain.com
```

#### 3. DNS Version Detection
```bash
# Attempt to identify DNS server version
dig CH TXT version.bind @dns-server
dig CH TXT version.bind @10.129.120.85

# Alternative version detection
nslookup -type=txt -class=chaos version.bind dns-server
```

#### 4. SOA Record Analysis
```bash
# Get Start of Authority information
dig SOA domain.com

# Extract administrator email from SOA
# Note: dot (.) is replaced with @ in email
dig SOA www.inlanefreight.com
```

#### 5. Zone Transfer Attacks
```bash
# Attempt full zone transfer (AXFR)
dig axfr domain.com @dns-server
dig axfr inlanefreight.htb @10.129.14.128

# Attempt incremental zone transfer (IXFR)
dig ixfr=serial domain.com @dns-server
```

#### 6. Reverse DNS Lookups
```bash
# Reverse IP lookup
dig -x 10.129.14.5
nslookup 10.129.14.5

# Reverse lookup on subnet
for ip in $(seq 1 254); do host 10.129.14.$ip | grep -v "not found"; done
```

### Advanced DNS Enumeration

#### Subdomain Discovery
```bash
# Manual subdomain brute forcing
for sub in $(cat subdomains.txt); do
    dig $sub.domain.com @dns-server | grep -v ';' | grep $sub
done

# Using common subdomain wordlist
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
    dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done
```

#### Using DNSenum
```bash
# Comprehensive DNS enumeration
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

# DNSenum with specific options
dnsenum --dnsserver dns-server --enum domain.com
dnsenum --threads 10 --timeout 5 domain.com
```

#### Using Fierce
```bash
# Subdomain enumeration with Fierce
fierce -dns domain.com
fierce -dns domain.com -wordlist wordlist.txt
```

#### Using Sublist3r
```bash
# Subdomain enumeration with multiple sources
sublist3r -d domain.com
sublist3r -d domain.com -t 10 -o subdomains.txt
```

### DNS Security Assessment

#### Zone Transfer Testing
```bash
# Test zone transfer on all name servers
dig NS domain.com
dig axfr domain.com @ns1.domain.com
dig axfr domain.com @ns2.domain.com

# Test for internal zones
dig axfr internal.domain.com @dns-server
```

#### DNS Cache Poisoning Tests
```bash
# Test for cache poisoning vulnerabilities
dig @dns-server random-subdomain.domain.com
dig @dns-server random-subdomain.domain.com A
```

#### DNS Amplification Testing
```bash
# Test for DNS amplification potential
dig @dns-server domain.com ANY
dig @dns-server . NS
```

### Information Extraction from DNS

#### Email Server Discovery
```bash
# Find mail servers
dig MX domain.com

# Common mail server subdomains
dig mail.domain.com
dig smtp.domain.com
dig pop.domain.com
dig imap.domain.com
```

#### TXT Record Analysis
```bash
# Extract TXT records for useful information
dig TXT domain.com

# Common TXT record types to look for:
# - SPF records: v=spf1 include:...
# - DMARC records: v=DMARC1; p=...
# - Verification records: MS=..., google-site-verification=...
# - Domain verification: atlassian-domain-verification=...
```

#### Internal Infrastructure Discovery
```bash
# Look for internal hostnames in zone transfers
dig axfr internal.domain.com @dns-server

# Common internal subdomains to test
dig dc1.internal.domain.com
dig dc2.internal.domain.com
dig vpn.internal.domain.com
dig wsus.internal.domain.com
```

### DNS Enumeration Checklist

#### Initial Discovery
- [ ] Identify DNS servers for target domain
- [ ] Query NS records for name servers
- [ ] Test DNS server version detection
- [ ] Perform basic record type queries (A, AAAA, MX, TXT, SOA)

#### Zone Transfer Testing
- [ ] Attempt AXFR zone transfer on all name servers
- [ ] Test for internal zone transfers
- [ ] Check for misconfigured allow-transfer settings
- [ ] Document all discovered hosts and IP addresses

#### Subdomain Discovery
- [ ] Perform subdomain brute forcing
- [ ] Use multiple wordlists and tools
- [ ] Test common internal subdomains
- [ ] Cross-reference with other reconnaissance data

#### Information Analysis
- [ ] Extract email addresses from SOA records
- [ ] Analyze TXT records for useful information
- [ ] Map discovered infrastructure
- [ ] Identify internal IP ranges and systems

### Tools and Scripts

#### Essential DNS Tools
```bash
# Standard tools
dig                    # Primary DNS lookup tool
nslookup              # Alternative DNS lookup
host                  # Simple DNS lookup

# Advanced enumeration
dnsenum               # Comprehensive DNS enumeration
fierce                # DNS brute forcer
sublist3r             # Subdomain enumeration
dnsrecon              # DNS reconnaissance tool
```

#### Custom Scripts
```bash
# Simple subdomain brute forcer
#!/bin/bash
domain=$1
wordlist=$2
for sub in $(cat $wordlist); do
    result=$(dig +short $sub.$domain)
    if [ -n "$result" ]; then
        echo "$sub.$domain - $result"
    fi
done

# Zone transfer scanner
#!/bin/bash
domain=$1
for ns in $(dig +short NS $domain); do
    echo "Testing $ns for zone transfer..."
    dig axfr $domain @$ns
done
```

### Defensive Measures

#### Secure DNS Configuration
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

#### Monitoring and Detection
```bash
# Monitor DNS queries
tail -f /var/log/named/queries.log

# Check for suspicious patterns
grep "axfr" /var/log/named/queries.log
grep -i "version.bind" /var/log/named/queries.log
```

---

## **Third-Party Service Identification**

### **Services and Attack Vectors**

| Service | Attack Vectors | Notes |
|---------|---------------|--------|
| **Atlassian** | JIRA/Confluence exploits, credential attacks | Software development platform |
| **Google Gmail** | Open GDrive folders, document access | Email management |
| **LogMeIn** | Centralized remote access, credential reuse | Single point of failure |
| **Mailgun** | API vulnerabilities (IDOR, SSRF) | Email API service |
| **Outlook/Office365** | OneDrive, Azure blob storage, SMB | Document management |
| **INWX** | Domain management, DNS poisoning | Hosting provider |

### **IP Address Discovery from SPF**

**SPF Records reveal internal IPs:**
```bash
# From SPF record
ip4:10.129.24.8    # Internal mail server
ip4:10.129.27.2    # Internal service
ip4:10.72.82.106   # Additional internal host
```

## **Passive Information Gathering Workflow**

### **Phase 1: Initial Domain Analysis**
1. **Certificate Transparency** - crt.sh enumeration
2. **DNS enumeration** - All record types
3. **Subdomain compilation** - Unique list creation

### **Phase 2: Infrastructure Mapping**
1. **IP resolution** - Direct vs CDN/third-party
2. **Shodan reconnaissance** - Port/service discovery
3. **Technology stack** - Service fingerprinting

### **Phase 3: Third-Party Analysis**
1. **TXT record analysis** - Service identification
2. **Provider mapping** - Attack surface expansion
3. **Integration points** - API endpoints, SSO

### **Phase 4: Cloud Resource Discovery**
1. **Google dorking** - Cloud storage enumeration
2. **GrayHatWarfare** - Bucket/container discovery
3. **Source code analysis** - Direct cloud links
4. **Automated scanning** - Cloud enumeration tools

### **Phase 5: Intelligence Synthesis**
1. **Attack vector prioritization**
2. **Credential attack targets**
3. **Technical debt identification**
4. **Cloud exposure assessment**

## **Tools and Commands**

### **Essential Tools**
```bash
# Certificate transparency
curl + jq + crt.sh

# DNS enumeration
dig, nslookup, host

# Infrastructure reconnaissance  
shodan, censys

# Cloud storage discovery
domain.glass, grayhatwarfare.com

# Subdomain enumeration
sublist3r, amass, subfinder

# Cloud enumeration tools
cloud_enum, s3scanner, AWSBucketDump

# Visual reconnaissance
aquatone, eyewitness
```

### **One-Liner Commands**
```bash
# Quick subdomain extraction
curl -s https://crt.sh/\?q\=DOMAIN\&output\=json | jq -r '.[].name_value' | sort -u

# IP address compilation
for i in $(cat subs.txt); do host $i | grep "has address" | cut -d" " -f4; done | sort -u

# Bulk Shodan scanning
cat ips.txt | while read ip; do shodan host $ip; done

# Cloud storage detection in DNS
for i in $(cat subdomains.txt); do host $i | grep -E "(amazonaws|blob\.core\.windows|storage\.googleapis)"; done

# Check website source for cloud references
curl -s https://target.com | grep -E "(amazonaws|blob\.core\.windows|storage\.googleapis)" 

# AWS S3 bucket access test
aws s3 ls s3://bucket-name --no-sign-request

# Generate bucket name variations
echo "company" | sed 's/.*/&\n&-backup\n&-backups\n&-dev\n&-prod\n&-assets\n&-logs/'
```

## **Defensive Considerations**

### **Information Leakage Prevention**
- Minimize certificate transparency exposure
- Secure TXT record information
- Implement proper SPF/DMARC policies
- Regular third-party service audits

### **Monitoring and Detection**
- Certificate transparency monitoring
- DNS query logging
- Shodan/Censys alerts
- Third-party integration reviews

## **Cloud Resources Discovery**

### **Overview**

Cloud services (AWS, Azure, GCP) are essential for modern companies but often misconfigured, leading to unauthorized access to sensitive data.

### **Common Cloud Storage Types**

| Provider | Storage Type | URL Pattern |
|----------|-------------|-------------|
| **AWS** | S3 Buckets | `*.amazonaws.com` |
| **Azure** | Blob Storage | `*.blob.core.windows.net` |
| **GCP** | Cloud Storage | `*.storage.googleapis.com` |

### **Discovery Methods**

#### **1. DNS Enumeration**
```bash
# Often cloud storage appears in DNS records
for i in $(cat subdomainlist);do host $i | grep "has address" | grep company.com | cut -d" " -f1,4;done

# Example output showing AWS S3:
blog.company.com 10.129.24.93
company.com 10.129.27.33
matomo.company.com 10.129.127.22
s3-website-us-west-2.amazonaws.com 10.129.95.250  # ← AWS S3 detected
```

#### **2. Google Dorking for Cloud Storage**

**AWS S3 Discovery:**
```bash
# Google search queries
intext:"company_name" inurl:amazonaws.com
site:amazonaws.com "company_name"
site:s3.amazonaws.com "company_name"
filetype:pdf site:amazonaws.com "company_name"
```

**Azure Blob Discovery:**
```bash
intext:"company_name" inurl:blob.core.windows.net
site:blob.core.windows.net "company_name" 
filetype:pdf site:blob.core.windows.net "company_name"
```

**GCP Storage Discovery:**
```bash
intext:"company_name" inurl:storage.googleapis.com
site:storage.googleapis.com "company_name"
```

#### **3. Source Code Analysis**

**Check website source for cloud references:**
```html
<!-- DNS prefetch hints in HTML -->
<link rel="dns-prefetch" href="//company.blob.core.windows.net">
<link rel="preconnect" href="https://company.blob.core.windows.net" crossorigin>

<!-- Direct links to cloud resources -->
<img src="https://company-assets.s3.amazonaws.com/logo.png">
<script src="https://company.blob.core.windows.net/js/app.js"></script>
```

### **Specialized Tools**

#### **1. Domain.Glass**
```bash
# Website: https://domain.glass/
# Features:
- Infrastructure mapping
- Cloudflare detection
- SSL certificate analysis
- Social media presence
- External tool integration
```

#### **2. GrayHatWarfare**
```bash
# Website: https://grayhatwarfare.com/
# Features:
- AWS S3 bucket enumeration
- Azure blob container search
- GCP storage bucket discovery
- File type filtering
- Content preview
```

**GrayHatWarfare Search Examples:**
```bash
# Search patterns
company_name
company-name
company_abbreviation
companyname

# File type filters
.pdf, .doc, .xlsx, .txt, .zip, .sql, .config
```

#### **3. Automated Tools**
```bash
# CloudEnum
git clone https://github.com/initstring/cloud_enum.git
python3 cloud_enum.py -k company_name

# S3Scanner  
python3 s3scanner.py -l buckets.txt

# AWSBucketDump
python3 AWSBucketDump.py -l buckets.txt
```

### **High-Value Targets**

#### **Critical Files to Search For**

| File Type | Examples | Risk Level |
|-----------|----------|------------|
| **SSH Keys** | `id_rsa`, `id_rsa.pub`, `.pem` | 🔴 Critical |
| **Configurations** | `config.xml`, `.env`, `settings.conf` | 🔴 Critical |
| **Database Dumps** | `.sql`, `.db`, `.sqlite` | 🔴 Critical |
| **Source Code** | `.git`, `.zip`, `.tar.gz` | 🟡 High |
| **Documents** | `.pdf`, `.docx`, `.xlsx` | 🟡 Medium |
| **Credentials** | `passwords.txt`, `.htpasswd` | 🔴 Critical |

#### **Example: SSH Key Discovery**
```bash
# GrayHatWarfare search results showing leaked SSH keys
Bucket: company-backups.s3.amazonaws.com
Files:
- id_rsa          (1.6KB) - Private SSH key
- id_rsa.pub      (0.4KB) - Public SSH key  
- server_backup.tar.gz (45MB)
```

### **Common Misconfigurations**

#### **AWS S3 Bucket Issues**
```bash
# Public read access
aws s3 ls s3://company-bucket --no-sign-request

# List bucket contents
aws s3 sync s3://company-bucket . --no-sign-request

# Common bucket naming patterns
company-name
company-backups
company-logs
company-dev
company-prod
company-assets
```

#### **Azure Blob Storage**
```bash
# Anonymous access patterns
https://company.blob.core.windows.net/container/file.pdf

# Common container names
backups, logs, assets, documents, uploads, temp
```

### **Cloud Resource Workflow**

#### **Phase 1: Initial Discovery**
1. **DNS enumeration** - Look for cloud storage references
2. **Source code analysis** - Check website for cloud links
3. **Google dorking** - Search for public cloud storage

#### **Phase 2: Targeted Search**
1. **Company name variations** - Full name, abbreviations, domains
2. **GrayHatWarfare** - Systematic bucket enumeration
3. **Domain.glass** - Infrastructure mapping

#### **Phase 3: Content Analysis**
1. **File enumeration** - List accessible files
2. **Sensitive data identification** - SSH keys, configs, databases
3. **Access testing** - Download capabilities

#### **Phase 4: Exploitation**
1. **SSH key usage** - Access to company servers
2. **Configuration abuse** - Database access, API keys
3. **Data exfiltration** - Sensitive document download

### **Detection and Prevention**

#### **Defensive Measures**
- **Bucket policies** - Restrict public access
- **IAM controls** - Least privilege access
- **Monitoring** - Log bucket access
- **Encryption** - Encrypt data at rest
- **Regular audits** - Check for public buckets

#### **Detection Methods**
- **Cloud security tools** - AWS Config, Azure Security Center
- **Third-party scanners** - Check for public exposure
- **Certificate monitoring** - Track cloud-related certificates

### **Real-World Impact**

#### **Common Scenarios**
1. **Employee mistakes** - Accidental public bucket creation
2. **Legacy configurations** - Old buckets left public
3. **Development oversight** - Test/dev buckets exposed
4. **Third-party integrations** - Vendor access misconfigurations

#### **Business Impact**
- **Data breaches** - Customer information exposure
- **Intellectual property theft** - Source code, documents
- **Compliance violations** - GDPR, HIPAA penalties
- **Infrastructure compromise** - SSH key-based access

## **Key Takeaways**

1. **Certificate Transparency** is a goldmine for subdomain discovery
2. **TXT records** reveal extensive third-party integrations
3. **Shodan** provides detailed technical intelligence
4. **SPF records** can leak internal IP addresses
5. **Third-party services** expand attack surface significantly
6. **Cloud resources** are often misconfigured and publicly accessible
7. **Google dorking** is highly effective for cloud storage discovery
8. **SSH keys in cloud storage** provide direct server access

## **References**

- HTB Academy: Footprinting Module
- Certificate Transparency: https://crt.sh/
- Shodan: https://www.shodan.io/
- RFC 6962: Certificate Transparency 