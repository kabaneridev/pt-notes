# External Information Gathering

## 🎯 Overview

**External Information Gathering** is the critical first phase of enterprise network attacks. This process involves **systematic reconnaissance** to map the attack surface, identify services, discover subdomains, and gather intelligence for targeted exploitation against external-facing infrastructure.

## 🔍 Initial Network Reconnaissance

### 📊 Quick Port Discovery
```bash
# Initial top 1000 ports scan
sudo nmap --open -oA target_tcp_1k -iL scope

# Key findings analysis:
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
25/tcp   open  smtp
53/tcp   open  domain
80/tcp   open  http
110/tcp  open  pop3
143/tcp  open  imap
993/tcp  open  imaps
995/tcp  open  pop3s
8080/tcp open  http-proxy

# Service categories identified:
- Web services (80, 8080)
- Email services (25, 110, 143, 993, 995)
- File transfer (21)
- Remote access (22)
- DNS services (53)
```

### 🔧 Comprehensive Service Enumeration
```bash
# Full port aggressive scan
sudo nmap --open -p- -A -oA target_tcp_all_svc -iL scope

# Key service discoveries:
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
25/tcp   open  smtp     Postfix smtpd
53/tcp   open  domain   (unknown banner: 1337_HTB_DNS)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
8080/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))

# Anonymous FTP access discovered:
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              38 May 30 17:16 flag.txt
```

### 📈 Service Analysis with Nmap Grep
```bash
# Extract service information efficiently
egrep -v "^#|Status: Up" target_tcp_all_svc.gnmap | cut -d ' ' -f4- | tr ',' '\n' | \
sed -e 's/^[ \t]*//' | awk -F '/' '{print $7}' | grep -v "^$" | sort | uniq -c | sort -k 1 -nr

# Results:
      2 Dovecot pop3d
      2 Dovecot imapd (Ubuntu)
      2 Apache httpd 2.4.41 ((Ubuntu))
      1 vsftpd 3.0.3
      1 Postfix smtpd
      1 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
      1 2-4 (RPC #100000)
```

## 🌐 DNS Enumeration

### 📋 DNS Zone Transfer Attack
```bash
# Attempt zone transfer for subdomain discovery
dig axfr inlanefreight.local @TARGET_IP

# Successful zone transfer results:
inlanefreight.local.     86400  IN  SOA   ns1.inlanfreight.local. dnsadmin.inlanefreight.local.
blog.inlanefreight.local.     86400  IN  A    127.0.0.1
careers.inlanefreight.local.  86400  IN  A    127.0.0.1
dev.inlanefreight.local.      86400  IN  A    127.0.0.1
flag.inlanefreight.local.     86400  IN  TXT  "HTB{..."
gitlab.inlanefreight.local.   86400  IN  A    127.0.0.1
ir.inlanefreight.local.       86400  IN  A    127.0.0.1
status.inlanefreight.local.   86400  IN  A    127.0.0.1
support.inlanefreight.local.  86400  IN  A    127.0.0.1
tracking.inlanefreight.local. 86400  IN  A    127.0.0.1
vpn.inlanefreight.local.      86400  IN  A    127.0.0.1

# Discovery: 9 additional subdomains + flag in TXT record
```

### 🔍 Alternative DNS Enumeration
```bash
# If zone transfer fails, use passive methods:
# - DNSDumpster.com
# - Certificate transparency logs
# - Search engine dorking
# - Subdomain brute forcing

# Active subdomain enumeration:
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.inlanefreight.local
```

## 🌐 Virtual Host Discovery

### 📊 VHost Enumeration Process
```bash
# Step 1: Determine invalid vhost response size
curl -s -I http://TARGET_IP -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
# Result: Content-Length: 15157

# Step 2: Fuzz vhosts filtering invalid responses
ffuf -w /opt/useful/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://TARGET_IP/ -H 'Host:FUZZ.inlanefreight.local' -fs 15157

# Results discovered:
blog                    [Status: 200, Size: 8708]
careers                 [Status: 200, Size: 51810]
dev                     [Status: 200, Size: 2048]
gitlab                  [Status: 302, Size: 113]
ir                      [Status: 200, Size: 28545]
monitoring              [Status: 200, Size: 56]    # ← Additional vhost not in DNS
status                  [Status: 200, Size: 917]
support                 [Status: 200, Size: 26635]
tracking                [Status: 200, Size: 35185]
vpn                     [Status: 200, Size: 1578]
```

### 🔧 Alternative VHost Tools
```bash
# Gobuster vhost enumeration
gobuster vhost -u http://TARGET_IP -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt --domain inlanefreight.local

# Wfuzz vhost discovery
wfuzz -c -f sub-fighter -w /opt/useful/seclists/Discovery/DNS/namelist.txt -u "http://TARGET_IP" -H "Host: FUZZ.inlanefreight.local" --hh 15157
```

## 📝 Host File Configuration

### 🔧 Adding Discovered Hosts
```bash
# Add all discovered subdomains to /etc/hosts
sudo tee -a /etc/hosts > /dev/null <<EOT

## inlanefreight hosts 
TARGET_IP inlanefreight.local blog.inlanefreight.local careers.inlanefreight.local dev.inlanefreight.local gitlab.inlanefreight.local ir.inlanefreight.local status.inlanefreight.local support.inlanefreight.local tracking.inlanefreight.local vpn.inlanefreight.local monitoring.inlanefreight.local
EOT

# Verify configuration
cat /etc/hosts | grep inlanefreight
```

## 🎯 HTB Academy Lab Solutions

### Lab Environment
```bash
# Target: 10.129.211.225 (ACADEMY-AEN-DMZ01)
# Add to /etc/hosts:
sudo sh -c 'echo "TARGET_IP inlanefreight.local" >> /etc/hosts'
```

### 🔍 Question 1: Banner Grab Non-Standard Service
```bash
# Service enumeration with version detection
sudo nmap -sC -sV inlanefreight.local

# Key finding in DNS service:
53/tcp   open  domain   (unknown banner: 1337_HTB_DNS)
| dns-nsid:
|_  bind.version: 1337_HTB_DNS

# Answer: 1337_HTB_DNS
```

### 🌐 Question 2: DNS Zone Transfer Flag
```bash
# Perform zone transfer
dig AXFR inlanefreight.local @TARGET_IP

# Flag discovered in TXT record:
flag.inlanefreight.local. 86400  IN  TXT  "HTB{..."

# Answer: HTB{DNs_ZOn3_Tr@nsf3r}
```

### 📍 Question 3: Flag Subdomain FQDN
```bash
# From zone transfer output:
flag.inlanefreight.local. 86400  IN  TXT  "HTB{..."

# Answer: flag.inlanefreight.local
```

### 🔍 Question 4: Additional VHost Discovery
```bash
# Determine invalid response size
curl -sI http://TARGET_IP/ -H "Host: defnotvalid.inlanefreight.local" | grep "Content-Length:"
# Result: Content-Length: 15157

# Fuzz for additional vhosts
ffuf -s -w /opt/useful/SecLists/Discovery/DNS/namelist.txt:FUZZ -u http://TARGET_IP/ -H 'Host: FUZZ.inlanefreight.local' -fs 15157

# Additional vhost found:
monitoring              [Status: 200, Size: 56]

# Answer: monitoring
```

## 🔄 Information Gathering Workflow

### 📊 Systematic Approach
```bash
# 1. Initial port discovery
sudo nmap --open -oA quick_scan -iL scope

# 2. Service enumeration
sudo nmap --open -p- -A -oA full_scan -iL scope

# 3. DNS zone transfer attempt
dig axfr DOMAIN @TARGET_IP

# 4. Subdomain/vhost discovery
ffuf -w wordlist -u http://TARGET/ -H 'Host:FUZZ.domain' -fs INVALID_SIZE

# 5. Host file configuration
sudo tee -a /etc/hosts <<< "TARGET_IP domain subdomain1.domain subdomain2.domain"

# 6. Service-specific enumeration
# Continue with FTP, HTTP, SMTP, etc. detailed analysis
```

### 🎯 Attack Surface Mapping
```cmd
# Service categorization:
Web Services:     80, 443, 8080, 8443
Email Services:   25, 110, 143, 587, 993, 995
File Transfer:    21, 22, 69, 873
Database:         1433, 3306, 5432, 1521
Management:       161, 623, 8080, 9090
Remote Access:    22, 23, 3389, 5985, 5986

# Priority targets:
1. Web applications (immediate attack surface)
2. Anonymous/weak authentication services
3. Known vulnerable service versions
4. Management interfaces
5. Email services for user enumeration
```

## ⚠️ Reconnaissance Best Practices

### 🔒 Stealth Considerations
```bash
# Timing controls for stealth
nmap -T2 --scan-delay 5s TARGET_IP

# Fragmented packets
nmap -f TARGET_IP

# Source port spoofing
nmap --source-port 53 TARGET_IP

# Decoy scanning
nmap -D RND:10 TARGET_IP
```

### 📋 Documentation Standards
```cmd
# Essential documentation:
- All scan outputs saved with timestamps
- Service version information recorded
- Subdomain/vhost discovery results
- Anonymous access findings
- Potential attack vectors identified
- Evidence screenshots for findings
```

## 💡 Key Takeaways

1. **Systematic enumeration** reveals complete attack surface
2. **DNS zone transfers** provide valuable subdomain intelligence
3. **VHost discovery** uncovers hidden applications
4. **Service versioning** enables vulnerability research
5. **Anonymous access** often provides immediate foothold opportunities
6. **Comprehensive documentation** essential for attack planning
7. **Multiple enumeration methods** ensure complete coverage

---

*External information gathering establishes the foundation for enterprise network attacks by mapping the complete external attack surface and identifying high-value targets for exploitation.* 