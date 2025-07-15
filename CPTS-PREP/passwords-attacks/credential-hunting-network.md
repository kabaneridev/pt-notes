# Credential Hunting in Network Traffic

## 🎯 Overview

**Network traffic credential hunting** focuses on intercepting and analyzing unencrypted network communications to extract credentials, authentication tokens, and sensitive information. While most modern applications use encryption (TLS/SSL), legacy systems, misconfigured services, and test environments often still transmit credentials in cleartext.

> **"Legacy systems, misconfigured services, or test applications launched without HTTPS can still result in the use of unencrypted protocols, presenting valuable opportunities for credential hunting."**

## 🔓 Cleartext vs Encrypted Protocols

### Common Unencrypted Protocols
| Unencrypted Protocol | Encrypted Counterpart | Description | Credential Risk |
|---------------------|----------------------|-------------|-----------------|
| **HTTP** | HTTPS | Web pages and resources | ⚠️ Forms, Basic Auth, Cookies |
| **FTP** | FTPS/SFTP | File transfer | ⚠️ Username/Password in AUTH |
| **SNMP** | SNMPv3 (encrypted) | Network device monitoring | ⚠️ Community strings |
| **POP3** | POP3S | Email retrieval | ⚠️ Username/Password |
| **IMAP** | IMAPS | Email access | ⚠️ Username/Password |
| **SMTP** | SMTPS | Email sending | ⚠️ AUTH credentials |
| **LDAP** | LDAPS | Directory services | ⚠️ Bind credentials |
| **Telnet** | SSH | Remote terminal | ⚠️ All keystrokes |
| **DNS** | DNS over HTTPS (DoH) | Domain resolution | ⚠️ Query information |
| **SMB v1/v2** | SMB 3.0 with TLS | File sharing | ⚠️ NTLM hashes |
| **VNC** | VNC with TLS/SSL | Remote desktop | ⚠️ Passwords, screen data |

### Risk Assessment
```bash
# High Risk (Credentials in cleartext)
- HTTP Basic Authentication
- FTP LOGIN/PASS commands
- Telnet login sessions
- SNMP community strings
- Unencrypted email protocols

# Medium Risk (Hashes/tokens)
- NTLM authentication over SMB
- Kerberos tickets
- HTTP NTLM headers

# Information Disclosure
- DNS queries revealing internal infrastructure
- HTTP headers with version information
- SNMP system information
```

## 🔍 Wireshark Analysis Techniques

### Essential Wireshark Filters

#### Network and Transport Layer Filters
```bash
# IP Address filtering
ip.addr == 192.168.1.100           # Specific IP traffic
ip.src == 192.168.1.100            # Source IP
ip.dst == 192.168.1.100            # Destination IP
ip.src == 192.168.1.100 && ip.dst == 10.0.0.1  # Between specific hosts

# Port filtering
tcp.port == 80                     # HTTP traffic
tcp.port == 21                     # FTP traffic
tcp.port == 23                     # Telnet traffic
udp.port == 161                    # SNMP traffic
tcp.port == 443                    # HTTPS traffic (for comparison)

# MAC Address filtering
eth.addr == 00:11:22:33:44:55      # Specific MAC address
```

#### Protocol-Specific Filters
```bash
# HTTP Analysis
http                               # All HTTP traffic
http.request.method == "POST"      # POST requests (likely credentials)
http.request.method == "GET"       # GET requests
http.response.code == 401          # Authentication required
http.response.code == 403          # Forbidden (auth failure)

# Authentication Headers
http.authorization                 # HTTP Basic/NTLM auth
http contains "Authorization: Basic"  # Basic auth specifically
http contains "WWW-Authenticate"   # Auth challenges

# FTP Analysis
ftp                               # All FTP traffic
ftp.request.command == "USER"     # Username commands
ftp.request.command == "PASS"     # Password commands
ftp.request.command == "RETR"     # File downloads
ftp.request.command == "STOR"     # File uploads

# Email Protocol Analysis
pop                               # POP3 traffic
imap                              # IMAP traffic
smtp                              # SMTP traffic

# Network Management
snmp                              # SNMP traffic
ldap                              # LDAP traffic
```

#### Advanced Filtering Techniques
```bash
# TCP Stream Analysis
tcp.stream eq 0                   # Follow specific TCP conversation
tcp.stream eq 1                   # Next TCP stream

# TCP Flags
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN packets (connection attempts)
tcp.flags.rst == 1                # Reset packets (connection issues)

# Content-based filtering
frame contains "password"          # Packets containing "password"
frame contains "login"            # Packets containing "login"
frame contains "user"             # Packets containing "user"
tcp contains "admin"              # TCP packets with "admin"

# Credential hunting patterns
http contains "passw"             # HTTP with password patterns
ftp contains "230"                # FTP login success
telnet contains "login:"          # Telnet login prompts
```

### Wireshark Search Techniques

#### Manual Packet Search
```bash
# Via Display Filter
1. Enter filter: http contains "password"
2. Apply filter
3. Analyze results

# Via Find Packet (Ctrl+F)
1. Edit → Find Packet
2. Search Options:
   - Display filter
   - Hex value
   - String
   - Regular expression

# String searches
"password"
"login"
"auth"
"admin"
"secret"
```

#### Following TCP Streams
```bash
# Right-click packet → Follow → TCP Stream
# Shows complete conversation between hosts
# Useful for:
- HTTP request/response pairs
- FTP command sequences
- Telnet login sessions
- SMTP email transmissions
```

## 🛠️ Pcredz - Automated Credential Extraction

### Installation and Setup
```bash
# Clone Pcredz repository
git clone https://github.com/lgandx/PCredz.git
cd PCredz

# Install dependencies
pip install Cython
pip install python-libpcap

# Alternative: Docker installation
docker pull lgandx/pcredz
```

### Pcredz Usage

#### Basic Analysis
```bash
# Analyze packet capture file
python3 ./Pcredz -f capture.pcap

# Verbose output
python3 ./Pcredz -f capture.pcap -v

# Extract to text file
python3 ./Pcredz -f capture.pcap -t

# Analyze specific file types
python3 ./Pcredz -f capture.pcap -v -t
```

#### Live Traffic Analysis
```bash
# Monitor live interface
sudo python3 ./Pcredz -i eth0

# Monitor with verbose output
sudo python3 ./Pcredz -i eth0 -v

# Monitor and save to file
sudo python3 ./Pcredz -i eth0 -t
```

### Pcredz Extraction Capabilities

#### Supported Credential Types
```bash
# Network Authentication
- HTTP Basic Authentication
- HTTP NTLM Authentication
- HTTP Form credentials
- FTP credentials
- POP3/IMAP/SMTP credentials
- LDAP bind credentials

# Windows Authentication
- NTLMv1/v2 hashes (SMB, LDAP, MSSQL, HTTP)
- Kerberos AS-REQ hashes (etype 23)
- DCE-RPC authentication

# Network Management
- SNMP community strings
- Network device credentials

# Financial Data
- Credit card numbers
- Payment information
```

#### Example Pcredz Output
```bash
$ python3 ./Pcredz -f demo.pcapng -t -v

Pcredz 2.0.2
Author: Laurent Gaffie

[SNMPv2 Community String Found]
Source: 192.168.31.211:59022 → 192.168.31.238:161
Community: public

[FTP Credentials Found]
Source: 192.168.31.243:55707 → 192.168.31.211:21
FTP User: admin
FTP Pass: password123

[HTTP Basic Auth Found]
Source: 192.168.1.100:54321 → 10.0.0.50:80
Username: testuser
Password: secretpass

[Credit Card Found]
Card Number: 4532-1234-5678-9012
Type: Visa
```

## 🌐 Protocol-Specific Analysis

### HTTP Credential Hunting

#### HTTP Basic Authentication
```bash
# Wireshark filter
http.authorization

# Manual analysis
1. Look for "Authorization: Basic" header
2. Decode base64 string: echo "dXNlcjpwYXNz" | base64 -d
3. Result: user:pass

# Common Basic Auth patterns
Authorization: Basic YWRtaW46cGFzc3dvcmQ=  # admin:password
```

#### HTTP Form Authentication
```bash
# Wireshark filters
http.request.method == "POST"
http contains "password"
http contains "login"

# Look for POST data containing:
- username=admin&password=secret
- login=user&pwd=pass123
- email=user@domain.com&password=secret
```

#### HTTP NTLM Authentication
```bash
# Wireshark filter
http contains "NTLM"

# NTLM Challenge/Response analysis
1. Type 1 Message (Negotiate)
2. Type 2 Message (Challenge)
3. Type 3 Message (Authentication) ← Contains NTLM hash
```

### FTP Analysis

#### FTP Command Sequence
```bash
# Wireshark filters
ftp.request.command == "USER"
ftp.request.command == "PASS"
ftp.response.code == 230        # Login successful

# Typical FTP login sequence
USER admin
PASS secretpassword
230 Login successful
```

#### FTP Data Analysis
```bash
# Track file transfers
ftp.request.command == "RETR"   # Downloads
ftp.request.command == "STOR"   # Uploads
ftp.request.command == "LIST"   # Directory listings

# Follow FTP data channel
tcp.port == 20                  # FTP data port
```

### SNMP Community String Extraction
```bash
# Wireshark filter
snmp

# Common community strings
- public (read-only)
- private (read-write)
- admin
- community
- secret

# SNMP version analysis
- SNMPv1: Community string in plaintext
- SNMPv2c: Community string in plaintext  
- SNMPv3: Encrypted (secure)
```

### Email Protocol Analysis

#### POP3 Credential Extraction
```bash
# Wireshark filter
pop

# POP3 authentication sequence
USER username
PASS password
+OK Login successful

# Common POP3 commands
USER, PASS, STAT, LIST, RETR, DELE, QUIT
```

#### SMTP Authentication
```bash
# Wireshark filter
smtp

# SMTP AUTH sequence
AUTH LOGIN
334 VXNlcm5hbWU6          # Username: (base64)
334 UGFzc3dvcmQ6          # Password: (base64)
235 Authentication successful
```

## 🕵️ Advanced Network Hunting Techniques

### Network Reconnaissance from Traffic
```bash
# DNS Analysis
dns                           # All DNS traffic
dns.qry.name contains "internal"  # Internal domain queries
dns.qry.name contains "admin"     # Admin-related queries

# Network mapping from traffic
ip.addr == 192.168.0.0/16    # Internal networks
arp                           # ARP requests (network discovery)
icmp.type == 8                # Ping requests
```

### Wireless Network Credential Hunting
```bash
# WiFi authentication analysis
wlan.fc.type_subtype == 0x0b  # Authentication frames
eapol                         # WPA/WPA2 handshakes

# WPA handshake capture
1. Capture 4-way handshake
2. Extract to .hccapx format
3. Crack with hashcat
```

### VPN and Tunneled Traffic
```bash
# IPSec analysis
esp                           # Encrypted Security Payload
isakmp                        # IKE negotiations

# OpenVPN detection
udp.port == 1194
tcp.port == 443 && ssl        # SSL VPN
```

## 🎯 HTB Academy Lab Exercise

### Lab Setup
- **Objective**: Analyze demo.pcapng for credential extraction
- **Tools**: Wireshark and Pcredz
- **Target Information**: Mixed network traffic with cleartext credentials

### Lab Questions and Analysis

#### Question 1: Credit Card Information
**Objective**: Find cleartext credit card number
**Analysis approach**:
```bash
# Wireshark analysis
http contains "4"             # Look for card numbers starting with 4
frame contains "credit"       # Search for credit-related terms
http.request.method == "POST" # Payment forms

# Pcredz analysis
python3 ./Pcredz -f demo.pcapng -v
# Look for: "CC number scanning activated"
```

#### Question 2: SNMPv2 Community String
**Objective**: Extract SNMP community string
**Analysis approach**:
```bash
# Wireshark analysis
snmp                          # Filter SNMP traffic
snmp.community               # Community string field

# Pcredz analysis
python3 ./Pcredz -f demo.pcapng -v
# Look for: "Found SNMPv2 Community string"
```

#### Question 3: FTP Password
**Objective**: Find FTP login password
**Analysis approach**:
```bash
# Wireshark analysis
ftp.request.command == "PASS" # FTP password commands
tcp.stream eq X               # Follow FTP conversation

# Pcredz analysis
python3 ./Pcredz -f demo.pcapng -v
# Look for: "FTP Pass:"
```

#### Question 4: Downloaded File
**Objective**: Identify file downloaded via FTP
**Analysis approach**:
```bash
# Wireshark analysis
ftp.request.command == "RETR" # File retrieval commands
ftp                           # Follow FTP data stream

# Manual analysis
1. Find FTP login sequence
2. Look for RETR commands
3. Note filename in command
```

### Systematic Analysis Workflow
```bash
# Step 1: Open pcap in Wireshark
wireshark demo.pcapng

# Step 2: Protocol hierarchy analysis
Statistics → Protocol Hierarchy

# Step 3: Filter for credentials
http contains "password"
ftp
snmp

# Step 4: Run Pcredz analysis
python3 ./Pcredz -f demo.pcapng -v -t

# Step 5: Follow interesting TCP streams
Right-click → Follow → TCP Stream

# Step 6: Export specific data if needed
File → Export Objects → HTTP/FTP
```

## 📋 Network Credential Hunting Checklist

### Pre-Analysis Setup
- [ ] Identify capture source and timeframe
- [ ] Check file integrity and size
- [ ] Review capture filters used
- [ ] Understand network topology

### Protocol Analysis
- [ ] HTTP traffic for forms and Basic Auth
- [ ] FTP for username/password sequences
- [ ] SNMP for community strings
- [ ] Email protocols (POP3/IMAP/SMTP)
- [ ] Telnet for cleartext sessions
- [ ] LDAP for bind credentials

### Automated Analysis
- [ ] Run Pcredz with verbose output
- [ ] Check for credit card patterns
- [ ] Extract NTLM hashes
- [ ] Identify Kerberos tickets
- [ ] Parse authentication headers

### Manual Verification
- [ ] Verify automated findings
- [ ] Follow relevant TCP streams
- [ ] Decode base64 credentials
- [ ] Cross-reference timestamps
- [ ] Document credential context

### Reporting
- [ ] Catalog all discovered credentials
- [ ] Note protocols and timestamps
- [ ] Assess credential strength
- [ ] Identify affected systems
- [ ] Recommend remediation

## 🛡️ Detection and Prevention

### Network Security Recommendations
```bash
# Protocol Migration
HTTP → HTTPS                  # Implement TLS certificates
FTP → SFTP/FTPS              # Use secure file transfer
Telnet → SSH                 # Replace with encrypted shell
SNMP v1/v2c → SNMPv3         # Enable SNMP encryption
POP3/IMAP → POP3S/IMAPS      # Enable email encryption
```

### Network Monitoring
```bash
# Detect credential hunting activities
- Promiscuous mode detection
- Unusual packet capture patterns
- Network sniffing tool signatures
- Abnormal traffic analysis queries
```

## 💡 Key Takeaways

1. **Legacy protocols** - Many environments still use unencrypted protocols
2. **Wireshark mastery** - Essential for network traffic analysis
3. **Pcredz efficiency** - Automates credential extraction from captures
4. **Protocol knowledge** - Understanding authentication flows is crucial
5. **Stream analysis** - Following TCP conversations reveals full context
6. **Pattern recognition** - Learn to identify credential-bearing traffic
7. **Automated tools** - Combine manual analysis with automated extraction
8. **Defense awareness** - Recommend encrypted alternatives

---

*This guide provides comprehensive network traffic credential hunting techniques using Wireshark and Pcredz, based on HTB Academy's Password Attacks module.* 