# Email Enumeration (IMAP/POP3)

## Overview
IMAP and POP3 are email retrieval protocols that allow clients to access email messages stored on mail servers. During enumeration, these services can reveal valuable information about the organization, system configuration, and potentially provide access to email data.

**Key Characteristics:**
- **POP3**: Port 110 (plain), 995 (SSL/TLS)
- **IMAP**: Port 143 (plain), 993 (SSL/TLS)
- **Protocol**: Text-based commands
- **Authentication**: Username/password based
- **Encryption**: STARTTLS or SSL/TLS

## IMAP vs POP3 Differences

| Feature | IMAP | POP3 |
|---------|------|------|
| **Email Storage** | Server-side (emails remain on server) | Client-side (downloads to local) |
| **Multi-device Access** | Yes (synchronization across devices) | Limited (downloads remove from server) |
| **Folder Management** | Yes (hierarchical mailboxes) | No (single inbox only) |
| **Offline Access** | Limited (requires sync) | Full (emails downloaded locally) |
| **Server Storage** | Higher (emails stored on server) | Lower (emails removed after download) |
| **Functionality** | Advanced (search, flags, folders) | Basic (list, retrieve, delete) |
| **Typical Usage** | Modern email clients, webmail | Legacy systems, simple clients |

## Port Overview

| Service | Port | Description |
|---------|------|-------------|
| **POP3** | 110 | Post Office Protocol v3 (plain text) |
| **POP3S** | 995 | POP3 over SSL/TLS |
| **IMAP** | 143 | Internet Message Access Protocol (plain text) |
| **IMAPS** | 993 | IMAP over SSL/TLS |

## Protocol Commands

### IMAP Commands
| Command | Description |
|---------|-------------|
| `1 LOGIN username password` | User's login |
| `1 LIST "" *` | Lists all directories |
| `1 CREATE "INBOX"` | Creates a mailbox with specified name |
| `1 DELETE "INBOX"` | Deletes a mailbox |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox |
| `1 LSUB "" *` | Returns subset of names from active/subscribed mailboxes |
| `1 SELECT INBOX` | Selects a mailbox for message access |
| `1 UNSELECT INBOX` | Exits the selected mailbox |
| `1 FETCH <ID> all` | Retrieves data associated with a message |
| `1 CLOSE` | Removes all messages with Deleted flag set |
| `1 LOGOUT` | Closes connection with IMAP server |

### POP3 Commands
| Command | Description |
|---------|-------------|
| `USER username` | Identifies the user |
| `PASS password` | Authentication of the user using password |
| `STAT` | Requests number of saved emails from server |
| `LIST` | Requests number and size of all emails |
| `RETR id` | Requests server to deliver requested email by ID |
| `DELE id` | Requests server to delete requested email by ID |
| `CAPA` | Requests server to display server capabilities |
| `RSET` | Requests server to reset transmitted information |
| `QUIT` | Closes connection with POP3 server |

## Dangerous Settings

IMAP/POP3 servers like Dovecot can be misconfigured, potentially exposing sensitive information:

| Setting | Description | Risk Level |
|---------|-------------|------------|
| `auth_debug` | Enables all authentication debug logging | High |
| `auth_debug_passwords` | Logs submitted passwords and schemes | Critical |
| `auth_verbose` | Logs unsuccessful authentication attempts and reasons | Medium |
| `auth_verbose_passwords` | Passwords used for authentication are logged | Critical |
| `auth_anonymous_username` | Username for ANONYMOUS SASL mechanism | Medium |

## Enumeration Techniques

### 1. Service Detection
```bash
# Nmap service detection
nmap -p110,143,993,995 -sV -sC target

# Comprehensive mail server enumeration
nmap -p110,143,993,995 --script imap-capabilities,pop3-capabilities target
```

### 2. Banner Grabbing
```bash
# POP3 banner grabbing
telnet target 110
nc target 110

# IMAP banner grabbing
telnet target 143
nc target 143
```

### 3. SSL Certificate Analysis
```bash
# Connect to IMAPS and analyze certificate
openssl s_client -connect target:993

# Connect to POP3S and analyze certificate
openssl s_client -connect target:995

# Show certificate details
openssl s_client -connect target:993 -showcerts

# Extract certificate information
openssl s_client -connect target:993 < /dev/null 2>/dev/null | openssl x509 -text
```

### 4. Service Capabilities
```bash
# IMAP capability enumeration
telnet target 143
CAPABILITY

# POP3 capability enumeration
telnet target 110
CAPA
```

## Advanced Enumeration

### Using OpenSSL for Encrypted Connections
```bash
# Connect to IMAPS
openssl s_client -connect target:993
# Look for flags in server response: HTB{...}

# Connect to POP3S
openssl s_client -connect target:995
# Extract server information

# Connect with specific TLS version
openssl s_client -connect target:993 -tls1_2
```

### Using cURL for IMAP/POP3 Testing
```bash
# Basic IMAP connection with cURL
curl -k 'imaps://target' --user user:password

# IMAP with verbose output to see TLS details
curl -k 'imaps://target' --user cry0l1t3:1234 -v

# List IMAP folders
curl -k 'imaps://target' --user username:password -X 'LIST "" "*"'

# POP3 connection
curl -k 'pop3s://target' --user username:password

# POP3 with verbose output
curl -k 'pop3s://target' --user username:password -v
```

**Example cURL Verbose Output Analysis:**
```bash
# cURL -v provides detailed TLS and protocol information:
curl -k 'imaps://target' --user cry0l1t3:1234 -v

# Key information extracted:
# * TLS version: TLSv1.3 / TLS_AES_256_GCM_SHA384
# * Certificate details:
#   subject: C=US; ST=California; L=Sacramento; O=Inlanefreight; 
#           CN=mail1.inlanefreight.htb; emailAddress=cry0l1t3@inlanefreight.htb
# * Server banner: * OK [CAPABILITY...] HTB-Academy IMAP4 v.0.21.4
# * Available folders: Important, INBOX
```

### SSL Certificate Information Extraction
```bash
# Extract organization information
openssl s_client -connect target:993 2>/dev/null | grep -E "subject|issuer|commonName|organizationName"

# Example output analysis:
# Subject: commonName=dev.inlanefreight.htb/organizationName=InlaneFreight Ltd
# organizationName=InlaneFreight Ltd
# commonName=dev.inlanefreight.htb
```

### Authentication Testing
```bash
# IMAP authentication
openssl s_client -connect target:993
tag0 LOGIN username password

# POP3 authentication
openssl s_client -connect target:995
USER username
PASS password
```

## IMAP Enumeration

### Basic IMAP Commands
```bash
# Common IMAP commands
CAPABILITY          # List server capabilities
LOGIN user pass     # Authenticate user
LIST "" "*"         # List all folders
SELECT folder       # Select folder
FETCH n (BODY[])    # Fetch message body
LOGOUT             # Disconnect
```

### IMAP Enumeration Session
```bash
# Connect to IMAPS
openssl s_client -connect target:993

# Authentication
tag0 LOGIN username password

# List folders
tag1 LIST "" "*"

# Select INBOX
tag2 SELECT "INBOX"

# Fetch first message
tag3 FETCH 1 (BODY[])
```

## POP3 Enumeration

### Basic POP3 Commands
```bash
# Common POP3 commands
USER username       # Specify username
PASS password       # Specify password
LIST               # List messages
RETR n             # Retrieve message n
DELE n             # Delete message n
QUIT               # Disconnect
```

### POP3 Enumeration Session
```bash
# Connect to POP3S
openssl s_client -connect target:995

# Authentication
USER username
PASS password

# List messages
LIST

# Retrieve first message
RETR 1
```

## Information Gathering

### SSL Certificate Analysis
```bash
# Extract useful information from certificates
openssl s_client -connect target:993 2>/dev/null | grep -E "commonName|organizationName|stateOrProvinceName|countryName"

# Common certificate fields to analyze:
# - commonName: Server FQDN
# - organizationName: Company name
# - stateOrProvinceName: Location
# - countryName: Country code
```

### Email Header Analysis
```bash
# After connecting and authenticating, analyze email headers
tag3 FETCH 1 (BODY[HEADER])

# Look for:
# - Internal IP addresses
# - Server names
# - Email addresses
# - Routing information
```

## Practical Examples

### HTB Academy Style Enumeration
```bash
# Step 1: Service detection
nmap -p110,143,993,995 -sV -sC target

# Step 2: SSL certificate analysis
openssl s_client -connect target:993
# Extract: organizationName=InlaneFreight Ltd
# Extract: commonName=dev.inlanefreight.htb

# Step 3: Authentication with found credentials
openssl s_client -connect target:993
tag0 LOGIN robin robin

# Step 4: Folder enumeration
tag1 LIST "" "*"

# Step 5: Email content analysis
tag2 SELECT "INBOX"
tag3 FETCH 1 (BODY[])
```

### HTB Academy Lab Questions Examples
```bash
# Question 1: "Figure out the exact organization name from the IMAP/POP3 service"
nmap -p110,143,993,995 -sV -sC target
# Look at SSL certificate in output:
# Subject: commonName=mail1.inlanefreight.htb/organizationName=Inlanefreight
# Answer: Inlanefreight

# Question 2: "What is the FQDN that the IMAP and POP3 servers are assigned to?"
# From same SSL certificate:
# commonName=mail1.inlanefreight.htb
# Answer: mail1.inlanefreight.htb

# Question 3: "Enumerate the IMAP service and submit the flag"
openssl s_client -connect target:993
# Look for banner: * OK [CAPABILITY...] HTB-Academy IMAP4 v.0.21.4
# Extract flag from banner: HTB{...}

# Question 4: "What is the customized version of the POP3 server?"
openssl s_client -connect target:995
# Look for banner: +OK HTB-Academy POP3 Server
# Answer: HTB-Academy POP3 Server

# Question 5: "What is the admin email address?"
# From SSL certificate subject:
# emailAddress=cry0l1t3@inlanefreight.htb
# Answer: cry0l1t3@inlanefreight.htb

# Question 6: "Try to access the emails on the IMAP server and submit the flag"
openssl s_client -connect target:993
tag0 LOGIN robin robin
tag1 LIST "" "*"
tag2 SELECT "INBOX"
tag3 FETCH 1 (BODY[])
# Look for flag in email content: HTB{...}
```

### Custom Version Detection
```bash
# Connect to POP3 and grab custom version
telnet target 110
# Look for: +OK InFreight POP3 v9.188

# Connect to IMAP and grab custom version
telnet target 143
# Look for custom banners and capabilities
```

### Certificate Information Extraction
```bash
# Detailed certificate analysis from HTB Academy
openssl s_client -connect target:993 2>/dev/null | grep -E "subject|issuer"

# Example detailed output:
# subject: C=US; ST=California; L=Sacramento; O=Inlanefreight; 
#         OU=Customer Support; CN=mail1.inlanefreight.htb; 
#         emailAddress=cry0l1t3@inlanefreight.htb
# 
# Extract all useful information:
# - Organization: Inlanefreight  
# - FQDN: mail1.inlanefreight.htb
# - Admin email: cry0l1t3@inlanefreight.htb
# - Location: Sacramento, California, US
```

## Security Assessment

### Common Vulnerabilities
1. **Weak Authentication**: Default or weak passwords
2. **Plaintext Transmission**: Unencrypted connections
3. **Information Disclosure**: Verbose error messages
4. **Certificate Issues**: Self-signed or invalid certificates

### Authentication Testing
```bash
# Test common credentials
USER admin
PASS admin

USER root
PASS root

# Test with discovered usernames
USER discovered_user
PASS common_password
```

## Enumeration Checklist

### Initial Discovery
- [ ] Port scan for 110, 143, 993, 995
- [ ] Service version detection
- [ ] Banner grabbing
- [ ] SSL certificate analysis

### Information Gathering
- [ ] Extract organization name from certificates
- [ ] Identify server FQDN
- [ ] Analyze custom version strings
- [ ] Document server capabilities

### Authentication Testing
- [ ] Test common credential combinations
- [ ] Use discovered usernames
- [ ] Test for authentication bypass
- [ ] Check for account lockout policies

### Content Analysis
- [ ] Enumerate email folders
- [ ] Analyze email headers
- [ ] Search for sensitive information
- [ ] Document administrative contacts

## Tools and Techniques

### Essential Tools
```bash
# Manual testing
telnet               # Basic connection testing
nc                   # Banner grabbing
openssl              # SSL/TLS connection testing

# Automated enumeration
nmap                 # Service detection and scripts
smtp-user-enum       # Can also test IMAP/POP3 in some cases
```

### Custom Scripts
```bash
# IMAP banner grabber
#!/bin/bash
echo "CAPABILITY" | nc $1 143

# POP3 banner grabber
#!/bin/bash
echo "CAPA" | nc $1 110

# SSL certificate extractor
#!/bin/bash
openssl s_client -connect $1:993 2>/dev/null | openssl x509 -text | grep -E "Subject|Issuer"
```

## Defensive Measures

### Secure Configuration
```bash
# Disable plaintext authentication
# In dovecot.conf:
auth_mechanisms = plain login
disable_plaintext_auth = yes

# Force SSL/TLS
ssl = required
ssl_cert = </path/to/cert.pem
ssl_key = </path/to/key.pem
```

### Best Practices
1. **Enforce SSL/TLS**: Disable plaintext protocols
2. **Strong Authentication**: Implement strong password policies
3. **Rate Limiting**: Prevent brute force attacks
4. **Monitoring**: Log authentication attempts
5. **Certificate Management**: Use valid certificates

### Detection and Monitoring
```bash
# Monitor mail server logs
tail -f /var/log/maillog

# Check for authentication failures
grep "authentication failure" /var/log/maillog
grep "Login failed" /var/log/maillog
```

## Common Attack Vectors

### 1. Credential Brute Force
```bash
# Manual testing
for user in admin root test; do
    for pass in admin password 123456; do
        # Test credentials
    done
done
```

### 2. Information Disclosure
- Server version information
- Internal network details
- Email addresses and contacts
- Organizational structure

### 3. Man-in-the-Middle
- Intercept plaintext connections
- Certificate validation bypass
- Credential harvesting
