# SMTP (Simple Mail Transfer Protocol) Enumeration

## Overview
Simple Mail Transfer Protocol (SMTP) is a communication protocol for electronic mail transmission. SMTP is an application layer protocol that enables the sending of email messages between servers and clients. During enumeration, SMTP servers can reveal valuable information about the system and valid user accounts.

**Key Characteristics:**
- **Port 25**: Standard SMTP port
- **Port 587**: SMTP submission port (often with STARTTLS)
- **Port 465**: SMTP over SSL/TLS (deprecated but still used)
- **Protocol**: Text-based, human-readable commands
- **Authentication**: Optional, varies by configuration

**SMTP Process Flow:**
```
Client (MUA) → Submission Agent (MSA) → Open Relay (MTA) → Mail Delivery Agent (MDA) → Mailbox (POP3/IMAP)
```

## SMTP Commands and Responses

### Common SMTP Commands
```bash
# Basic SMTP commands
HELO/EHLO    # Identify client to server (EHLO for Extended SMTP)
MAIL FROM    # Specify sender
RCPT TO      # Specify recipient
DATA         # Begin message content
QUIT         # Close connection
VRFY         # Verify user exists
EXPN         # Expand mailing list
AUTH PLAIN   # Authentication (with ESMTP)
RSET         # Reset connection
NOOP         # No operation (prevent timeout)
```

### User Enumeration Commands
```bash
# VRFY - Verify if user exists
VRFY username

# EXPN - Expand mailing list
EXPN listname

# RCPT TO - Recipient verification
RCPT TO:username@domain.com
```

## Default Configuration

SMTP servers like Postfix can be configured in various ways. Understanding common configurations helps identify potential security issues.

### Example Postfix Configuration
```bash
# View Postfix main configuration
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"

# Key configuration parameters:
smtpd_banner = ESMTP Server 
myhostname = mail1.inlanefreight.htb
mydestination = $myhostname, localhost 
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
```

## Dangerous Settings

### Open Relay Configuration
The most dangerous SMTP misconfiguration is an open relay, which allows anyone to send emails through the server:

```bash
# DANGEROUS: Allows any IP to relay mail
mynetworks = 0.0.0.0/0

# SECURE: Only allow local networks
mynetworks = 127.0.0.0/8 10.129.0.0/16
```

**Open Relay Impact:**
- Spam distribution
- Reputation damage
- Potential for email spoofing
- Resource abuse

## Enumeration Techniques

### 1. Banner Grabbing and Initial Connection
```bash
# Telnet connection to grab banner
telnet target 25

# Netcat for banner grabbing
nc target 25

# Nmap banner grabbing
nmap -p25 --script smtp-commands target
```

### 2. SMTP Service Detection
```bash
# Nmap service detection
nmap -p25,587,465 -sV -sC target

# Comprehensive SMTP enumeration
nmap -p25,587,465 --script smtp-enum-users,smtp-commands,smtp-open-relay target
```

### 3. HELO vs EHLO Testing
```bash
# Basic HELO command
telnet target 25
HELO mail1.inlanefreight.htb

# Extended SMTP capabilities with EHLO
telnet target 25
EHLO mail1

# Example EHLO response showing capabilities:
250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

### 4. User Enumeration with VRFY
```bash
# Manual VRFY testing
telnet target 25
VRFY root
VRFY admin
VRFY test

# Example session
$ telnet target 25
220 ESMTP Server
VRFY root
252 2.0.0 root    # User might exist
VRFY admin
550 admin... User unknown
VRFY cry0l1t3
252 2.0.0 cry0l1t3   # User might exist

# Note: Some servers return 252 for all users to prevent enumeration
```

### 5. User Enumeration with EXPN
```bash
# Manual EXPN testing
telnet target 25
EXPN root
EXPN admin

# Example responses
250 root <root@mailserver>
550 admin... User unknown
```

### 6. Email Sending Testing
```bash
# Complete email sending session
telnet target 25
EHLO inlanefreight.htb
MAIL FROM: <attacker@inlanefreight.htb>
RCPT TO: <target@inlanefreight.htb> NOTIFY=success,failure
DATA
From: <attacker@inlanefreight.htb>
To: <target@inlanefreight.htb>
Subject: Test Email
Date: Tue, 28 Sept 2021 16:32:51 +0200

This is a test email.
.
QUIT
```

### 5. Automated User Enumeration
```bash
# Using smtp-user-enum
smtp-user-enum -M VRFY -U userlist.txt -t target
smtp-user-enum -M EXPN -U userlist.txt -t target
smtp-user-enum -M RCPT -U userlist.txt -t target

# With options
smtp-user-enum -M VRFY -U userlist.txt -t target -m 60 -w 20
```

## Advanced Enumeration

### Using Nmap NSE Scripts
```bash
# SMTP user enumeration
nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN} target

# SMTP command enumeration
nmap -p25 --script smtp-commands target

# SMTP open relay test
nmap -p25 --script smtp-open-relay target

# SMTP brute force
nmap -p25 --script smtp-brute target
```

### Open Relay Testing
```bash
# Test for open relay with Nmap
nmap -p25 --script smtp-open-relay -v target

# Example of comprehensive relay testing (16 different tests)
# The script tests various relay methods:
# - MAIL FROM:<> -> RCPT TO:<relaytest@external.com>
# - MAIL FROM:<user@target> -> RCPT TO:<relaytest@external.com>
# - MAIL FROM:<user@target> -> RCPT TO:<relaytest%external.com@target>
# - And many more combinations

# Manual relay testing
telnet target 25
EHLO test.com
MAIL FROM: <attacker@external.com>
RCPT TO: <victim@external.com>
DATA
Subject: Relay Test
This is a relay test
.
QUIT
```

### Manual Testing Session
```bash
# Complete manual enumeration
telnet target 25
EHLO test.com
HELP
VRFY root
VRFY admin
EXPN root
QUIT
```

## Security Issues and Attack Vectors

### 1. User Enumeration
- **Issue**: VRFY and EXPN commands reveal valid users
- **Impact**: Username harvesting for brute force attacks
- **Detection**: Different responses for valid vs invalid users
- **Note**: Some servers return 252 for all users to prevent enumeration

### 2. Open Relay
- **Issue**: Server allows relay of mail from any source
- **Impact**: Spam distribution, reputation damage, email spoofing
- **Testing**: Attempt to send mail through server to external addresses
- **Configuration**: `mynetworks = 0.0.0.0/0` creates open relay

### 3. Information Disclosure
- **Issue**: Verbose error messages and banners
- **Impact**: System information, software versions
- **Examples**: Server version, internal hostnames, configuration details
- **Mitigation**: Use generic banners

### 4. Authentication Bypass
- **Issue**: Weak or missing authentication
- **Impact**: Unauthorized mail sending
- **Testing**: Attempt unauthenticated mail sending

### 5. Email Spoofing
- **Issue**: Lack of SPF/DKIM/DMARC validation
- **Impact**: Phishing attacks, reputation damage
- **Testing**: Send emails with forged sender addresses

## Practical Examples

### HTB Academy Style Enumeration
```bash
# Step 1: Banner grabbing and version detection
telnet target 25
# Look for banner like: "220 InFreight ESMTP v2.11"

# Step 2: Capability enumeration
telnet target 25
EHLO test.com
# Look for supported features

# Step 3: User enumeration with wordlist
smtp-user-enum -M VRFY -U /path/to/wordlist.txt -t target -m 60 -w 20
# Look for: "target: username exists"

# Step 4: Verify findings
telnet target 25
VRFY discovered_user
# Confirm user exists
```

### HTB Academy Lab Questions Examples
```bash
# Question 1: "Enumerate the SMTP service and submit the banner"
telnet target 25
# Extract banner: "220 InFreight ESMTP v2.11"
# Answer: InFreight ESMTP v2.11

# Question 2: "Find the username that exists on the system"
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t target
# Look for successful enumeration
telnet target 25
VRFY discovered_username
# Answer: discovered_username
```

### Wordlist-based User Enumeration
```bash
# Create custom wordlist
cat > smtp_users.txt << EOF
admin
administrator
root
test
guest
mail
postmaster
webmaster
EOF

# Run enumeration
smtp-user-enum -M VRFY -U smtp_users.txt -t target
```

## Enumeration Checklist

### Initial Discovery
- [ ] Port scan for 25, 587, 465
- [ ] Banner grabbing and version identification
- [ ] EHLO/HELO command testing
- [ ] Available command enumeration

### User Enumeration
- [ ] VRFY command testing
- [ ] EXPN command testing
- [ ] RCPT TO method testing
- [ ] Automated user enumeration with wordlists

### Security Testing
- [ ] Open relay testing
- [ ] Authentication bypass attempts
- [ ] Information disclosure assessment
- [ ] Error message analysis

## Tools and Techniques

### Essential SMTP Tools
```bash
# Manual testing
telnet               # Basic SMTP interaction
nc                   # Banner grabbing

# Automated enumeration
smtp-user-enum       # User enumeration tool
nmap                 # Service detection and scripts

# Specialized tools
swaks                # SMTP testing toolkit
sendemail            # Command-line email sending
```

### Custom Scripts
```bash
# Simple SMTP user checker
#!/bin/bash
target=$1
userlist=$2

while read user; do
    echo "VRFY $user" | nc $target 25 | grep -E "(250|252)"
done < $userlist

# SMTP banner grabber
#!/bin/bash
echo "QUIT" | nc $1 25 | head -1
```

## Defensive Measures

### Secure SMTP Configuration
```bash
# Disable VRFY and EXPN
# In postfix main.cf:
disable_vrfy_command = yes
smtpd_discard_ehlo_keyword_address_maps = hash:/etc/postfix/discard_ehlo

# In sendmail.mc:
define(`confPRIVACY_FLAGS', `authwarnings,novrfy,noexpn,restrictqrun')
```

### Best Practices
1. **Disable VRFY/EXPN**: Prevent user enumeration
2. **Custom banners**: Hide version information
3. **Rate limiting**: Prevent brute force attacks
4. **Authentication**: Require authentication for mail sending
5. **Monitoring**: Log and monitor SMTP activities

### Detection and Monitoring
```bash
# Monitor SMTP logs
tail -f /var/log/maillog

# Check for enumeration attempts
grep -i "vrfy\|expn" /var/log/maillog
grep "User unknown" /var/log/maillog
```

## Common Vulnerabilities

### CVE Examples
- **CVE-2020-7247**: OpenSMTPD remote code execution
- **CVE-2016-10009**: Postfix denial of service
- **CVE-2014-3956**: Exim privilege escalation

### Mitigation Strategies
1. **Keep updated**: Regular security patches
2. **Minimal configuration**: Disable unnecessary features
3. **Access controls**: Restrict SMTP access
4. **Encryption**: Use TLS for mail transmission
