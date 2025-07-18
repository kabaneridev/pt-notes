# Summary

## 🎯 CPTS Preparation Guide

* [📚 Introduction](README.md)

## 📋 Information Gathering

### 🌐 Infrastructure Enumeration
* [🔍 Footprinting](footprinting.md)

### 🕷️ Web Application Information Gathering
* [🌐 Subdomain Enumeration & DNS Discovery](web-enumeration/subdomain-enumeration.md)
* [🔧 Web Application Enumeration](web-enumeration/web-application-enumeration.md)
* [📋 Web Information Gathering Overview](web-enumeration/web-information-gathering.md)


### 🗄️ Database Services
* [🔍 MySQL Enumeration](databases/mysql-enumeration.md)
* [🏢 MSSQL Enumeration](databases/mssql-enumeration.md)
* [⚡ Oracle TNS Enumeration](databases/oracle-enumeration.md)

### 📁 Network Services
* [📂 FTP Enumeration](services/ftp-enumeration.md)
* [🔗 SMB Enumeration](services/smb-enumeration.md)
* [📁 NFS Enumeration](services/nfs-enumeration.md)
* [📧 SMTP Enumeration](services/smtp-enumeration.md)
* [📮 Email Services (IMAP/POP3)](services/email-enumeration.md)
* [📊 SNMP Enumeration](services/snmp-enumeration.md)
* [⚙️ IPMI Enumeration](services/ipmi-enumeration.md)

## ⚔️ Attacking Common Services
* [📁 FTP Attacks](attacking-common-services/ftp-attacks.md)
* [🔗 SMB Attacks](attacking-common-services/smb-attacks.md)
* [🗄️ SQL Database Attacks](attacking-common-services/sql-attacks.md)
* [🌐 DNS Attacks](attacking-common-services/dns-attacks.md)
* [🖥️ RDP Attacks](attacking-common-services/rdp-attacks.md)
* [📧 Email Services Attacks (SMTP/IMAP/POP3)](attacking-common-services/smtp-attacks.md)
* [🎯 Skills Assessment - Complete Attack Chain Scenarios](attacking-common-services/skills-assessment.md)

### 🖥️ Remote Management Protocols
* [📋 Remote Management Overview](remote-management/remote-management.md)
* [🐧 Linux Remote Protocols](remote-management/linux-remote-protocols.md)
* [🪟 Windows Remote Protocols](remote-management/windows-remote-protocols.md)

## 🛡️ Network Security

### 🔥 Firewall & IDS/IPS Evasion
* [🛡️ Firewall Evasion](firewall-evasion.md)

### 🎯 Vulnerability Assessment
* [🎯 Vulnerability Assessment](vulnerability-assessment.md)

## 🔧 Shells & Payloads

### 🐚 Shell Fundamentals
* [📋 Shell Basics](shells-payloads/shell-basics.md)
* [🎯 Payloads](shells-payloads/payloads.md)
* [🔧 Metasploit Framework](shells-payloads/metasploit-framework.md)
* [🚀 Meterpreter Post-Exploitation](shells-payloads/meterpreter.md)

### 🐧 Platform-Specific Shells
* [🪟 Windows Shells](shells-payloads/windows-shells.md)
* [🐧 Linux/Unix Shells](shells-payloads/nix-shells.md)

### 🌐 Web Shells
* [🕷️ PHP Web Shells](shells-payloads/php-web-shells.md)
* [🔧 Web Shell Techniques](shells-payloads/web-shells.md)

### 📁 File Transfer Methods
* [🪟 Windows File Transfers](file-transfers/windows-file-transfers.md)
* [🐧 Linux File Transfers](file-transfers/linux-file-transfers.md)
* [💻 Code-Based File Transfers](file-transfers/code-file-transfers.md)
* [🔀 Miscellaneous File Transfers](file-transfers/miscellaneous-file-transfers.md)
* [🛡️ Protected File Transfers](file-transfers/protected-file-transfers.md)
* [🎯 Living off the Land Transfers](file-transfers/living-off-the-land-file-transfers.md)
* [🔍 File Transfer Detection](file-transfers/file-transfer-detection.md)

## 🔐 Password Attacks

### 📋 Complete Assessment Workflows
* [🎯 Skills Assessment - Complete Password Attacks Workflow](passwords-attacks/skills-assessment-workflow.md)

### 🎯 Active Directory Attacks
* [🎫 NTDS.dit Extraction & Analysis](passwords-attacks/active-directory-ntds-attacks.md)
* [🔍 Username Enumeration & OSINT](passwords-attacks/username-enumeration.md)
* [🗡️ Dictionary & Brute Force Attacks](passwords-attacks/dictionary-attacks.md)
* [⚔️ Pass-the-Hash Techniques](passwords-attacks/pass-the-hash.md)

### 🪟 Windows Password Attacks
* [🔧 Registry Hive Attacks (SAM, SYSTEM, SECURITY)](passwords-attacks/windows-passwords.md)
* [🧠 LSASS Memory Dumping](passwords-attacks/lsass-attacks.md)
* [💾 Credential Manager Attacks](passwords-attacks/credential-manager.md)
* [🕵️ Credential Hunting in Windows](passwords-attacks/credential-hunting-windows.md)

### 🐧 Linux Password Attacks
* [🔍 Credential Hunting in Linux](passwords-attacks/credential-hunting-linux.md)

### 🔨 Hash Cracking
* [⚡ Hashcat Techniques](passwords-attacks/hashcat.md)
* [🔓 John the Ripper](passwords-attacks/john-the-ripper.md)
* [📝 Custom Wordlists & Rules](passwords-attacks/custom-wordlists-rules.md)

### 🌐 Network Service Attacks
* [🔌 Network Services Brute Force](passwords-attacks/network-services.md)
* [📁 Protected File Cracking](passwords-attacks/cracking-protected-files.md)
* [🌐 Network Traffic Credential Hunting](passwords-attacks/credential-hunting-network.md)
* [📂 Network Shares Credential Hunting](passwords-attacks/credential-hunting-shares.md)

### ⚔️ Windows Lateral Movement
* [🔑 Pass the Hash (PtH) Attacks](passwords-attacks/pass-the-hash.md)
* [🎫 Pass the Ticket (PtT) Attacks](passwords-attacks/pass-the-ticket.md)
* [📜 Pass the Certificate (ESC8 & ADCS Attacks)](passwords-attacks/pass-the-certificate.md)
* [🐧 Pass the Ticket from Linux](passwords-attacks/pass-the-ticket-linux.md)

---

## 📖 Quick Reference

### 🕷️ Web Application Information Gathering
* **DNS Tools** - dig, dnsenum, amass, puredns for subdomain discovery
* **Web Enumeration** - gobuster, ffuf, whatweb for content discovery
* **CMS Tools** - wpscan, joomscan, droopescan for specific platforms
* **Parameter Discovery** - arjun, paramspider, ffuf for hidden parameters

### 🔧 Database Enumeration
* **MySQL** - Port 3306, default credentials, SQL injection
* **MSSQL** - Port 1433, Windows authentication, xp_cmdshell
* **Oracle TNS** - Port 1521, SID enumeration, privilege escalation

### 🌐 Network Service Enumeration
* **FTP** - Port 21, anonymous access, file upload/download
* **SMB** - Ports 139/445, share enumeration, EternalBlue (CVE-2017-0144)
* **NFS** - Port 2049, share mounting, UID/GID manipulation
* **SMTP** - Port 25, user enumeration, open relay testing
* **IMAP/POP3** - Ports 143/993/110/995, certificate analysis
* **SNMP** - Port 161, community strings, OID enumeration
* **IPMI** - Port 623, hash extraction, cipher zero vulnerability

### 🔐 Remote Access Protocols
* **SSH** - Port 22, key-based authentication, tunneling
* **RDP** - Port 3389, BlueKeep vulnerability, certificate analysis
* **WinRM** - Ports 5985/5986, PowerShell remoting, authentication bypass
* **WMI** - Port 135, remote queries, persistence mechanisms

---

## 🎯 HTB Academy Modules

### ✅ Completed
* Firewall and IDS/IPS Evasion
* Footprinting
* Host-Based Enumeration
* Web Application Information Gathering
* **Attacking Common Services** (Complete - 7 documents, 4,262 lines)

### 🔄 In Progress
* Vulnerability Assessment
* Web Application Attacks
* Password Attacks

### 📅 Planned
* Network Enumeration
* Active Directory Enumeration & Attacks
* Privilege Escalation
* Lateral Movement
* Post-Exploitation 