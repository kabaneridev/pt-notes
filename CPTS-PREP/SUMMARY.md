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

### 🖥️ Remote Management Protocols
* [📋 Remote Management Overview](remote-management/remote-management.md)
* [🐧 Linux Remote Protocols](remote-management/linux-remote-protocols.md)
* [🪟 Windows Remote Protocols](remote-management/windows-remote-protocols.md)

## 🛡️ Network Security

### 🔥 Firewall & IDS/IPS Evasion
* [🛡️ Firewall Evasion](firewall-evasion.md)

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

### 🔄 In Progress
* Vulnerability Assessment
* Web Application Attacks

### 📅 Planned
* Network Enumeration
* Password Attacks
* Active Directory Enumeration & Attacks
* Privilege Escalation
* Lateral Movement
* Post-Exploitation 