# 🎯 CPTS - Certified Penetration Testing Professional

## **Overview**

This folder contains comprehensive notes and resources for preparing for the CPTS (Certified Penetration Testing Professional) certification from HTB Academy. The materials are organized to follow the HTB Academy CPTS path structure.

---

## **Current Structure**

```
CPTS-PREP/
├── README.md                           # This overview file
├── footprinting.md                     # Infrastructure Based Enumeration (Domain + Cloud + DNS)
├── firewall-evasion.md                 # Firewall and IDS/IPS Evasion techniques
├── vulnerability-assessment.md         # Nessus vulnerability scanning and credentialed assessment
├── web-enumeration/                    # Web application enumeration guides
│   ├── web-information-gathering.md    # Web application information gathering overview
│   ├── subdomain-enumeration.md        # DNS enumeration and subdomain discovery
│   └── web-application-enumeration.md  # Directory enumeration and virtual hosts
├── databases/                          # Database enumeration guides
│   ├── mysql-enumeration.md            # MySQL service enumeration
│   ├── mssql-enumeration.md            # Microsoft SQL Server enumeration
│   └── oracle-enumeration.md           # Oracle TNS enumeration
├── services/                           # Network service enumeration
│   ├── ftp-enumeration.md              # FTP service enumeration
│   ├── smb-enumeration.md              # SMB share and authentication testing
│   ├── nfs-enumeration.md              # Network File System enumeration
│   ├── smtp-enumeration.md             # SMTP enumeration and testing
│   ├── email-enumeration.md            # IMAP/POP3 enumeration
│   ├── snmp-enumeration.md             # SNMP network management testing
│   └── ipmi-enumeration.md             # Hardware management interface testing
├── passwords-attacks/                  # Password attacks and lateral movement
│   ├── pass-the-hash.md               # Pass the Hash (PtH) attacks
│   ├── pass-the-ticket.md             # Pass the Ticket (PtT) attacks
│   ├── pass-the-certificate.md        # Pass the Certificate (ESC8 & ADCS attacks)
│   ├── active-directory-ntds-attacks.md # NTDS.dit extraction and analysis
│   └── [other password attack techniques]
├── attacking-common-services/          # Protocol exploitation techniques
│   ├── ftp-attacks.md                 # FTP exploitation and abuse
│   ├── smb-attacks.md                 # SMB protocol attacks and RCE
│   ├── sql-attacks.md                 # MySQL/MSSQL database exploitation
│   └── [other service exploitation]
└── remote-management/                  # Remote access protocols
    ├── remote-management.md            # Overview of remote management protocols
    ├── linux-remote-protocols.md      # SSH, Rsync, R-Services
    └── windows-remote-protocols.md    # RDP, WinRM, WMI
```

---

## **Study Materials**

### **📋 Phase 1: Information Gathering**

#### **🔍 Host-Based Enumeration**
*Complete service enumeration methodology organized by categories*

**🗄️ Database Services:**
- **[MySQL Enumeration](./databases/mysql-enumeration.md)** - MySQL service testing, authentication, and exploitation
- **[MSSQL Enumeration](./databases/mssql-enumeration.md)** - Microsoft SQL Server enumeration and attacks
- **[Oracle TNS Enumeration](./databases/oracle-enumeration.md)** - Oracle database service testing

**📁 Network Services:**
- **[FTP Enumeration](./services/ftp-enumeration.md)** - File Transfer Protocol testing and exploitation
- **[SMB Enumeration](./services/smb-enumeration.md)** - SMB share enumeration, authentication testing, and CVE exploitation
- **[NFS Enumeration](./services/nfs-enumeration.md)** - Network File System testing and security assessment
- **[SMTP Enumeration](./services/smtp-enumeration.md)** - Mail server testing and user enumeration
- **[Email Services](./services/email-enumeration.md)** - IMAP/POP3 enumeration and certificate analysis
- **[SNMP Enumeration](./services/snmp-enumeration.md)** - Network management protocol testing and information gathering
- **[IPMI Enumeration](./services/ipmi-enumeration.md)** - Hardware management interface testing and hash extraction

**⚔️ Attacking Common Services:**
- **[FTP Attacks](./attacking-common-services/ftp-attacks.md)** - FTP exploitation techniques, brute forcing, bounce attacks, and file transfer abuse
- **[SMB Attacks](./attacking-common-services/smb-attacks.md)** - SMB protocol exploitation, Pass-the-Hash, RCE, forced authentication, and NTLM relay
- **[SQL Database Attacks](./attacking-common-services/sql-attacks.md)** - MySQL/MSSQL exploitation, command execution, hash stealing, privilege escalation, and lateral movement
- **[DNS Attacks](./attacking-common-services/dns-attacks.md)** - DNS zone transfers, subdomain enumeration, domain takeover, and DNS-based attacks
- **[RDP Attacks](./attacking-common-services/rdp-attacks.md)** - RDP exploitation, password spraying, session hijacking, and Pass-the-Hash attacks
- **[Email Services Attacks](./attacking-common-services/smtp-attacks.md)** - SMTP/IMAP/POP3 exploitation, user enumeration, mail relay abuse, and credential harvesting
- **[Skills Assessment](./attacking-common-services/skills-assessment.md)** - Complete attack chain scenarios (Easy/Medium/Hard) with HTB Academy solutions

**🖥️ Remote Management:**
- **[Remote Management Overview](./remote-management/remote-management.md)** - Overview of remote access protocols
- **[Linux Remote Protocols](./remote-management/linux-remote-protocols.md)** - SSH, Rsync, R-Services enumeration
- **[Windows Remote Protocols](./remote-management/windows-remote-protocols.md)** - RDP, WinRM, WMI testing

**🕷️ Web Enumeration:**
- **[Web Information Gathering](./web-enumeration/web-information-gathering.md)** - Overview and quick start guide for web reconnaissance
- **[Subdomain Enumeration](./web-enumeration/subdomain-enumeration.md)** - DNS enumeration and subdomain discovery techniques
- **[Web Application Enumeration](./web-enumeration/web-application-enumeration.md)** - Directory enumeration, virtual hosts, and web application testing

**🔐 Password Attacks & Lateral Movement:**
- **[Skills Assessment Workflow](./passwords-attacks/skills-assessment-workflow.md)** - Complete password attacks methodology from foothold to domain compromise
- **[Pass the Hash Attacks](./passwords-attacks/pass-the-hash.md)** - NTLM hash relay and authentication bypass
- **[Pass the Ticket Attacks](./passwords-attacks/pass-the-ticket.md)** - Kerberos ticket manipulation and Golden Ticket attacks
- **[Pass the Certificate Attacks](./passwords-attacks/pass-the-certificate.md)** - ESC8 ADCS attacks and PKINIT exploitation
- **[NTDS.dit Attacks](./passwords-attacks/active-directory-ntds-attacks.md)** - Domain controller credential extraction

#### **🌐 [Infrastructure Enumeration](./footprinting.md)**
*Domain and cloud infrastructure reconnaissance*

**Topics Covered:**
- Domain Information Gathering
- DNS Enumeration and Zone Transfers
- Cloud Service Identification
- Certificate Transparency Analysis
- Subdomain Discovery

#### **🛡️ [Firewall Evasion](./firewall-evasion.md)**
*Techniques for bypassing security controls*

**Techniques Covered:**
- Firewall Detection and Fingerprinting
- IDS/IPS Evasion Methods
- Port Scanning Evasion
- Protocol Manipulation

---

## **Key Features**

### **🎯 Comprehensive Coverage**
- **30+ Service Types** - Complete enumeration guides for all major services
- **Complete Attack Modules** - Full HTB Academy "Attacking Common Services" (4,262 lines)
- **Skills Assessment Trilogy** - Easy/Medium/Hard difficulty scenarios with solutions
- **Web Application Focus** - Dedicated web reconnaissance and enumeration
- **CVE References** - Known vulnerabilities with exploitation examples
- **HTB Academy Style** - Lab questions and practical examples
- **Real-World Scenarios** - Practical penetration testing methodologies

### **📚 Practical Focus**
- **Step-by-step Commands** - Copy-paste ready enumeration commands
- **Tool Comparisons** - Multiple tools for each enumeration task
- **Security Assessment** - Vulnerability identification and exploitation
- **Defensive Measures** - Hardening and protection recommendations

---

## **Study Resources**

### **📖 Essential Reading**
- **HTB Academy CPTS Path** - Official certification curriculum
- **PTES Standard** - Penetration Testing Execution Standard
- **NIST Guidelines** - Cybersecurity framework references
- **OWASP Top 10** - Web application security fundamentals

### **🛠️ Required Tools**
- **Nmap** - Network discovery and security auditing
- **Burp Suite** - Web application security testing
- **Metasploit** - Penetration testing framework
- **Bloodhound** - Active Directory environment analysis
- **Custom Scripts** - Automation and efficiency tools

### **🏆 Certification Path**
1. **Study Phase** - Review all enumeration guides systematically
2. **Lab Practice** - Complete HTB Academy lab exercises
3. **Exam Preparation** - Review methodologies and checklists
4. **Certification Exam** - Apply knowledge in simulated environment


---

*This CPTS preparation guide is designed to provide comprehensive coverage of penetration testing methodologies while maintaining practical applicability for real-world security assessments.*
