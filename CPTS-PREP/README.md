# 🎯 CPTS - Certified Penetration Testing Professional

## **Overview**

This folder contains comprehensive notes and resources for preparing for the CPTS (Certified Penetration Testing Professional) certification from HTB Academy. The materials are organized to follow the HTB Academy CPTS path structure.

---

## **Current Structure**

```
CPTS-PREP/
├── README.md                           # This overview file
├── footprinting.md                     # Infrastructure Based Enumeration (Domain + Cloud + DNS)
├── web-information-gathering.md        # Web Application Information Gathering
├── firewall-evasion.md                 # Firewall and IDS/IPS Evasion techniques
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

**🖥️ Remote Management:**
- **[Remote Management Overview](./remote-management/remote-management.md)** - Overview of remote access protocols
- **[Linux Remote Protocols](./remote-management/linux-remote-protocols.md)** - SSH, Rsync, R-Services enumeration
- **[Windows Remote Protocols](./remote-management/windows-remote-protocols.md)** - RDP, WinRM, WMI testing

#### **🌐 [Infrastructure Enumeration](./footprinting.md)**
*Domain and cloud infrastructure reconnaissance*

**Topics Covered:**
- Domain Information Gathering
- DNS Enumeration and Zone Transfers
- Cloud Service Identification
- Certificate Transparency Analysis
- Subdomain Discovery

#### **🕷️ [Web Application Information Gathering](./web-information-gathering.md)**
*Web application-specific reconnaissance and enumeration*

**Topics Covered:**
- WHOIS Information Gathering and Analysis
- DNS Enumeration and Zone Transfer Attempts
- Technology Stack Identification (whatweb, Wappalyzer)
- Directory & File Enumeration (gobuster, ffuf, dirb)
- Parameter Discovery (Arjun, ffuf)
- Virtual Host Discovery
- API Enumeration and Documentation
- JavaScript Analysis and Endpoint Extraction
- CMS-Specific Enumeration (WordPress, Joomla, Drupal)
- Security Headers Analysis
- WAF Detection and Bypass Techniques

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
