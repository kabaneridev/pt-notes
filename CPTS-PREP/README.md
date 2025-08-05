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
├── pivoting-tunneling-port-forwarding/ # Network pivoting and tunneling techniques
│   ├── pivoting-overview.md           # Module overview and network segmentation concepts
│   ├── dynamic-port-forwarding.md     # SSH SOCKS tunneling
│   ├── remote-port-forwarding.md      # Reverse shells and Meterpreter pivoting
│   ├── ssh-tunneling.md               # Complete SSH forwarding guide (Local, Remote, Dynamic)
│   ├── chisel-socks5-tunneling.md     # Modern HTTP/SOCKS5 tunneling with Chisel
│   ├── sshuttle-pivoting.md           # VPN-like tunneling over SSH
│   ├── meterpreter-tunneling.md       # Metasploit autoroute and pivoting modules
│   ├── socat-redirection.md           # Socat for port forwarding and redirection
│   ├── plink-windows-pivoting.md      # Windows SSH client for tunneling
│   ├── netsh-windows-portforward.md   # Native Windows port forwarding
│   ├── socksoverrdp-windows-pivoting.md # RDP-based SOCKS tunneling
│   ├── rpivot-web-pivoting.md         # HTTP/HTTPS tunneling with rpivot
│   ├── dnscat2-dns-tunneling.md       # DNS tunneling techniques
│   ├── ptunnel-ng-icmp-tunneling.md   # ICMP tunneling with ptunnel-ng
│   └── skills-assessment-complete-walkthrough.md # Complete HTB Academy skills assessment (All 7 questions)
├── attacking-common-services/          # Protocol exploitation techniques
│   ├── ftp-attacks.md                 # FTP exploitation and abuse
├── active-directory-enumeration-attacks/ # Active Directory penetration testing
│   ├── initial-enumeration-domain.md     # Initial domain enumeration
│   ├── llmnr-nbt-ns-poisoning-linux.md   # LLMNR/NBT-NS poisoning with Responder
│   └── [additional AD attack modules]    # More AD techniques to be added
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

**🔀 Pivoting, Tunneling & Port Forwarding:**
- **[Module Overview](./pivoting-tunneling-port-forwarding/pivoting-overview.md)** - Concepts, network segmentation, and methodology
- **[SSH Tunneling Complete Guide](./pivoting-tunneling-port-forwarding/ssh-tunneling.md)** - Local, Remote, and Dynamic port forwarding
- **[Dynamic Port Forwarding](./pivoting-tunneling-port-forwarding/dynamic-port-forwarding.md)** - SSH SOCKS tunneling and proxychains
- **[Remote Port Forwarding](./pivoting-tunneling-port-forwarding/remote-port-forwarding.md)** - Reverse shells and Meterpreter pivoting
- **[Chisel SOCKS5 Tunneling](./pivoting-tunneling-port-forwarding/chisel-socks5-tunneling.md)** - Modern HTTP/SOCKS5 tunneling
- **[SSHuttle Pivoting](./pivoting-tunneling-port-forwarding/sshuttle-pivoting.md)** - VPN-like tunneling over SSH
- **[Meterpreter Tunneling](./pivoting-tunneling-port-forwarding/meterpreter-tunneling.md)** - Metasploit autoroute and framework integration
- **[Socat Redirection](./pivoting-tunneling-port-forwarding/socat-redirection.md)** - Advanced port forwarding and redirection
- **[Plink Windows Pivoting](./pivoting-tunneling-port-forwarding/plink-windows-pivoting.md)** - Windows SSH client for tunneling
- **[Netsh Port Forwarding](./pivoting-tunneling-port-forwarding/netsh-windows-portforward.md)** - Native Windows port forwarding
- **[SocksOverRDP](./pivoting-tunneling-port-forwarding/socksoverrdp-windows-pivoting.md)** - RDP-based SOCKS tunneling
- **[Rpivot Web Pivoting](./pivoting-tunneling-port-forwarding/rpivot-web-pivoting.md)** - HTTP/HTTPS tunneling techniques
- **[DNS Tunneling with dnscat2](./pivoting-tunneling-port-forwarding/dnscat2-dns-tunneling.md)** - DNS-based covert channels
- **[ICMP Tunneling with ptunnel-ng](./pivoting-tunneling-port-forwarding/ptunnel-ng-icmp-tunneling.md)** - ICMP-based tunneling

**🏰 Active Directory Enumeration & Attacks:**
- **[Initial Domain Enumeration](./active-directory-enumeration-attacks/initial-enumeration-domain.md)** - Network discovery, service enumeration, and user enumeration with Kerbrute
- **[LLMNR/NBT-NS Poisoning from Linux](./active-directory-enumeration-attacks/llmnr-nbt-ns-poisoning-linux.md)** - Responder attacks, hash capture, and credential harvesting
- **[LLMNR/NBT-NS Poisoning from Windows](./active-directory-enumeration-attacks/llmnr-nbt-ns-poisoning-windows.md)** - Inveigh attacks, hash capture, and credential extraction
- **[Password Policy Enumeration](./active-directory-enumeration-attacks/password-policy-enumeration.md)** - Domain password policy discovery and analysis
- **[Password Spraying User List Creation](./active-directory-enumeration-attacks/password-spraying-user-list.md)** - Username enumeration for password spraying attacks
- **[Password Spraying from Linux](./active-directory-enumeration-attacks/password-spraying-linux.md)** - rpcclient, Kerbrute, and CrackMapExec spraying techniques
- **[Password Spraying from Windows](./active-directory-enumeration-attacks/password-spraying-windows.md)** - DomainPasswordSpray.ps1 and Windows-based credential discovery
- **[Security Controls Enumeration](./active-directory-enumeration-attacks/security-controls-enumeration.md)** - Windows Defender, AppLocker, LAPS, and Constrained Language Mode assessment
- **[Credentialed Enumeration from Linux](./active-directory-enumeration-attacks/credentialed-enumeration-linux.md)** - CrackMapExec, SMBMap, rpcclient, Impacket, Windapsearch, and BloodHound.py
- **[Credentialed Enumeration from Windows](./active-directory-enumeration-attacks/credentialed-enumeration-windows.md)** - ActiveDirectory PowerShell, PowerView, SharpView, Snaffler, and BloodHound
- **[Living Off the Land](./active-directory-enumeration-attacks/living-off-the-land.md)** - Native Windows tools, PowerShell techniques, WMI, net commands, and dsquery
- **[Kerberoasting from Linux](./active-directory-enumeration-attacks/kerberoasting-linux.md)** - Impacket GetUserSPNs.py, TGS ticket extraction, and offline cracking with Hashcat
- **[Kerberoasting from Windows](./active-directory-enumeration-attacks/kerberoasting-windows.md)** - setspn.exe, PowerShell, Mimikatz, PowerView, Rubeus, and encryption type analysis
- **[ACL Enumeration](./active-directory-enumeration-attacks/acl-enumeration.md)** - PowerView ACL analysis, attack path discovery, BloodHound visualization, and privilege escalation chains
- **[ACL Abuse Tactics](./active-directory-enumeration-attacks/acl-abuse-tactics.md)** - Practical ACL attack execution, password manipulation, group membership abuse, targeted Kerberoasting, cleanup procedures, and detection evasion
- **[DCSync Attack](./active-directory-enumeration-attacks/dcsync-attack.md)** - Ultimate domain compromise technique using Directory Replication Service, secretsdump.py and Mimikatz execution, reversible encryption exploitation, and complete domain credential extraction
- **[Privileged Access](./active-directory-enumeration-attacks/privileged-access.md)** - Lateral movement and privilege expansion using BloodHound enumeration, WinRM/PSRemote exploitation, SQL Server administrative access, and multi-service attack chaining
- **[Kerberos "Double Hop" Problem](./active-directory-enumeration-attacks/kerberos-double-hop-problem.md)** - Overcoming Kerberos authentication limitations in multi-hop scenarios, PSCredential object workarounds, PSSession configuration methods, and advanced lateral movement techniques
- **[Bleeding Edge Vulnerabilities](./active-directory-enumeration-attacks/bleeding-edge-vulnerabilities.md)** - Latest critical AD attack vectors including NoPac (SamAccountName Spoofing), PrintNightmare, and PetitPotam (MS-EFSRPC) for rapid domain compromise
- **[Miscellaneous Misconfigurations](./active-directory-enumeration-attacks/miscellaneous-misconfigurations.md)** - Diverse AD vulnerabilities including Exchange attacks, GPP passwords, ASREPRoasting, DNS enumeration, Printer Bug, and various administrative oversights
- **[Domain Trusts Primer](./active-directory-enumeration-attacks/domain-trusts-primer.md)** - Foundation of AD trust relationships, enumeration techniques (PowerView, netdom, BloodHound), and trust-based attack path identification
- **[Child → Parent Trust Attacks](./active-directory-enumeration-attacks/child-parent-trust-attacks.md)** - SID History exploitation, ExtraSids attacks with Mimikatz/Rubeus, Golden Ticket creation for forest privilege escalation
- **[Child → Parent Trust Attacks - from Linux](./active-directory-enumeration-attacks/child-parent-trust-attacks-linux.md)** - Cross-platform ExtraSids attacks using Impacket toolkit (secretsdump, lookupsid, ticketer, psexec, raiseChild)
- **[Cross-Forest Trust Abuse - from Windows](./active-directory-enumeration-attacks/cross-forest-trust-abuse-windows.md)** - Cross-forest Kerberoasting, admin password reuse, foreign group membership enumeration, and SID History abuse across forest boundaries
- **[Cross-Forest Trust Abuse - from Linux](./active-directory-enumeration-attacks/cross-forest-trust-abuse-linux.md)** - Cross-platform cross-forest attacks using Impacket GetUserSPNs, bloodhound-python multi-domain collection, and foreign group membership discovery

**🎯 Skills Assessment:**
- **[Skills Assessment Part I - Complete Walkthrough](./active-directory-enumeration-attacks/skills-assessment-part-1.md)** - Comprehensive 8-question practical assessment covering web shells, Kerberoasting, pivoting, credential dumping, DCSync attacks, and domain takeover with working commands and troubleshooting
- **[Skills Assessment Part II - Advanced Professional Methodology](./active-directory-enumeration-attacks/skills-assessment-part-2.md)** - 12-question advanced assessment demonstrating superior SSH dynamic port forwarding + proxychains methodology, LLMNR poisoning, SQL exploitation, privilege escalation, and complete domain compromise with professional-grade techniques

**🖥️ Remote Management:**
- **[Remote Management Overview](./remote-management/remote-management.md)** - Overview of remote access protocols
- **[Linux Remote Protocols](./remote-management/linux-remote-protocols.md)** - SSH, Rsync, R-Services enumeration
- **[Windows Remote Protocols](./remote-management/windows-remote-protocols.md)** - RDP, WinRM, WMI testing

**🕷️ Web Enumeration:**
- **[Web Information Gathering](./web-enumeration/web-information-gathering.md)** - Overview and quick start guide for web reconnaissance
- **[Subdomain Enumeration](./web-enumeration/subdomain-enumeration.md)** - DNS enumeration and subdomain discovery techniques
- **[Web Application Enumeration](./web-enumeration/web-application-enumeration.md)** - Directory enumeration, virtual hosts, and web application testing

**🌐 Web Application Attacks:**
- **[Cross-Site Scripting (XSS)](./xss-cross-site-scripting.md)** - Complete XSS guide covering Stored, Reflected, and DOM-based XSS with HTB Academy techniques
- **[File Inclusion](./file-inclusion/)** - Comprehensive LFI/RFI module with 9 specialized guides covering Basic Techniques, Advanced Bypasses, PHP Wrappers RCE, Remote File Inclusion, File Upload + LFI, Log Poisoning, Automated Scanning, Prevention & Hardening, and complete HTB Academy Skills Assessment
- **[File Upload Attacks](./file-upload-attacks/)** - Complete file upload exploitation guide covering web shells, reverse shells, bypass techniques, and HTB Academy lab solutions
- **[Command Injection Attacks](./command-injection/)** - **🏆 COMPLETE MODULE** (10 comprehensive sections: Detection + Exploitation + Filter Bypasses + Advanced Obfuscation + Skills Assessment) - OS Command Execution with direct and blind injection techniques, filter bypass methods, advanced evasion and automated tools, complete methodology with HTB Academy lab solutions


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


**Practical Application:**
- **[Complete Skills Assessment](./pivoting-tunneling-port-forwarding/skills-assessment-complete-walkthrough.md)** - All 7 HTB Academy questions with full solutions and troubleshooting
- **[Skills Assessment](./pivoting-tunneling-port-forwarding/skills-assessment.md)** - Hands-on lab scenarios and HTB Academy exercises

---

## **Key Features**

### **🎯 Comprehensive Coverage**
- **30+ Service Types** - Complete enumeration guides for all major services
- **Complete Attack Modules** - Full HTB Academy "Attacking Common Services" (4,262 lines)
- **Web Application Attacks** - XSS (Cross-Site Scripting), File Inclusion module (9 specialized guides: LFI/RFI, PHP Wrappers, Log Poisoning, Automated Scanning, Prevention), File Upload Attacks (8 techniques + Skills Assessment), and Command Injection (10 comprehensive sections with complete Skills Assessment)
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
