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
│   ├── smb-attacks.md                 # SMB protocol attacks and RCE
│   ├── sql-attacks.md                 # MySQL/MSSQL database exploitation
│   └── [other service exploitation]
├── attacking-common-applications/      # Application-specific exploitation
│   ├── README.md                      # Module overview and methodology
│   ├── wordpress-discovery-enumeration.md # WordPress scanning and enumeration
│   ├── wordpress-attacks.md           # WordPress exploitation techniques
│   ├── joomla-discovery-enumeration.md # Joomla scanning and enumeration
│   ├── joomla-attacks.md              # Joomla exploitation techniques
│   ├── drupal-discovery-enumeration.md # Drupal scanning and enumeration
│   ├── drupal-attacks.md              # Drupal exploitation techniques
│   ├── tomcat-discovery-enumeration.md # Tomcat enumeration and analysis
│   ├── tomcat-attacks.md              # Tomcat exploitation and privilege escalation
│   ├── jenkins-discovery-enumeration.md # Jenkins scanning and enumeration
│   ├── jenkins-attacks.md             # Jenkins exploitation and credential extraction
│   ├── splunk-discovery-enumeration.md # Splunk enumeration and analysis
│   ├── splunk-attacks.md              # Splunk exploitation and privilege escalation
│   └── [other application attacks]    # CGI, IIS, ColdFusion, LDAP, etc.
├── active-directory-enumeration-attacks/ # Active Directory penetration testing
│   ├── initial-enumeration-domain.md     # Initial domain enumeration
│   ├── llmnr-nbt-ns-poisoning-linux.md   # LLMNR/NBT-NS poisoning with Responder
│   └── [additional AD attack modules]    # More AD techniques to be added
├── linux-priv-esc/                    # Linux privilege escalation techniques
│   ├── README.md                      # Module overview and methodology
│   ├── environment-enumeration.md     # System reconnaissance and information gathering
│   ├── services-internals-enumeration.md # Deep system analysis and service enumeration
│   ├── credential-hunting.md          # Systematic credential discovery across file system
│   ├── path-abuse.md                  # PATH variable manipulation and command hijacking
│   ├── wildcard-abuse.md              # Wildcard character exploitation for privilege escalation
│   ├── escaping-restricted-shells.md  # Techniques for breaking out of restricted shells
│   ├── special-permissions.md         # SUID/SGID binary exploitation and GTFOBins
│   ├── sudo-rights-abuse.md           # Sudo privilege misconfigurations and GTFOBins exploitation
│   ├── privileged-groups.md           # LXD, Docker, Disk, ADM group privilege escalation
│   ├── capabilities.md                # Linux capabilities privilege escalation exploitation
│   ├── vulnerable-services.md         # Known service vulnerabilities and exploitation
│   ├── cron-job-abuse.md              # Cron job misconfiguration exploitation
│   ├── lxd-container-escape.md        # LXD container privilege escalation exploitation
│   ├── docker-container-escape.md     # Docker container privilege escalation exploitation
│   ├── logrotate-exploitation.md      # Logrotate vulnerability exploitation and race conditions
│   ├── miscellaneous-techniques.md    # Additional techniques (traffic capture, NFS, tmux hijacking)
│   ├── shared-libraries.md            # LD_PRELOAD shared library hijacking exploitation
│   ├── shared-object-hijacking.md     # Custom library RUNPATH hijacking exploitation
│   ├── python-library-hijacking.md    # Python module import hijacking exploitation
│   ├── sudo-cve-exploits.md           # Sudo CVE exploitation (Baron Samedit, Policy Bypass)
│   ├── polkit-pwnkit.md               # Polkit CVE-2021-4034 Pwnkit privilege escalation
│   ├── dirty-pipe.md                  # Dirty Pipe CVE-2022-0847 kernel vulnerability exploitation
│   ├── netfilter-kernel-exploits.md   # Netfilter kernel module CVE exploits (advanced)
│   ├── linux-hardening.md             # Defensive measures and system hardening practices
│   ├── permissions-based-privesc.md   # File permissions, SUID/SGID exploitation
│   ├── service-based-privesc.md      # Running services and process exploitation
│   ├── configuration-based-privesc.md # Misconfigurations and weak settings
│   ├── kernel-exploitation.md        # Operating system vulnerabilities
│   ├── application-specific-privesc.md # Vulnerable installed software
│   ├── automated-tools.md            # LinPEAS, LinEnum, and enumeration scripts
│   ├── persistence-techniques.md     # Maintaining elevated access
│   └── skills-assessment.md          # Practical exercises and challenges
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

**🌐 Attacking Common Applications:**
- **[Module Overview](./attacking-common-applications/README.md)** - Comprehensive methodologies for attacking prevalent applications in penetration testing
- **CMS Attacks** - WordPress, Joomla, Drupal discovery, enumeration, and exploitation
  - **[WordPress Discovery & Enumeration](./attacking-common-applications/wordpress-discovery-enumeration.md)** - WPScan, plugin enumeration, and version detection
  - **[WordPress Attacks & Exploitation](./attacking-common-applications/wordpress-attacks.md)** - Theme manipulation, plugin vulnerabilities, Metasploit integration
  - **[Joomla Discovery & Enumeration](./attacking-common-applications/joomla-discovery-enumeration.md)** - JoomScan, version detection, component analysis
  - **[Joomla Attacks & Exploitation](./attacking-common-applications/joomla-attacks.md)** - Template RCE, CVE-2019-10945 directory traversal, core vulnerabilities
  - **[Drupal Discovery & Enumeration](./attacking-common-applications/drupal-discovery-enumeration.md)** - DroopeScan, CHANGELOG analysis, module discovery
  - **[Drupal Attacks & Exploitation](./attacking-common-applications/drupal-attacks.md)** - PHP Filter abuse, Drupalgeddon series, backdoored modules
- **Development Tools** - Tomcat, Jenkins discovery and exploitation
  - **[Tomcat Discovery & Enumeration](./attacking-common-applications/tomcat-discovery-enumeration.md)** - Servlet container fingerprinting, manager interface discovery
  - **[Tomcat Attacks & Exploitation](./attacking-common-applications/tomcat-attacks.md)** - Manager brute force, WAR uploads, JSP shells, CVE-2020-1938
  - **[Jenkins Discovery & Enumeration](./attacking-common-applications/jenkins-discovery-enumeration.md)** - CI/CD automation server reconnaissance, plugin analysis
  - **[Jenkins Attacks & Exploitation](./attacking-common-applications/jenkins-attacks.md)** - Script Console abuse, Groovy RCE, pipeline manipulation
- **Infrastructure Monitoring** - Splunk, PRTG, GitLab attacks
  - **[Splunk Discovery & Enumeration](./attacking-common-applications/splunk-discovery-enumeration.md)** - SIEM log analytics reconnaissance, license analysis
  - **[Splunk Attacks & Exploitation](./attacking-common-applications/splunk-attacks.md)** - Custom app RCE, scripted inputs, Universal Forwarder compromise
  - **[GitLab Discovery & Enumeration](./attacking-common-applications/gitlab-discovery-enumeration.md)** - Repository mining, user enumeration, CVE exploitation
  - **[PRTG Network Monitor Attacks](./attacking-common-applications/prtg-attacks.md)** - Command injection via notification parameters
- **Specialized Applications** - CGI, IIS, ColdFusion, LDAP, Binary Analysis
  - **[CGI Shellshock Attacks](./attacking-common-applications/cgi-shellshock-attacks.md)** - CVE-2014-6271 exploitation via HTTP headers
  - **[IIS Tilde Enumeration](./attacking-common-applications/iis-tilde-enumeration.md)** - Short filename discovery using 8.3 format
  - **[ColdFusion Discovery & Enumeration](./attacking-common-applications/coldfusion-discovery-enumeration.md)** - CFML application testing, port 5500 protocols
  - **[LDAP Injection Attacks](./attacking-common-applications/ldap-injection-attacks.md)** - Authentication bypass via environment variables
  - **[Binary Reverse Engineering](./attacking-common-applications/binary-reverse-engineering.md)** - Connection string extraction from compiled applications
  - **[osTicket System Exploitation](./attacking-common-applications/osticket-attacks.md)** - Support system credential harvesting
  - **[Other Notable Applications](./attacking-common-applications/other-notable-applications.md)** - WebLogic, Axis2, WebSphere, Zabbix, Nagios

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

**🪟 Windows Privilege Escalation:**
- **[Module Overview](./windows-priv-esc/README.md)** - Comprehensive Windows privilege escalation methodology
- **[Situational Awareness](./windows-priv-esc/situational-awareness.md)** - Network enumeration, security protections, system context assessment
- **[Initial Enumeration](./windows-priv-esc/initial-enumeration.md)** - System information, processes, users, groups, and services enumeration
- **[Communication with Processes](./windows-priv-esc/communication-with-processes.md)** - Network services and named pipes analysis for privilege escalation

**🐧 Linux Privilege Escalation:**
- **[Module Overview](./linux-priv-esc/README.md)** - Comprehensive Linux privilege escalation methodology
- **[Environment Enumeration](./linux-priv-esc/environment-enumeration.md)** - System reconnaissance and information gathering techniques
  - **System Information Gathering** - OS version, kernel, hardware details and security controls
  - **User and Group Analysis** - Account enumeration, permission mapping, and group membership
  - **Network Configuration** - Interface analysis, routing tables, and internal network discovery
  - **File System Analysis** - Mounted drives, hidden files, temporary directories, and block devices
  - **Manual Enumeration Checklist** - Systematic approach to Linux system reconnaissance
- **[Services & Internals Enumeration](./linux-priv-esc/services-internals-enumeration.md)** - Deep system analysis for privilege escalation vectors
  - **Running Services Analysis** - Process enumeration, service identification, and root process targeting
  - **User Activity Investigation** - Login history, active sessions, and command history analysis
  - **Scheduled Tasks Discovery** - Cron jobs, systemd timers, and automation script analysis
  - **Configuration Discovery** - System configs, application settings, and credential harvesting
- **[Credential Hunting](./linux-priv-esc/credential-hunting.md)** - Systematic credential discovery and extraction techniques
  - **File System Credential Search** - Configuration files, scripts, backups containing stored secrets
  - **SSH Key Discovery** - Private key enumeration, known_hosts analysis, lateral movement prep
  - **Database Credential Extraction** - WordPress, MySQL, PostgreSQL, application database passwords
  - **Advanced Discovery Methods** - Memory analysis, environment variables, process inspection
- **[PATH Abuse](./linux-priv-esc/path-abuse.md)** - PATH variable manipulation for privilege escalation
  - **PATH Variable Exploitation** - Directory precedence manipulation and command execution hijacking
  - **Writable Directory Detection** - PATH enumeration and write permission identification
  - **Script Hijacking Attacks** - Sudo scripts, cron jobs, and relative command exploitation
  - **Binary Substitution Techniques** - Malicious script creation and execution interception
- **[Wildcard Abuse](./linux-priv-esc/wildcard-abuse.md)** - Shell wildcard exploitation for argument injection
  - **Filename Expansion Attacks** - Wildcard character abuse for command argument injection
  - **tar Command Exploitation** - checkpoint-action parameter injection for code execution
  - **Cron Job Wildcard Targeting** - Automated script exploitation through file creation
- **[Escaping Restricted Shells](./linux-priv-esc/escaping-restricted-shells.md)** - Breaking out of rbash, rksh, rzsh limitations
  - **SSH Bypass Techniques** - Remote connection restriction circumvention
  - **Command Substitution Escapes** - Backtick and variable expansion exploitation
  - **Built-in Command Abuse** - Vi, less, man page escape sequences for shell access
- **[Special Permissions](./linux-priv-esc/special-permissions.md)** - SUID/SGID binary exploitation for privilege escalation
  - **SUID/SGID Binary Discovery** - Finding and enumerating special permission files
  - **GTFOBins Exploitation** - Leveraging known privilege escalation binaries and techniques
  - **Common Binary Abuse** - Text editors, interpreters, file utilities with elevated permissions
- **[Sudo Rights Abuse](./linux-priv-esc/sudo-rights-abuse.md)** - Sudo misconfiguration exploitation
  - **Sudo Permission Enumeration** - sudo -l analysis and configuration file review
  - **GTFOBins Sudo Exploitation** - Text editors, system tools, interpreter abuse via sudo
- **[Privileged Groups](./linux-priv-esc/privileged-groups.md)** - Dangerous group membership exploitation
  - **Container Group Abuse** - LXD/LXC and Docker group privilege escalation techniques
  - **System Group Exploitation** - Disk, ADM, shadow group access for privilege vectors
- **[Capabilities](./linux-priv-esc/capabilities.md)** - Linux capabilities privilege escalation
  - **Capability Enumeration** - Finding binaries with dangerous capability assignments  
  - **File Permission Bypass** - cap_dac_override exploitation for system file modification
- **[Vulnerable Services](./linux-priv-esc/vulnerable-services.md)** - Service vulnerability exploitation
  - **Service Version Enumeration** - Identifying outdated software with known CVEs
  - **Screen 4.5.0 Exploitation** - CVE-2017-5618 ld.so.preload overwrite privilege escalation
- **[Cron Job Abuse](./linux-priv-esc/cron-job-abuse.md)** - Scheduled task misconfiguration exploitation
  - **Cron Job Discovery** - Finding writable scripts in scheduled tasks
  - **Process Monitoring** - pspy usage for automated task pattern detection
- **[LXD Container Escape](./linux-priv-esc/lxd-container-escape.md)** - Container manager privilege escalation
  - **LXD Group Exploitation** - Privileged container creation and host filesystem mounting
  - **Container Image Management** - Importing, configuring, and exploiting container images
- **[Docker Container Escape](./linux-priv-esc/docker-container-escape.md)** - Docker runtime privilege escalation
  - **Docker Group Exploitation** - Container runtime privilege escalation via host mounting
  - **Privileged Container Execution** - Bypassing isolation through privileged containers
- **[Logrotate Exploitation](./linux-priv-esc/logrotate-exploitation.md)** - Log management vulnerability exploitation
  - **Logrotate Vulnerability Assessment** - Version identification and vulnerable configuration detection
  - **Logrotten Race Condition Exploit** - Race condition exploitation via log rotation hijacking
- **[Miscellaneous Techniques](./linux-priv-esc/miscellaneous-techniques.md)** - Additional privilege escalation vectors
  - **Passive Traffic Capture** - Network sniffing for credential extraction using tcpdump
  - **Weak NFS Privileges** - no_root_squash exploitation for SUID binary upload and system access
- **[Shared Libraries](./linux-priv-esc/shared-libraries.md)** - LD_PRELOAD exploitation for privilege escalation
  - **LD_PRELOAD Environment Abuse** - Shared library injection through environment variable manipulation
  - **Malicious Library Deployment** - Custom shared object creation and sudo command hijacking
- **[Shared Object Hijacking](./linux-priv-esc/shared-object-hijacking.md)** - RUNPATH library hijacking exploitation
  - **RUNPATH Directory Exploitation** - Writable library path abuse in SUID binaries
  - **Custom Library Injection** - Missing function implementation for privilege escalation
- **[Python Library Hijacking](./linux-priv-esc/python-library-hijacking.md)** - Python module import system exploitation
  - **Python Module Import Hijacking** - sys.path manipulation and module precedence abuse
  - **PYTHONPATH Environment Manipulation** - Environment variable abuse for import redirection
- **[Sudo CVE Exploits](./linux-priv-esc/sudo-cve-exploits.md)** - Critical sudo vulnerability exploitation
  - **CVE-2021-3156 Baron Samedit** - Heap buffer overflow for immediate root shell access
  - **CVE-2019-14287 Policy Bypass** - Negative user ID exploitation for privilege escalation
- **[Polkit/Pwnkit](./linux-priv-esc/polkit-pwnkit.md)** - Universal privilege escalation via polkit vulnerability
  - **CVE-2021-4034 Pwnkit Exploitation** - Memory corruption in pkexec for universal root access
  - **Zero-Prerequisite Escalation** - Any local user exploitation without authentication
- **[Dirty Pipe](./linux-priv-esc/dirty-pipe.md)** - Kernel vulnerability exploitation for file modification
  - **CVE-2022-0847 Kernel Exploitation** - Pipe mechanism abuse for arbitrary root file writes
  - **File Modification Attacks** - /etc/passwd modification and SUID binary hijacking via kernel exploit
- **[Netfilter Kernel Exploits](./linux-priv-esc/netfilter-kernel-exploits.md)** - ⚠️ **Advanced kernel exploits (high risk)**
  - **Multiple Kernel CVEs** - CVE-2021-22555, CVE-2022-25636, CVE-2023-32233 targeting kernels 2.6-6.3.1
  - **High-Risk Kernel Exploitation** - Direct kernel attacks with significant system stability risks
- **[Linux Hardening](./linux-priv-esc/linux-hardening.md)** - Defensive security measures and system hardening
  - **Update Management** - Kernel and package update strategies for vulnerability mitigation
  - **Configuration Hardening** - File system, service, and user management security practices

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
- **Complete Attack Modules** - Full HTB Academy "Attacking Common Services" (4,262 lines) + "Attacking Common Applications" (22 documents)
- **Web Application Attacks** - XSS (Cross-Site Scripting), File Inclusion module (9 specialized guides), File Upload Attacks (9 comprehensive sections), Command Injection (10 comprehensive sections), and Web Attacks (HTTP Verb Tampering, IDOR, XXE)
- **Application-Specific Exploitation** - WordPress, Joomla, Drupal, Tomcat, Jenkins, Splunk, and specialized applications
- **Windows Privilege Escalation** - New module covering situational awareness, initial enumeration, user/group privileges, and systematic escalation techniques
- **Linux Privilege Escalation** - Complete module with 24 techniques covering environment enumeration, permissions-based attacks, service exploitation, container escapes, kernel exploits, and defensive hardening
- **Skills Assessment Coverage** - Multiple complete walkthroughs for different difficulty levels
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
