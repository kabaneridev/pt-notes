# 🌐 Attacking Enterprise Networks

## 🎯 Overview

**Attacking Enterprise Networks** demonstrates a **complete external-to-internal penetration testing methodology** covering the full attack chain from **external reconnaissance** to **Domain Administrator access** and **protected network compromise**. This module provides comprehensive coverage of **real-world enterprise assessment techniques** with practical HTB Academy lab solutions.

## 🏆 Complete Attack Chain

### 📊 Phase-by-Phase Progression
```cmd
# Phase 1: External Reconnaissance
DNS zone transfers → 11 subdomains → Web application discovery

# Phase 2: Web Application Testing  
EyeWitness automation → 11 vulnerabilities → Command injection RCE

# Phase 3: Initial Access & Persistence
Reverse shell → TTY upgrade → Root access → SSH key extraction

# Phase 4: Internal Reconnaissance
SSH pivoting → Host discovery → NFS exploitation → Credential harvesting

# Phase 5: Lateral Movement
BloodHound enumeration → Share hunting → Multiple host compromise

# Phase 6: Active Directory Compromise  
GenericWrite abuse → Targeted Kerberoasting → DCSync → Domain Admin

# Phase 7: Protected Network Access
Double pivoting → SSH keys → Management network → DirtyPipe root
```

## 📋 Module Contents

### 🔍 **[External Information Gathering](external-information-gathering.md)**
- Systematic reconnaissance methodology
- Nmap enumeration techniques
- DNS zone transfer attacks
- Virtual host discovery
- Attack surface mapping

### ⚔️ **[Service Enumeration & Exploitation](service-enumeration-exploitation.md)**
- FTP anonymous access testing
- SSH authentication assessment
- SMTP user enumeration
- Email services configuration analysis
- Vulnerability research methodology

### 🌐 **[Web Enumeration & Exploitation](web-enumeration-exploitation.md)**
- EyeWitness automation for application discovery
- HTTP verb tampering exploitation
- Unrestricted file upload bypasses
- WordPress administrative compromise
- SQL injection with SQLMap
- Cross-Site Scripting (XSS) attacks
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) injection
- Command injection filter bypasses
- **11 comprehensive lab solutions**

### 🚀 **[Initial Access](initial-access.md)**
- Socat reverse shell establishment
- Character filter bypass techniques
- TTY upgrade methodologies
- Audit log credential mining
- Privilege escalation discovery

### 🔒 **[Post-Exploitation Persistence](post-exploitation-persistence.md)**
- SSH key extraction via GTFOBins
- OpenSSL privilege escalation
- Stable access establishment
- Multiple persistence mechanisms
- Operational security practices

### 🔍 **[Internal Information Gathering](internal-information-gathering.md)**
- SSH dynamic port forwarding setup
- Metasploit autoroute configuration
- Internal host discovery techniques
- NFS share exploitation
- Configuration file credential mining

### ⚔️ **[Exploitation & Privilege Escalation](exploitation-privilege-escalation.md)**
- DotNetNuke administrative exploitation
- SQL Server xp_cmdshell enablement
- PrintSpoofer SeImpersonate attacks
- SAM database extraction techniques
- Registry credential harvesting

### 🔄 **[Lateral Movement](lateral-movement.md)**
- BloodHound Active Directory enumeration
- ForceChangePassword privilege abuse
- File share credential hunting
- Kerberoasting attacks
- Password spraying campaigns
- Sysax Automation privilege escalation

### 👑 **[Active Directory Compromise](active-directory-compromise.md)**
- GenericWrite ACL abuse techniques
- Targeted Kerberoasting attacks
- Server Admins group escalation
- DCSync privilege exploitation
- Complete domain administrator access

### 🏆 **[Post-Exploitation](post-exploitation.md)**
- Domain password analysis with DPAT
- PingCastle Active Directory auditing
- Double pivoting for protected networks
- DirtyPipe kernel exploitation
- Comprehensive impact demonstration

## 🎯 Key Learning Objectives

### 🔧 Technical Skills Mastered
```cmd
# External testing:
- Advanced web application security testing
- Complex filter bypass techniques
- Multi-stage exploitation chains
- Professional evidence collection

# Internal testing:
- Complex pivoting and tunneling
- Active Directory attack methodologies
- Privilege escalation techniques
- Post-exploitation value maximization

# Professional methodology:
- Systematic assessment approaches
- Evidence-based reporting
- Client value demonstration
- Operational security practices
```

### 🏆 Real-World Application
```cmd
# Enterprise assessment capabilities:
- Complete external-to-internal attack chains
- Multi-network environment testing
- Complex Active Directory exploitation
- Protected network access demonstration

# Professional deliverables:
- Comprehensive vulnerability assessments
- Detailed attack path documentation
- Business impact demonstration
- Executive summary preparation
```

## 📊 Assessment Statistics

### 🎯 Comprehensive Coverage
```cmd
# Vulnerabilities discovered: 15+ high/medium risk findings
# Hosts compromised: 4 systems (dmz01, DEV01, MS01, MGMT01)
# Network segments: 3 networks (external, internal, management)
# Credentials harvested: 10+ account compromises
# Privilege levels: User → Local Admin → Domain Admin → Root
# Lab solutions: 20+ hands-on exercises with detailed walkthroughs
```

### 🔍 Attack Techniques Demonstrated
```cmd
# Web application attacks:
- HTTP verb tampering, file upload bypasses, SQL injection
- XSS session hijacking, SSRF file read, XXE injection
- Command injection with advanced filter bypasses

# Network attacks:
- DNS zone transfers, service enumeration, pivoting
- SSH tunneling, Metasploit routing, ProxyChains integration

# Active Directory attacks:
- BloodHound enumeration, ACL abuse, Kerberoasting
- Password spraying, DCSync attacks, privilege escalation

# Post-exploitation:
- Credential harvesting, persistence establishment
- Network segmentation bypass, kernel exploitation
```

## 🛡️ Defensive Value

### 🔒 Security Recommendations
```cmd
# Application security:
- Input validation and sanitization
- Proper authentication mechanisms
- Secure file upload implementations
- Regular security assessments

# Network security:
- Proper network segmentation
- Monitoring and detection systems
- Access control implementations
- Privilege management solutions

# Active Directory security:
- Least privilege principles
- Regular permission audits
- Strong password policies
- Advanced threat detection
```

### 📋 Professional Assessment Standards
```cmd
# Assessment methodology:
- Systematic external-to-internal progression
- Comprehensive evidence collection
- Professional documentation standards
- Client communication best practices

# Value-add activities:
- Domain password analysis
- Active Directory security auditing
- Protected network assessment
- Business impact demonstration
```

## 🎓 Prerequisites

### 📚 Required Knowledge
```cmd
# Technical foundations:
- Web application security testing
- Linux/Windows privilege escalation
- Active Directory enumeration and attacks
- Network pivoting and tunneling

# Tools proficiency:
- Nmap, Burp Suite, SQLMap, Gobuster
- BloodHound, PowerView, CrackMapExec
- Metasploit, SSH, ProxyChains
- Mimikatz, Secretsdump, Hashcat
```

### 🔗 Related Modules
```cmd
# Prerequisite modules:
- Web application security testing
- Windows/Linux privilege escalation
- Active Directory enumeration & attacks
- Pivoting, tunneling, and port forwarding

# Complementary modules:
- Documentation and reporting
- Password attacks and cracking
- Network enumeration techniques
```

## 🚀 Getting Started

### 🎯 Module Progression
```cmd
# Recommended study order:
1. External Information Gathering
2. Service Enumeration & Exploitation  
3. Web Enumeration & Exploitation
4. Initial Access
5. Post-Exploitation Persistence
6. Internal Information Gathering
7. Exploitation & Privilege Escalation
8. Lateral Movement
9. Active Directory Compromise
10. Post-Exploitation

# Lab environment:
- HTB Academy Attacking Enterprise Networks module
- Multiple interconnected systems
- Complete enterprise network simulation
- Real-world vulnerability scenarios
```

### 📋 Success Metrics
```cmd
# Completion indicators:
✅ External reconnaissance mastery
✅ Web application exploitation proficiency
✅ Internal pivoting capabilities
✅ Active Directory compromise techniques
✅ Post-exploitation value demonstration
✅ Professional documentation standards
✅ Client communication effectiveness
```

This module represents the **pinnacle of penetration testing education**, combining all previous learning into a **comprehensive enterprise assessment methodology** that mirrors **real-world professional engagements**. 