# 🏠 /home/kabaneridev/.pt-notes

Welcome to my penetration testing notes page - a project started with the idea to share and document my knowledge gained in the world of offensive security.

My current knowledge comes from CTFs, real world penetration testing, but also from studying for certifications such as the PJPT, CPTS.

---

## **About me**

My Profiles 
* [GitHub](https://github.com/kabaneridev)

Current CVEs 
* None yet - working on it!

Certifications 
* ✅ **PJPT** - Practical Junior Penetration Tester (Completed)
* 🔄 **CPTS** - Certified Penetration Testing Professional (In Progress)
* 📅 **OSCP** - Offensive Security Certified Professional (Planned)

---

## **Content**

### 🎯 **CPTS Preparation**
* **[🎯 CPTS-PREP](CPTS-PREP/README.md)** - Comprehensive CPTS certification preparation
  * **[🏰 Active Directory Enumeration & Attacks](CPTS-PREP/active-directory-enumeration-attacks/)** - **🔥 COMPLETE AD MODULE** 
    * **26 Advanced Techniques** - LLMNR poisoning, Kerberoasting, ACL abuse, Trust attacks, Bleeding edge vulnerabilities
    * **2 Skills Assessments** - Part I (8 questions) & Part II (12 questions) with professional methodologies
    * **Superior Pivoting** - SSH dynamic port forwarding + proxychains methodology vs Meterpreter
    * **Professional Toolkit** - CrackMapExec, Impacket, BloodHound integration
  * **[🗄️ Database Services](CPTS-PREP/databases/)** - MySQL, MSSQL, Oracle enumeration & SQL injection guides
  * **[📁 Network Services](CPTS-PREP/services/)** - FTP, SMB, NFS, SMTP, SNMP, IPMI enumeration
  * **[🖥️ Remote Management](CPTS-PREP/remote-management/)** - SSH, RDP, WinRM, WMI protocols
  * **[🌐 Web Application Attacks](CPTS-PREP/)** - Complete web attack module with XSS, File Inclusion, File Upload, and Command Injection
    * **[🔥 Cross-Site Scripting (XSS)](CPTS-PREP/xss-cross-site-scripting.md)** - Stored, Reflected, DOM-based XSS
    * **[📁 File Inclusion Module](CPTS-PREP/file-inclusion/)** - 9 specialized guides (LFI, RFI, PHP Wrappers, Log Poisoning)
    * **[📤 File Upload Attacks](CPTS-PREP/file-upload-attacks/)** - **🏆 COMPLETE MODULE** (10 sections: Upload Exploitation + Client-Side Bypass + Filter Evasion + Advanced Techniques + Skills Assessment)
      * **Web Shell Deployment** - PHP, ASP.NET, JSP reverse shells and command execution
      * **Comprehensive Bypasses** - Extension, Content-Type, MIME-Type, and advanced filter evasion  
      * **Professional Methodology** - Burp Suite integration, payload crafting, exploitation chains
    * **[⚡ Command Injection Attacks](CPTS-PREP/command-injection/)** - **🏆 COMPLETE MODULE** (10 sections: Detection + Exploitation + Filter Bypasses + Advanced Obfuscation + Skills Assessment)
      * **OS Command Execution** - Direct and blind injection techniques
      * **Filter Bypass Methods** - Advanced evasion and exploitation
      * **Complete Methodology** - Detection, exploitation, and prevention
    * **[🌐 Web Attacks](CPTS-PREP/web-attacks/)** - **🏆 COMPLETE MODULE** (4 sections: HTTP Verb Tampering + IDOR + XXE + Skills Assessment)
      * **HTTP Verb Tampering** - Authorization bypass via method manipulation
      * **IDOR Attacks** - User enumeration and privilege escalation
      * **XXE Injection** - External entity exploitation and file disclosure
      * **Attack Chaining** - Professional methodology combining multiple vulnerabilities
    * **[⚔️ Attacking Common Applications](CPTS-PREP/attacking-common-applications/)** - **🚀 NEW MODULE** (WordPress + Joomla + CMS + Development Tools + Infrastructure)
      * **WordPress Discovery & Enumeration** - WPScan, manual enumeration, and vulnerability assessment  
      * **WordPress Attacks & Exploitation** - Theme manipulation, plugin vulnerabilities, Metasploit integration
      * **Joomla Discovery & Enumeration** - DroopeScan, version detection, component analysis
      * **Joomla Attacks & Exploitation** - Template RCE, CVE-2019-10945 directory traversal, core vulnerabilities
      * **Drupal Discovery & Enumeration** - Node enumeration, CHANGELOG analysis, module discovery
      * **Drupal Attacks & Exploitation** - PHP Filter abuse, Drupalgeddon series, backdoored modules
      * **Tomcat Discovery & Enumeration** - Servlet container fingerprinting, manager interface discovery
      * **Tomcat Attacks & Exploitation** - Manager brute force, WAR uploads, JSP shells, CVE-2020-1938
      * **Jenkins Discovery & Enumeration** - CI/CD automation server reconnaissance, plugin analysis
      * **Jenkins Attacks & Exploitation** - Script Console abuse, Groovy RCE, pipeline manipulation
      * **Splunk Discovery & Enumeration** - SIEM log analytics reconnaissance, license analysis
      * **Splunk Attacks & Exploitation** - Custom app RCE, scripted inputs, Universal Forwarder compromise
      * **CMS Attack Vectors** - WordPress, Drupal, Joomla exploitation techniques
      * **Development Tools** - Tomcat, Jenkins, GitLab security testing
      * **Infrastructure Applications** - Splunk, PRTG, monitoring tool attacks
  * **[🌐 Infrastructure Enumeration](CPTS-PREP/footprinting.md)** - Domain and cloud reconnaissance
  * **[🛡️ Firewall Evasion](CPTS-PREP/firewall-evasion.md)** - IDS/IPS bypass techniques

### ✅ **PJPT Preparation** 
* **[🎯 PJPT-PREP](PJPT-prep/README.md)** - Complete PJPT certification notes (Completed ✅)
  * **[🏢 Active Directory Attacks](PJPT-prep/)** - LLMNR poisoning, Kerberoasting, Pass attacks
  * **[🔧 Post-Exploitation](PJPT-prep/)** - NTDS.dit extraction, Golden tickets, Persistence
  * **[🌐 Web Application Testing](PJPT-prep/)** - SQL injection and web attack techniques

### 🔧 **Core Knowledge Areas**
* **[🔍 Information Gathering](information-gathering.md)** - Reconnaissance techniques and tools
* **[🐧 Linux Privilege Escalation](linux-privilege-escalation/README.md)** - Methods to escalate privileges on Linux systems
* **[🪟 Windows Privilege Escalation](windows-privilege-escalation/README.md)** - Windows privilege escalation techniques
* **[🛠️ Tools Documentation](tools/README.md)** - Notes on common penetration testing tools

---

## **Key Features**

### 🎯 **Comprehensive Coverage**
- **🏰 Complete Active Directory Module** - 26 advanced AD techniques + 2 comprehensive Skills Assessments (20 questions total)
- **🌐 Complete Web Application Attacks** - XSS + File Inclusion (9 guides) + File Upload Attacks (10 comprehensive sections + Skills Assessment) + Command Injection (10 comprehensive sections + Skills Assessment) + Web Attacks (4 comprehensive sections: HTTP Verb Tampering, IDOR, XXE + Skills Assessment) + Attacking Common Applications (WordPress + Joomla + CMS + Development Tools + Infrastructure)
- **🚀 Revolutionary Pivoting Methodology** - SSH dynamic port forwarding + proxychains (superior to Meterpreter)
- **25+ Service Enumeration Guides** - Complete methodology for all major services
- **CVE References** - Known vulnerabilities with exploitation examples
- **HTB Academy Style** - Lab questions and practical scenarios
- **Real-World Techniques** - Proven penetration testing methodologies

### 📚 **Practical Focus**
- **🎯 Complete AD Attack Chains** - End-to-end domain compromise scenarios with working commands
- **📤 Real-World Upload Exploitation** - 6-phase attack methodology with source code analysis and defense-in-depth bypasses
- **🔧 Professional Methodology** - SSH tunneling + proxychains for reliable pivoting
- **🛠️ Industry-Standard Tools** - CrackMapExec, Impacket, BloodHound, Responder, Burp Suite integration
- **Step-by-step Commands** - Copy-paste ready enumeration procedures
- **Multiple Tool Coverage** - Various tools for each enumeration task
- **Security Assessment** - Vulnerability identification and exploitation
- **Defensive Measures** - Hardening and protection recommendations

---

## **Disclaimer**

> This page is intended for educational and informational purposes only.  
> The content within this project doesn't give warranties of any kind, express or implied, about the completeness, accuracy, reliability, suitability, or availability of the information, products, services, or related graphics contained within it. Any reliance you place on such information is therefore strictly at your own risk. The author and publisher shall in no event be liable for any loss or damage arising the use of this project's content. Furthermore, the techniques and tips described are provided for educational and informational purposes only, and should not be used for any illegal or malicious activities. The author does not condone or support any illegal or unethical activities, and any use of the information contained within this page is at the user's own risk and discretion. The user is solely responsible for any actions taken based on the information contained within this project. The user agrees to release the author from any and all liability and responsibility for any damage, loss, or harm that may result from the use of any technique, information or content described in this project.
