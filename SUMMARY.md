# Table of contents

* [🏠 /home/kabaneridev/.pt-notes](README.md)

## 🏆 Certification Preparation

* [🎯 CPTS - In Progress](CPTS-PREP/README.md)
  * [🌐 Infrastructure Enumeration](CPTS-PREP/footprinting.md)
  * [🛡️ Firewall Evasion](CPTS-PREP/firewall-evasion.md)
  * [🔍 Vulnerability Assessment](CPTS-PREP/vulnerability-assessment.md)
  * 📂 File Transfer Methods
    * [📂 Windows File Transfer Methods](CPTS-PREP/file-transfers/windows-file-transfers.md)
    * [🐧 Linux File Transfer Methods](CPTS-PREP/file-transfers/linux-file-transfers.md)
    * [⚡ Code File Transfer Methods](CPTS-PREP/file-transfers/code-file-transfers.md)
    * [🔀 Miscellaneous File Transfer Methods](CPTS-PREP/file-transfers/miscellaneous-file-transfers.md)
    * [🔒 Protected File Transfer Methods](CPTS-PREP/file-transfers/protected-file-transfers.md)
    * [🎭 Living off The Land File Transfers](CPTS-PREP/file-transfers/living-off-the-land-file-transfers.md)
    * [👁️ File Transfer Detection](CPTS-PREP/file-transfers/file-transfer-detection.md)
  * 🐚 Shells & Payloads
    * [🔧 Shell Basics](CPTS-PREP/shells-payloads/shell-basics.md)
    * [💥 Payloads](CPTS-PREP/shells-payloads/payloads.md)
    * [🪟 Windows Shells](CPTS-PREP/shells-payloads/windows-shells.md)
    * [🐧 NIX Shells](CPTS-PREP/shells-payloads/nix-shells.md)
    * [🌐 Web Shells](CPTS-PREP/shells-payloads/web-shells.md)
  * 🗄️ Database Services
    * [MySQL Enumeration](CPTS-PREP/databases/mysql-enumeration.md)
    * [MSSQL Enumeration](CPTS-PREP/databases/mssql-enumeration.md)
    * [Oracle TNS Enumeration](CPTS-PREP/databases/oracle-enumeration.md)
  * 📁 Network Services
    * [FTP Enumeration](CPTS-PREP/services/ftp-enumeration.md)
    * [SMB Enumeration](CPTS-PREP/services/smb-enumeration.md)
    * [NFS Enumeration](CPTS-PREP/services/nfs-enumeration.md)
    * [SMTP Enumeration](CPTS-PREP/services/smtp-enumeration.md)
    * [Email Services (IMAP/POP3)](CPTS-PREP/services/email-enumeration.md)
    * [SNMP Enumeration](CPTS-PREP/services/snmp-enumeration.md)
    * [IPMI Enumeration](CPTS-PREP/services/ipmi-enumeration.md)
  * 🖥️ Remote Management
    * [Remote Management Overview](CPTS-PREP/remote-management/remote-management.md)
    * [Linux Remote Protocols](CPTS-PREP/remote-management/linux-remote-protocols.md)
    * [Windows Remote Protocols](CPTS-PREP/remote-management/windows-remote-protocols.md)
  * 🕷️ Web Enumeration
    * [Web Information Gathering](CPTS-PREP/web-enumeration/web-information-gathering.md)
    * [Subdomain Enumeration](CPTS-PREP/web-enumeration/subdomain-enumeration.md)
    * [Web Application Enumeration](CPTS-PREP/web-enumeration/web-application-enumeration.md)

* [✅ PJPT - Completed](PJPT-prep/README.md)
  * [🎯 Quick Reference](PJPT-prep/PJPT-QUICK-REFERENCE.md)
  * [✅ Master Checklist](PJPT-prep/PJPT-MASTER-CHECKLIST.md)
  * 📊 Mind Maps & Attack Flows
    * [Attack Flow Diagram](PJPT-prep/PJPT-GitBook-MindMap.md)
    * [Techniques Mind Map](PJPT-prep/PJPT-GitBook-Techniques-Map.md)
  * 🎯 Active Directory Techniques
    * [LLMNR Poisoning](PJPT-prep/llmnr-poisoning.md)
    * [Kerberoasting](PJPT-prep/kerberoasting.md)
    * [GPP/cPassword Attacks](PJPT-prep/gpp-cpassword-attacks.md)
    * [Pass Attacks (PTH/PTT)](PJPT-prep/pass-attacks.md)
    * [Domain Enumeration](PJPT-prep/domain-enumeration.md)
    * [Golden Ticket Attacks](PJPT-prep/golden-ticket-attacks.md)
    * [IPv6 Attacks](PJPT-prep/ipv6-attacks.md)
    * [SMB Relay Attacks](PJPT-prep/smb-relay-attacks.md)
    * [Token Impersonation](PJPT-prep/token-impersonation.md)
    * [NTDS.dit Extraction](PJPT-prep/ntds-dit-extraction.md)
    * [Windows Persistence](PJPT-prep/windows-persistence-techniques.md)
    * [Post-Compromise Strategy](PJPT-prep/post-compromise-attack-strategy.md)
  * 🌐 Web & Wireless
    * [SQL Injection Techniques](PJPT-prep/sql-injection-techniques.md)
    * [WPA2 PSK Cracking](PJPT-prep/wpa2-psk-cracking.md)

---

## 🔧 Core Knowledge Areas

* [🔍 Information Gathering](information-gathering.md)
  * [📋 OSCP Tools Restrictions](oscp-tools-restrictions.md)

* [🐧 Linux Privilege Escalation](linux-privilege-escalation/README.md)
  * [Enumeration](linux-privilege-escalation/enumeration.md)
  * [Programs, Jobs and Services](linux-privilege-escalation/programs-jobs-and-services.md)
  * [Environment Variables Abuse](linux-privilege-escalation/environment-variables-abuse.md)
  * [Capabilities Abuse](linux-privilege-escalation/capabilities-abuse.md)
  * [Persistence](linux-privilege-escalation/persistence.md)
  * [Security Bypass](linux-privilege-escalation/security-bypass.md)
  * [Privilege Escalation Checklist](linux-privilege-escalation/checklist.md)

* [🪟 Windows Privilege Escalation](windows-privilege-escalation/README.md)
  * [Enumeration](windows-privilege-escalation/enumeration.md)
  * [Credential Hunting](windows-privilege-escalation/credential-hunting.md)
  * [Service Exploitation](windows-privilege-escalation/service-exploitation.md)
  * [Registry Exploits](windows-privilege-escalation/registry-exploits.md)
  * [Scheduled Tasks](windows-privilege-escalation/scheduled-tasks.md)
  * [Token Impersonation](windows-privilege-escalation/token-impersonation.md)
  * [Kernel Exploits](windows-privilege-escalation/kernel-exploits.md)
  * [Privilege Escalation Checklist](windows-privilege-escalation/checklist.md)

* [🛠️ Tools & Utilities](tools/README.md)
  * [Nmap](tools/nmap.md)
  * [Gobuster](tools/gobuster.md)
  * [John the Ripper](tools/john.md)
  * [Hydra](tools/hydra.md)
  * [Linux Commands Cheatsheet](utilities-scripts-and-payloads/linux-commands.md)
  * [Windows Commands Cheatsheet](utilities-scripts-and-payloads/windows-commands.md)
  * [File Transfer Techniques](utilities-scripts-and-payloads/file-transfers.md) 