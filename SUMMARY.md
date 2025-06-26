# Table of contents

* [🏠 /home/kabaneridev/.pt-notes](README.md)
* [🔍 Information Gathering](information-gathering.md)
* [📋 OSCP Tools Restrictions](oscp-tools-restrictions.md)

## Linux

* [Linux Privilege Escalation](linux-privilege-escalation/README.md)
  * [Enumeration](linux-privilege-escalation/enumeration.md)
  * [Programs, Jobs and Services](linux-privilege-escalation/programs-jobs-and-services.md)
  * [Environment Variables Abuse](linux-privilege-escalation/environment-variables-abuse.md)
  * [Capabilities Abuse](linux-privilege-escalation/capabilities-abuse.md)
  * [Persistence](linux-privilege-escalation/persistence.md)
  * [Security Bypass](linux-privilege-escalation/security-bypass.md)
  * [Privilege Escalation Checklist](linux-privilege-escalation/checklist.md)

## Windows

* [Windows Privilege Escalation](windows-privilege-escalation/README.md)
  * [Enumeration](windows-privilege-escalation/enumeration.md)
  * [Enumeration Tools](windows-privilege-escalation/enumeration-tools.md)
  * [Credential Hunting](windows-privilege-escalation/credential-hunting.md)
  * [Service Exploitation](windows-privilege-escalation/service-exploitation.md)
  * [Scheduled Tasks](windows-privilege-escalation/scheduled-tasks.md)
  * [Registry Exploits](windows-privilege-escalation/registry-exploits.md)
  * [Token Impersonation](windows-privilege-escalation/token-impersonation.md)
  * [Software Exploits](windows-privilege-escalation/software-exploits.md)
  * [Kernel Exploits](windows-privilege-escalation/kernel-exploits.md)
  * [RunAs Command](windows-privilege-escalation/runas.md)
  * [Spawning Administrator Shells](windows-privilege-escalation/spawning-shells.md)
  * [Privilege Escalation Checklist](windows-privilege-escalation/checklist.md)

## Tools & Utilities

* [Tools Documentation](tools/README.md)
  * [Nmap](tools/nmap.md)
  * [Gobuster](tools/gobuster.md)
  * [John the Ripper](tools/john.md)
  * [Hydra](tools/hydra.md)
  * [Winexe](tools/winexe.md)
  * [PTH-Winexe](tools/pth-winexe.md)
  * [WinPEAS](tools/winpeas.md)
* [Linux Commands Cheatsheet](utilities-scripts-and-payloads/linux-commands.md)
* [Windows Commands Cheatsheet](utilities-scripts-and-payloads/windows-commands.md)
* [File Transfer Techniques](utilities-scripts-and-payloads/file-transfers.md)

## 🎯 PJPT Preparation

* [PJPT Master Checklist](PJPT-prep/README.md)
* [📊 Mind Maps & Attack Flows](PJPT-prep/README.md)
  * [Attack Flow Diagram](PJPT-prep/PJPT-GitBook-MindMap.md)
  * [Techniques Mind Map](PJPT-prep/PJPT-GitBook-Techniques-Map.md)
* [✅ Checklists & References](PJPT-prep/README.md)
  * [Master Checklist](PJPT-prep/PJPT-MASTER-CHECKLIST.md)
  * [Quick Commands](PJPT-prep/PJPT-QUICK-REFERENCE.md)

### Active Directory Attacks

#### Initial Access
* [LLMNR Poisoning](PJPT-prep/llmnr-poisoning.md)
* [IPv6 Attacks](PJPT-prep/ipv6-attacks.md)
* [SMB Relay Attacks](PJPT-prep/smb-relay-attacks.md)
* [Passback Attacks](PJPT-prep/passback-attacks.md)
* [Initial Internal Strategy](PJPT-prep/initial-internal-attack-strategy.md)

#### Credential Attacks
* [Kerberoasting](PJPT-prep/kerberoasting.md)
* [GPP/cPassword Attacks](PJPT-prep/gpp-cpassword-attacks.md)
* [Pass Attacks (PTH/PTT)](PJPT-prep/pass-attacks.md)
* [Token Impersonation](PJPT-prep/token-impersonation.md)
* [Mimikatz Overview](PJPT-prep/mimikatz-overview.md)

#### Enumeration & Exploitation
* [Domain Enumeration](PJPT-prep/domain-enumeration.md)
* [Recent AD Vulnerabilities](PJPT-prep/recent-ad-vulnerabilities.md)
* [LNK File Attacks](PJPT-prep/lnk-file-attacks.md)

#### Post-Exploitation
* [NTDS.dit Extraction](PJPT-prep/ntds-dit-extraction.md)
* [Golden Ticket Attacks](PJPT-prep/golden-ticket-attacks.md)
* [Windows Persistence](PJPT-prep/windows-persistence-techniques.md)
* [Pivoting Techniques](PJPT-prep/pivoting-techniques.md)

#### Attack Strategies
* [Post-Compromise Strategy](PJPT-prep/post-compromise-attack-strategy.md)
* [Post-Domain Strategy](PJPT-prep/post-domain-compromise-strategy.md)

### Web Application
* [SQL Injection Techniques](PJPT-prep/sql-injection-techniques.md)

### Wireless
* [WPA2 PSK Cracking](PJPT-prep/wpa2-psk-cracking.md) 