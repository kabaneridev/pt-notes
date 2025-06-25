# OSCP Tools Restrictions and Alternatives

This document provides information about tools that are restricted or allowed in the OSCP exam environment, along with alternatives for restricted tools.

## Prohibited Tools for OSCP

The following tools are generally **NOT allowed** on the OSCP exam:

### Automated Vulnerability Scanners
- **Nuclei** ❌ - Automated vulnerability scanner
- **Nessus** ❌ - Comprehensive vulnerability scanner
- **OpenVAS** ❌ - Open-source vulnerability scanner
- **Nexpose** ❌ - Commercial vulnerability scanner
- **Qualys** ❌ - Cloud-based vulnerability scanner

### Automated Exploitation Tools
- **SQLMap** ❌ - Automated SQL injection tool
- **Automated form bruteforcing** ❌ - Tools that automate web form attacks
- **Mass vulnerability scanners** ❌ - Tools that scan for multiple vulnerabilities automatically

### Commercial Tools
- **Burp Suite Pro** ❌ - Only the free Community edition is allowed
- **Cobalt Strike** ❌ - Commercial post-exploitation framework
- **Core Impact** ❌ - Commercial penetration testing software

### Specific Tools Mentioned
- **theHarvester** ⚠️ - Can be used for information gathering outside the exam environment, but not particularly useful inside the exam
- **OWASP ZAP** ⚠️ - Technically allowed but with restrictions on automated scanning features
- **Mimikatz** ⚠️ - Full version not allowed, but some techniques can be replicated with allowed PowerShell scripts
- **PowerSploit** ⚠️ - Some modules are allowed (like PowerUp), but others that automate exploitation are not

## Allowed Tools and Alternatives

### Information Gathering
- **Manual OSINT** ✅ - Instead of theHarvester, use manual OSINT techniques
- **Nmap** ✅ - For network discovery and service enumeration

### Web Application Testing
- **Burp Suite Community** ✅ - Instead of OWASP ZAP or Burp Pro
- **Manual testing** ✅ - For SQL injection instead of SQLMap
- **Custom Python scripts** ✅ - For specific, targeted tasks

### Windows Privilege Escalation
Instead of full Mimikatz or PowerSploit, use:
- **WinPEAS** ✅ - Windows Privilege Escalation Awesome Script
- **PowerUp.ps1** ✅ - PowerShell script for finding common Windows privilege escalation vectors
- **Individual PowerShell commands** ✅ - For specific tasks like dumping SAM hashes

### Credential Access
Instead of Mimikatz, use:
- **reg save** ✅ - To save SAM and SYSTEM hives
- **Impacket's secretsdump.py** ✅ - To extract hashes from registry hives
- **PowerShell commands** ✅ - For specific credential extraction tasks

## Best Practices for OSCP

1. **Focus on manual techniques** - OSCP values understanding over automation
2. **Document everything** - Show your methodology, not just tool output
3. **Use targeted commands** - Instead of broad automated scans
4. **Develop your own scripts** - For repetitive tasks or specific exploits
5. **When in doubt, ask** - Contact the OSCP support if you're unsure about a specific tool

## Useful Commands to Replace Restricted Tools

### Instead of SQLMap
```bash
# Manual SQL injection testing
' OR 1=1 --
' UNION SELECT 1,2,3,4,5 --
```

### Instead of Mimikatz
```powershell
# Save registry hives
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive

# On Kali
python3 -m impacket.secretsdump -sam sam.hive -system system.hive LOCAL
```

### Instead of automated scanners
```bash
# Manual service enumeration
nmap -sV -p- -T4 <target>

# Manual web directory discovery
gobuster dir -u http://<target>/ -w /usr/share/wordlists/dirb/common.txt
```

Remember that OSCP is about demonstrating your understanding of the penetration testing process, not just running tools. The exam is designed to test your ability to perform manual exploitation and think critically about security vulnerabilities. 