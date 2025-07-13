# Windows Privilege Escalation

This section covers techniques, tools, and methods to escalate privileges on Windows systems during penetration testing. Windows privilege escalation is a critical component of the OSCP exam and real-world pentests.

## Key Areas Covered

- [Enumeration](./enumeration.md) - Collecting system information for privilege escalation vectors
- [Credential Hunting](./credential-hunting.md) - Finding stored passwords and credentials 
- [Service Exploitation](./service-exploitation.md) - Exploiting vulnerable services and misconfigurations
- [Token Impersonation](./token-impersonation.md) - Leveraging Windows token privileges
- [Registry Exploits](./registry-exploits.md) - Exploiting registry-based vulnerabilities
- [Scheduled Tasks](./scheduled-tasks.md) - Exploiting scheduled tasks and jobs
- [Kernel Exploits](./kernel-exploits.md) - Using Windows kernel vulnerabilities
- [UAC Bypass](./uac-bypass.md) - Bypassing User Account Control
- [Windows Persistence](./persistence.md) - Maintaining access to compromised systems
- [Windows Privilege Escalation Checklist](./checklist.md) - Comprehensive checklist of attack vectors

## Automated Tools

- **PowerUp**: PowerShell script for Windows privilege escalation checks
- **WinPEAS**: Windows Privilege Escalation Awesome Script
- **Bloodhound**: Active Directory reconnaissance tool
- **PowerView**: PowerShell tool for network/AD reconnaissance
- **SharpUp**: C# port of PowerUp

## External Resources

- [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [Absolomb's Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [Fuzzy Security Windows Privilege Escalation](https://fuzzysecurity.com/tutorials/16.html)

## Disclaimer

These techniques are documented for educational purposes and should only be used in legitimate, authorized penetration testing activities. Always ensure you have proper authorization before performing privilege escalation attempts. 