# PJPT Attack Flow - GitBook Version

```mermaid
graph TD
    START[PJPT EXAM START] --> PASSIVE[1. Passive Attacks]
    START --> ACTIVE[2. Active Attacks]
    
    PASSIVE --> LLMNR[LLMNR Poisoning<br/>responder -I eth0]
    PASSIVE --> IPV6[IPv6 Attacks<br/>mitm6 -d domain]
    PASSIVE --> SMB[SMB Relay<br/>ntlmrelayx.py]
    
    LLMNR --> CREDS{Got Credentials?}
    IPV6 --> CREDS
    SMB --> CREDS
    
    ACTIVE --> SPRAY[Password Spraying<br/>crackmapexec smb]
    ACTIVE --> WEB[Web Apps<br/>admin:admin]
    ACTIVE --> VULNS[Check Vulns<br/>ZeroLogon]
    
    SPRAY --> CREDS
    WEB --> CREDS
    VULNS --> CREDS
    
    CREDS -->|YES| QUICKWINS[3. Quick Wins]
    CREDS -->|NO| ACTIVE
    
    QUICKWINS --> KERB[Kerberoasting<br/>GetUserSPNs.py]
    QUICKWINS --> GPP[GPP Passwords<br/>Get-GPPPassword]
    QUICKWINS --> BLOOD[BloodHound<br/>SharpHound.exe]
    
    KERB --> ADMIN{Got Admin?}
    GPP --> ADMIN
    BLOOD --> ADMIN
    
    ADMIN -->|YES| DUMP[4. Dump Creds]
    ADMIN -->|NO| PRIVESC[Privilege Escalation]
    
    DUMP --> MIMIKATZ[Mimikatz<br/>sekurlsa::logonpasswords]
    DUMP --> TOKEN[Token Impersonation<br/>incognito]
    
    MIMIKATZ --> LATERAL[5. Lateral Movement]
    TOKEN --> LATERAL
    PRIVESC --> LATERAL
    
    LATERAL --> PTH[Pass-the-Hash<br/>psexec.py -hashes]
    LATERAL --> PTT[Pass-the-Ticket<br/>getTGT.py]
    LATERAL --> RDP[RDP/WinRM<br/>evil-winrm]
    
    PTH --> DA{Domain Admin?}
    PTT --> DA
    RDP --> DA
    
    DA -->|YES| VICTORY[6. Domain Domination]
    DA -->|NO| LATERAL
    
    VICTORY --> NTDS[Dump NTDS.dit<br/>secretsdump.py]
    VICTORY --> GOLDEN[Golden Ticket<br/>krbtgt hash]
    VICTORY --> PERSIST[Persistence<br/>Backdoors]
    
    style START fill:#90EE90
    style QUICKWINS fill:#FFD700
    style VICTORY fill:#FF6347
    style CREDS fill:#87CEEB
    style ADMIN fill:#DDA0DD
    style DA fill:#FFA500
```

## Attack Steps Reference

### 1. Initial Access
- [LLMNR Poisoning](llmnr-poisoning.md)
- [IPv6 Attacks](ipv6-attacks.md)
- [SMB Relay Attacks](smb-relay-attacks.md)
- [Passback Attacks](passback-attacks.md)

### 2. Post-Compromise
- [Kerberoasting](kerberoasting.md)
- [GPP Passwords](gpp-cpassword-attacks.md)
- [Token Impersonation](token-impersonation.md)
- [Domain Enumeration](domain-enumeration.md)

### 3. Credential Dumping
- [Mimikatz Overview](mimikatz-overview.md)
- [NTDS.dit Extraction](ntds-dit-extraction.md)

### 4. Lateral Movement
- [Pass Attacks](pass-attacks.md)
- [Pivoting Techniques](pivoting-techniques.md)

### 5. Privilege Escalation
- [Windows Persistence](windows-persistence-techniques.md)
- [Recent AD Vulnerabilities](recent-ad-vulnerabilities.md)

### 6. Post-Domain Compromise
- [Golden Ticket Attacks](golden-ticket-attacks.md)
- [Post-Domain Strategy](post-domain-compromise-strategy.md) 