---
type: mindmap-plugin
tags:
  - mindmap
  - pjpt
  - exam
---

<%%

%%>

```json
{
  "name": "PJPT EXAM",
  "children": [
    {
      "name": "STEP 1: Initial Access",
      "children": [
        {
          "name": "Passive Attacks",
          "children": [
            {"name": "[[llmnr-poisoning|LLMNR Poisoning]]"},
            {"name": "[[ipv6-attacks|IPv6 Attacks]]"},
            {"name": "[[smb-relay-attacks|SMB Relay]]"},
            {"name": "[[passback-attacks|Passback Attacks]]"}
          ]
        },
        {
          "name": "Active Attacks",
          "children": [
            {"name": "[[initial-internal-attack-strategy|Initial Strategy]]"},
            {"name": "[[sql-injection-techniques|SQL Injection]]"},
            {"name": "[[wpa2-psk-cracking|Wireless Attacks]]"}
          ]
        }
      ]
    },
    {
      "name": "STEP 2: Post-Compromise",
      "children": [
        {
          "name": "Quick Wins",
          "children": [
            {"name": "[[kerberoasting|Kerberoasting]]"},
            {"name": "[[gpp-cpassword-attacks|GPP Passwords]]"},
            {"name": "[[token-impersonation|Token Impersonation]]"},
            {"name": "[[lnk-file-attacks|LNK File Attacks]]"}
          ]
        },
        {
          "name": "Enumeration",
          "children": [
            {"name": "[[domain-enumeration|Domain Enumeration]]"},
            {"name": "[[post-compromise-attack-strategy|Post-Compromise Strategy]]"}
          ]
        },
        {
          "name": "Credential Dumping",
          "children": [
            {"name": "[[mimikatz-overview|Mimikatz]]"},
            {"name": "[[ntds-dit-extraction|NTDS.dit]]"}
          ]
        }
      ]
    },
    {
      "name": "STEP 3: Lateral Movement",
      "children": [
        {
          "name": "[[pass-attacks|Pass Attacks]]",
          "children": [
            {"name": "Pass-the-Hash"},
            {"name": "Pass-the-Ticket"},
            {"name": "Pass-the-Certificate"}
          ]
        },
        {
          "name": "[[pivoting-techniques|Pivoting]]",
          "children": [
            {"name": "SSH Tunneling"},
            {"name": "Chisel"},
            {"name": "ProxyChains"}
          ]
        }
      ]
    },
    {
      "name": "STEP 4: Privilege Escalation",
      "children": [
        {
          "name": "Domain Escalation",
          "children": [
            {"name": "[[recent-ad-vulnerabilities|Recent AD Vulns]]"},
            {"name": "Delegation Abuse"},
            {"name": "ACL Exploitation"}
          ]
        },
        {
          "name": "Local Escalation",
          "children": [
            {"name": "[[windows-persistence-techniques|Windows Techniques]]"},
            {"name": "Service Exploits"},
            {"name": "Registry Keys"}
          ]
        }
      ]
    },
    {
      "name": "STEP 5: Domain Admin",
      "children": [
        {
          "name": "[[post-domain-compromise-strategy|Post-Domain Strategy]]",
          "children": [
            {"name": "DCSync Attack"},
            {"name": "Shadow Copies"},
            {"name": "Backup Systems"}
          ]
        },
        {
          "name": "[[golden-ticket-attacks|Golden Tickets]]",
          "children": [
            {"name": "Extract krbtgt"},
            {"name": "Forge Tickets"},
            {"name": "Silver Tickets"}
          ]
        }
      ]
    },
    {
      "name": "STEP 6: Persistence",
      "children": [
        {"name": "[[windows-persistence-techniques|Windows Persistence]]"},
        {"name": "Backdoor Accounts"},
        {"name": "Scheduled Tasks"},
        {"name": "Registry Autorun"}
      ]
    },
    {
      "name": "TOOLS & REFERENCES",
      "children": [
        {"name": "[[README|Master Checklist]]"},
        {"name": "[[PJPT-QUICK-REFERENCE|Quick Commands]]"},
        {"name": "[[PJPT-MASTER-CHECKLIST|Status Check]]"}
      ]
    }
  ]
}
```
