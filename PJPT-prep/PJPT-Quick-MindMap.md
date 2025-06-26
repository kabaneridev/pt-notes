---
type: mindmap-plugin
tags:
  - mindmap
  - pjpt
  - quick-reference
---

<%%

%%>

```json
{
  "name": "PJPT QUICK WIN",
  "children": [
    {
      "name": "🚀 START HERE",
      "children": [
        {
          "name": "responder -I eth0 -wrf",
          "children": [
            {"name": "Passive credential capture"},
            {"name": "Run in background"}
          ]
        },
        {
          "name": "crackmapexec smb RANGE",
          "children": [
            {"name": "Find SMB signing disabled"},
            {"name": "--gen-relay-list targets.txt"}
          ]
        }
      ]
    },
    {
      "name": "🎯 MUST DO",
      "children": [
        {
          "name": "Kerberoasting",
          "children": [
            {"name": "GetUserSPNs.py -request"},
            {"name": "90% success rate"},
            {"name": "Service account passwords"}
          ]
        },
        {
          "name": "BloodHound",
          "children": [
            {"name": "SharpHound.exe -c all"},
            {"name": "Find shortest path to DA"},
            {"name": "Visual attack paths"}
          ]
        },
        {
          "name": "GPP Passwords",
          "children": [
            {"name": "Get-GPPPassword"},
            {"name": "Free passwords in SYSVOL"},
            {"name": "Legacy but common"}
          ]
        }
      ]
    },
    {
      "name": "💰 QUICK WINS",
      "children": [
        {
          "name": "Token Impersonation",
          "children": [
            {"name": "After local admin"},
            {"name": "incognito → list_tokens"},
            {"name": "Instant domain admin"}
          ]
        },
        {
          "name": "Default Credentials",
          "children": [
            {"name": "Printers: admin:admin"},
            {"name": "Jenkins: admin:admin"},
            {"name": "Tomcat: tomcat:tomcat"}
          ]
        },
        {
          "name": "Password Spraying",
          "children": [
            {"name": "Password123!"},
            {"name": "Welcome2024!"},
            {"name": "CompanyName2024!"}
          ]
        }
      ]
    },
    {
      "name": "🔥 LATERAL MOVEMENT",
      "children": [
        {
          "name": "Pass-the-Hash",
          "children": [
            {"name": "psexec.py -hashes :HASH"},
            {"name": "No password needed"},
            {"name": "Admin → Admin"}
          ]
        },
        {
          "name": "RDP",
          "children": [
            {"name": "xfreerdp /v:IP /u:USER"},
            {"name": "GUI access"},
            {"name": "Run mimikatz locally"}
          ]
        }
      ]
    },
    {
      "name": "👑 DOMAIN ADMIN",
      "children": [
        {
          "name": "DCSync",
          "children": [
            {"name": "secretsdump.py -just-dc"},
            {"name": "All domain hashes"},
            {"name": "Game over"}
          ]
        },
        {
          "name": "Golden Ticket",
          "children": [
            {"name": "krbtgt hash required"},
            {"name": "10 year persistence"},
            {"name": "Ultimate backdoor"}
          ]
        }
      ]
    },
    {
      "name": "📸 SCREENSHOTS",
      "children": [
        {"name": "Initial shell"},
        {"name": "Kerberoast success"},
        {"name": "Local admin proof"},
        {"name": "Domain admin proof"},
        {"name": "Sensitive data access"}
      ]
    }
  ]
}
```
