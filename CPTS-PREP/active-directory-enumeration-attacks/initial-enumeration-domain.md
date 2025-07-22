# HTB Academy: Active Directory Enumeration & Attacks
## Page 5 - Initial Enumeration of the Domain

### Overview
Starting phase of Active Directory penetration testing against Inlanefreight domain. Beginning from an attack host placed inside the network without domain credentials.

### Test Environment Setup
**Client Configuration:**
- Custom pentest VM within internal network (calls back to jump host)
- Windows host available for tool loading
- Starting unauthenticated with standard domain user account available (htb-student)
- Network range: `172.16.5.0/23`
- Grey box testing approach
- Non-evasive testing

### Key Objectives
1. **Enumerate internal network** - identify hosts, services, attack vectors
2. **Document findings** for later use  
3. **Find domain user account** or SYSTEM access on domain-joined host

---

## Enumeration Methodology

### 1. Passive Network Analysis

#### Wireshark Traffic Capture
**Technique:** Monitor network traffic to identify hosts and services
```bash
# Start Wireshark GUI
sudo -E wireshark

# Command line alternative
sudo tcpdump -i ens224
```

**Key Findings:**
- **ARP packets** reveal active hosts: `172.16.5.5`, `172.16.5.25`, `172.16.5.50`, `172.16.5.100`, `172.16.5.125`
- **MDNS queries** reveal hostnames: `ACADEMY-EA-WEB01.local`

#### Responder Passive Analysis
**Technique:** Analyze LLMNR, NBT-NS, and MDNS traffic passively
```bash
# Passive analysis mode (no poisoning)
sudo responder -I ens224 -A
```

**Benefits:**
- Non-intrusive reconnaissance
- Discovers additional hosts not seen in basic scans
- Identifies naming conventions and network structure

---

### 2. Active Host Discovery

#### FPing Network Sweep
**Technique:** ICMP sweep to identify live hosts
```bash
# Quick ICMP sweep with summary
fping -asgq 172.16.5.0/23
```

**Example Output:**
```
172.16.5.5
172.16.5.25
172.16.5.50
172.16.5.100
172.16.5.125
172.16.5.200
172.16.5.225
172.16.5.238
172.16.5.240

     510 targets
       9 alive
     501 unreachable
```

**Flags Explained:**
- `-a` : Show targets that are alive
- `-s` : Print stats at end of scan  
- `-g` : Generate target list from CIDR
- `-q` : Quiet (don't show per-target results)

---

### 3. Service Enumeration

#### Nmap Comprehensive Scanning
**Technique:** Detailed service and version detection
```bash
# Aggressive scan against host list
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum

# Single host detailed scan
sudo nmap -A -v -Pn 172.16.5.5

# Network-wide scan with grepable output
sudo nmap -A -Pn -T5 -oG ./nmapOutput 172.16.5.0/23
```

#### Critical Service Discovery
**Domain Controller (172.16.5.5) - ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL:**
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

**Legacy System (172.16.5.100) - Potential Quick Win:**
```
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 7.5
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2008 R2 Standard 7600
1433/tcp open  ms-sql-s     Microsoft SQL Server 2008 R2 10.50.1600.00
```

**⚠️ Security Note:** Legacy systems present high-value targets for exploits like EternalBlue, MS08-067. Always get client approval before exploiting to avoid system instability.

---

### 4. User Enumeration

#### Kerbrute Installation & Setup
**Technique:** Kerberos pre-authentication username enumeration
```bash
# Clone repository
sudo git clone https://github.com/ropnop/kerbrute.git
cd kerbrute

# View compile options
make help

# Compile for all platforms
sudo make all

# Install binary
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

#### Username Enumeration Attack
**Technique:** Leverage Kerberos pre-auth failures (often doesn't trigger alerts)
```bash
# Enumerate users against DC with wordlist
kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

**Example Results:**
```
[+] VALID USERNAME:       jjones@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       sbrown@INLANEFREIGHT.LOCAL  
[+] VALID USERNAME:       tjohnson@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       evalentin@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       sgage@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       jshay@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       jhermann@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       whouse@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       emercer@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:       wshepherd@INLANEFREIGHT.LOCAL

Done! Tested 48705 usernames (56 valid) in 9.940 seconds
```

**Benefits of Kerbrute:**
- ✅ Stealthy (pre-auth failures often don't log)
- ✅ Fast (thousands of usernames in seconds)
- ✅ Builds target list for password spraying
- ⚠️ **Caution:** Can cause account lockouts if not careful

---

## Key Data Points to Document

| Data Point | Description | Use Cases |
|------------|-------------|-----------|
| **AD Users** | Valid user accounts discovered | Password spraying, targeted attacks |
| **AD Computers** | Domain Controllers, file servers, SQL servers, web servers, Exchange | Service enumeration, lateral movement |
| **Key Services** | Kerberos, NetBIOS, LDAP, DNS | Protocol-specific attacks |
| **Vulnerable Hosts** | Legacy systems, unpatched services | Quick wins, privilege escalation |

---

## Paths to Domain Access

### SYSTEM-Level Access Benefits
Gaining **NT AUTHORITY\SYSTEM** on domain-joined host provides:
- Domain enumeration capabilities (computer account impersonation)
- Kerberoasting/ASREPRoasting attacks
- Net-NTLMv2 hash gathering with Inveigh
- SMB relay attacks
- Token impersonation for privileged accounts
- ACL attacks

### Common SYSTEM Access Methods
1. **Remote exploits:** MS08-067, EternalBlue, BlueKeep
2. **Service abuse:** SYSTEM services + SeImpersonate (Juicy Potato)
3. **Local privilege escalation:** Windows Task Scheduler 0-day
4. **Local admin + Psexec:** Launch SYSTEM cmd window

---

## Scanning Best Practices

### Operational Security Considerations
- **Evasive vs Non-evasive:** Understand engagement rules
- **Network impact:** Some scans can destabilize systems
- **Industrial environments:** Be cautious with sensors/controllers
- **Documentation:** Always use `-oA` flag for multiple output formats

### Recommended Scan Approach
1. **Start passive:** Wireshark, Responder analysis
2. **Light active:** fping, basic port scans
3. **Targeted enumeration:** Focus on discovered services
4. **Deep dive:** Service-specific enumeration tools

---

## Lab Questions & Solutions

### Question 1: CommonName of host 172.16.5.5
**Task:** Find the commonName in SSL certificate

**Solution:**
```bash
# SSH to attack host
ssh htb-student@10.129.226.51
# Password: HTB_@cademy_stdnt!

# Scan target host
sudo nmap -A -v -Pn 172.16.5.5
```

**Answer:** `ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`

**Location:** Found in SSL-Cert details under port 3389 (RDP)

### Question 2: Host running Microsoft SQL Server 2019 15.00.2000.00
**Task:** Find IP address of host running specific SQL Server version

**Solution:**
```bash
# Network-wide scan with grepable output
sudo nmap -A -Pn -T5 -oG ./nmapOutput 172.16.5.0/23

# Extract SQL Server hosts
awk '/1433\/open/ {print $2}' nmapOutput

# Alternative: grep for SQL Server version
grep "Microsoft SQL Server 2019 15.00.2000.00" nmapOutput
```

**Answer:** `172.16.5.130`

**Location:** Found on port 1433 during service detection

---

## Key Takeaways

1. **Methodical approach:** Passive → Active → Targeted enumeration
2. **Documentation crucial:** Save all scan outputs for later analysis  
3. **Multiple tools:** Different tools reveal different information
4. **Legacy systems:** High-value targets but require caution
5. **User enumeration:** Critical for subsequent password attacks
6. **Service focus:** Target AD-specific protocols (LDAP, Kerberos, DNS)

### Next Steps
- Password spraying against enumerated users
- Service-specific enumeration (SMB, LDAP, etc.)
- Vulnerability assessment of discovered hosts
- Search for foothold opportunities

### Useful Wordlists
- **Usernames:** jsmith.txt, jsmith2.txt (from Insidetrust repository)
- **Passwords:** Common corporate passwords, season+year patterns
- **Subdomain enumeration:** SecLists various wordlists

---

## Command Reference

### Network Discovery
```bash
# Passive analysis
sudo wireshark
sudo tcpdump -i ens224
sudo responder -I ens224 -A

# Active discovery  
fping -asgq 172.16.5.0/23
sudo nmap -sn 172.16.5.0/23

# Service enumeration
sudo nmap -A -v -Pn TARGET
sudo nmap -A -Pn -T5 -oA scan_results 172.16.5.0/23
```

### User Enumeration
```bash
# Kerbrute setup
git clone https://github.com/ropnop/kerbrute.git
make all
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# Username enumeration
kerbrute userenum -d DOMAIN --dc DC_IP wordlist.txt -o valid_users
```

### Data Processing
```bash
# Extract specific services
awk '/PORT_NUMBER\/open/ {print $2}' nmap_output.gnmap
grep "SERVICE_NAME" nmap_output

# Format for further tools
cat valid_users | cut -d@ -f1 > usernames.txt
```

This methodology provides a systematic approach to initial AD enumeration, balancing thoroughness with operational security considerations.
