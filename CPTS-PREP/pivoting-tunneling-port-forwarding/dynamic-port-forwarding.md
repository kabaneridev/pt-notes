# 🔀 Dynamic Port Forwarding with SSH and SOCKS Tunneling - CPTS

## **Overview**

Dynamic port forwarding with SSH creates a SOCKS proxy that allows us to pivot through compromised hosts to access internal networks. This technique is essential when we need to access multiple services on networks that are not directly reachable from our attack host.

---

## **Port Forwarding in Context**

Port forwarding redirects communication requests from one port to another using TCP as the primary communication layer. Different application layer protocols (SSH, SOCKS) can encapsulate the forwarded traffic to:
- Bypass firewalls
- Use existing services on compromised hosts
- Pivot to other networks

---

## **SSH Local Port Forwarding (-L)**

### **Basic Concept**
Forward a local port to a remote destination through an SSH server (pivot host).

**Syntax:**
```bash
ssh -L [local_port]:[destination_host]:[destination_port] [user]@[ssh_server]
```

### **Practical Example from HTB**

**Scenario:** We have compromised Ubuntu server (10.129.202.64) with MySQL running locally on port 3306.

**Initial Scan:**
```bash
nmap -sT -p22,3306 10.129.202.64

PORT     STATE  SERVICE
22/tcp   open   ssh
3306/tcp closed mysql    # Closed because it's bound to localhost only
```

**Setting up Local Port Forward:**
```bash
# Forward local port 1234 to MySQL on the Ubuntu server
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
```

**Traffic Flow:**
```
[Attack Host] → [Ubuntu Server] → [MySQL Service]
localhost:1234 → 10.129.202.64:22 → localhost:3306
```

**Verification:**
```bash
# Check if tunnel is active
netstat -antp | grep 1234
tcp        0      0 127.0.0.1:1234          0.0.0.0:*               LISTEN      4034/ssh

# Scan the forwarded port
nmap -v -sV -p1234 localhost
PORT     STATE SERVICE VERSION
1234/tcp open  mysql   MySQL 8.0.28-0ubuntu0.20.04.3
```

### **Multiple Port Forwarding**
```bash
# Forward multiple services simultaneously
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

---

## **Dynamic Port Forwarding (-D) - SOCKS Proxy**

### **When to Use Dynamic Port Forwarding**

Use dynamic port forwarding when:
- You need to access multiple services on an internal network
- You don't know which services are available beforehand
- You want to tunnel various tools through the compromised host

### **Setting up SOCKS Proxy**

**Example Scenario:** Ubuntu server has multiple network interfaces:
- `ens192`: 10.129.202.64 (external, accessible from attack host)
- `ens224`: 172.16.5.129 (internal network interface)
- `lo`: 127.0.0.1 (loopback)

### **Discovery Process: How We Found 172.16.5.19**

**Step 1: Identify Internal Networks**
```bash
# SSH to pivot and check interfaces
ssh ubuntu@10.129.202.64
ifconfig

# Results show:
# ens224: 172.16.5.129 (netmask 255.255.254.0 = /23)
# This indicates internal network: 172.16.5.0/23
```

**Step 2: Network Range Calculation**
```bash
# Network range analysis:
# 172.16.5.129/23 means:
# Network: 172.16.4.0 - 172.16.5.255 (512 hosts)
# Focus on: 172.16.5.0 - 172.16.5.255 (256 hosts)
```

**Step 3: Live Host Discovery**
```bash
# Scan for live hosts in the range
ssh -D 9050 ubuntu@10.129.202.64
proxychains nmap -sn 172.16.5.1-200

# Found live hosts:
# 172.16.5.5  - Unknown
# 172.16.5.19 - Unknown (investigate further)
# 172.16.5.129 - Our pivot host
```

**Step 4: Service Identification**
```bash
# Port scan the interesting host
proxychains nmap -Pn -sT 172.16.5.19

# Results identify it as Windows:
# 445/tcp  - SMB (Windows file sharing)
# 135/tcp  - Windows RPC
# 3389/tcp - RDP (Windows Remote Desktop)
# 139/tcp  - NetBIOS (Windows networking)
```

**Checking Network Interfaces on Pivot:**
```bash
ubuntu@WEB01:~$ ifconfig 

ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.202.64  netmask 255.255.0.0  broadcast 10.129.255.255

ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
```

**Creating SOCKS Proxy:**
```bash
# Enable dynamic port forwarding on port 9050
ssh -D 9050 ubuntu@10.129.202.64
```

---

## **Configuring Proxychains**

### **Configuration File Setup**
```bash
# Edit proxychains configuration
nano /etc/proxychains.conf

# Add to the end of [ProxyList] section
socks4 127.0.0.1 9050
```

**Complete Configuration Example:**
```bash
# /etc/proxychains.conf
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks4 127.0.0.1 9050
```

### **Verify Configuration**
```bash
# Check the last few lines of config
tail -4 /etc/proxychains.conf
socks4 	127.0.0.1 9050
```

---

## **Using Tools through SOCKS Proxy**

### **Nmap through Proxychains**

**Important Notes:**
- Only **TCP connect scans (-sT)** work through proxychains
- Use **-Pn** to skip ping probes (Windows Defender blocks ICMP)
- Partial packets (SYN scans) return incorrect results

**Network Discovery:**
```bash
# Scan for live hosts in the internal network
proxychains nmap -v -sn 172.16.5.1-200

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.5:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:80-<><>-OK  # Windows target discovered

# Key findings:
# 172.16.5.5  - Live host
# 172.16.5.19 - Live host (our Windows target)
```

**Port Scanning Specific Host:**
```bash
# Scan discovered host 172.16.5.19 for services
proxychains nmap -v -Pn -sT 172.16.5.19

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:445-<><>-OK
Discovered open port 445/tcp on 172.16.5.19    # SMB - Windows file sharing
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:135-<><>-OK
Discovered open port 135/tcp on 172.16.5.19    # RPC - Windows RPC endpoint mapper
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Discovered open port 3389/tcp on 172.16.5.19   # RDP - Windows Remote Desktop
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:139-<><>-OK
Discovered open port 139/tcp on 172.16.5.19    # NetBIOS - Windows networking

# Port signature analysis:
# 445 + 135 + 3389 + 139 = Clearly a Windows machine
# This combination is typical for Windows Server/Workstation
```

### **Metasploit through Proxychains**

**Starting Metasploit:**
```bash
proxychains msfconsole

ProxyChains-3.1 (http://proxychains.sf.net)
msf6 > 
```

**Using Auxiliary Modules:**
```bash
# RDP scanner module to confirm Windows and get OS details
msf6 > use auxiliary/scanner/rdp/rdp_scanner
msf6 auxiliary(scanner/rdp/rdp_scanner) > set rhosts 172.16.5.19
msf6 auxiliary(scanner/rdp/rdp_scanner) > run

|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
[*] 172.16.5.19:3389 - Detected RDP on 172.16.5.19:3389 (name:DC01) (domain:DC01) (os_version:10.0.17763) (Requires NLA: No)

# Key Intelligence Gathered:
# - Computer Name: DC01 (Domain Controller)
# - Domain: DC01 (likely workgroup or standalone)
# - OS Version: 10.0.17763 (Windows Server 2019)
# - RDP Authentication: No Network Level Auth required
# - Confirmed: This is our Windows target for Page 4 reverse shell
```

### **RDP Connection through Proxy**
```bash
# Connect to Windows host via RDP through SOCKS proxy
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

ProxyChains-3.1 (http://proxychains.sf.net)
[INFO] - freerdp_connect:freerdp_set_last_error_ex resetting error state
```

---

## **SOCKS Protocol Details**

### **SOCKS vs Regular Proxies**

**SOCKS (Socket Secure) Protocol:**
- Works at Session Layer (Layer 5)
- Can handle any type of traffic (TCP/UDP)
- Client initiates connection to SOCKS server
- Server forwards traffic on behalf of client

**Types:**
- **SOCKS4**: No authentication, no UDP support
- **SOCKS5**: Authentication support, UDP support, better security

### **Traffic Flow in SOCKS Tunneling**
```
[Attack Host] → [SOCKS Client] → [SSH Tunnel] → [Pivot Host] → [Target Network]
     ↓              ↓               ↓              ↓              ↓
Tool Request → Proxychains → SSH Port 22 → Internal Interface → Target Service
```

---

## **Advanced Techniques**

### **Multiple Simultaneous Tunnels**
```bash
# Terminal 1: SOCKS proxy for general scanning
ssh -D 9050 ubuntu@10.129.202.64

# Terminal 2: Specific port forward for RDP
ssh -L 3389:172.16.5.19:3389 ubuntu@10.129.202.64

# Terminal 3: Port forward for SMB
ssh -L 445:172.16.5.19:445 ubuntu@10.129.202.64
```

### **Background Tunnels**
```bash
# Run SOCKS proxy in background
ssh -fNT -D 9050 ubuntu@10.129.202.64

# -f: Fork to background
# -N: Don't execute remote command
# -T: Disable pseudo-terminal allocation
```

### **Compressed Tunnels**
```bash
# Enable compression for slow connections
ssh -C -D 9050 ubuntu@10.129.202.64
```

---

## **Troubleshooting**

### **Common Issues and Solutions**

**1. Proxychains Connection Timeouts**
```bash
# Increase timeout values in /etc/proxychains.conf
tcp_read_time_out 30000
tcp_connect_time_out 15000
```

**2. DNS Resolution Problems**
```bash
# Enable proxy_dns in configuration
proxy_dns

# Use IP addresses instead of hostnames when possible
proxychains nmap 172.16.5.19  # Instead of internal.domain.com
```

**3. Windows Firewall Blocking Scans**
```bash
# Use -Pn to skip ping probes
proxychains nmap -Pn -sT 172.16.5.19

# Focus on common ports
proxychains nmap -Pn -sT -p 22,80,135,139,443,445,3389 172.16.5.19
```

**4. SSH Connection Issues**
```bash
# Test basic SSH connectivity first
ssh ubuntu@10.129.202.64

# Verify tunnel is established
netstat -antp | grep 9050
```

### **Debugging Commands**
```bash
# Verbose proxychains output
proxychains -v nmap 172.16.5.19

# Check SSH tunnel status
ps aux | grep ssh
lsof -i :9050
```

---

## **Best Practices**

### **Security Considerations**
1. **Use key-based authentication** when possible
2. **Clean up tunnels** after use
3. **Monitor tunnel stability** for long operations
4. **Use compression (-C)** for slow connections

### **Performance Optimization**
1. **Use specific port ranges** instead of full scans
2. **Target known live hosts** when possible
3. **Use multiple parallel tunnels** for different services
4. **Keep tunnel sessions active** with `ServerAliveInterval`

### **Operational Security**
1. **Mimic legitimate traffic patterns**
2. **Use encrypted tunnels** (SSH)
3. **Avoid suspicious port combinations**
4. **Document tunnel configurations** for team use

---

## **Lab Exercises (HTB Style)**

### **Exercise 1: Basic Port Forward**
```bash
# Goal: Access MySQL service on compromised host
ssh -L 1234:localhost:3306 ubuntu@[TARGET_IP]
nmap -sV -p1234 localhost
```

### **Exercise 2: SOCKS Proxy Setup**
```bash
# Goal: Scan internal network through pivot
ssh -D 9050 ubuntu@[TARGET_IP]
echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf
proxychains nmap -Pn -sT 172.16.5.0/24
```

### **Exercise 3: RDP Access**
```bash
# Goal: Connect to Windows host via RDP through proxy
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

## **Quick Reference Commands**

| **Task** | **Command** |
|----------|-------------|
| Local port forward | `ssh -L 1234:target:3306 user@pivot` |
| SOCKS proxy | `ssh -D 9050 user@pivot` |
| Background tunnel | `ssh -fNT -D 9050 user@pivot` |
| Proxychains scan | `proxychains nmap -Pn -sT target` |
| Metasploit via proxy | `proxychains msfconsole` |
| RDP via proxy | `proxychains xfreerdp /v:target /u:user /p:pass` |
| Check tunnel | `netstat -antp \| grep 9050` |

---

## **Network Diagrams**

### **Local Port Forward Flow**
```
[Attack Host] ──ssh──► [Pivot Host] ──internal──► [Target Service]
localhost:1234         10.129.x.x:22            localhost:3306
```

### **SOCKS Proxy Flow**
```
[Attack Host] ──proxychains──► [SOCKS:9050] ──ssh──► [Pivot] ──► [Internal Network]
nmap/tools                     localhost:9050       SSH:22     172.16.5.0/24
```

---

## **References**

- HTB Academy: Pivoting, Tunneling & Port Forwarding
- SSH Manual: `man ssh`
- Proxychains: `/etc/proxychains.conf`
- SOCKS Protocol: RFC 1928 (SOCKS5) 