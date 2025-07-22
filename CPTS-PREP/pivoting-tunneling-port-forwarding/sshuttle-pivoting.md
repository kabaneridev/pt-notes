# **sshuttle SSH Pivoting - HTB Academy Page 9**

## **📋 Module Overview**

**Purpose:** Automated SSH pivoting with transparent traffic routing  
**Tool:** sshuttle - Python-based SSH tunnel manager  
**Key Feature:** Automatic iptables configuration (no proxychains needed)  
**Protocol:** SSH-only (no TOR/HTTPS proxy support)  
**Advantage:** Direct tool usage without proxy configuration  

---

## **1. Introduction to sshuttle**

### **What is sshuttle?**
- **Language:** Python-based networking tool
- **Function:** Automated SSH pivot with transparent routing
- **Mechanism:** Creates iptables rules for traffic redirection
- **Scope:** SSH tunneling only (no other protocols)
- **Philosophy:** "VPN over SSH" approach

### **sshuttle vs Traditional Methods**

| **Aspect** | **sshuttle** | **SSH + proxychains** |
|------------|--------------|------------------------|
| **Setup** | Single command | SSH tunnel + proxychains config |
| **iptables** | Automatic | Manual/none |
| **Application Support** | All TCP traffic | SOCKS-aware only |
| **Transparency** | Completely transparent | Requires proxy awareness |
| **Performance** | High (kernel-level) | Lower (userspace proxy) |
| **Protocol Support** | SSH only | SSH/SOCKS/HTTP/TOR |

### **Key Advantages**
1. **No proxychains configuration** required
2. **Automatic iptables management** for routing
3. **Transparent operation** - tools work normally
4. **Kernel-level routing** - better performance
5. **Simple command syntax** - easy to use

### **Limitations**
1. **SSH-only protocol** support
2. **No TOR/HTTPS proxy** integration
3. **Requires root privileges** for iptables
4. **TCP traffic only** (no UDP support with default method)
5. **Python dependency** required

---

## **2. Installation and Setup**

### **Installing sshuttle**

#### **Ubuntu/Debian Systems**
```bash
# Install from package manager
sudo apt-get install sshuttle

# Expected output:
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
Suggested packages:
  autossh
The following NEW packages will be installed:
  sshuttle
0 upgraded, 1 newly installed, 0 to remove and 4 not upgraded.
Need to get 91.8 kB of archives.
After this operation, 508 kB of additional disk space will be used.
```

#### **Alternative Installation Methods**
```bash
# Install via pip (latest version)
sudo pip3 install sshuttle

# Install from source
git clone https://github.com/sshuttle/sshuttle.git
cd sshuttle
sudo python3 setup.py install

# Arch Linux
sudo pacman -S sshuttle

# macOS with Homebrew
brew install sshuttle
```

### **Verification**
```bash
# Check installation
sshuttle --version
# sshuttle 1.1.0

# Check help
sshuttle --help
```

---

## **3. Basic sshuttle Usage**

### **Network Topology**
```
[Attack Host] → [Ubuntu Pivot] → [Internal Network]
10.10.14.18      10.129.202.64     172.16.5.0/23
sshuttle         SSH Server        Target Network
iptables rules
```

### **Basic Command Syntax**
```bash
# Basic sshuttle pivoting
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

# Command breakdown:
# -r                    - Remote SSH server
# ubuntu@10.129.202.64  - Username and pivot host
# 172.16.5.0/23         - Network to route through pivot
# -v                    - Verbose output
```

### **Expected Connection Output**
```bash
Starting sshuttle proxy (version 1.1.0).
c : Starting firewall manager with command: ['/usr/bin/python3', '/usr/local/lib/python3.9/dist-packages/sshuttle/__main__.py', '-v', '--method', 'auto', '--firewall']
fw: Starting firewall with Python version 3.9.2
fw: ready method name nat.
c : IPv6 enabled: Using default IPv6 listen address ::1
c : Method: nat
c : IPv4: on
c : IPv6: on
c : UDP : off (not available with nat method)
c : DNS : off (available)
c : User: off (available)
c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
c :   (<AddressFamily.AF_INET: 2>, '172.16.5.0', 32, 0, 0)
c : Subnets to exclude from forwarding:
c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
c :   (<AddressFamily.AF_INET6: 10>, '::1', 128, 0, 0)
c : TCP redirector listening on ('::1', 12300, 0, 0).
c : TCP redirector listening on ('127.0.0.1', 12300).
c : Starting client with Python version 3.9.2
c : Connecting to server...
ubuntu@10.129.202.64's password: HTB_@cademy_stdnt!
 s: Running server on remote host with /usr/bin/python3 (version 3.8.10)
 s: latency control setting = True
 s: auto-nets:False
c : Connected to server.
```

### **iptables Rules Creation**
```bash
# sshuttle automatically creates these rules:
fw: setting up.
fw: ip6tables -w -t nat -N sshuttle-12300
fw: ip6tables -w -t nat -F sshuttle-12300
fw: ip6tables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: ip6tables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN --dest ::1/128 -p tcp
fw: iptables -w -t nat -N sshuttle-12300
fw: iptables -w -t nat -F sshuttle-12300
fw: iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: iptables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN --dest 127.0.0.1/32 -p tcp
fw: iptables -w -t nat -A sshuttle-12300 -j REDIRECT --dest 172.16.5.0/32 -p tcp --to-ports 12300
```

---

## **4. Direct Tool Usage (No Proxychains)**

### **Transparent nmap Scanning**
```bash
# Direct nmap scan through sshuttle tunnel
nmap -v -sV -p3389 172.16.5.19 -A -Pn

# Expected results:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-08 11:16 EST
NSE: Loaded 155 scripts for scanning.

Nmap scan report for 172.16.5.19
Host is up.

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: INLANEFREIGHT
|   NetBIOS_Domain_Name: INLANEFREIGHT
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: inlanefreight.local
|   DNS_Computer_Name: DC01.inlanefreight.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-08-14T02:58:25+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### **Direct Tool Benefits**
```bash
# ALL tools work transparently:

# Web requests
curl http://172.16.5.19

# Database connections
mysql -h 172.16.5.19 -u admin -p

# FTP access
ftp 172.16.5.19

# SSH connections
ssh administrator@172.16.5.19

# RDP connections
xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

## **5. Advanced sshuttle Options**

### **Authentication Methods**

#### **Password Authentication**
```bash
# Interactive password prompt
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23

# Password from file (less secure)
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --ssh-cmd 'ssh -o PasswordAuthentication=yes'
```

#### **Key-based Authentication**
```bash
# Using SSH key
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --ssh-cmd 'ssh -i /path/to/key'

# Using ssh-agent
eval $(ssh-agent)
ssh-add ~/.ssh/pivot_key
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23
```

### **Multiple Network Routing**
```bash
# Route multiple networks
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 192.168.1.0/24 10.0.0.0/8

# Auto-detect networks (dangerous!)
sudo sshuttle -r ubuntu@10.129.202.64 0/0

# Exclude specific networks
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -x 172.16.5.1/32
```

### **DNS Routing**
```bash
# Route DNS queries through tunnel
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --dns

# Custom DNS server
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --dns --ns 172.16.5.1
```

### **Advanced Options**
```bash
# Custom method (for special cases)
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --method=nat

# Custom SSH port
sudo sshuttle -r ubuntu@10.129.202.64:2222 172.16.5.0/23

# Daemon mode
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -D

# Custom pidfile
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --pidfile=/var/run/sshuttle.pid
```

---

## **6. HTB Academy Lab Exercise**

### **Lab Challenge**
**Task:** "Try using sshuttle from Pwnbox to connect via RDP to the Windows target (172.16.5.19) with 'victor:pass@123'"

### **Complete Solution**

#### **Step 1: Install sshuttle (if needed)**
```bash
# Check if sshuttle is available
which sshuttle

# Install if missing
sudo apt-get update
sudo apt-get install sshuttle
```

#### **Step 2: Establish sshuttle Tunnel**
```bash
# Connect through Ubuntu pivot to internal network
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

# Enter password when prompted:
ubuntu@10.129.202.64's password: HTB_@cademy_stdnt!

# Wait for connection confirmation:
c : Connected to server.
fw: setting up.
# ... iptables rules created automatically
```

#### **Step 3: Verify Network Routing**
```bash
# Test connectivity to target
ping -c 3 172.16.5.19

# Scan RDP port
nmap -p 3389 172.16.5.19

# Expected: Port 3389 open
```

#### **Step 4: RDP Connection**
```bash
# Connect via RDP (multiple methods)

# Method 1: xfreerdp
xfreerdp /v:172.16.5.19 /u:victor /p:pass@123 /cert:ignore

# Method 2: rdesktop
rdesktop -u victor -p pass@123 172.16.5.19

# Method 3: krdc (KDE)
krdc rdp://victor:pass@123@172.16.5.19
```

#### **Step 5: Verification and Cleanup**
```bash
# Verify successful RDP connection to Windows target
# Should see Windows desktop as user "victor"

# When done, stop sshuttle (Ctrl+C in terminal)
^C
c : Keyboard interrupt: exiting.
fw: undoing changes.
# iptables rules automatically cleaned up
```

#### **Step 6: Submit Answer**
```
Answer: "I tried sshuttle"
```

---

## **7. sshuttle vs Other Pivoting Methods**

### **Comprehensive Comparison**

| **Method** | **Setup Complexity** | **Tool Transparency** | **Performance** | **Protocol Support** |
|------------|----------------------|----------------------|-----------------|---------------------|
| **sshuttle** | Low (single command) | High (fully transparent) | High (kernel-level) | SSH only |
| **SSH + proxychains** | Medium (config files) | Medium (SOCKS-aware) | Medium (userspace) | Multiple protocols |
| **Meterpreter** | High (payload + handler) | Low (manual forwarding) | Medium | Multiple protocols |
| **Socat** | Medium (multiple commands) | Low (manual setup) | High | Any TCP/UDP |
| **Plink + Proxifier** | High (Windows GUI config) | High (app-specific) | Medium | Windows-centric |

### **When to Use sshuttle**
✅ **SSH access available** to pivot host  
✅ **Transparent tool usage** required  
✅ **Multiple tools** need network access  
✅ **Performance is critical** (kernel routing)  
✅ **Simple setup** preferred over complex configurations  

### **When NOT to Use sshuttle**
❌ **No SSH access** (use Meterpreter/Socat)  
❌ **UDP traffic required** (use SSH local forwards)  
❌ **TOR/HTTP proxy** needed (use proxychains)  
❌ **Windows-only environment** (use Plink)  
❌ **Stealth operation** (iptables changes detectable)  

---

## **8. Troubleshooting sshuttle**

### **Common Issues and Solutions**

#### **Permission Denied Errors**
```bash
# Problem: iptables modification failed
ERROR: Failed to modify iptables rules

# Solutions:
1. Run with sudo
   sudo sshuttle -r user@host network

2. Check iptables permissions
   sudo iptables -L

3. Verify user has sudo rights
   sudo -l
```

#### **SSH Authentication Failures**
```bash
# Problem: Cannot connect to SSH server
Permission denied (publickey,password)

# Solutions:
1. Test SSH connection first
   ssh ubuntu@10.129.202.64

2. Use key authentication
   sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --ssh-cmd 'ssh -i key'

3. Check SSH service status
   sudo systemctl status ssh
```

#### **Network Routing Issues**
```bash
# Problem: Cannot reach target network
Network unreachable

# Solutions:
1. Verify network range
   ip route show | grep 172.16.5

2. Test SSH server routing
   ssh ubuntu@10.129.202.64 'ip route'

3. Check target network existence
   ssh ubuntu@10.129.202.64 'ping 172.16.5.19'
```

#### **iptables Cleanup Problems**
```bash
# Problem: iptables rules not cleaned up
Rules persist after sshuttle exit

# Solutions:
1. Manual cleanup
   sudo iptables -t nat -F sshuttle-12300
   sudo iptables -t nat -X sshuttle-12300

2. Force kill and cleanup
   sudo pkill sshuttle
   sudo iptables -t nat -L | grep sshuttle

3. Restart networking
   sudo systemctl restart networking
```

---

## **9. Advanced Scenarios**

### **Multiple Pivot Chains**
```bash
# Chain multiple sshuttle connections
# Terminal 1: First pivot
sudo sshuttle -r user1@pivot1 10.0.0.0/8

# Terminal 2: Second pivot (through first)
sudo sshuttle -r user2@10.0.1.5 192.168.0.0/16 --ssh-cmd 'ssh -o ProxyCommand="ssh -W %h:%p user1@pivot1"'
```

### **Persistent sshuttle Service**
```bash
# Create systemd service
sudo cat > /etc/systemd/system/sshuttle-pivot.service << EOF
[Unit]
Description=sshuttle pivot tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable sshuttle-pivot
sudo systemctl start sshuttle-pivot
```

### **sshuttle with SSH Tunnels**
```bash
# Combine with local port forwards
ssh -L 8080:172.16.5.19:80 ubuntu@10.129.202.64 &
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23

# Access both ways:
curl http://localhost:8080        # SSH local forward
curl http://172.16.5.19          # sshuttle routing
```

---

## **10. Performance and Monitoring**

### **Performance Optimization**
```bash
# Enable compression for slow links
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --ssh-cmd 'ssh -C'

# Adjust buffer sizes
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --python /usr/bin/python3

# Use specific SSH cipher
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --ssh-cmd 'ssh -c aes128-ctr'
```

### **Traffic Monitoring**
```bash
# Monitor sshuttle traffic
sudo tcpdump -i any host 10.129.202.64

# Check iptables packet counts
sudo iptables -t nat -L sshuttle-12300 -v

# Monitor bandwidth usage
iftop -i eth0 -f "host 10.129.202.64"
```

### **Resource Usage**
```bash
# Check sshuttle processes
ps aux | grep sshuttle

# Monitor memory usage
top -p $(pgrep sshuttle)

# Check network connections
ss -tuln | grep :12300
```

---

## **11. Security Considerations**

### **Operational Security**
1. **iptables Modifications** - detectable by system administrators
2. **Process Visibility** - sshuttle processes visible in ps output
3. **Network Traffic** - SSH connections to pivot hosts logged
4. **DNS Queries** - may leak information if --dns used
5. **Root Privileges** - requires elevated access

### **Detection Mitigation**
```bash
# Use non-standard SSH ports
sudo sshuttle -r ubuntu@10.129.202.64:2222 172.16.5.0/23

# Vary connection timing
sleep $((RANDOM % 300)); sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23

# Clean process names (limited effectiveness)
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --python /usr/bin/python3
```

### **Cleanup Procedures**
```bash
# Proper shutdown
# Use Ctrl+C to stop sshuttle (auto-cleanup)

# Emergency cleanup
sudo pkill -f sshuttle
sudo iptables -t nat -F
sudo iptables -t nat -X

# Clear SSH known_hosts entries
ssh-keygen -R 10.129.202.64
```

---

## **12. Integration with Other Tools**

### **Metasploit Integration**
```ruby
# Use Metasploit normally with sshuttle active
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.0/24
msf6 auxiliary(scanner/portscan/tcp) > run

# No proxy configuration needed!
```

### **Nmap Advanced Usage**
```bash
# Full network scans through sshuttle
nmap -sS -A 172.16.5.0/24

# Service enumeration
nmap -sV -p- 172.16.5.19

# Vulnerability scanning
nmap --script vuln 172.16.5.19
```

### **Custom Applications**
```bash
# Any TCP application works transparently
telnet 172.16.5.19 23
nc 172.16.5.19 445
python3 -c "import socket; s=socket.socket(); s.connect(('172.16.5.19', 80))"
```

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 9
- **sshuttle GitHub**: [Official Repository](https://github.com/sshuttle/sshuttle)
- **sshuttle Documentation**: [ReadTheDocs](https://sshuttle.readthedocs.io/)
- **Man Page**: `man sshuttle`
- **Python SSH Tunneling**: [SSH Tunnel Techniques](https://www.pythonsecrets.com/ssh-tunneling/) 