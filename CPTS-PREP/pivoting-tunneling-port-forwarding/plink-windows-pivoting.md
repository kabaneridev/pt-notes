# **Plink.exe Windows Pivoting - HTB Academy Page 8**

## **📋 Module Overview**

**Purpose:** Windows-based SSH tunneling and pivoting using Plink.exe  
**Tool:** PuTTY Link (plink.exe) - Windows command-line SSH client  
**Scenario:** Windows attack host or compromised Windows pivot  
**Technique:** Dynamic port forwarding with SOCKS proxy  
**Integration:** Proxifier for Windows application tunneling  

---

## **1. Introduction to Plink.exe**

### **What is Plink?**
- **Full Name:** PuTTY Link
- **Type:** Windows command-line SSH tool
- **Package:** Part of PuTTY suite
- **Capability:** SSH tunneling, port forwarding, SOCKS proxy
- **Era:** Pre-Windows 10 standard (before native OpenSSH)

### **Why Use Plink?**
1. **Living off the Land** - often pre-installed on Windows systems
2. **Windows Native** - no need to transfer additional tools
3. **Stealth** - uses legitimate administrative tool
4. **Compatibility** - works on older Windows versions
5. **Integration** - pairs well with Windows tools like Proxifier

### **Common Scenarios**
- **Windows-based attack host** instead of Linux
- **Compromised Windows system** as pivot point
- **Locked down environment** where uploading tools is risky
- **Legacy systems** with PuTTY already installed
- **File share access** to plink.exe without installation

---

## **2. Plink vs SSH Comparison**

| **Aspect** | **SSH (Linux)** | **Plink (Windows)** |
|------------|-----------------|---------------------|
| **Platform** | Linux/Unix | Windows |
| **Syntax** | `ssh -D 9050 user@host` | `plink -ssh -D 9050 user@host` |
| **Authentication** | Key/password | Key/password |
| **Integration** | Native Linux tools | Proxifier, Windows apps |
| **Stealth** | Standard on Linux | Legitimate Windows tool |
| **Availability** | Always present | Depends on PuTTY install |

---

## **3. Basic Plink Dynamic Port Forwarding**

### **Network Topology**
```
[Windows Attack Host] → [Ubuntu Pivot] → [Internal Network]
    10.10.15.5           10.129.15.50      172.16.5.0/24
    Plink Client         SSH Server        Target Systems
    SOCKS :9050
```

### **Command Syntax**
```bash
# Basic dynamic port forward with Plink
plink -ssh -D 9050 ubuntu@10.129.15.50

# Command breakdown:
# -ssh        - Use SSH protocol
# -D 9050     - Dynamic port forward on local port 9050
# ubuntu      - Username on pivot host
# @10.129.15.50 - Pivot host IP address
```

### **Expected Output**
```
Using username "ubuntu".
ubuntu@10.129.15.50's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Mon Mar  7 15:30:45 2022 from 10.10.15.5
ubuntu@pivot:~$
```

### **Verification**
```cmd
# Check if SOCKS proxy is listening (Windows Command Prompt)
netstat -an | findstr :9050

# Expected output:
TCP    127.0.0.1:9050         0.0.0.0:0              LISTENING
```

---

## **4. Proxifier Integration**

### **What is Proxifier?**
- **Purpose:** Windows SOCKS/HTTP proxy client
- **Function:** Routes application traffic through proxies
- **Capability:** Proxy chaining, application-specific routing
- **Target:** Desktop applications (RDP, browsers, etc.)

### **Proxifier Configuration Steps**

#### **Step 1: Add SOCKS Server**
```
Proxifier → Profile Menu → Proxy Servers → Add

Server Configuration:
- Address: 127.0.0.1
- Port: 9050
- Protocol: SOCKS Version 4
- Authentication: None (for basic setup)
```

#### **Step 2: Create Proxification Rules**
```
Proxifier → Profile Menu → Proxification Rules → Add

Rule Configuration:
- Name: "RDP through Plink"
- Applications: mstsc.exe
- Target hosts: 172.16.5.*
- Action: Proxy SOCKS 127.0.0.1:9050
```

#### **Step 3: Enable Proxification**
```
Proxifier → Profile Menu → Proxification Rules → Enable Rules
Check: "Process all connections through proxy"
```

---

## **5. RDP Through Plink SOCKS Tunnel**

### **Complete Workflow**

#### **Step 1: Start Plink SOCKS Tunnel**
```cmd
# Windows Command Prompt
plink -ssh -D 9050 ubuntu@10.129.15.50

# Keep this session active for tunneling
```

#### **Step 2: Configure Proxifier**
```
1. Open Proxifier
2. Add SOCKS proxy: 127.0.0.1:9050
3. Create rule for mstsc.exe
4. Enable proxification
```

#### **Step 3: Launch RDP Session**
```cmd
# Start Remote Desktop Connection
mstsc.exe

# Connect to internal target:
Computer: 172.16.5.19
Username: victor
Password: pass@123
```

### **Traffic Flow Analysis**
```
[mstsc.exe] → [Proxifier] → [Plink SOCKS] → [SSH Tunnel] → [Ubuntu Pivot] → [Windows Target RDP]
Windows RDP     Proxy        Local :9050     Encrypted      SSH Server      172.16.5.19:3389
Client          Client                       Connection
```

---

## **6. Advanced Plink Techniques**

### **Authentication Methods**

#### **Password Authentication**
```cmd
# Interactive password prompt
plink -ssh -D 9050 ubuntu@10.129.15.50

# Scripted password (less secure)
echo password | plink -ssh -D 9050 ubuntu@10.129.15.50 -pw
```

#### **Key-based Authentication**
```cmd
# Using PuTTY private key format (.ppk)
plink -ssh -D 9050 -i C:\keys\ubuntu.ppk ubuntu@10.129.15.50

# Convert OpenSSH key to PuTTY format with PuTTYgen if needed
```

### **Multiple Port Forwards**
```cmd
# Dynamic + Local port forwards
plink -ssh -D 9050 -L 8080:172.16.5.19:80 ubuntu@10.129.15.50

# Multiple local forwards
plink -ssh -L 3389:172.16.5.19:3389 -L 445:172.16.5.19:445 ubuntu@10.129.15.50
```

### **Background Process**
```cmd
# Run Plink in background (Windows)
start /B plink -ssh -D 9050 ubuntu@10.129.15.50

# Check running processes
tasklist | findstr plink
```

---

## **7. Windows Application Integration**

### **Applications That Work with SOCKS Proxies**

#### **Native SOCKS Support**
```
✅ Web Browsers (Firefox, Chrome with proxy)
✅ FTP Clients (WinSCP, FileZilla)
✅ SSH Clients (PuTTY, KiTTY)
✅ Tor Browser (built-in SOCKS)
```

#### **Proxifier-Required Applications**
```
⚙️ mstsc.exe (Remote Desktop)
⚙️ Windows Explorer (SMB shares)
⚙️ Command line tools (ping, telnet)
⚙️ Custom applications
```

### **Browser Configuration Example**
```
Firefox → Settings → Network Settings → Manual Proxy Configuration
SOCKS Host: 127.0.0.1
Port: 9050
SOCKS v4
```

---

## **8. Operational Security with Plink**

### **Stealth Considerations**
1. **Legitimate Tool** - Plink is standard administrative software
2. **Network Noise** - SSH traffic appears normal
3. **Process Name** - plink.exe is not suspicious
4. **Registry Traces** - Minimal system footprint

### **Detection Risks**
1. **Network Monitoring** - SSH connections to pivot hosts
2. **Process Monitoring** - Unusual plink.exe usage patterns
3. **Proxy Detection** - SOCKS traffic analysis
4. **Authentication Logs** - SSH login records

### **Mitigation Strategies**
```cmd
# Use legitimate-looking SSH sessions
plink -ssh -D 9050 admin@server.company.com

# Vary timing and ports
plink -ssh -D 8080 ubuntu@10.129.15.50

# Clean up processes when done
taskkill /F /IM plink.exe
```

---

## **9. Troubleshooting Plink Issues**

### **Common Problems and Solutions**

#### **Authentication Failures**
```cmd
# Problem: Access denied
plink: Access denied

# Solutions:
1. Verify username/password
2. Check SSH key permissions
3. Confirm SSH service is running
4. Test with PuTTY GUI first
```

#### **Connection Refused**
```cmd
# Problem: Network unreachable
plink: Network error: Connection refused

# Solutions:
1. Verify pivot host IP
2. Check SSH port (default 22)
3. Confirm firewall rules
4. Test with telnet
```

#### **SOCKS Proxy Not Working**
```cmd
# Problem: Applications can't connect through proxy
# Solutions:
1. Verify port 9050 is listening
   netstat -an | findstr :9050

2. Check Proxifier configuration
3. Test with SOCKS-aware application
4. Restart Plink session
```

#### **Proxifier Issues**
```
# Problem: Proxifier not routing traffic
# Solutions:
1. Check proxy server settings (127.0.0.1:9050)
2. Verify proxification rules
3. Enable debug logging
4. Restart Proxifier service
```

---

## **10. Alternative Windows SSH Tools**

### **Built-in Windows SSH (Windows 10+)**
```cmd
# Modern Windows has native SSH client
ssh -D 9050 ubuntu@10.129.15.50

# Check if available:
where ssh
```

### **Other Windows SSH Clients**
```cmd
# KiTTY (PuTTY fork)
kitty -ssh -D 9050 ubuntu@10.129.15.50

# Bitvise SSH Client
BvSsh -host=10.129.15.50 -user=ubuntu -localFwd=9050:127.0.0.1:9050

# MobaXterm
MobaXterm with SSH tunneling
```

---

## **11. Lab Exercise Recreation**

### **HTB Academy Optional Exercise**
**Task:** "Attempt to use Plink from a Windows-based attack host. Set up a proxy connection and RDP to the Windows target (172.16.5.19) with 'victor:pass@123'"

### **Complete Solution Steps**

#### **Step 1: Environment Setup**
```cmd
# Requirements:
- Windows attack host
- Plink.exe available
- Network access to 10.129.202.64 (pivot)
- Target: 172.16.5.19 (internal Windows)
```

#### **Step 2: Establish Plink Tunnel**
```cmd
# Create SOCKS tunnel through Ubuntu pivot
plink -ssh -D 9050 ubuntu@10.129.202.64

# Enter password when prompted
ubuntu@10.129.202.64's password: HTB_@cademy_stdnt!
```

#### **Step 3: Configure Proxifier**
```
1. Open Proxifier
2. Profile → Proxy Servers → Add
   - Address: 127.0.0.1
   - Port: 9050
   - Type: SOCKS4
3. Profile → Proxification Rules → Add
   - Applications: mstsc.exe
   - Target Hosts: 172.16.5.19
   - Action: Proxy 127.0.0.1:9050
```

#### **Step 4: RDP Connection**
```cmd
# Launch Remote Desktop
mstsc.exe

# Connection details:
Computer: 172.16.5.19
User name: victor
Password: pass@123
```

#### **Step 5: Submit Answer**
```
Answer: "I tried Plink"
```

---

## **12. Comparison with Linux SSH Methods**

### **Functionality Comparison**

| **Feature** | **Linux SSH** | **Windows Plink** |
|-------------|---------------|-------------------|
| **Dynamic Forward** | `ssh -D 9050` | `plink -ssh -D 9050` |
| **Local Forward** | `ssh -L 8080:target:80` | `plink -ssh -L 8080:target:80` |
| **Remote Forward** | `ssh -R 8080:localhost:80` | `plink -ssh -R 8080:localhost:80` |
| **Background** | `ssh -fN -D 9050` | `start /B plink -ssh -D 9050` |
| **Key Auth** | `ssh -i key` | `plink -i key.ppk` |

### **Integration Differences**

#### **Linux Integration**
```bash
# Direct proxychains support
proxychains nmap -sT 172.16.5.19

# Built-in SOCKS applications
curl --socks5 127.0.0.1:9050 http://172.16.5.19
```

#### **Windows Integration**
```cmd
# Requires Proxifier for most applications
Proxifier → mstsc.exe → 172.16.5.19

# Some native SOCKS support
firefox → proxy settings → SOCKS 127.0.0.1:9050
```

---

## **13. Real-World Scenarios**

### **Scenario 1: Corporate Windows Environment**
```
Situation: Pentesting corporate network
Environment: Windows workstations with PuTTY installed
Goal: Pivot through DMZ host to internal network
Solution: Use Plink for SOCKS tunneling + Proxifier for RDP
```

### **Scenario 2: Legacy System Compromise**
```
Situation: Compromised older Windows server
Limitation: Cannot upload new tools
Available: PuTTY suite installed for administration
Solution: Leverage existing Plink for tunneling
```

### **Scenario 3: Windows Red Team Operation**
```
Situation: Windows-based red team infrastructure
Challenge: Need to blend in with Windows environment
Approach: Use Windows-native tools (Plink, Proxifier, mstsc)
Benefit: Reduced detection, natural tool usage
```

---

## **14. Best Practices**

### **Operational Guidelines**
1. **Test Locally First** - Verify Plink works before deployment
2. **Multiple Tunnels** - Create redundant paths when possible
3. **Authentication Security** - Use keys when possible
4. **Clean Exit** - Properly terminate sessions
5. **Documentation** - Record tunnel configurations

### **Security Recommendations**
1. **Timing Variation** - Don't establish tunnels at predictable times
2. **Port Diversity** - Use different SOCKS ports
3. **Session Management** - Monitor and limit session duration
4. **Log Cleanup** - Clear relevant Windows event logs
5. **Process Hiding** - Consider process migration techniques

### **Performance Optimization**
1. **Compression** - Use SSH compression for slow links
2. **Keep-Alive** - Maintain persistent connections
3. **Concurrent Sessions** - Balance load across multiple tunnels
4. **Bandwidth Monitoring** - Track usage patterns

---

## **15. Integration with Other Tools**

### **Metasploit Integration**
```ruby
# Metasploit with SOCKS proxy (requires Proxychains4Windows)
msf6 > setg Proxies socks4:127.0.0.1:9050
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.19
msf6 auxiliary(scanner/portscan/tcp) > run
```

### **PowerShell Integration**
```powershell
# PowerShell with proxy settings
$proxy = New-Object System.Net.WebProxy("socks://127.0.0.1:9050")
$webClient = New-Object System.Net.WebClient
$webClient.Proxy = $proxy
$webClient.DownloadString("http://172.16.5.19")
```

### **Nmap through Proxy**
```cmd
# Using ProxyChains4Windows (if available)
proxychains4 nmap -sT -Pn 172.16.5.19

# Alternative: nmap with HTTP proxy (if SOCKS-to-HTTP converter used)
nmap --proxy socks4://127.0.0.1:9050 172.16.5.19
```

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 8
- **PuTTY Documentation**: [Official PuTTY Manual](https://www.chiark.greenend.org.uk/~sgtatham/putty/docs.html)
- **Proxifier Manual**: [Proxifier Documentation](https://www.proxifier.com/documentation/)
- **SANS**: [SSH Tunneling with Windows](https://www.sans.org/blog/ssh-tunneling-with-windows/)
- **Microsoft**: [Windows SSH Client](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) 