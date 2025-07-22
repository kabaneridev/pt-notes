# **Windows Netsh Port Forwarding - HTB Academy Page 11**

## **📋 Module Overview**

**Purpose:** Native Windows port forwarding using built-in tools  
**Tool:** netsh.exe - Windows network configuration utility  
**Technique:** IPv4-to-IPv4 port proxy forwarding  
**Advantage:** No external tools required (living off the land)  
**Scenario:** Windows workstation as pivot to internal network  

---

## **1. Introduction to Windows Netsh**

### **What is Netsh?**
- **Full Name:** Network Shell (netsh.exe)
- **Type:** Built-in Windows command-line utility
- **Purpose:** Network configuration and management
- **Location:** `C:\Windows\System32\netsh.exe`
- **Availability:** Present on all Windows systems
- **Privileges:** Requires administrator privileges for port forwarding

### **Netsh Capabilities**
1. **Finding routes** - network path discovery
2. **Viewing firewall configuration** - Windows Firewall management
3. **Adding proxies** - proxy server configuration
4. **Creating port forwarding rules** - IPv4-to-IPv4 forwarding
5. **Network interface management** - adapter configuration

### **Netsh vs Other Windows Tools**

| **Tool** | **Type** | **Availability** | **Configuration** | **Stealth** |
|----------|----------|------------------|-------------------|-------------|
| **Netsh** | Built-in | Always present | Command-line | High (legitimate tool) |
| **Plink** | External | PuTTY required | SSH-based | Medium (admin tool) |
| **PowerShell** | Built-in | Windows 7+ | Script-based | High (native) |
| **SSH** | External | Windows 10+ | SSH tunneling | Medium (newer feature) |

### **Network Topology Example**
```
[Attack Host] → [Windows 10 Pivot] → [Windows Server]
10.10.15.5       10.129.15.150        172.16.5.25:3389
xfreerdp         netsh portproxy      RDP service
:8080            :8080 → :3389        Domain Controller
```

---

## **2. Basic Netsh Port Forwarding**

### **IPv4-to-IPv4 Port Proxy**

#### **Creating Port Forward Rule**
```cmd
# Basic netsh port forwarding syntax
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25

# Command breakdown:
# interface portproxy  - portproxy interface
# add v4tov4           - add IPv4-to-IPv4 forwarding rule
# listenport=8080      - port to listen on (pivot host)
# listenaddress=       - IP to bind listener (pivot host)
# connectport=3389     - destination port (target)
# connectaddress=      - destination IP (target)
```

#### **Verifying Port Forward**
```cmd
# Show all IPv4-to-IPv4 port forwards
netsh.exe interface portproxy show v4tov4

# Expected output:
Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.15.150   8080        172.16.5.25     3389
```

### **Understanding the Configuration**
- **Listen Address:** 10.129.15.150 (Windows 10 pivot host)
- **Listen Port:** 8080 (accessible from attack host)
- **Connect Address:** 172.16.5.25 (internal Windows server)
- **Connect Port:** 3389 (RDP service)

---

## **3. Practical Implementation**

### **Step 1: Access Windows Pivot Host**
```cmd
# RDP to Windows 10 pivot (from HTB Academy lab)
xfreerdp /v:<windows_pivot_ip> /u:htb-student /p:HTB_@cademy_stdnt!

# Verify current network configuration
ipconfig
netstat -an | findstr :3389
```

### **Step 2: Create Port Forward Rule**
```cmd
# Open Command Prompt as Administrator
# Run netsh port forwarding command
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.19

# Note: Adjust IP addresses based on lab environment
```

### **Step 3: Verify Configuration**
```cmd
# Check if rule was created successfully
netsh.exe interface portproxy show v4tov4

# Verify port is listening
netstat -an | findstr :8080

# Expected output:
TCP    10.129.15.150:8080     0.0.0.0:0         LISTENING
```

### **Step 4: Test Port Forward**
```bash
# From attack host (Pwnbox), connect through port forward
xfreerdp /v:10.129.15.150:8080 /u:victor /p:pass@123 /cert:ignore

# Traffic flow: Attack Host → Pivot:8080 → DC:3389
```

---

## **4. Advanced Netsh Configurations**

### **Multiple Port Forwards**
```cmd
# Forward multiple services simultaneously
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.19
netsh.exe interface portproxy add v4tov4 listenport=8445 listenaddress=10.129.15.150 connectport=445 connectaddress=172.16.5.19
netsh.exe interface portproxy add v4tov4 listenport=8135 listenaddress=10.129.15.150 connectport=135 connectaddress=172.16.5.19

# Verify all forwards
netsh.exe interface portproxy show v4tov4
```

### **Different Interface Binding**
```cmd
# Bind to all interfaces (0.0.0.0)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.19

# Bind to specific interface only
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=192.168.1.100 connectport=3389 connectaddress=172.16.5.19
```

### **IPv6 Support**
```cmd
# IPv6-to-IPv6 forwarding
netsh.exe interface portproxy add v6tov6 listenport=8080 listenaddress=::1 connectport=3389 connectaddress=fe80::1

# IPv4-to-IPv6 forwarding
netsh.exe interface portproxy add v4tov6 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=fe80::1

# IPv6-to-IPv4 forwarding
netsh.exe interface portproxy add v6tov4 listenport=8080 listenaddress=::1 connectport=3389 connectaddress=172.16.5.19
```

---

## **5. HTB Academy Lab Exercise**

### **Lab Challenge**
**"Using the concepts covered in this section, take control of the DC (172.16.5.19) using xfreerdp by pivoting through the Windows 10 target host. Submit the approved contact's name found inside the 'VendorContacts.txt' file located in the 'Approved Vendors' folder on Victor's desktop (victor's credentials: victor:pass@123)."**

### **Complete Solution Steps**

#### **Step 1: Connect to Windows 10 Pivot**
```bash
# RDP to Windows 10 pivot host
xfreerdp /v:<windows10_ip> /u:htb-student /p:HTB_@cademy_stdnt! /cert:ignore

# Example IP from lab environment
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt! /cert:ignore
```

#### **Step 2: Configure Netsh Port Forward**
```cmd
# In Windows 10 Command Prompt (Run as Administrator)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19

# Verify configuration
netsh.exe interface portproxy show v4tov4

# Expected output:
Listen on ipv4:             Connect to ipv4:
Address         Port        Address         Port
--------------- ----------  --------------- ----------
10.129.42.198   8080        172.16.5.19     3389
```

#### **Step 3: Test Port Forward**
```cmd
# Verify port is listening
netstat -an | findstr :8080

# Expected output:
TCP    10.129.42.198:8080     0.0.0.0:0         LISTENING
```

#### **Step 4: Connect to DC through Port Forward**
```bash
# From attack host (Pwnbox)
xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123 /cert:ignore

# This connects: Attack Host → Windows10:8080 → DC:3389
```

#### **Step 5: Navigate to File Location**
```
# Once logged in as victor on DC (172.16.5.19):
1. Open File Explorer
2. Navigate to Desktop
3. Open "Approved Vendors" folder
4. Open "VendorContacts.txt" file
5. Find the approved contact name
```

#### **Step 6: Submit Answer**
```
# Format: 1 space, not case-sensitive
Answer: [Approved contact name from VendorContacts.txt]
```

**Expected File Path:** `C:\Users\victor\Desktop\Approved Vendors\VendorContacts.txt`

---

## **6. Troubleshooting Netsh Issues**

### **Common Problems**

#### **Access Denied Errors**
```cmd
# Problem: Insufficient privileges
Access is denied.

# Solutions:
1. Run Command Prompt as Administrator
   Right-click CMD → "Run as administrator"

2. Verify user privileges
   whoami /priv

3. Check if user is in Administrators group
   net user %username%
```

#### **Port Already in Use**
```cmd
# Problem: Listen port already bound
The process cannot access the file because it is being used by another process.

# Solutions:
1. Check what's using the port
   netstat -ano | findstr :8080

2. Kill process using port
   taskkill /PID <process_id> /F

3. Use different port
   netsh.exe interface portproxy add v4tov4 listenport=8081 ...
```

#### **Connection Refused**
```cmd
# Problem: Cannot connect to forwarded port
Connection refused

# Solutions:
1. Verify port forward exists
   netsh.exe interface portproxy show v4tov4

2. Check Windows Firewall
   netsh advfirewall firewall show rule name=all

3. Test local connectivity
   telnet 172.16.5.19 3389
```

#### **Firewall Blocking**
```cmd
# Problem: Windows Firewall blocking connections
# Solutions:

1. Add firewall exception for port
   netsh advfirewall firewall add rule name="Port 8080" dir=in action=allow protocol=TCP localport=8080

2. Temporarily disable firewall (testing only)
   netsh advfirewall set allprofiles state off

3. Check existing rules
   netsh advfirewall firewall show rule name=all | findstr 8080
```

---

## **7. Management and Cleanup**

### **Listing Port Forwards**
```cmd
# Show all IPv4-to-IPv4 forwards
netsh.exe interface portproxy show v4tov4

# Show all IPv6-to-IPv6 forwards
netsh.exe interface portproxy show v6tov6

# Show all port proxy configurations
netsh.exe interface portproxy show all
```

### **Deleting Port Forwards**
```cmd
# Delete specific IPv4-to-IPv4 forward
netsh.exe interface portproxy delete v4tov4 listenport=8080 listenaddress=10.129.15.150

# Delete all IPv4-to-IPv4 forwards
netsh.exe interface portproxy reset

# Delete specific IPv6 forwards
netsh.exe interface portproxy delete v6tov6 listenport=8080 listenaddress=::1
```

### **Persistent Configuration**
```cmd
# Port forwards created with netsh are persistent across reboots
# They survive system restarts automatically

# To make temporary (session-only) forwards, consider alternatives:
# - SSH local forwarding
# - PowerShell port forwarding scripts
# - Third-party tools
```

---

## **8. Security Considerations**

### **Operational Security (OPSEC)**
1. **Legitimate Tool** - netsh.exe is standard Windows utility
2. **Administrative Logs** - commands logged in Windows Event Log
3. **Persistent Rules** - forwards survive reboots (good for persistence)
4. **Firewall Integration** - works with Windows Firewall
5. **Process Visibility** - no additional processes required

### **Detection Risks**
1. **Command Line Auditing** - PowerShell/CMD logging may capture commands
2. **Event Log Entries** - Windows Security log may record configuration changes
3. **Network Monitoring** - unusual port listeners detectable
4. **Registry Changes** - port proxy rules stored in registry
5. **Forensic Artifacts** - commands may be recoverable from memory/disk

### **Registry Storage**
```cmd
# Port proxy rules stored in registry
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp

# View registry entries
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```

---

## **9. Integration with Other Techniques**

### **Netsh + SSH Tunneling**
```bash
# Combine netsh port forwarding with SSH tunnels
# 1. Create netsh forward on Windows pivot
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=22 connectaddress=172.16.5.100

# 2. SSH through the forward from attack host
ssh -L 9999:172.16.5.19:3389 user@10.129.15.150 -p 8080
```

### **Netsh + Meterpreter**
```ruby
# Use Meterpreter to execute netsh commands
meterpreter > shell
C:\> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.19

# Or use Meterpreter's portfwd along with netsh
meterpreter > portfwd add -l 8081 -p 3389 -r 172.16.5.19
```

### **PowerShell Integration**
```powershell
# PowerShell wrapper for netsh commands
function New-PortForward {
    param(
        [int]$ListenPort,
        [string]$ListenAddress,
        [int]$ConnectPort,
        [string]$ConnectAddress
    )
    
    $cmd = "netsh.exe interface portproxy add v4tov4 listenport=$ListenPort listenaddress=$ListenAddress connectport=$ConnectPort connectaddress=$ConnectAddress"
    Invoke-Expression $cmd
}

# Usage
New-PortForward -ListenPort 8080 -ListenAddress "10.129.15.150" -ConnectPort 3389 -ConnectAddress "172.16.5.19"
```

---

## **10. Advanced Scenarios**

### **Multi-Hop Pivoting**
```cmd
# Chain multiple netsh forwards
# Windows Pivot 1 (DMZ)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=192.168.1.100 connectport=8080 connectaddress=10.0.0.50

# Windows Pivot 2 (Internal)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.0.0.50 connectport=3389 connectaddress=10.0.1.10
```

### **Service-Specific Forwarding**
```cmd
# RDP forwarding
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.19

# SMB forwarding
netsh.exe interface portproxy add v4tov4 listenport=8445 listenaddress=0.0.0.0 connectport=445 connectaddress=172.16.5.19

# WinRM forwarding
netsh.exe interface portproxy add v4tov4 listenport=8985 listenaddress=0.0.0.0 connectport=5985 connectaddress=172.16.5.19

# HTTPS forwarding
netsh.exe interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=443 connectaddress=172.16.5.19
```

### **Load Balancing Simulation**
```cmd
# Forward to multiple backends (manual round-robin)
netsh.exe interface portproxy add v4tov4 listenport=8081 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.5.10
netsh.exe interface portproxy add v4tov4 listenport=8082 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.5.11
netsh.exe interface portproxy add v4tov4 listenport=8083 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.5.12
```

---

## **11. Comparison with Other Windows Tools**

### **Netsh vs Windows Alternatives**

| **Tool** | **Complexity** | **Persistence** | **Admin Required** | **Stealth** |
|----------|----------------|-----------------|-------------------|-------------|
| **Netsh** | Low | High (persistent) | Yes | High |
| **PowerShell** | Medium | Low (script-based) | Depends | Medium |
| **Windows Firewall** | High | High | Yes | High |
| **IIS URL Rewrite** | High | High | Yes | Medium |

### **When to Use Netsh**
✅ **Windows environment** with admin access  
✅ **Persistent forwarding** needed across reboots  
✅ **Simple port forwarding** requirements  
✅ **Living off the land** approach preferred  
✅ **No external tools** can be installed  

### **When NOT to Use Netsh**
❌ **No admin privileges** available  
❌ **Complex routing** requirements  
❌ **Cross-platform** compatibility needed  
❌ **Temporary forwarding** only (creates persistent rules)  
❌ **Stealth operation** (logged extensively)  

---

## **12. Best Practices**

### **Operational Guidelines**
1. **Test locally first** - verify connectivity before deployment
2. **Use non-standard ports** - avoid common port detection
3. **Document configurations** - track created port forwards
4. **Clean up after use** - remove forwards when done
5. **Monitor connections** - watch for unexpected traffic

### **Security Recommendations**
1. **Minimize exposure time** - create forwards only when needed
2. **Use specific bind addresses** - avoid 0.0.0.0 when possible
3. **Implement access controls** - Windows Firewall rules
4. **Monitor event logs** - watch for detection indicators
5. **Rotate ports regularly** - vary port usage patterns

### **Performance Considerations**
1. **Limit concurrent forwards** - avoid resource exhaustion
2. **Monitor bandwidth usage** - track network utilization
3. **Consider connection limits** - Windows has TCP connection limits
4. **Optimize for target services** - tune for specific protocols
5. **Test under load** - verify performance with multiple connections

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 11
- **Microsoft Netsh Documentation**: [Official Netsh Reference](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh)
- **Netsh Portproxy**: [Port Proxy Commands](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy)
- **Windows Network Security**: [Security Considerations](https://docs.microsoft.com/en-us/windows/security/threat-protection/)
- **SANS Windows Pivoting**: [Windows Lateral Movement Techniques](https://www.sans.org/blog/windows-lateral-movement/) 