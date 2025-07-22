# 🔀 Pivoting, Tunneling & Port Forwarding - CPTS Overview

## **Module Introduction**

This module covers pivoting, tunneling, and port forwarding techniques essential for CPTS certification. Based on HTB Academy's comprehensive course, these techniques allow penetration testers to:

- **Pivot**: Use compromised machines as stepping stones to access other network segments
- **Tunnel**: Encapsulate traffic through established connections to bypass network restrictions  
- **Port Forward**: Redirect network traffic from one port to another to access services

---

## **What You'll Learn**

### **Core Concepts**
- Understanding network segmentation and NAT
- Identifying pivot opportunities 
- Traffic flow analysis and routing
- Security implications of tunneling

### **Practical Techniques**
- SSH port forwarding (Local, Remote, Dynamic)
- SOCKS proxy implementation
- Tool integration through proxychains
- Multiple hop scenarios
- Modern tunneling tools (Chisel, Ligolo-ng)

### **Real-world Applications**
- DMZ to internal network pivoting
- Firewall bypass techniques
- Multi-segment network traversal
- Maintaining persistent access

---

## **Network Scenarios Covered**

### **Typical Corporate Network**
```
[Internet] → [Edge Router] → [Firewall] → [DMZ] → [Internal Firewall] → [LAN]
                                         ↓                               ↓
                                   Web Servers                    Workstations
                                   Mail Servers                   Domain Controllers
                                                                 Database Servers
```

### **Common Pivot Points**
- **Web servers in DMZ** with internal network access
- **Jump boxes** with multiple network interfaces
- **VPN endpoints** bridging networks
- **Dual-homed hosts** spanning network segments

---

## **Module Structure**

### **📁 File Organization**
```
pivoting-tunneling-port-forwarding/
├── pivoting-overview.md              # This overview file
├── dynamic-port-forwarding.md        # SSH SOCKS tunneling (HTB Page 3)
├── remote-port-forwarding.md         # SSH Remote/Reverse forwarding (HTB Page 4)
├── ssh-tunneling.md                  # Complete SSH forwarding guide
├── proxychains-socks.md              # Proxychains configuration and usage
├── chisel-tunneling.md               # Modern HTTP tunneling
├── ligolo-ng.md                      # Next-gen tunneling agent
├── metasploit-pivoting.md            # MSF autoroute and pivoting
├── windows-pivoting-tools.md         # Windows native tools
├── dns-icmp-tunneling.md             # Alternative tunneling protocols
└── skills-assessment.md              # Practical scenarios and labs
```

### **📚 Learning Path**
1. **Start Here**: [Dynamic Port Forwarding](./dynamic-port-forwarding.md) - HTB Academy Page 3 foundation
2. **Reverse Shells**: [Remote Port Forwarding](./remote-port-forwarding.md) - HTB Academy Page 4 (Meterpreter)
3. **SSH Mastery**: [SSH Tunneling](./ssh-tunneling.md) - Complete SSH techniques
4. **Tool Integration**: [Proxychains & SOCKS](./proxychains-socks.md) - Tool tunneling
5. **Modern Tools**: [Chisel](./chisel-tunneling.md) and [Ligolo-ng](./ligolo-ng.md)
6. **Framework Integration**: [Metasploit Pivoting](./metasploit-pivoting.md)
7. **Practice**: [Skills Assessment](./skills-assessment.md) - Hands-on scenarios

---

## **Key HTB Academy Concepts**

### **Dynamic Port Forwarding (Page 3)**
Based on HTB Academy module demonstrating:
- **Local Port Forwarding (-L)**: Access specific services
- **Dynamic Port Forwarding (-D)**: Create SOCKS proxy
- **Network Discovery**: Scanning internal networks via pivot
- **Tool Integration**: Nmap, Metasploit, RDP through proxychains

### **Remote/Reverse Port Forwarding (Page 4)**
Advanced HTB Academy scenarios covering:
- **Remote Port Forwarding (-R)**: Expose local services to remote networks
- **Reverse Shell Pivoting**: Meterpreter payload through pivot host
- **Network Isolation**: When targets can't directly reach attack host
- **Payload Delivery**: File transfer and execution through pivot

**Lab Scenario:**
```
Attack Host (10.10.15.x) ← Ubuntu Server (10.129.202.64) ← Windows Target (172.16.5.19)
MSF Handler :8000          SSH -R :8080 Forward              Meterpreter Payload
```

**Network Topology:**
```
Attack Host (10.10.15.x) → Ubuntu Server (10.129.202.64) → Internal Network (172.16.5.0/23)
                           ens192: 10.129.202.64         ens224: 172.16.5.129
```

### **Traffic Flow Understanding**
```
[Attack Host] → [SOCKS Client] → [SSH Tunnel] → [Pivot Host] → [Target Network]
     ↓              ↓               ↓              ↓              ↓
Tool Request → Proxychains → SSH Port 22 → Internal Interface → Target Service
```

---

## **Essential Commands Quick Reference**

### **SSH Tunneling**
| **Technique** | **Command** | **Use Case** |
|---------------|-------------|--------------|
| Local Forward | `ssh -L 1234:target:3306 user@pivot` | Access specific service |
| Dynamic Forward | `ssh -D 9050 user@pivot` | SOCKS proxy for multiple tools |
| Remote Forward | `ssh -R 8080:localhost:80 user@pivot` | Expose local service |
| Background Tunnel | `ssh -fNT -D 9050 user@pivot` | Persistent background proxy |

### **Proxychains Integration**
```bash
# Configure proxychains
echo "socks4 127.0.0.1 9050" >> /etc/proxychains.conf

# Use tools through proxy
proxychains nmap -Pn -sT 172.16.5.19
proxychains msfconsole
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### **Network Discovery**
```bash
# Check pivot interfaces
ifconfig  # Linux
ipconfig /all  # Windows

# Scan internal networks
proxychains nmap -sn 172.16.5.1-200
proxychains nmap -Pn -sT -p 22,80,135,139,443,445,3389 172.16.5.19
```

---

## **Common Network Ranges**

| **Range** | **Type** | **Description** |
|-----------|----------|-----------------|
| `10.0.0.0/8` | Private | Class A private networks |
| `172.16.0.0/12` | Private | Class B private networks |
| `192.168.0.0/16` | Private | Class C private networks |
| `169.254.0.0/16` | Link-Local | APIPA addresses |
| `127.0.0.0/8` | Loopback | Localhost |

---

## **Pivoting Opportunities Identification**

### **Multi-homed Hosts**
```bash
# Linux
ip route show
ip addr show
arp -a

# Windows  
route print
ipconfig /all
arp -a
```

### **Network Connectivity Testing**
```bash
# Test common private ranges
ping -c 1 192.168.1.1
ping -c 1 10.10.10.1
ping -c 1 172.16.1.1

# Port connectivity
nc -zv 192.168.1.100 22
telnet 172.16.5.19 3389
```

### **Service Discovery**
```bash
# Through SOCKS proxy
proxychains nmap -Pn -sT --top-ports 1000 172.16.5.0/24
proxychains masscan -p1-65535 --rate=1000 172.16.5.0/24
```

---

## **Tool Compatibility Matrix**

| **Tool** | **SSH Tunnel** | **SOCKS Proxy** | **HTTP Tunnel** | **Notes** |
|----------|----------------|-----------------|-----------------|-----------|
| **Nmap** | ✅ (Local Forward) | ✅ (TCP Connect only) | ✅ | Use -sT scan type |
| **Metasploit** | ✅ | ✅ | ✅ | Full framework support |
| **Web Browsers** | ✅ | ✅ | ✅ | Configure proxy settings |
| **cURL/wget** | ✅ | ✅ | ✅ | Use --proxy flag |
| **Database Tools** | ✅ | ✅ | ✅ | Connect to forwarded ports |
| **RDP/VNC** | ✅ | ✅ | ✅ | Remote desktop access |

---

## **Security Considerations**

### **Operational Security (OPSEC)**
1. **Encrypt tunnels** when possible (SSH, HTTPS)
2. **Mimic legitimate traffic** patterns
3. **Use standard ports** when feasible (80, 443, 53)
4. **Clean up** connections after assessment
5. **Monitor** tunnel stability and performance

### **Network Detection**
- **DPI (Deep Packet Inspection)** may detect tunneling
- **Traffic analysis** can reveal unusual patterns
- **Connection monitoring** may alert on new services
- **Log correlation** might expose pivot activities

---

## **Troubleshooting Guide**

### **Common Issues**
| **Problem** | **Cause** | **Solution** |
|-------------|-----------|--------------|
| Connection timeout | Firewall blocking | Try different ports/protocols |
| DNS resolution fails | DNS not proxied | Enable proxy_dns in proxychains |
| Slow performance | Network latency | Use compression (-C flag) |
| Tool incompatibility | Partial packet support | Use TCP connect scans only |

### **Debugging Commands**
```bash
# Check tunnel status
netstat -antp | grep :9050
ss -tlnp | grep :9050

# Test connectivity
nc -v 127.0.0.1 9050
telnet 127.0.0.1 9050

# Verbose output
proxychains -v nmap target
ssh -v -D 9050 user@pivot
```

---

## **Lab Environment Setup**

### **HTB Academy Lab Scenario**
**Credentials:**
- Ubuntu Server: `ubuntu:HTB_@cademy_stdnt!`
- Windows Target: `victor:pass@123`

**Network Topology:**
```
Attack Host → Ubuntu Server (10.129.202.64) → Windows DC (172.16.5.19)
            ens192: 10.129.202.64       ens224: 172.16.5.129
```

**Objectives:**
1. Enumerate network interfaces on pivot
2. Set up SOCKS proxy via SSH
3. Scan internal network through proxy
4. Access Windows host via RDP
5. Retrieve flag from Desktop

---

## **Best Practices Checklist**

### **Pre-Assessment**
- [ ] Map network topology
- [ ] Identify trust relationships  
- [ ] Locate multi-homed hosts
- [ ] Test basic connectivity

### **During Assessment**
- [ ] Use encrypted tunnels
- [ ] Monitor connection stability
- [ ] Document tunnel configurations
- [ ] Test tool compatibility

### **Post-Assessment**
- [ ] Clean up all connections
- [ ] Remove configuration files
- [ ] Document findings
- [ ] Verify cleanup completion

---

## **Exam Tips for CPTS**

### **Key Skills to Master**
1. **Quick tunnel setup** under time pressure
2. **Tool integration** through proxies
3. **Multi-hop scenarios** planning
4. **Troubleshooting** common issues
5. **Documentation** of pivot paths

### **Practice Scenarios**
- Set up tunnels in under 2 minutes
- Chain multiple pivots successfully  
- Use various tools through proxies
- Handle connection failures gracefully
- Maintain operational security

---

## **Next Steps**

1. **Start with Dynamic Port Forwarding**: Review HTB Academy Page 3 concepts
2. **Practice SSH Tunneling**: Master all forwarding types
3. **Learn Proxychains**: Configure and use with various tools
4. **Explore Modern Tools**: Chisel and Ligolo-ng alternatives
5. **Complete Skills Assessment**: Hands-on lab scenarios

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding Module
- **SSH Documentation**: `man ssh`, `man ssh_config`
- **Proxychains**: `/etc/proxychains.conf` configuration
- **SOCKS Protocol**: RFC 1928 (SOCKS5), RFC 1929 (Authentication)
- **Network Fundamentals**: RFC 1918 (Private Address Space) 