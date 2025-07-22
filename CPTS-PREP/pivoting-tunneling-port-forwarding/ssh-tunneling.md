# 🔐 SSH Tunneling - CPTS

## **Overview**

SSH tunneling is one of the most reliable and commonly used methods for pivoting and port forwarding. SSH provides encrypted tunnels that can bypass firewalls and access internal services.

---

## **SSH Tunnel Types**

### **1. Local Port Forwarding (-L)**

**Purpose:** Forward local port to remote destination through SSH server

**Syntax:**
```bash
ssh -L [local_ip:]local_port:destination_host:destination_port user@ssh_server

# Common usage
ssh -L 8080:192.168.1.100:80 user@10.10.10.50
```

**Traffic Flow:**
```
[Your Machine] → [SSH Server/Pivot] → [Target Service]
localhost:8080 → 10.10.10.50:22 → 192.168.1.100:80
```

**Real-world Examples:**
```bash
# Access internal web server
ssh -L 8080:192.168.1.100:80 user@pivot.com
# Then browse: http://localhost:8080

# Access internal RDP
ssh -L 3389:192.168.1.50:3389 user@pivot.com
# Then RDP to: localhost:3389

# Access database server
ssh -L 1433:db.internal.com:1433 user@jumpbox.com

# Forward multiple ports
ssh -L 8080:web.internal:80 -L 3389:dc.internal:3389 user@pivot.com
```

### **2. Remote Port Forwarding (-R)**

**Purpose:** Forward remote port back to local machine (reverse tunnel)

**Syntax:**
```bash
ssh -R [remote_ip:]remote_port:local_host:local_port user@remote_server

# Common usage
ssh -R 8080:127.0.0.1:80 user@remote.com
```

**Traffic Flow:**
```
[Remote Machine] → [SSH Server] → [Your Local Service]
remote:8080 → your_machine:22 → localhost:80
```

**Use Cases:**
```bash
# Expose local web server to remote network
ssh -R 8080:127.0.0.1:80 user@target.com

# Expose local listener for reverse shells
ssh -R 4444:127.0.0.1:4444 user@target.com

# Expose local SMB share
ssh -R 445:127.0.0.1:445 user@target.com
```

### **3. Dynamic Port Forwarding (-D)**

**Purpose:** Create SOCKS proxy for multiple connections

**Syntax:**
```bash
ssh -D [local_ip:]local_port user@ssh_server

# Common usage
ssh -D 1080 user@10.10.10.50
```

**Configuration:**
```bash
# Set up SOCKS proxy
ssh -D 1080 user@pivot.com

# Configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf

# Use with tools
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains firefox
```

---

## **SSH Options and Flags**

### **Essential Flags**
```bash
-L    # Local port forwarding
-R    # Remote port forwarding  
-D    # Dynamic port forwarding (SOCKS)
-N    # Don't execute remote command (useful for tunneling only)
-f    # Fork into background
-q    # Quiet mode
-T    # Disable pseudo-terminal allocation
-C    # Enable compression
-g    # Allow remote hosts to connect to forwarded ports
```

### **Practical Combinations**
```bash
# Background tunnel with no shell
ssh -fNT -L 8080:192.168.1.100:80 user@pivot.com

# Multiple port forwards in background
ssh -fNT -L 8080:web.internal:80 -L 3389:dc.internal:3389 user@pivot.com

# SOCKS proxy in background
ssh -fNT -D 1080 user@pivot.com

# Compressed tunnel for slow connections
ssh -fNTC -D 1080 user@pivot.com
```

---

## **Advanced SSH Tunneling**

### **Multiple Hops (ProxyJump)**
```bash
# SSH through multiple hosts
ssh -J user1@hop1.com,user2@hop2.com user3@final-target.com

# Port forward through multiple hops
ssh -J user@pivot1.com -L 8080:internal.local:80 user@pivot2.com
```

### **SSH Config File**
```bash
# ~/.ssh/config
Host pivot
    HostName 10.10.10.50
    User pentester
    Port 22
    LocalForward 8080 192.168.1.100:80
    LocalForward 3389 192.168.1.50:3389
    DynamicForward 1080

# Usage
ssh pivot
```

### **Persistent Tunnels with autossh**
```bash
# Install autossh
apt install autossh

# Persistent tunnel that reconnects
autossh -M 20000 -fNT -L 8080:192.168.1.100:80 user@pivot.com

# Monitor port 20000 for connection health
# Automatically reconnects if connection drops
```

---

## **Troubleshooting SSH Tunnels**

### **Common Issues**

**1. Permission Denied**
```bash
# Check SSH key permissions
chmod 600 ~/.ssh/id_rsa
chmod 644 ~/.ssh/id_rsa.pub
chmod 700 ~/.ssh/

# Test SSH connection first
ssh -v user@pivot.com
```

**2. Port Already in Use**
```bash
# Check what's using the port
netstat -tlnp | grep :8080
lsof -i :8080

# Kill process or use different port
ssh -L 8081:192.168.1.100:80 user@pivot.com
```

**3. Connection Refused**
```bash
# Test from SSH server first
ssh user@pivot.com
curl http://192.168.1.100:80

# Check if service is running on target
nmap -p 80 192.168.1.100
```

**4. GatewayPorts Issue**
```bash
# Allow external connections to forwarded ports
ssh -g -L 0.0.0.0:8080:192.168.1.100:80 user@pivot.com

# Or set in SSH server config (/etc/ssh/sshd_config)
GatewayPorts yes
```

### **Debugging Commands**
```bash
# Verbose SSH output
ssh -v -L 8080:192.168.1.100:80 user@pivot.com

# Check tunnel status
netstat -tlnp | grep :8080
ss -tlnp | grep :8080

# Test tunnel connectivity
curl -v http://localhost:8080
nc -v localhost 8080
```

---

## **SSH Tunneling in Different Scenarios**

### **Scenario 1: Web Application Testing**
```bash
# Set up tunnel to internal web app
ssh -fNT -L 8080:internal-web.corp.com:80 user@jumpbox.corp.com

# Set up Burp Suite proxy
ssh -fNT -L 8080:internal-web.corp.com:80 -L 8443:internal-web.corp.com:443 user@jumpbox.corp.com

# Access through browser
firefox http://localhost:8080
```

### **Scenario 2: Database Access**
```bash
# Access internal SQL Server
ssh -fNT -L 1433:sql.internal.corp:1433 user@jumpbox.corp.com

# Connect with sqlcmd
sqlcmd -S localhost,1433 -U sa -P password

# Access MySQL
ssh -fNT -L 3306:mysql.internal.corp:3306 user@jumpbox.corp.com
mysql -h 127.0.0.1 -P 3306 -u root -p
```

### **Scenario 3: RDP/VNC Access**
```bash
# Forward RDP port
ssh -fNT -L 3389:windows.internal.corp:3389 user@jumpbox.corp.com

# Connect with rdesktop
rdesktop localhost:3389

# Forward VNC port
ssh -fNT -L 5900:linux.internal.corp:5900 user@jumpbox.corp.com
vncviewer localhost:5900
```

---

## **SSH Tunneling with Metasploit**

### **Using SSH Sessions**
```bash
# Get SSH session in Metasploit
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.50
set USERNAME user
set PASSWORD password
run

# Use session for port forwarding
sessions -i 1
portfwd add -l 8080 -p 80 -r 192.168.1.100
```

---

## **Security Considerations**

### **SSH Server Configuration**
```bash
# Secure SSH config (/etc/ssh/sshd_config)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding yes
GatewayPorts no
ClientAliveInterval 60
```

### **Key Management**
```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -f ~/.ssh/pivot_key

# Copy public key to target
ssh-copy-id -i ~/.ssh/pivot_key.pub user@pivot.com

# Use specific key
ssh -i ~/.ssh/pivot_key user@pivot.com
```

### **Firewall Evasion**
```bash
# Use non-standard SSH port
ssh -p 2222 user@pivot.com

# SSH over HTTP tunnel (if needed)
# Use tools like HTTPTunnel or similar
```

---

## **Best Practices**

1. **Always test basic SSH connectivity first**
2. **Use key-based authentication when possible**
3. **Clean up tunnels after use (`kill` background processes)**
4. **Monitor tunnel stability with `autossh`**
5. **Use compression (-C) for slow connections**
6. **Employ least privilege (specific ports only)**
7. **Log tunnel activities for documentation**

---

## **Quick Reference**

| **Task** | **Command** |
|----------|-------------|
| Local forward | `ssh -L 8080:target:80 user@pivot` |
| Remote forward | `ssh -R 8080:localhost:80 user@target` |
| SOCKS proxy | `ssh -D 1080 user@pivot` |
| Background tunnel | `ssh -fNT -L 8080:target:80 user@pivot` |
| Multiple ports | `ssh -L 8080:web:80 -L 3389:dc:3389 user@pivot` |
| Through jump host | `ssh -J jump.com -L 8080:target:80 user@final` |

---

## **References**

- SSH Manual: `man ssh`
- SSH Config: `man ssh_config`
- OpenSSH Cookbook: https://en.wikibooks.org/wiki/OpenSSH
- HTB Academy: Pivoting, Tunneling & Port Forwarding 