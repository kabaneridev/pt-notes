# SNMP (Simple Network Management Protocol) Enumeration

## Overview
Simple Network Management Protocol (SNMP) is a network protocol used for monitoring and managing network devices. SNMP can reveal extensive information about network infrastructure, system configuration, and running processes, making it valuable for both administration and penetration testing.

**Key Characteristics:**
- **Port 161**: SNMP (UDP) - Queries and commands
- **Port 162**: SNMP Traps (UDP) - Unsolicited notifications  
- **Versions**: SNMPv1, SNMPv2c, SNMPv3
- **Authentication**: Community strings (v1/v2c), user-based (v3)
- **Data Structure**: Management Information Base (MIB)

**SNMP Communication:**
- **Traditional**: Client actively requests information from server
- **Traps**: Server sends data packets to client without explicit request
- **Addressing**: Uses Object Identifiers (OIDs) for unique addressing

## MIB (Management Information Base)
MIB is an independent format for storing device information in a standardized tree hierarchy. It contains:
- **Object Identifier (OID)**: Unique address for each object
- **Name**: Human-readable identifier  
- **Type**: Data type specification
- **Access Rights**: Read/write permissions
- **Description**: Object functionality description

**Key MIB Characteristics:**
- Written in Abstract Syntax Notation One (ASN.1) format
- ASCII text-based
- Explains where to find information and data types
- Does not contain actual data, only structure definitions

## OID (Object Identifier)
OIDs represent nodes in a hierarchical namespace using dot notation:
- **Structure**: Sequence of numbers (e.g., 1.3.6.1.2.1.1.1.0)
- **Hierarchy**: Longer chains = more specific information
- **Universal**: Standardized across vendors and systems
- **Registry**: Many OIDs documented in Object Identifier Registry

## SNMP Versions

| Version | Security | Authentication | Description |
|---------|----------|----------------|-------------|
| **SNMPv1** | None | Community string | Original version, no encryption, no built-in authentication |
| **SNMPv2c** | None | Community string | Improved performance, community-based, no encryption |
| **SNMPv3** | Yes | User-based | Username/password authentication, encryption via pre-shared key, high complexity |

**Detailed Version Analysis:**
- **SNMPv1**: First version, still used in small networks, supports information retrieval, device configuration, and traps, but lacks authentication and encryption
- **SNMPv2c**: Extended version with additional functions, community string transmitted in plain text, no built-in encryption
- **SNMPv3**: Significantly increased security with authentication and encryption, but also increased complexity requiring more configuration

## Default Configuration

The default SNMP daemon configuration defines basic settings including IP addresses, ports, MIB, OIDs, authentication, and community strings.

### Example SNMP Daemon Config (`/etc/snmp/snmpd.conf`)
```bash
# View SNMP daemon configuration
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'

# Example configuration:
sysLocation    Sitting on the Dock of the Bay
sysContact     Me <me@example.org>
sysServices    72
master  agentx
agentaddress  127.0.0.1,[::1]
view   systemonly  included   .1.3.6.1.2.1.1
view   systemonly  included   .1.3.6.1.2.1.25.1
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
rouser authPrivUser authpriv -V systemonly
```

**Key Configuration Parameters:**
- **sysLocation**: Physical location description
- **sysContact**: Administrative contact (often contains email)
- **sysServices**: Services provided by the entity
- **agentaddress**: IP addresses and ports for SNMP agent
- **rocommunity**: Read-only community string configuration
- **rouser**: Read-only user configuration for SNMPv3

## Dangerous Settings

Some dangerous settings that administrators can configure with SNMP:

| Setting | Description | Risk Level |
|---------|-------------|------------|
| `rwuser noauth` | Provides access to full OID tree without authentication | Critical |
| `rwcommunity <community> <IPv4>` | Provides access to full OID tree regardless of request source | Critical |
| `rwcommunity6 <community> <IPv6>` | Same as rwcommunity but for IPv6 addresses | Critical |

**High-Risk Configuration Examples:**
```bash
# DANGEROUS: Write access without authentication
rwuser noauth

# DANGEROUS: Write access from any source
rwcommunity public 0.0.0.0/0

# DANGEROUS: IPv6 write access from any source  
rwcommunity6 public ::/0
```

## Community Strings

Community strings act as passwords that determine whether requested information can be viewed or not. They are transmitted in plain text, making them vulnerable to interception.

**Key Issues with Community Strings:**
- Lack of encryption in SNMPv1/v2c
- Transmitted over network in plain text
- Can be intercepted and read
- Many organizations still use default values
- Often bound to specific IP addresses but with predictable patterns

### Common Default Community Strings
```bash
# Read-only community strings
public
private
community
snmp
read
manager
admin
guest

# Read-write community strings
private
write
admin
root
```

**Community String Patterns:**
- Often named with hostname of the host
- Sometimes include symbols to make identification harder
- In large networks (100+ servers), labels follow patterns
- Can be brute-forced using custom wordlists

## Enumeration Techniques

### 1. Service Detection
```bash
# Nmap SNMP detection
nmap -sU -p161 target

# Comprehensive SNMP enumeration
nmap -sU -p161 --script snmp-info,snmp-netstat,snmp-processes target
```

### 2. Community String Brute Force
```bash
# Using onesixtyone for community string brute forcing
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt target

# Custom community string list
onesixtyone -c community_strings.txt target

# Using snmpwalk to test community strings
snmpwalk -v2c -c public target
snmpwalk -v2c -c private target
```

### 3. SNMP Walking
```bash
# Basic SNMP walk
snmpwalk -v2c -c public target

# Walk specific OID
snmpwalk -v2c -c public target 1.3.6.1.2.1.1

# Save output for analysis
snmpwalk -v2c -c public target | tee snmp_output.txt
```

### 4. Specific Information Gathering
```bash
# System information
snmpwalk -v2c -c public target 1.3.6.1.2.1.1.1.0

# Network interfaces
snmpwalk -v2c -c public target 1.3.6.1.2.1.2.2.1.2

# Process information
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.1.6.0

# User accounts
snmpwalk -v2c -c public target 1.3.6.1.4.1.77.1.2.25
```

### 5. Using Braa for OID Brute Forcing
```bash
# Install braa
sudo apt install braa

# Basic braa syntax
braa <community_string>@<IP>:.1.3.6.*

# Example usage
braa public@target:.1.3.6.*

# Braa example output
target:20ms:.1.3.6.1.2.1.1.1.0:Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64
target:20ms:.1.3.6.1.2.1.1.2.0:.1.3.6.1.4.1.8072.3.2.10
target:20ms:.1.3.6.1.2.1.1.3.0:548
target:20ms:.1.3.6.1.2.1.1.4.0:mrb3n@inlanefreight.htb
target:20ms:.1.3.6.1.2.1.1.5.0:htb
target:20ms:.1.3.6.1.2.1.1.6.0:US
target:20ms:.1.3.6.1.2.1.1.7.0:78
```

### 6. Detailed SNMP Walking with Real Output
```bash
# Complete SNMP walk example
snmpwalk -v2c -c public target

# Example detailed output analysis:
iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic #36~20.04.1-Ubuntu SMP Fri Aug 27 08:06:32 UTC 2021 x86_64"
iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "htb"
iso.3.6.1.2.1.1.6.0 = STRING: "Sitting on the Dock of the Bay"

# Extract Python packages (software enumeration):
iso.3.6.1.2.1.25.6.3.1.2.1232 = STRING: "printer-driver-sag-gdi_0.1-7_all"
iso.3.6.1.2.1.25.6.3.1.2.1233 = STRING: "printer-driver-splix_2.0.0+svn315-7fakesync1build1_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1234 = STRING: "procps_2:3.3.16-1ubuntu2.3_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1235 = STRING: "proftpd-basic_1.3.6c-2_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1236 = STRING: "proftpd-doc_1.3.6c-2_all"
iso.3.6.1.2.1.25.6.3.1.2.1243 = STRING: "python3_3.8.2-0ubuntu2_amd64"
iso.3.6.1.2.1.25.6.3.1.2.1244 = STRING: "python3-acme_1.1.0-1_all"
iso.3.6.1.2.1.25.6.3.1.2.1245 = STRING: "python3-apport_2.20.11-0ubuntu27.21_all"
```

## Important OIDs (Object Identifiers)

### System Information OIDs
```bash
# System description
1.3.6.1.2.1.1.1.0

# System contact (admin email)
1.3.6.1.2.1.1.4.0

# System name
1.3.6.1.2.1.1.5.0

# System location
1.3.6.1.2.1.1.6.0

# System uptime
1.3.6.1.2.1.1.3.0
```

### Network Information OIDs
```bash
# Network interfaces
1.3.6.1.2.1.2.2.1.2

# IP addresses
1.3.6.1.2.1.4.20.1.1

# Routing table
1.3.6.1.2.1.4.21.1.1

# ARP table
1.3.6.1.2.1.4.22.1.2
```

### Process and Service OIDs
```bash
# Running processes
1.3.6.1.2.1.25.1.6.0

# Process table
1.3.6.1.2.1.25.4.2.1.2

# Service information
1.3.6.1.2.1.25.1.7.1.2

# Software installed
1.3.6.1.2.1.25.6.3.1.2
```

## Advanced Enumeration

### Using Nmap NSE Scripts
```bash
# Comprehensive SNMP enumeration
nmap -sU -p161 --script snmp-info,snmp-netstat,snmp-processes,snmp-sysdescr target

# SNMP brute force community strings
nmap -sU -p161 --script snmp-brute target

# SNMP interface information
nmap -sU -p161 --script snmp-interfaces target

# SNMP system information
nmap -sU -p161 --script snmp-system-info target
```

### Custom OID Queries
```bash
# Query specific OID
snmpget -v2c -c public target 1.3.6.1.2.1.1.4.0

# Query multiple OIDs
snmpget -v2c -c public target 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.4.0

# Walk specific branch
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.1.7
```

## Information Extraction

### System Administrator Contact
```bash
# Extract admin email from system contact
snmpwalk -v2c -c public target 1.3.6.1.2.1.1.4.0

# Example output analysis:
# iso.3.6.1.2.1.1.4.0 = STRING: "devadmin <devadmin@inlanefreight.htb>"
# Admin email: devadmin@inlanefreight.htb
```

### Custom Version Information
```bash
# Extract custom SNMP version
snmpwalk -v2c -c public target 1.3.6.1.2.1.1.6.0

# Example output:
# iso.3.6.1.2.1.1.6.0 = STRING: "InFreight SNMP v0.91"
```

### Running Processes and Scripts
```bash
# Extract custom scripts and processes
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.1.7.1.2

# Look for custom scripts like:
# iso.3.6.1.2.1.25.1.7.1.2.1.2.4.70.76.65.71 = STRING: "/usr/share/flag.sh"
```

## Practical Examples

### HTB Academy Style Enumeration
```bash
# Step 1: Community string brute force
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt target
# Result: Found community string "backup"

# Step 2: SNMP walking with found community string
snmpwalk -v2c -c backup target

# Step 3: Extract admin email
snmpwalk -v2c -c backup target | grep -i "@"
# Result: devadmin@inlanefreight.htb

# Step 4: Extract custom version
snmpwalk -v2c -c backup target | grep -i "version"
# Result: InFreight SNMP v0.91

# Step 5: Look for custom scripts and flags
snmpwalk -v2c -c backup target | grep -i "htb\|flag"
# Result: HTB{5nMp_fl4g_uidhfljnsldiuhbfsdij44738b2u763g}
```

### HTB Academy Lab Questions Examples
```bash
# Question 1: "Enumerate the SNMP service and obtain the email address of the admin"
# Step 1: Find valid community string
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt target
# Step 2: Extract admin contact
snmpwalk -v2c -c found_community target 1.3.6.1.2.1.1.4.0
# Look for: iso.3.6.1.2.1.1.4.0 = STRING: "admin <admin@inlanefreight.htb>"
# Answer: admin@inlanefreight.htb

# Question 2: "What is the customized version of the SNMP server?"
# Extract from system location or custom OID
snmpwalk -v2c -c found_community target 1.3.6.1.2.1.1.6.0
# Look for: iso.3.6.1.2.1.1.6.0 = STRING: "InFreight SNMP v0.91"
# Answer: InFreight SNMP v0.91

# Question 3: "Enumerate the custom script that is running on the system"
# Look for custom scripts in process/service OIDs
snmpwalk -v2c -c found_community target 1.3.6.1.2.1.25.1.7.1.2
# Look for custom script paths like:
# iso.3.6.1.2.1.25.1.7.1.2.1.2.4.70.76.65.71 = STRING: "/usr/share/flag.sh"
# Execute or analyze the script output
# Answer: Script output or HTB{...} flag
```

### Real Output Analysis from HTB Academy
```bash
# Example misconfigured SNMP server output
snmpwalk -v2c -c public target

# Key information to extract:
# 1. System contact (admin email):
iso.3.6.1.2.1.1.4.0 = STRING: "mrb3n@inlanefreight.htb"

# 2. Installed packages (reconnaissance):
iso.3.6.1.2.1.25.6.3.1.2.1235 = STRING: "proftpd-basic_1.3.6c-2_amd64"

# 3. System information:
iso.3.6.1.2.1.1.1.0 = STRING: "Linux htb 5.11.0-34-generic"

# 4. Network interfaces and configuration details

# This information reveals:
# - Admin contact: mrb3n@inlanefreight.htb
# - ProFTPD installed (potential attack vector)
# - Linux system details
# - Network configuration
```

### Information Parsing
```bash
# Parse SNMP output for specific information
snmpwalk -v2c -c public target > snmp_full.txt

# Extract email addresses
grep -i "@" snmp_full.txt

# Extract IP addresses
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' snmp_full.txt

# Extract file paths
grep -oE '"/[^"]*"' snmp_full.txt

# Extract process information
grep -i "process\|service" snmp_full.txt
```

## Security Assessment

### Common Vulnerabilities
1. **Default Community Strings**: Using default "public" or "private"
2. **Information Disclosure**: Excessive information exposure
3. **Weak Community Strings**: Easily guessable strings
4. **SNMPv1/v2c Usage**: Unencrypted protocols
5. **Write Access**: Unauthorized configuration changes

### Community String Testing
```bash
# Test common community strings
for community in public private community snmp read manager admin; do
    echo "Testing: $community"
    snmpwalk -v2c -c $community target 1.3.6.1.2.1.1.1.0
done
```

## Enumeration Checklist

### Initial Discovery
- [ ] Port scan for 161/UDP
- [ ] Service version detection
- [ ] SNMP version identification
- [ ] Community string brute force

### Information Gathering
- [ ] System information extraction
- [ ] Network interface enumeration
- [ ] Process and service discovery
- [ ] User account identification

### Detailed Analysis
- [ ] Custom script identification
- [ ] Configuration file discovery
- [ ] Credential extraction
- [ ] Network topology mapping

### Security Testing
- [ ] Write access testing
- [ ] Information disclosure assessment
- [ ] Weak community string identification
- [ ] Encryption status verification

## Tools and Techniques

### Essential SNMP Tools
```bash
# Basic tools
snmpwalk             # SNMP tree walking
snmpget              # Specific OID queries
snmpset              # SNMP value setting (if write access)

# Enumeration tools
onesixtyone          # Community string brute forcing
braa                 # OID brute forcing and fast SNMP scanner
snmp-check           # Comprehensive SNMP enumeration
nmap                 # NSE script-based enumeration

# Analysis tools
snmptranslate        # OID translation
snmpnetstat          # Network statistics via SNMP
```

### Tool Installation and Usage
```bash
# Install SNMP tools
sudo apt install snmp snmp-mibs-downloader

# Install onesixtyone
sudo apt install onesixtyone

# Install braa
sudo apt install braa

# Download MIBs
sudo download-mibs

# Tool comparison:
# - snmpwalk: Comprehensive but slower
# - onesixtyone: Fast community string discovery
# - braa: Fast OID enumeration and bulk queries
# - nmap: Integrated with other reconnaissance
```

### Custom Scripts
```bash
# SNMP community string tester
#!/bin/bash
target=$1
wordlist=$2

while read community; do
    result=$(snmpwalk -v2c -c $community $target 1.3.6.1.2.1.1.1.0 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo "Found valid community: $community"
    fi
done < $wordlist

# SNMP information extractor
#!/bin/bash
target=$1
community=$2

echo "System Information:"
snmpwalk -v2c -c $community $target 1.3.6.1.2.1.1

echo "Network Interfaces:"
snmpwalk -v2c -c $community $target 1.3.6.1.2.1.2.2.1.2

echo "Process Information:"
snmpwalk -v2c -c $community $target 1.3.6.1.2.1.25.1.6.0
```

## Defensive Measures

### Secure SNMP Configuration
```bash
# Disable SNMP if not needed
systemctl stop snmpd
systemctl disable snmpd

# Configure SNMPv3 with authentication
# In /etc/snmp/snmpd.conf:
createUser myuser MD5 mypassword DES
rouser myuser

# Disable SNMPv1/v2c
# Remove community string configurations
```

### Best Practices
1. **Use SNMPv3**: Implement encryption and authentication
2. **Strong Community Strings**: Use complex, unique strings
3. **Access Controls**: Limit SNMP access by IP/network
4. **Minimal Exposure**: Only expose necessary information
5. **Regular Audits**: Monitor SNMP access and configuration

### Detection and Monitoring
```bash
# Monitor SNMP access
tcpdump -i any port 161

# Check SNMP logs
tail -f /var/log/snmpd.log

# Analyze unusual SNMP queries
grep "snmp" /var/log/syslog
```

## Common Attack Vectors

### 1. Information Gathering
- Network topology discovery
- System configuration extraction
- User account enumeration
- Process and service identification

### 2. Credential Harvesting
- Extract stored passwords
- Identify service accounts
- Discover configuration files
- Find backup credentials

### 3. Network Reconnaissance
- ARP table analysis
- Routing table examination
- Interface configuration review
- Network device identification
