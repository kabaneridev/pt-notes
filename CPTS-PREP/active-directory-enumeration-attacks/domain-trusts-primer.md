# 🔗 **Domain Trusts Primer**

## 🎯 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

**Domain Trusts** are authentication relationships between Active Directory domains/forests that allow users to access resources across domain boundaries. Understanding trust relationships is critical for penetration testers as they often provide unintended attack paths and "end-around" routes into target environments, especially in M&A scenarios where security may not have been properly considered during trust establishment.

---

## 🏗️ **Domain Trust Types**

### **Trust Classifications**

| Trust Type | Description | Use Case |
|------------|-------------|----------|
| **Parent-child** | Two-way transitive trust within same forest | Child domain ↔ Parent domain authentication |
| **Cross-link** | Trust between child domains | Speed up authentication between siblings |
| **External** | Non-transitive trust between separate forests | Business partnerships, limited access |
| **Tree-root** | Two-way transitive between forest root and new tree | New tree root domain creation |
| **Forest** | Transitive trust between forest root domains | Complete forest-to-forest access |
| **ESAE** | Bastion forest for AD management | High-security administrative isolation |

### **Trust Properties**

#### **Transitivity:**
- **Transitive**: Trust extends through relationships (A→B→C = A→C)
- **Non-transitive**: Direct trust only, no extension

#### **Direction:**
- **One-way**: Trusted domain users access trusting domain resources
- **Bidirectional**: Mutual access between both domains

---

## 🔍 **Trust Enumeration Techniques**

### **Method 1: Built-in AD Module**
```powershell
# Import Active Directory module
Import-Module activedirectory

# Enumerate all domain trusts
Get-ADTrust -Filter *
```

### **Method 2: PowerView**
```powershell
# Basic trust enumeration
Get-DomainTrust

# Comprehensive trust mapping
Get-DomainTrustMapping

# Cross-domain user enumeration
Get-DomainUser -Domain CHILD.DOMAIN.LOCAL | select SamAccountName
```

### **Method 3: netdom**
```cmd
# Query domain trusts
netdom query /domain:inlanefreight.local trust

# Query domain controllers
netdom query /domain:inlanefreight.local dc

# Query workstations and servers
netdom query /domain:inlanefreight.local workstation
```

### **Method 4: BloodHound**
- **Pre-built query**: "Map Domain Trusts"
- **Visual representation**: Trust relationships and directions
- **Attack path analysis**: Trust-based privilege escalation routes

---

## 🎯 **HTB Academy Lab Solutions**

### **Lab Environment Setup**
```bash
# RDP connection to target
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!

# PowerShell preparation
cd C:\Tools\
Import-Module .\PowerView.ps1
```

### **🔍 Question 1: "What is the child domain of INLANEFREIGHT.LOCAL?"**

**Solution:**
```powershell
# Enumerate domain trust relationships
Get-DomainTrustMapping

# Lab output analysis:
SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST          # ← Child domain indicator
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 6:20:22 PM
WhenChanged     : 3/29/2022 5:14:31 PM

SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE      # ← Forest trust indicator
TrustDirection  : Bidirectional
WhenCreated     : 11/1/2021 8:07:09 PM
WhenChanged     : 3/29/2022 4:48:04 PM
```

**🎯 Answer: `LOGISTICS.INLANEFREIGHT.LOCAL`**

**Analysis**: Look for `TrustAttributes : WITHIN_FOREST` to identify child domains.

### **🌲 Question 2: "What domain does INLANEFREIGHT.LOCAL have a forest transitive trust with?"**

**Solution:**
```powershell
# Same Get-DomainTrustMapping output analysis
# Look for TrustAttributes : FOREST_TRANSITIVE
```

**🎯 Answer: `FREIGHTLOGISTICS.LOCAL`**

**Analysis**: Look for `TrustAttributes : FOREST_TRANSITIVE` to identify forest trusts.

### **↔️ Question 3: "What direction is this trust?"**

**Solution:**
```powershell
# From same Get-DomainTrustMapping output
# Check TrustDirection field for FREIGHTLOGISTICS.LOCAL trust
```

**🎯 Answer: `Bidirectional`**

**Analysis**: `TrustDirection : Bidirectional` indicates mutual access between forests.

---

## ⚠️ **Security Implications**

### **Attack Vectors Through Trusts**
- **Cross-domain privilege escalation**: Compromise child → attack parent
- **Forest-to-forest attacks**: External trust exploitation
- **Kerberoasting across trusts**: Service accounts in trusted domains
- **"End-around" attacks**: Target softer trusted domains for indirect access

### **Assessment Considerations**
- **Scope verification**: Ensure trusted domains are within Rules of Engagement
- **Trust purpose analysis**: Legitimate business need vs security risk
- **Bidirectional risk**: Mutual access increases attack surface
- **M&A trust reviews**: Recently acquired companies may have weaker security posture

---

## 🔑 **Key Takeaways**

### **Trust Enumeration Workflow**
```
PowerView Trust Mapping → Trust Type Analysis → Cross-Domain Enumeration → Attack Path Planning
    (Get-DomainTrustMapping)    (WITHIN_FOREST vs     (Get-DomainUser)      (Privilege Escalation)
                               FOREST_TRANSITIVE)
```

### **Critical Trust Attributes**
- **WITHIN_FOREST**: Child domain relationship (high attack value)
- **FOREST_TRANSITIVE**: External forest trust (lateral movement opportunity)
- **Bidirectional**: Mutual access (increased attack surface)

### **Professional Impact**
- **Reconnaissance foundation**: Trust discovery enables advanced attack planning
- **Risk assessment**: Understanding trust implications for organizational security
- **Attack path identification**: Trust relationships often provide privilege escalation routes

**🔗 Domain trust enumeration provides critical infrastructure mapping for advanced Active Directory attacks - essential foundation for trust-based privilege escalation and cross-domain exploitation!**

--- 