# MSSQL Enumeration

## Overview
Microsoft SQL (MSSQL) is Microsoft's SQL-based relational database management system. Unlike MySQL, which is open-source, MSSQL is closed source and was initially written to run on Windows operating systems. It is popular among database administrators and developers when building applications that run on Microsoft's .NET framework due to its strong native support for .NET.

**Key Characteristics:**
- **Port 1433**: Default MSSQL port
- **Authentication**: Windows Authentication or SQL Server Authentication
- **Default Instance**: MSSQLSERVER
- **Protocol**: Tabular Data Stream (TDS)
- **Platform**: Primarily Windows (Linux/MacOS versions available)

## MSSQL Clients

### SQL Server Management Studio (SSMS)
**SQL Server Management Studio (SSMS)** comes as a feature that can be installed with the MSSQL install package or downloaded separately. Key points:
- Commonly installed on the server for initial configuration
- Can be installed on any system for remote database management
- May contain saved credentials on vulnerable systems
- Provides full database management capabilities

### Alternative MSSQL Clients
| Client | Description |
|--------|-------------|
| **mssql-cli** | Command-line interface for MSSQL |
| **SQL Server PowerShell** | PowerShell module for MSSQL |
| **HeidiSQL** | Lightweight GUI client |
| **SQLPro** | Professional database client |
| **Impacket's mssqlclient.py** | Python-based client (preferred for pentesting) |

### Locating Impacket MSSQL Client
```bash
# Find impacket mssqlclient location
locate mssqlclient

# Common locations:
/usr/bin/impacket-mssqlclient
/usr/share/doc/python3-impacket/examples/mssqlclient.py
```

## Default System Databases

MSSQL has default system databases that help understand the structure of all databases hosted on a target server:

| Database | Description |
|----------|-------------|
| **master** | Tracks all system information for an SQL server instance |
| **model** | Template database that acts as a structure for every new database created |
| **msdb** | Used by SQL Server Agent to schedule jobs & alerts |
| **tempdb** | Stores temporary objects |
| **resource** | Read-only database containing system objects included with SQL server |

## Default Configuration

### Initial Setup
When an admin initially installs and configures MSSQL to be network accessible:
- **Service Account**: SQL service runs as `NT SERVICE\MSSQLSERVER`
- **Authentication**: Windows Authentication by default
- **Encryption**: Not enforced by default
- **Access Control**: Uses Windows OS for authentication processing

### Authentication Methods
1. **Windows Authentication**: 
   - Uses local SAM database or domain controller
   - Integrates with Active Directory
   - Can lead to privilege escalation if compromised

2. **SQL Server Authentication**:
   - Uses database-specific user accounts
   - Independent of Windows authentication

## Dangerous Settings

Common misconfigurations that can lead to security issues:

| Setting | Risk Level | Description |
|---------|------------|-------------|
| **No encryption** | High | MSSQL clients not using encryption to connect |
| **Self-signed certificates** | Medium | Can be spoofed during attacks |
| **Named pipes enabled** | Medium | Additional attack surface |
| **Default SA credentials** | Critical | Weak or unchanged SA account passwords |
| **SA account enabled** | High | Admins may forget to disable default SA account |

## Footprinting the Service

### Comprehensive Nmap Scan
```bash
# Complete MSSQL enumeration with all scripts
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 target
```

### Example Nmap Output Analysis
```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-08 09:40 EST
Nmap scan report for target
Host is up (0.15s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: SQL-01
|   NetBIOS_Domain_Name: SQL-01
|   NetBIOS_Computer_Name: SQL-01
|   DNS_Domain_Name: SQL-01
|   DNS_Computer_Name: SQL-01
|_  Product_Version: 10.0.17763

Host script results:
| ms-sql-dac: 
|_  Instance: MSSQLSERVER; DAC port: 1434 (connection failed)
| ms-sql-info: 
|   Windows server name: SQL-01
|   target\MSSQLSERVER: 
|     Instance name: MSSQLSERVER
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|     TCP port: 1433
|     Named pipe: \\target\pipe\sql\query
|_    Clustered: false
```

**Key Information Extracted:**
- **Hostname**: SQL-01
- **Instance**: MSSQLSERVER
- **Version**: Microsoft SQL Server 2019 RTM (15.00.2000.00)
- **Named Pipes**: Enabled (\\target\pipe\sql\query)
- **Clustering**: Not clustered

### Metasploit MSSQL Ping Scanner
```bash
# Use Metasploit auxiliary scanner
msf6 > use auxiliary/scanner/mssql/mssql_ping
msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts target
msf6 auxiliary(scanner/mssql/mssql_ping) > run

# Example output:
[*] target:       - SQL Server information for target:
[+] target:       -    ServerName      = SQL-01
[+] target:       -    InstanceName    = MSSQLSERVER
[+] target:       -    IsClustered     = No
[+] target:       -    Version         = 15.0.2000.5
[+] target:       -    tcp             = 1433
[+] target:       -    np              = \\SQL-01\pipe\sql\query
[*] target:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

## Connecting with mssqlclient.py

### Windows Authentication
```bash
# Connect using Windows authentication
python3 mssqlclient.py Administrator@target -windows-auth

# Example connection output:
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-01): Line 1: Changed database context to 'master'.
[*] INFO(SQL-01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
```

### Basic Database Enumeration
```bash
# List all databases
SQL> select name from sys.databases

name                                                                                                                               
--------------------------------------------------------------------------------------
master                                                                                                                             
tempdb                                                                                                                             
model                                                                                                                              
msdb                                                                                                                               
Transactions
```

### SQL Server Authentication
```bash
# Connect with SQL Server authentication
python3 mssqlclient.py sa@target

# Connect with specific credentials
python3 mssqlclient.py backdoor@target -windows-auth
```

## Advanced Enumeration

### Database Information Gathering
```bash
# Get MSSQL version
SQL> SELECT @@version;

# Get server information
SQL> SELECT @@servername;

# Get database information
SQL> SELECT name, database_id FROM sys.databases;

# Get user information
SQL> SELECT name FROM sys.server_principals WHERE type = 'S';

# Get database permissions
SQL> SELECT * FROM sys.database_permissions;
```

### System Information
```bash
# Get system configuration
SQL> SELECT name, value FROM sys.configurations WHERE name = 'xp_cmdshell';

# Get linked servers
SQL> SELECT * FROM sys.servers;

# Get database files
SQL> SELECT name, physical_name FROM sys.master_files;
```

## HTB Academy Lab Questions

### Question 1: Hostname Detection
**Task**: Enumerate the target and list the hostname of MSSQL server

**Solution**:
```bash
# Step 1: Comprehensive nmap scan
sudo nmap --script ms-sql-info,ms-sql-ntlm-info -p1433 target

# Step 2: Extract hostname from nmap output
# Look for:
# |   Target_Name: SQL-01
# |   Windows server name: SQL-01

# Answer: SQL-01
```

### Question 2: Non-Default Database Discovery
**Task**: Connect using account (backdoor:Password1) and list non-default database

**Solution**:
```bash
# Step 1: Connect with provided credentials
python3 mssqlclient.py backdoor@target -windows-auth
# Password: Password1

# Step 2: List all databases
SQL> select name from sys.databases;

# Step 3: Identify non-default databases
# Default databases: master, tempdb, model, msdb, resource
# Non-default database: Look for custom database names

# Example result: "Employees" or "Transactions"
```

## Enumeration Techniques

### 1. Service Detection
```bash
# Basic MSSQL detection
nmap -p1433 -sV target

# Comprehensive enumeration
nmap -p1433 --script ms-sql-info,ms-sql-config,ms-sql-tables target
```

### 2. Authentication Testing
```bash
# Test Windows authentication
impacket-mssqlclient administrator@target -windows-auth

# Test SQL Server authentication
impacket-mssqlclient sa@target

# Test with specific credentials
impacket-mssqlclient backdoor@target -windows-auth
```

### 3. Database Analysis
```bash
# List databases
SELECT name FROM sys.databases;

# Use specific database
USE database_name;

# List tables
SELECT name FROM sys.tables;

# Query table data
SELECT * FROM table_name;
```

## Security Assessment

### Common Vulnerabilities
1. **Default Credentials**: SA account with weak passwords
2. **Windows Authentication**: Compromised domain accounts
3. **Missing Encryption**: Plaintext communication
4. **Excessive Permissions**: Over-privileged database users
5. **Outdated Software**: Unpatched MSSQL instances

### Enumeration Checklist
- [ ] Port scan for 1433
- [ ] Service version detection
- [ ] Hostname extraction
- [ ] Authentication method testing
- [ ] Default credential testing
- [ ] Database enumeration
- [ ] System database analysis
- [ ] Custom database discovery
- [ ] User and permission assessment

## Attack Vectors

### 1. Credential-based Access
```bash
# Brute force SA account
hydra -l sa -P passwords.txt mssql://target

# Password spraying
crackmapexec mssql target -u users.txt -p passwords.txt
```

### 2. Command Execution
```bash
# Enable xp_cmdshell
SQL> EXEC sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;

# Execute commands
SQL> EXEC xp_cmdshell 'whoami';
```

### 3. Data Extraction
```bash
# Extract sensitive data
SQL> SELECT * FROM sys.sql_logins;

# Access system databases
SQL> USE master;
SQL> SELECT * FROM sys.server_principals;
```

## Tools and Techniques

### Essential Tools
```bash
# Impacket mssqlclient
impacket-mssqlclient user@target -windows-auth

# Nmap scripts
nmap --script ms-sql-* target

# Metasploit modules
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
```

## Defensive Measures

### Security Best Practices
1. **Disable SA account**: Use Windows Authentication only
2. **Enable encryption**: Force SSL/TLS connections
3. **Least privilege**: Restrict database permissions
4. **Regular updates**: Apply security patches
5. **Monitor access**: Enable audit logging
6. **Network security**: Firewall restrictions 