# MySQL Enumeration

## Overview
MySQL is an open-source SQL relational database management system developed and supported by Oracle. A database is simply a structured collection of data organized for easy use and retrieval. The database system can quickly process large amounts of data with high performance.

**Key Characteristics:**
- **Port 3306**: Default MySQL port
- **Protocol**: MySQL native protocol over TCP
- **Authentication**: Username/password based
- **Default Users**: root, mysql
- **File Extension**: .sql files (e.g., wordpress.sql)

## MySQL Architecture

### MySQL Clients
The MySQL clients can retrieve and edit data using structured queries to the database engine. Operations include:
- **Inserting**: Adding new records
- **Deleting**: Removing records
- **Modifying**: Updating existing records
- **Retrieving**: Querying data

### MySQL Databases
MySQL is ideally suited for applications such as:
- **Dynamic websites**: Efficient syntax and high response speed
- **Web applications**: Content management systems like WordPress
- **LAMP Stack**: Linux, Apache, MySQL, PHP
- **LEMP Stack**: Linux, Nginx, MySQL, PHP

### Database Content Types
MySQL databases commonly store:

| Content Type | Examples |
|-------------|----------|
| **Headers** | Page titles, meta information |
| **Texts** | Article content, descriptions |
| **Meta tags** | SEO tags, keywords |
| **Forms** | Contact forms, registration data |
| **Users** | Customers, Usernames, Administrators, Moderators |
| **Authentication** | Email addresses, User information, Permissions, Passwords |
| **Links** | External/Internal links, Links to Files |
| **Content** | Specific contents, Values |

**Security Note**: Sensitive data like passwords can be stored in plain-text form by MySQL, but are generally encrypted by PHP scripts using secure methods like One-Way-Encryption.

## MySQL Commands
A MySQL database translates commands internally into executable code. SQL commands can:
- Display, modify, add, or delete rows in tables
- Change table structure
- Create or delete relationships and indexes
- Manage users and permissions

## Default Configuration

### Installation and Configuration Analysis
```bash
# Install MySQL server
sudo apt install mysql-server -y

# Analyze default configuration
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
```

### Default Configuration Output
```bash
[client]
port		= 3306
socket		= /var/run/mysqld/mysqld.sock

[mysqld_safe]
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
nice		= 0

[mysqld]
skip-host-cache
skip-name-resolve
user		= mysql
pid-file	= /var/run/mysqld/mysqld.pid
socket		= /var/run/mysqld/mysqld.sock
port		= 3306
basedir		= /usr
datadir		= /var/lib/mysql
tmpdir		= /tmp
lc-messages-dir	= /usr/share/mysql
explicit_defaults_for_timestamp

symbolic-links=0

!includedir /etc/mysql/conf.d/
```

## Dangerous Settings

### Security-Relevant Configuration Options

| Setting | Description | Risk Level |
|---------|-------------|------------|
| `user` | Sets which user the MySQL service will run as | High |
| `password` | Sets the password for the MySQL user | Critical |
| `admin_address` | IP address for TCP/IP connections on administrative network interface | High |
| `debug` | Indicates current debugging settings | Medium |
| `sql_warnings` | Controls whether single-row INSERT statements produce information strings | Medium |
| `secure_file_priv` | Limits the effect of data import and export operations | High |

### Security Issues
1. **Plain-text Credentials**: user, password, and admin_address entries are in plain text
2. **File Permissions**: Configuration files often have incorrect permissions  
3. **Information Disclosure**: debug and sql_warnings provide verbose error output
4. **Privilege Escalation**: Verbose errors can reveal system information
5. **Command Execution**: SQL injections can potentially execute system commands

## Footprinting the Service

### Service Detection
```bash
# Nmap MySQL detection
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*

# Example comprehensive output
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 00:53 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE     VERSION
3306/tcp open  nagios-nsca Nagios NSCA
| mysql-brute: 
|   Accounts: 
|     root:<empty> - Valid credentials
|_  Statistics: Performed 45010 guesses in 5 seconds, average tps: 9002.0
|_mysql-databases: ERROR: Script execution failed (use -d to debug)
|_mysql-dump-hashes: ERROR: Script execution failed (use -d to debug)
| mysql-empty-password: 
|_  root account has empty password
| mysql-enum: 
|   Valid usernames: 
|     root:<empty> - Valid credentials
|     netadmin:<empty> - Valid credentials
|     guest:<empty> - Valid credentials
|     user:<empty> - Valid credentials
|     web:<empty> - Valid credentials
|     sysadmin:<empty> - Valid credentials
|     administrator:<empty> - Valid credentials
|     webadmin:<empty> - Valid credentials
|     admin:<empty> - Valid credentials
|     test:<empty> - Valid credentials
|_  Statistics: Performed 10 guesses in 1 seconds, average tps: 10.0
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.26-0ubuntu0.20.04.1
|   Thread ID: 13
|   Capabilities flags: 65535
|   Some Capabilities: SupportsLoadDataLocal, SupportsTransactions, Speaks41ProtocolOld, LongPassword, DontAllowDatabaseTableColumn, Support41Auth, IgnoreSigpipes, SwitchToSSLAfterHandshake, FoundRows, InteractiveClient, Speaks41ProtocolNew, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, LongColumnFlag, SupportsCompression, ODBCClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: YTSgMfqvx\x0F\x7F\x16\&\x1EAeK>0
|_  Auth Plugin Name: caching_sha2_password
|_mysql-users: ERROR: Script execution failed (use -d to debug)
|_mysql-variables: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
```

**Important Note**: Scan results should be manually verified as some information might be false-positive.

### Connection Testing
```bash
# Test connection without password (will fail if password required)
mysql -u root -h 10.129.14.132

# Expected error for protected server
ERROR 1045 (28000): Access denied for user 'root'@'10.129.14.1' (using password: NO)

# Connect with discovered/guessed credentials
mysql -u root -pP4SSw0rd -h 10.129.14.128
```

### SSL/TLS Connection Issues
```bash
# Common SSL/TLS error with self-signed certificates
mysql -u robin -probin -h 10.129.42.195
ERROR 2026 (HY000): TLS/SSL error: self-signed certificate in certificate chain

# Solution: Disable SSL verification
mysql -u robin -probin -h 10.129.42.195 --ssl=0

# Alternative SSL options
mysql -u robin -probin -h 10.129.42.195 --ssl-mode=DISABLED
mysql -u robin -probin -h 10.129.42.195 --ssl-mode=REQUIRED --ssl-verify-server-cert=false
mysql -u robin -probin -h 10.129.42.195 --skip-ssl
```

**SSL/TLS Error Types:**
- **ERROR 2026**: TLS/SSL error with self-signed certificates
- **Solution**: Use `--ssl=0` or `--ssl-mode=DISABLED` to bypass SSL verification
- **Security Note**: Only disable SSL in testing environments, not production

## Interaction with MySQL Server

### Successful Connection Example
```bash
mysql -u root -pP4SSw0rd -h 10.129.14.128

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 150165
Server version: 8.0.27-0ubuntu0.20.04.1 (Ubuntu)
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
4 rows in set (0.006 sec)

MySQL [(none)]> select version();
+-------------------------+
| version()               |
+-------------------------+
| 8.0.27-0ubuntu0.20.04.1 |
+-------------------------+
1 row in set (0.001 sec)
```

### System Schema Exploration
```bash
# Use mysql system database
MySQL [(none)]> use mysql;

# Show tables in mysql database
MySQL [mysql]> show tables;
+------------------------------------------------------+
| Tables_in_mysql                                      |
+------------------------------------------------------+
| columns_priv                                         |
| component                                            |
| db                                                   |
| default_roles                                        |
| engine_cost                                          |
| func                                                 |
| general_log                                          |
| global_grants                                        |
| gtid_executed                                        |
| help_category                                        |
| help_keyword                                         |
| help_relation                                        |
| help_topic                                           |
| innodb_index_stats                                   |
| innodb_table_stats                                   |
| password_history                                     |
...SNIP...
| user                                                 |
+------------------------------------------------------+
37 rows in set (0.002 sec)
```

### System Schema (sys) Analysis
```bash
# Use sys database for metadata
mysql> use sys;

# Show sys tables
mysql> show tables;
+-----------------------------------------------+
| Tables_in_sys                                 |
+-----------------------------------------------+
| host_summary                                  |
| host_summary_by_file_io                       |
| host_summary_by_file_io_type                  |
| host_summary_by_stages                        |
| host_summary_by_statement_latency             |
| host_summary_by_statement_type                |
| innodb_buffer_stats_by_schema                 |
| innodb_buffer_stats_by_table                  |
| innodb_lock_waits                             |
| io_by_thread_by_latency                       |
...SNIP...
| x$waits_global_by_latency                     |
+-----------------------------------------------+

# Get host summary information
mysql> select host, unique_users from host_summary;
+-------------+--------------+
| host        | unique_users |
+-------------+--------------+
| 10.129.14.1 |            1 |
| localhost   |            2 |
+-------------+--------------+
2 rows in set (0,01 sec)
```

## Essential MySQL Commands

### Connection and Basic Operations

| Command | Description |
|---------|-------------|
| `mysql -u <user> -p<password> -h <IP address>` | Connect to MySQL server (no space between -p and password) |
| `show databases;` | Show all databases |
| `use <database>;` | Select one of the existing databases |
| `show tables;` | Show all available tables in the selected database |
| `show columns from <table>;` | Show all columns in the selected table |
| `select * from <table>;` | Show everything in the desired table |
| `select * from <table> where <column> = "<string>";` | Search for needed string in the desired table |

### Advanced Query Examples
```bash
# Database exploration
SHOW DATABASES;
USE customers;
SHOW TABLES;
DESCRIBE customers;

# Data extraction
SELECT * FROM customers;
SELECT * FROM customers WHERE name = 'Otto Lang';
SELECT email FROM customers WHERE name = 'Otto Lang';

# User enumeration
SELECT User, Host FROM mysql.user;
SELECT * FROM mysql.user WHERE User='root';
```

## Database Schema Information

### Important System Databases
- **information_schema**: Contains metadata about all databases (ANSI/ISO standard)
- **mysql**: Contains MySQL server system data and configurations
- **performance_schema**: Contains performance monitoring information
- **sys**: Contains system schema with interpreted performance data

**Schema Differences:**
- **System Schema**: Microsoft system catalog (more comprehensive)
- **Information Schema**: ANSI/ISO standard metadata (standardized)

## HTB Academy Lab Questions

### Question 1: Version Detection
**Task**: Enumerate the MySQL server and determine the version in use
**Format**: MySQL X.X.XX

**Solution**:
```bash
# Step 1: Service detection
nmap -p3306 -sV target

# Step 2: Version extraction from nmap output
# Look for: mysql   MySQL 8.0.27-0ubuntu0.20.04.1

# Step 3: Format the answer
# Answer: MySQL 8.0.27
```

### Question 2: Data Extraction
**Task**: Using credentials "robin:robin", find email address of customer "Otto Lang"

**Solution**:
```bash
# Step 1: Connect with provided credentials (with SSL disabled)
mysql -u robin -probin -h target --ssl=0

# Step 2: List all databases
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| customers          |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.085 sec)

# Step 3: Select the customers database
MySQL [(none)]> use customers;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

# Step 4: List tables in the customers database
MySQL [customers]> show tables;
+---------------------+
| Tables_in_customers |
+---------------------+
| myTable             |
+---------------------+
1 row in set (0.078 sec)

# Step 5: Examine table structure
MySQL [customers]> describe myTable;
+-----------+--------------------+------+-----+---------+----------------+
| Field     | Type               | Null | Key | Default | Extra          |
+-----------+--------------------+------+-----+---------+----------------+
| id        | mediumint unsigned | NO   | PRI | NULL    | auto_increment |
| name      | varchar(255)       | YES  |     | NULL    |                |
| email     | varchar(255)       | YES  |     | NULL    |                |
| country   | varchar(100)       | YES  |     | NULL    |                |
| postalZip | varchar(20)        | YES  |     | NULL    |                |
| city      | varchar(255)       | YES  |     | NULL    |                |
| address   | varchar(255)       | YES  |     | NULL    |                |
| pan       | varchar(255)       | YES  |     | NULL    |                |
| cvv       | varchar(255)       | YES  |     | NULL    |                |
+-----------+--------------------+------+-----+---------+----------------+
9 rows in set (0.079 sec)

# Step 6: Extract Otto Lang's email address
MySQL [customers]> SELECT email FROM myTable WHERE name = "Otto Lang";
+---------------------+
| email               |
+---------------------+
| ultrices@google.htb |
+---------------------+
1 row in set (0.078 sec)

# Result: ultrices@google.htb
```

## Security Assessment

### Common Vulnerabilities
1. **Default Credentials**: Testing root with empty password
2. **Weak Passwords**: Common password patterns
3. **Information Disclosure**: Version information, database names
4. **Excessive Privileges**: Users with unnecessary permissions
5. **Configuration Issues**: Dangerous settings enabled
6. **Network Exposure**: MySQL accessible from external networks

### Enumeration Checklist
- [ ] Port scan for 3306
- [ ] Service version detection
- [ ] Default credential testing
- [ ] Anonymous access testing
- [ ] Database enumeration
- [ ] User account discovery
- [ ] Privilege assessment
- [ ] Configuration analysis
- [ ] Data extraction testing

## MariaDB Relationship
**MariaDB** is a fork of MySQL created when Oracle acquired MySQL AB. Key points:
- Created by original MySQL chief developer
- Based on MySQL source code
- Often used interchangeably with MySQL
- Compatible with MySQL protocols and commands
- Common in Linux distributions

## Reference Documentation
- **MySQL Reference Manual**: Comprehensive configuration options
- **Security Issues Section**: Best practices for securing MySQL servers
- **HTB Academy**: Practical enumeration techniques
- **Penetration Testing**: Real-world attack scenarios 