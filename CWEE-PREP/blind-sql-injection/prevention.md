# 🛡️ Preventing SQL Injection

## Core Principles

1. **Treat all user input as dangerous**
2. **Use parameterized queries**
3. **Apply least privilege**
4. **Defense in depth**

---

## Input Validation / Sanitization

### Always Sanitize

- Validate input format (email, phone, etc.)
- Escape special characters
- Whitelist allowed characters
- Reject unexpected input

### Example Validation

```php
// Validate email format
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    die("Invalid email format");
}

// Whitelist alphanumeric only
if (!preg_match('/^[a-zA-Z0-9]+$/', $_POST['username'])) {
    die("Invalid characters in username");
}
```

---

## Parameterized Queries

### The Problem (Vulnerable Code)

```php
// ❌ VULNERABLE - User input concatenated into query
$sql = "SELECT email FROM accounts WHERE username = '" . $_POST['username'] . "'";
$stmt = sqlsrv_query($conn, $sql);
$row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC);
sqlsrv_free_stmt($stmt);
```

### The Solution (Parameterized)

```php
// ✅ SECURE - User input passed as parameter
$sql = "SELECT email FROM accounts WHERE username = ?";  
$stmt = sqlsrv_query($conn, $sql, array($_POST['username'])); 
$row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC); 
sqlsrv_free_stmt($stmt);
```

### Why It Works

| Approach | Query | Data |
|----------|-------|------|
| Concatenation | Mixed together | Can escape context |
| Parameterized | Sent separately | Treated as literal data |

Server understands what is **code** vs **data**, regardless of input content.

---

## Parameterized Queries by Language

### PHP (PDO)

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['username']]);
```

### Python (psycopg2)

```python
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### Java (PreparedStatement)

```java
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE username = ?");
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

### C# (.NET)

```csharp
SqlCommand cmd = new SqlCommand("SELECT * FROM users WHERE username = @username", conn);
cmd.Parameters.AddWithValue("@username", username);
```

### Node.js (mysql2)

```javascript
connection.execute('SELECT * FROM users WHERE username = ?', [username]);
```

---

## Output Sanitization

> ⚠️ **Don't trust data from the database!**

### Why?

- May have missed input sanitization
- **2nd-level SQL attacks** - execute on output, not input
- Stored XSS from compromised data

### Solution

Apply sanitization/filtering on **data output**, especially user-generated content.

```php
// Escape output for HTML context
echo htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8');
```

---

## MSSQL-Specific Precautions

### Don't Run as Sysadmin!

**Never use `sa` for application queries.**

Use account with **minimal privileges** needed.

### MSSQL Database Roles

| Role | Privileges |
|------|------------|
| `public` | Default role (minimal) |
| `db_datareader` | Read all data |
| `db_datawriter` | Write all data |
| `db_owner` | Full control (DANGEROUS) |

### Recommended Approach

```sql
-- Create limited user
CREATE LOGIN webapp_user WITH PASSWORD = 'StrongPassword123!';
CREATE USER webapp_user FOR LOGIN webapp_user;

-- Grant only needed permissions
GRANT SELECT ON users TO webapp_user;
GRANT INSERT ON orders TO webapp_user;
-- Don't grant more than necessary!
```

---

## Disable Dangerous Functions

### Functions Attackers Abuse

| Function | Attack |
|----------|--------|
| `xp_cmdshell` | Command execution (RCE) |
| `xp_dirtree` | NetNTLM hash leaking |
| `xp_fileexist` | File enumeration |
| `xp_subdirs` | Directory enumeration |
| `OPENROWSET` | File read |

### Revoke Execution Privileges

```sql
-- Revoke xp_dirtree from all public users
REVOKE EXECUTE ON xp_dirtree TO public;

-- Revoke xp_cmdshell
REVOKE EXECUTE ON xp_cmdshell TO public;

-- Revoke xp_fileexist
REVOKE EXECUTE ON xp_fileexist TO public;
```

> **Note**: Don't completely disable functions like `xp_dirtree` - the server uses them internally. Just revoke user access.

---

## Defense in Depth

### Multiple Layers

```
1. Input Validation     → Filter bad input
2. Parameterized Queries → Prevent injection
3. Least Privilege       → Limit damage if exploited
4. WAF                   → Block common payloads
5. Monitoring            → Detect attacks
6. Output Sanitization   → Prevent 2nd-level attacks
```

### WAF Rules

Block common SQLi patterns:
- `' OR 1=1`
- `UNION SELECT`
- `xp_cmdshell`
- `WAITFOR DELAY`

---

## Checklist

### Development

- [ ] Use parameterized queries everywhere
- [ ] Validate all user input
- [ ] Escape output data
- [ ] Use ORM with built-in protections

### Database

- [ ] Application uses non-admin account
- [ ] Minimal privileges granted
- [ ] Dangerous functions revoked
- [ ] Strong passwords for all accounts

### Infrastructure

- [ ] WAF deployed
- [ ] SQL query logging enabled
- [ ] Alerting on suspicious queries
- [ ] Regular security audits

---

## Quick Reference

### Parameterized Query

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
```

### Revoke Dangerous Functions

```sql
REVOKE EXECUTE ON xp_cmdshell TO public;
REVOKE EXECUTE ON xp_dirtree TO public;
```

### Least Privilege User

```sql
CREATE USER app_user FOR LOGIN app_login;
GRANT SELECT, INSERT ON app_tables TO app_user;
```

