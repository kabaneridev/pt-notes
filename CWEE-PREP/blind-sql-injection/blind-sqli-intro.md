# 🔍 Introduction to Blind SQL Injection

## Non-Blind vs Blind SQLi

### Non-Blind SQL Injection

The "easy-to-exploit" type where results are **returned to the attacker**.

**Example**: Vulnerable search feature

```sql
' UNION SELECT table_name, table_schema FROM information_schema.tables;--
```

Result: Tables listed directly in the response.

---

### Blind SQL Injection

Attacker **doesn't see query results** - must rely on **differences in response** to infer data.

**Example**: Login form uses input in query but doesn't return output.

---

## Two Categories of Blind SQLi

| Type | Detection Method |
|------|------------------|
| **Boolean-based** (Content-based) | Differences in response (length, content) |
| **Time-based** | Response time differences |

> **Note**: All time-based techniques work in boolean-based scenarios. The opposite is **not possible**.

---

## Boolean-Based SQLi

### How It Works

1. Inject query that evaluates to **True** or **False**
2. Observe **response differences**
3. Infer data bit by bit

### Detection Signals

| True Response | False Response |
|---------------|----------------|
| Longer response | Shorter response |
| "Email found" | "Email not found" |
| HTTP 200 | HTTP 500 |
| Content differs | Different content |

---

## Vulnerable Code Example

```php
<?php
$connectionInfo = Array(
    "UID" => "db_user", 
    "PWD" => "db_P@55w0rd#", 
    "Database" => "prod"
);
$conn = sqlsrv_connect("SQL05", $connectionInfo);

// VULNERABLE - unsanitized input
$sql = "SELECT * FROM accounts WHERE email = '" . $_POST['email'] . "'";

$stmt = sqlsrv_query($conn, $sql);
$row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC);

if ($row === null) {
    echo "Email found";
} else {
    echo "Email not found";
}
?>
```

### Vulnerability Analysis

| Issue | Description |
|-------|-------------|
| **No sanitization** | `$_POST['email']` directly concatenated |
| **String interpolation** | Input placed inside SQL string |
| **Different responses** | "Found" vs "Not found" = oracle |

### Exploitation Logic

```
Inject: ' OR 1=1--
Query:  SELECT * FROM accounts WHERE email = '' OR 1=1--'
Result: Always true → "Email found"

Inject: ' AND 1=2--
Query:  SELECT * FROM accounts WHERE email = '' AND 1=2--'
Result: Always false → "Email not found"
```

---

## Time-Based SQLi

### How It Works

1. Inject **sleep/delay** command
2. Measure **response time**
3. Long response = True, Normal = False

### Common Delay Functions

| Database | Function |
|----------|----------|
| **MSSQL** | `WAITFOR DELAY '0:0:5'` |
| **MySQL** | `SLEEP(5)` |
| **PostgreSQL** | `pg_sleep(5)` |
| **Oracle** | `DBMS_LOCK.SLEEP(5)` |

### Example Payload

```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

| Condition | Response Time |
|-----------|---------------|
| 1=1 (True) | ~5 seconds |
| 1=2 (False) | Immediate |

---

## Comparison

| Aspect | Boolean-Based | Time-Based |
|--------|---------------|------------|
| **Detection** | Response content/length | Response time |
| **Speed** | Faster | Slower |
| **Reliability** | More reliable | Network latency issues |
| **Stealth** | Less detectable | Delays may trigger alerts |
| **Compatibility** | Needs visible difference | Works when no visible diff |

---

## When to Use Each

### Boolean-Based

✅ Response differs based on query result
✅ Need faster extraction
✅ Stable network conditions

### Time-Based

✅ No visible response difference
✅ Error messages suppressed
✅ Boolean detection not possible

---

## Key Takeaways

1. **Blind SQLi** = No direct output, infer from differences
2. **Boolean-based** = Content/length differences
3. **Time-based** = Response time differences
4. **Root cause** = Same as regular SQLi (unsanitized input)
5. **Exploitation** = Requires custom scripts for data extraction

---

## Next Steps

- [Boolean-Based Exploitation](boolean-based.md)
- [Time-Based Exploitation](time-based.md)

