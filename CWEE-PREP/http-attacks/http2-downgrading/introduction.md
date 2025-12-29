# 🌐 Introduction to HTTP/2

## What is HTTP/2?

HTTP/2 was introduced in **2015** with improvements while maintaining backward compatibility.

### Key Differences from HTTP/1.1

| Feature | HTTP/1.1 | HTTP/2 |
|---------|----------|--------|
| **Format** | Text-based (string) | Binary protocol |
| **Readability** | Human-readable | Not human-readable |
| **Multiplexing** | One request per connection | Multiple streams |
| **Server Push** | Not supported | Supported |
| **Header Compression** | None | HPACK compression |

---

## HTTP/2 Pseudo-Headers

HTTP/2 uses pseudo-headers instead of traditional request line.

### HTTP/1.1 Request

```http
GET /index.php HTTP/1.1
Host: http2.htb
```

### HTTP/2 Equivalent

```
:method     GET
:path       /index.php
:authority  http2.htb
:scheme     https
```

### Pseudo-Headers Reference

| Header | Description |
|--------|-------------|
| `:method` | HTTP method (GET, POST, etc.) |
| `:scheme` | Protocol (http or https) |
| `:authority` | Similar to Host header |
| `:path` | Requested path + query string |

> **Note**: Burp displays HTTP/2 requests in HTTP/1.1 format. View pseudo-headers in **Burp Inspector**.

---

## HTTP/2 Security Improvements

### No Chunked Encoding

From RFC:
> The "chunked" transfer encoding MUST NOT be used in HTTP/2.

### Built-in Length Mechanism

- Data frames contain **built-in length field**
- No explicit `Content-Length` needed
- Eliminates CL/TE ambiguity

### Result

**Request smuggling is nearly impossible** when HTTP/2 is used correctly end-to-end.

---

## Detection in Burp

### Identifying HTTP/2

1. Send request to Repeater
2. Check **Inspector** panel
3. Look for pseudo-headers:
   - `:scheme`
   - `:method`
   - `:path`
   - `:authority`

### Protocol Indicator

```
Request Attributes:
  Protocol: HTTP/2
```

---

## Why HTTP/2 Can Still Be Vulnerable

Despite security improvements, vulnerabilities arise when:

1. **HTTP/2 Downgrading** - Proxy converts to HTTP/1.1
2. **Improper header validation** - CL/TE headers accepted in HTTP/2
3. **Character handling** - CRLF injection via pseudo-headers

See [HTTP/2 Downgrading](downgrading.md) for exploitation techniques.

---

## References

- [HTTP/2 RFC 9113](https://httpwg.org/specs/rfc9113.html)
- [RFC 9113 Section 8.3.1 - Pseudo-Headers](https://httpwg.org/specs/rfc9113.html#rfc.section.8.3.1)
