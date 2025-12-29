# 🛡️ HTTP/2 Tools & Prevention

## Tools of the Trade

### HTTP Request Smuggler (Burp Extension)

The same Burp extension used for HTTP/1.1 smuggling works for HTTP/2.

---

## CL.0 Vulnerability Scanning

### What is CL.0?

Another name for **H2.CL** vulnerability where:
- `Content-Length: 0` is set
- Request body contains only the smuggled request

### Running the Scan

1. Send any HTTP/2 request to Repeater:

```http
GET /index.php?param1=HelloWorld HTTP/2
Host: http2.htb
```

2. Right-click → **Extensions** → **HTTP Request Smuggler** → **CL.0**

3. Leave default settings, press **Enter**

4. View results in **Extensions** → **Installed** → **HTTP Request Smuggler** → **Output**

### Example Output

```
Queueing request scan: CL.0
Found issue: CL.0 desync: h2CL|TRACE /
Target: https://172.17.0.2

Evidence: 
======================================
GET /index.php HTTP/2
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com

======================================
POST /index.php HTTP/1.1
Host: 172.17.0.2:8443
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

TRACE / HTTP/1.1
X-YzBqv: 
======================================
```

### Verifying the Finding

**Request 1** (Smuggling):

```http
POST /index.php HTTP/1.1
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

TRACE / HTTP/1.1
X-YzBqv: 
```

**Request 2** (Probe):

```http
GET /index.php HTTP/2
Host: 172.17.0.2:8443
Origin: https://wguglsurkz2.com
```

### Expected Results

| Request | Response |
|---------|----------|
| Request 1 | 200 OK (normal index) |
| Request 2 | **405 Method Not Allowed** |

405 on Request 2 = **Vulnerability confirmed!**

---

## Verification Steps

1. Create **tab group** in Burp Repeater
2. **Uncheck** "Update Content-Length" for first request
3. Send via **separate TCP connections** (to prove cross-user impact)
4. Check for different response on second request

---

## HTTP/2 Prevention

### Root Cause

**HTTP/2 downgrading** is the primary cause of these vulnerabilities.

```
Problem:  HTTP/2 → Proxy → HTTP/1.1 → Backend
Solution: HTTP/2 → Proxy → HTTP/2 → Backend
```

### Prevention Strategies

#### 1. End-to-End HTTP/2

```
✅ Implement HTTP/2 between ALL components
✅ No protocol downgrading
✅ Eliminates rewriting vulnerabilities
```

#### 2. Disable HTTP/1.1 Fallback

```
✅ Configure proxy to reject HTTP/1.1 backend
✅ Force HTTP/2 or fail
```

#### 3. Proper Header Validation

```
✅ Validate CL header matches actual body
✅ Reject TE header in HTTP/2 requests
✅ Check for forbidden characters (CR, LF, NUL)
```

#### 4. Update Software

```
✅ Apply security patches
✅ Monitor CVEs for proxy software
✅ Test after updates
```

---

### Configuration Examples

#### Nginx (Force HTTP/2 to Backend)

```nginx
upstream backend {
    server backend:443;
    # Force HTTP/2
    http2_push_preload on;
}
```

#### HAProxy

```
# Reject mixed protocols
http-request deny if !{ ssl_fc_alpn -i h2 }
```

---

## Summary

| Tool | Purpose |
|------|---------|
| **HTTP Request Smuggler** | Automated CL.0/H2.CL detection |
| **Burp Repeater** | Manual verification |
| **Tab Groups** | Sequential request testing |

### Prevention Priority

1. 🔄 **HTTP/2 end-to-end** - Eliminate downgrading
2. ✅ **Validate headers** - CL must match body
3. 🚫 **Reject TE in HTTP/2** - Per RFC
4. 🔍 **Validate characters** - No CR/LF/NUL in headers

---

## References

- [HTTP Request Smuggler - BApp Store](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
- [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [HTTP/2 RFC 9113](https://httpwg.org/specs/rfc9113.html)

