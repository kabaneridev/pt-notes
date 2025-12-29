# 🚀 HTTP Request Smuggling/Desync Attacks

## Overview

HTTP Request Smuggling (also known as HTTP Desync attacks) exploits discrepancies in how front-end servers (reverse proxies, load balancers, CDNs) and back-end servers parse HTTP requests. When these components disagree on request boundaries, attackers can "smuggle" malicious requests through security controls.

## How It Works

Modern web architectures typically involve:

```
[Client] → [Front-end/Reverse Proxy] → [Back-end Server]
```

The front-end and back-end servers may interpret request boundaries differently based on:
- **Content-Length (CL)** header - specifies exact body length in bytes
- **Transfer-Encoding (TE)** header - uses chunked encoding

When both headers are present, servers may disagree on which to use, creating a **desynchronization**.

## Vulnerability Types

| Type | Front-end Uses | Back-end Uses | Description |
|------|----------------|---------------|-------------|
| **CL.TE** | Content-Length | Transfer-Encoding | Front-end doesn't support chunked encoding |
| **TE.CL** | Transfer-Encoding | Content-Length | Back-end doesn't support chunked encoding |
| **TE.TE** | Transfer-Encoding | Transfer-Encoding | One server can be induced to ignore TE header |

## RFC 2616 Specification

According to the HTTP/1.1 specification:

> If a message is received with both a Transfer-Encoding header field and a Content-Length header field, the latter MUST be ignored.

However, not all implementations follow this correctly.

## Attack Impact

- **Bypass security controls** (WAFs, access controls)
- **Cache poisoning**
- **Session hijacking**
- **Credential theft**
- **Force users to perform unintended actions**

## Detection Methodology

1. Send request with both CL and TE headers
2. Observe timing differences or error responses
3. Verify with differential responses technique
4. Confirm by influencing subsequent requests

## Tools

- **Burp Suite** - Manual testing with Repeater
- **smuggler.py** - Automated detection
- **HTTP Request Smuggler** (Burp extension)

## Prerequisites for Exploitation

1. HTTP/1.1 connection (HTTP/2 handles this differently)
2. Connection reuse between front-end and back-end
3. Discrepancy in header parsing between components

---

## Section Contents

- [CL.TE Vulnerabilities](cl-te.md)
- [TE.CL Vulnerabilities](te-cl.md)
- [TE.TE Vulnerabilities](te-te.md)
- [Prevention](prevention.md)

