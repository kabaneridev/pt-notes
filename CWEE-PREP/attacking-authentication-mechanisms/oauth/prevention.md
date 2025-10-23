# OAuth Vulnerability Prevention

To prevent critical OAuth vulnerabilities seen in previous scenarios, both the client and authorization server must implement strict security practices:

---

## Core Prevention Checklist
- **Always validate redirect_uri:** Only exact, pre-registered URIs should be allowed. No wildcards, subdomains, userinfo tricks or open redirects!
- **Enforce the state parameter:** Make it mandatory for all flows and always validate it. Never use predictable state values.
- **Prefer Authorization Code Grant:** Use code grant instead of implicit. Never expose tokens directly to the browser if not strictly necessary.
- **Enforce HTTPS everywhere:** All tokens must be transported and stored over secure (encrypted) channels.
- **Validate token audience/scope:** Clients must ensure tokens are meant for them (never blindly accept tokens from elsewhere).
- **Input sanitization:** Sanitize all GET/POST/query params and reflect nothing unescaped in authorization forms (protect against XSS).
- **No token/credential storage in URLs, logs, or browser storage.**
- **OAuth servers:** Regularly audit code/configs, perform security/pentest reviews, keep dependencies up to date.
- **Consider Multi-Factor Authentication:** Enhance credential security with one-time codes, biometrics, etc., to reduce impact if account hijack occurs.

---

## Responsibilities
- **Authorization Server:** Strictly validate and enforce all standards (redirect_uri, state, scope/audience, etc.). Provide secure registration and documentation to clients.
- **Clients:** Never try to "DIY" the protocol. Use mature OAuth client libraries and follow all recommendations from server/provider.

---

**Summary:**
- OAuth security is only as strong as the least secure participant. Strict validation, safe-by-default configs, and regular review are essential to prevent vulnerabilities leading to token theft, CSRF, or account compromise.
