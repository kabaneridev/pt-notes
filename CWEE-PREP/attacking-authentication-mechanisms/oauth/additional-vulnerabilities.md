# Additional OAuth Vulnerabilities

OAuth integrations can introduce further critical vulnerabilities, especially when the client or authorization server mishandle untrusted input.

---

## 1. Reflected Cross-Site Scripting (XSS)
- Parameters such as `client_id`, `redirect_uri`, and `state` submitted in OAuth authorization flows are often reflected in authorization forms/pages.
- If any of these values are unsanitized, an attacker can inject malicious code (e.g. `<script>alert(1)</script>` as state).
- Example workflow:
  - Attacker crafts authorization URL with e.g. `state=<script>alert(1)</script>`
  - Victim opens the link, and is served a page where script executes in authentication context of the authorization server (session hijack possible!)

---

## 2. Open Redirect & Chaining Vulnerabilities
- Even with correct origin/host-based whitelisting on `redirect_uri`, an OAuth client with an open redirect can be chained into a code/token stealing attack.
- Example:
   - OAuth client hosts callback at: `http://academy.htb/callback`, and ALSO has open redirect at: `http://academy.htb/redirect?u=...`
   - Authorization server only checks that `redirect_uri` starts with `http://academy.htb/`
   - Attacker submits `redirect_uri=http://academy.htb/redirect?u=http://attacker.htb/callback`
   - OAuth flow completes, code delivered first to open redirect, which immediately bounces to attacker — code gets stolen!
- Mitigation: Whitelist only exact, pre-registered callback URIs; fix any open redirects in client applications.

---

## 3. Abusing Malicious Clients (Client Impersonation)
- Authorization servers often let anyone register new OAuth clients.
- Attacker registers their own app (e.g. evil.htb)
- Victim logs in via OAuth at evil.htb, attacker steals their token (with proper scopes for evil.htb)
- If other client apps (e.g. academy.htb) do not verify *audience* (intended recipient), and accept tokens issued for evil.htb, attacker can use victim’s token to hijack their session/privileges in unrelated apps.
- Mitigation: Audience and scope checks; never trust bearer tokens issued for one client in another context.

---

**Always treat every input in OAuth and SSO flows as untrusted — XSS, SSRF, open redirect, and token context flaws are high risk!**
