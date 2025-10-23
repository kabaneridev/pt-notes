# Introduction to OAuth

OAuth is a widely adopted standard for authorization and delegated access between services. It lets users grant limited access to third-party applications without sharing their credentials, commonly enabling Single Sign-On (SSO).

**Entities in OAuth:**
- **Resource Owner:** Typically the user
- **Client:** The application requesting access (e.g., academy.htb)
- **Authorization Server:** Authenticates the user and issues tokens (e.g., hubgit.htb)
- **Resource Server:** Hosts protected resources (may be same as Authorization Server)

## Typical Authorization Code Grant Flow (Recommended)
1. **Authorization Request:**
   - User clicks "Login with Provider" (e.g., Login with GitHub)
   - Client redirects browser to Authorization Server with client_id, redirect_uri, etc.
   - Example:
     ```http
     GET /auth?client_id=app123&redirect_uri=https://client/cb&response_type=code&scope=profile&state=xyz HTTP/1.1
     Host: auth.server
     ```
2. **User Authenticates & Consents**  (at Authorization Server)
3. **Authorization Code Issued:**
   - Browser is redirected back to client with `?code=...` (and usually `&state=`)
4. **Client Gets Access Token:**
   - Client makes direct POST to Authorization Server
     ```http
     POST /token
     client_id=app123&client_secret=secret&redirect_uri=...&code=...&grant_type=authorization_code
     ```
5. **Resources Requested:**
   - Client uses in-protocol access token in API requests to Resource Server

## Implicit Grant Flow (legacy)
- Used in some browser-side apps but being phased out due to security risks
- Access token returned in URL fragment during redirect, no code exchange
- **NOTE:** OAuth 2.1 removes this flow, always prefer Authorization Code Grant

## Why is OAuth security critical?
- If an attacker can manipulate tokens, scopes, or redirect flows, they may impersonate users, gain unauthorized access, or steal data.
- OAuth flows are frequently a target for phishing, token leakage, or misuse attacks.

This section provides the technical foundation for understanding and hacking (misusing) real OAuth integrations.
