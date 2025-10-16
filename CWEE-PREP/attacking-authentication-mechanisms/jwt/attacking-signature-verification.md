# Attacking JWT Signature Verification

When a web app does not properly verify JWT signatures, attackers can create or alter tokens to escalate privileges.

## 1. Missing Signature Verification
- **Vulnerability:** Server trusts data from JWTs without verifying if the signature is valid.
- **Practical Exploit:**
    1. Log in to the app normally, extract your JWT from the session/cookie (e.g. using browser dev tools).
    2. Decode the JWT header and payload (e.g. using https://jwt.io or CyberChef).
    3. Change a low-privilege field such as `"isAdmin": false` to `"isAdmin": true` in the payload.
    4. Re-encode the JWT (do not re-sign, leave/break the signature, or reuse original signature bytes).
    5. Replace your session cookie with the manipulated JWT.
    6. Visit a protected page — if the backend does not verify the signature, you gain unauthorized access.
- **Typical Lab Workflow:**
    - Login → steal JWT → manipulate → send as session → get admin.
    - Tools: jwt.lannysport.net, jwt.io, CyberChef for viewing/editing tokens.

---

## 2. 'none' Algorithm Attack (alg: none)
- **Vulnerability:** Server accepts JWTs with `alg": "none"` which disables signature checking entirely.
- **Practical Exploit:**
    1. Recreate the JWT header: `{ "alg": "none", "typ": "JWT" }` and encode using base64url.
    2. Craft the payload (e.g. set `"isAdmin": true`).
    3. Encode the header and payload, concatenated with a period (e.g. `header.payload.`).
    4. The JWT must end with a period (empty signature section!)
    5. Set this token as your session cookie and access protected resources.
- **Example Tools:**
    - In CyberChef: use "JWT Sign" with "None" as the signing algorithm to build a valid unsigned JWT.

---

**Note:**
- Always check that a JWT-based application verifies signatures and never accepts `alg: none` unless required for a special reason (rare, almost always a vulnerability in auth context).
- Simple JWT alteration is *not* usually a productive attack unless these specific misconfigurations are present.
