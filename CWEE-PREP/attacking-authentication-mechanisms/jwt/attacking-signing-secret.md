# Attacking the JWT Signing Secret

If a JWT is signed with a weak secret and a symmetric algorithm (HS256/HS384/HS512), an attacker can brute-force the secret and forge tokens with any claims.

## Workflow:
1. **Obtain a valid JWT issued by the app.**
    - Log in with normal credentials, capture the token from session/cookies or API response.

2. **Identify algorithm:**
    - Decode the JWT header with jwt.io or CyberChef. Check for `"alg": "HS256"` (or similar).
    - Only symmetric algorithms like "HS256" are vulnerable to secret brute-forcing.

3. **Save the JWT (one line) to a file:**

```bash
echo -n eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ...wtNnrIMwvHeSZf0eB0 > jwt.txt
```

4. **Crack the secret using hashcat:**

```bash
hashcat -m 16500 jwt.txt /path/to/wordlist.txt
# For example, most common: /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

5. **Check for cracked secrets:**

```bash
hashcat -m 16500 jwt.txt /path/to/wordlist.txt --show
# Output will be in form: <jwt>:<cracked_secret>
```

---

## Forging a Malicious JWT
- Once the secret is recovered, modify the JWT payload (e.g., set `isAdmin: true`).
- Use jwt.io or CyberChef to resign your manipulated token using the cracked secret (paste it in the "Secret" field).
- Copy the new JWT (with valid signature!) and supply as your session cookie to escalate privileges or impersonate users.
- Example: GET /home HTTP/1.1 with `Cookie: session=<your_forged_jwt>`

---

**Tips:**
- Only symmetric (`HS...`) JWTs are vulnerable to this (not RS256!).
- Use CyberChef/jwt.io for quick testing of JWT secrets.
- A strong, truly random key makes brute-forcing practically infeasible.

---
**Never post the cracked secret or flag in writeups.**
