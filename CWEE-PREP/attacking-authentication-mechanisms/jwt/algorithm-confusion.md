# Algorithm Confusion Attack (JWT)

**Algorithm confusion** occurs when a server supports both asymmetric (e.g. RS256) and symmetric (e.g. HS256) JWT signing methods, but does not enforce the correct algorithm during verification. Attackers can "downgrade" the JWT to HS256, forging a valid signature using the public key as the symmetric secret.

## Workflow (Lab Example)

1. **Obtain valid JWT(s)**
   - Log in to the target app (e.g., with credentials `htb-stdnt:AcademyStudent!`).
   - Obtain at least two JWTs signed with RS256 from your session/cookies (e.g., Burp Repeater or browser dev console).

2. **Identify vulnerability**
   - Decode the JWT header (via jwt.io or CyberChef); confirm `alg: RS256` (asymmetric RSA).
   - If public key is not published, derive it from two or more JWTs, as they share the same modulus.

3. **Extract public key**
   - Use rsa_sign2n (https://github.com/silentsignal/rsa_sign2n):
   - Build/run the docker image:
     ```bash
     git clone https://github.com/silentsignal/rsa_sign2n
     cd rsa_sign2n/standalone/
     sudo docker build . -t sig2n
     sudo docker run -it sig2n /bin/bash
     ```
   - Inside the container, run:
     ```bash
     python3 jwt_forgery.py <jwt1> <jwt2> [...]
     ```
   - The output includes:
     - The public key PEM file (e.g. `xxxx_x509.pem`)
     - Example "tampered" JWTs using alg: HS256, signed using the public key as symmetric secret

4. **Forge tampered JWT**
   - Edit the payload (e.g., set `isAdmin: true`) and set header { "alg": "HS256", ... }
   - Sign the token using HS256 and the extracted public key as "shared secret".
   - Use CyberChef or jwt.io:
     - In CyberChef: JWT Sign → Algorithm: HS256 → Private/Secret key: paste public key (with trailing newline)

5. **Exploit:**
   - Supply your tampered JWT as the session cookie (`session=<jwt>`)
   - Successfully escalate to admin and gain access as the target user

---

**Summary:**
- Only works when servers trust JWT's `alg` field from attacker and use public key for symmetric verification (critical misconfiguration!)
- Mitigate by hardcoding JWT verification algorithm (do not accept from header) and never use the public key as an HMAC key
- Tools: rsa_sign2n (Docker), CyberChef, jwt.io

**Never publish lab secrets or flags!**
