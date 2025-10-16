# JWT Tools of the Trade & Vulnerability Prevention

## Tools of the Trade

- **jwt_tool** (https://github.com/ticarpi/jwt_tool)
  - Swiss Army knife for analysis, fuzzing, and attacking JWTs
  - Supports: decoding, brute-forcing secret, forging tokens, alg:none, JWK/JKU confusion, key confusion, and more
  - Installation:
    ```bash
    git clone https://github.com/ticarpi/jwt_tool
    cd jwt_tool
    pip3 install -r requirements.txt
    python3 jwt_tool.py -h
    ```
  - Usage examples:
    - Decode and analyze:
      ```bash
      python3 jwt_tool.py <jwt>
      ```
    - Crack secret:
      ```bash
      python3 jwt_tool.py -C -d /path/to/wordlist.txt <jwt>
      ```
    - Exploit alg:none:
      ```bash
      python3 jwt_tool.py -X a -pc isAdmin -pv true -I <jwt>
      ```
    - Spoof JWK/JKU:
      ```bash
      python3 jwt_tool.py -X s -ju <url> <jwt>
      ```
  - Use jwt_tool to automate PoCs/lab solutions covered in previous sections.

- **jwt.io, CyberChef**
  - For manual crafting/testing of tokens, header/payload inspection, base64url work etc.

- **hashcat (-m 16500)**
  - For brute-forcing HMAC secrets in JWTs (see previous lab steps)

---

## Vulnerability Prevention Checklist

- Use mature, actively maintained JWT libraries. Do NOT write your own parser/verification logic.
- Hardcode allowed signature algorithm (never accept alg header from attacker)
- Never support 'none' for authentication tokens
- Always use distinct secrets per app/environment
- Reject tokens if signature fails, is missing, or algorithm does not match expected
- For claims like jku or jwk:
    - Only allow values from trusted sources (allowlist URLs/domains or block them completely)
    - Never allow attacker to dictate public keys in header
- Validate critical claims (exp, nbf) for timing constraints
- Always set exp (expiration) claim to limit token lifetime
- Limit key IDs (kid), certificate URLs (x5u) and other dynamic fields
- Monitor libraries for CVEs and keep them up to date

**Summary:**
- Well-configured JWT validation and strict interpretation of algorithms/claims prevents all attacks from the previous sections!
- Further resources: official JWT RFC, modern web framework docs, and jwt_tool's help/README.
