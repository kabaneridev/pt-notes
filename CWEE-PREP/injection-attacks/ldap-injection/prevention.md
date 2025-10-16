# LDAP Injection Prevention

LDAP injection stems from concatenating untrusted input into search filters. Prevent it with proper escaping, strict validation, and safer auth flows.

## Escaping Special Characters

Escape these characters in filter values (RFC 4515):

- `(` → `\28`
- `)` → `\29`
- `*` → `\2a`
- `\` → `\5c`
- NUL → `\00`

Note: DN components require DN-safe escaping (RFC 4514); use library helpers with DN mode.

## PHP Example (filter-based auth)

Vulnerable (no escaping):

```php
$filter = '(&(cn=' . $_POST['username'] . ')(userPassword=' . $_POST['password'] . '))';
```

Safe (escape user input):

```php
$filter = '(&(cn=' . ldap_escape($_POST['username']) . ')(userPassword=' . ldap_escape($_POST['password']) . '))';
```

## Prefer Bind-Based Authentication

Delegate password checking to the DS by binding with user-supplied credentials instead of searching with a filter:

```php
$dn = 'cn=' . ldap_escape($_POST['username'], '', LDAP_ESCAPE_DN) . ',dc=example,dc=htb';
$pw = $_POST['password'];
$bind = ldap_bind($conn, $dn, $pw);
```

This removes the need to compose a filter for password checks, reducing injection risk.

## Best Practices

- Least privilege: bind account for searches should have minimal read rights.
- Input allow-listing: restrict to expected character sets and formats.
- Fixed enums: map selector-like inputs to constant strings (no free-form joining).
- Centralize validation/escaping: avoid scattered ad-hoc handling.
- Disable anonymous binds on the DS.
- Log rejects/rate-limit abnormal patterns.

## References

- RFC 4515 (LDAP: String Representation of Search Filters)
- RFC 4514 (LDAP: String Representation of Distinguished Names)
- PHP `ldap_escape` documentation
