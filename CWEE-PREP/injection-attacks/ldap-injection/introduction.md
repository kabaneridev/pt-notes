# Introduction to LDAP Injection

Lightweight Directory Access Protocol (LDAP) is used to access directory servers (e.g., Active Directory, OpenLDAP). Web apps often integrate with LDAP for authentication and lookups. If user input is inserted into LDAP search filters without proper sanitization, LDAP Injection vulnerabilities arise.

## LDAP Terminology

- Directory Server (DS): stores directory data (e.g., OpenLDAP, AD DS).
- Entry: object holding data with:
  - Distinguished Name (DN): unique identifier composed of RDNs (e.g., `uid=admin,dc=hackthebox,dc=com`).
  - Attributes: key→values (e.g., `cn`, `mail`, `member`).
  - Object Classes: define required/allowed attributes (e.g., `person`, `group`).
- Operations: bind (auth), unbind (close), add, delete, modify, search.

## LDAP Search Filter Syntax (RFC 4515)

Filters are parenthesized components joined by boolean operators. Base form: `(attribute operand value)`.

### Base operands

- Equality: `=` → `(name=Kaylie)`
- Greater-or-equal: `>=` → `(uid>=10)`
- Less-or-equal: `<=` → `(uid<=10)`
- Approximate match: `~=` → `(name~=Kaylie)` (implementation-dependent)

### Boolean composition

- AND: `&` → `(&(name=Kaylie)(title=Manager))`
- OR: `|` → `(|(name=Kaylie)(title=Manager))`
- NOT: `!` → `(!(name=Kaylie))`

Notes:
- AND/OR accept multiple args: `(&(...)(...)(...))`
- Constants: True → `(&)`, False → `(|)`

### Wildcards

- `(name=*)` — attribute exists
- `(name=K*)` — starts with K
- `(name=*a*)` — contains `a`

## Common Attribute Types (non-exhaustive)

- `cn` (Common name), `givenName`, `sn` (surname), `uid`
- `objectClass`, `distinguishedName`, `ou` (Org Unit)
- `title`, `telephoneNumber`, `description`, `mail`, `street`, `postalCode`
- `member` (group membership), `userPassword`

For details: RFC 2256 (attribute types) and RFC 4515 (filters).

## Injection Risk

Concatenating user input into filters like:

```text
"(&(uid=" + user + ")(userPassword=" + pass + "))"
```

enables payloads such as:

```text
user = ")(|(uid=*))("   # widens to any uid
pass = anything
```

Or boolean bypass:

```text
user = admin)(|(objectClass=*))(
```

Mitigations are covered in the prevention note; prefer strict allow-lists and safe filter builders.
