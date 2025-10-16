# Preventing NoSQL Injection Vulnerabilities

## General Principles
- Never use raw user input directly in database queries
- Always cast user-controlled input explicitly to the expected type (e.g. strval in PHP)
- Use whitelisting: allow only values that fit an expected pattern (emails, IDs, codes etc)
- Avoid the `$where` operator and JavaScript expressions unless absolutely necessary
- Prefer standard MongoDB query operators
- If possible, disable server-side JS in MongoDB

## Example Fixes for Common Cases

### 1. String Casting with Input Validation

**Vulnerable PHP (MangoMail):**
```php
$query = new MongoDB\Driver\Query(array("email" => $_POST['email'], "password" => $_POST['password']));
```
**Fixed:**
```php
$query = new MongoDB\Driver\Query(array(
    "email" => strval($_POST['email']),
    "password" => strval($_POST['password'])
));
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    // Invalid email
}
```

### 2. Regex for Tracking Number Structure (MangoPost):
```php
if (!preg_match('/^[a-z0-9\{\}]+$/i', $trackingNum)) {
    // Invalid tracking number
}
```

### 3. Avoiding `$where` Expressions (MangoOnline):
**Vulnerable:**
```php
$q = array('$where' => 'this.username === "' . $_POST['username'] . '" ...');
```
**Fixed (no $where!):**
```php
$query = new MongoDB\Driver\Query(array('username' => strval($_POST['username']), 'password' => md5($_POST['password'])));
```

## Recommended Checklist
- [ ] Sanitize all user input (cast to string, use regex, validate format)
- [ ] Use whitelists or strict patterns for IDs, emails, codes, etc
- [ ] Avoid $where and server-side JS everywhere possible
- [ ] Disable server-side JS eval if not needed (Mongo config)
- [ ] Always review how your framework (PHP, Python, etc.) maps web input to query objects (dict vs array)
- [ ] Audit/monitor for suspicious query patterns (e.g. use of operators in user fields)
