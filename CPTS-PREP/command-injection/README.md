# Command Injection Attacks

> **⚡ OS Command Execution:** Comprehensive guide to discovering and exploiting command injection vulnerabilities in web applications

## Overview

**Command Injection** occurs when an attacker can execute arbitrary operating system commands on a server that is running an application. This vulnerability is typically the result of insufficient input validation and can lead to complete system compromise.

This module covers the complete spectrum of command injection attacks, from basic detection techniques to advanced exploitation methods and defensive measures.

---

## Module Contents

### 🔍 **Discovery & Detection**
- Input validation bypass techniques
- Blind command injection detection
- Time-based detection methods
- Error-based identification

### ⚡ **Exploitation Techniques**
- Basic command injection
- Blind command injection
- Filter bypass methods
- Command chaining and separation

### 🛠️ **Advanced Methods**
- Out-of-band exploitation
- Data exfiltration techniques
- Privilege escalation via command injection
- Persistence mechanisms

### 🛡️ **Defense & Prevention**
- Input validation best practices
- Secure coding techniques
- WAF configuration
- System hardening

---

## Learning Objectives

By completing this module, you will understand:

1. **Fundamentals** - How command injection vulnerabilities occur
2. **Detection** - Methods to identify injection points
3. **Exploitation** - Techniques to execute arbitrary commands
4. **Bypasses** - Methods to circumvent security controls
5. **Impact** - Real-world consequences and attack scenarios
6. **Prevention** - Secure development practices

---

## Prerequisites

- Basic understanding of web applications
- Command line interface familiarity
- HTTP request/response structure knowledge
- Basic scripting knowledge (bash, Python)

---

## Tools Used

- **Burp Suite** - Request interception and modification
- **OWASP ZAP** - Vulnerability scanning
- **curl/wget** - Command line HTTP clients
- **nc (netcat)** - Network connections and reverse shells
- **Custom scripts** - Automated exploitation tools

---

## Practical Applications

This module prepares you for:
- **Web Application Penetration Testing**
- **Bug Bounty Hunting** 
- **Security Code Review**
- **Incident Response**
- **Secure Development**

---

## Module Structure

Each technique includes:
- ✅ **Theoretical background**
- ✅ **Practical examples**
- ✅ **Lab exercises**
- ✅ **Real-world scenarios**
- ✅ **Defense recommendations**

---

## Section Breakdown

1. **[Detection Methods](detection-methods.md)**
   - OS command injection operators
   - URL encoding techniques
   - Cross-platform compatibility
   - Detection methodology

2. **[Basic Exploitation](basic-exploitation.md)**
   - Front-end validation bypass
   - Web proxy usage (Burp Suite)
   - HTTP request modification
   - Initial command execution

3. **[Advanced Operators](advanced-operators.md)**
   - AND/OR logic operators
   - Pipe and background execution
   - Newline and separator methods
   - Cross-injection operator reference

4. **[Filter Identification](filter-identification.md)**
   - Application vs WAF detection
   - Blacklisted character discovery
   - Systematic filter testing
   - HTB Academy lab solutions

5. **[Bypassing Space Filters](bypassing-space-filters.md)**
   - Tab character replacement
   - `$IFS` environment variable
   - Bash brace expansion
   - Alternative whitespace methods

6. **[Bypassing Character Filters](bypassing-character-filters.md)**
   - Environment variable extraction (`${PATH:0:1}`)
   - Windows character techniques
   - ASCII character shifting methods
   - Variable syntax alternatives

7. **[Bypassing Blacklisted Commands](bypassing-blacklisted-commands.md)**
   - Command obfuscation techniques
   - Quote injection methods (`w'h'o'am'i`)
   - Platform-specific bypasses
   - Advanced payload construction

8. **[Advanced Command Obfuscation](advanced-command-obfuscation.md)**
   - Case manipulation techniques
   - Reversed command execution
   - Base64/hex encoding methods
   - WAF evasion strategies

9. **[Evasion Tools](evasion-tools.md)**
   - Bashfuscator (Linux automation)
   - DOSfuscation (Windows automation)
   - Automated payload generation
   - Tool comparison and integration

10. **[Skills Assessment - Command Injection](skills-assessment-walkthrough.md)**
    - Real-world web file manager scenario
    - Complete exploitation walkthrough
    - Multiple payload construction methods
    - Professional penetration testing methodology

🎯 **Congratulations! You've mastered command injection attacks!** 🚀 