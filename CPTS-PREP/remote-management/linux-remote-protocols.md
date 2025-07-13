# Linux Remote Management Protocols

## Overview
Linux systems commonly use various remote management protocols for secure access and file transfer. These protocols enable remote administration, file synchronization, and system management across networks.

## SSH (Secure Shell)

### Overview
SSH (Secure Shell) is a network protocol that enables secure network communication and remote access to network services. It uses encryption to secure the communication channel between client and server.

**Key Characteristics:**
- **Port 22**: Default SSH port
- **Authentication**: Public key, password, or certificate-based
- **Encryption**: AES, 3DES, ChaCha20-Poly1305
- **Integrity**: HMAC-SHA256, HMAC-SHA1
- **Key Exchange**: Diffie-Hellman, ECDH

### SSH Features
- **Secure Remote Access**: Encrypted terminal sessions
- **File Transfer**: SCP and SFTP protocols
- **Port Forwarding**: Local and remote port forwarding
- **Tunneling**: Secure tunneling of other protocols
- **X11 Forwarding**: Remote GUI application access

### SSH Authentication Methods
```bash
# Password authentication
ssh username@hostname

# Public key authentication
ssh -i private_key username@hostname

# Certificate-based authentication
ssh -i certificate username@hostname
```

### SSH Configuration
```bash
# Client configuration (/etc/ssh/ssh_config)
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    PasswordAuthentication no
    PubkeyAuthentication yes

# Server configuration (/etc/ssh/sshd_config)
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers normaluser
```

### SSH Enumeration
```bash
# Banner grabbing
nc target 22
telnet target 22
nmap -p22 --script ssh-brute target

# SSH version detection
ssh -V
nmap -p22 --script ssh-hostkey target

# SSH algorithm enumeration
nmap -p22 --script ssh2-enum-algos target
```

### SSH Security Issues
1. **Weak Authentication**: Default or weak passwords
2. **Key Management**: Unprotected private keys
3. **Configuration**: Insecure SSH daemon settings
4. **Brute Force**: Password guessing attacks
5. **Version Vulnerabilities**: Outdated SSH versions

## Rsync

### Overview
Rsync is a utility for efficiently transferring and synchronizing files between computers. It uses the rsync protocol to transfer only the differences between files, making it bandwidth-efficient.

**Key Characteristics:**
- **Port 873**: Default rsync daemon port
- **Protocol**: Custom rsync protocol over TCP
- **Efficiency**: Delta-sync algorithm (only transfers changes)
- **Authentication**: Module-based access control
- **Encryption**: Can tunnel through SSH

### Rsync Modes
| Mode | Description | Usage |
|------|-------------|--------|
| **Local** | Files on same machine | `rsync source destination` |
| **Remote Shell** | SSH/RSH transport | `rsync -e ssh source user@host:dest` |
| **Rsync Daemon** | Native rsync protocol | `rsync source rsync://host/module` |

### Rsync Configuration
```bash
# Rsync daemon configuration (/etc/rsyncd.conf)
uid = nobody
gid = nobody
use chroot = yes
max connections = 10
log file = /var/log/rsyncd.log
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsync.lock

[backup]
    path = /backup
    comment = Backup files
    read only = false
    hosts allow = 192.168.1.0/24
```

### Rsync Enumeration
```bash
# Check if rsync daemon is running
nmap -p873 target

# List available modules
rsync target::
rsync rsync://target/

# Enumerate module contents
rsync target::module_name/
rsync rsync://target/module_name/

# Download files
rsync -av target::module_name/file ./
```

### Rsync Security Issues
1. **Anonymous Access**: Unauthenticated access to shares
2. **Information Disclosure**: Directory listings and file access
3. **Data Exfiltration**: Ability to download sensitive files
4. **Configuration**: Overly permissive access controls
5. **Network Exposure**: Rsync accessible from untrusted networks

## R-Services (RSH, RCP, RLOGIN)

### Overview
R-Services are a suite of remote access services developed for Unix systems. They provide remote shell access, file copying, and remote login capabilities. **WARNING**: R-Services are inherently insecure and should not be used in production environments.

### R-Service Components
| Service | Port | Description |
|---------|------|-------------|
| **RSH** | 514 | Remote shell execution |
| **RCP** | 514 | Remote file copy |
| **RLOGIN** | 513 | Remote login |

### R-Service Authentication
R-Services use host-based authentication through:
- **`.rhosts`**: Per-user access control
- **`/etc/hosts.equiv`**: System-wide access control
- **Trusted hosts**: IP-based authentication

### R-Service Configuration Files
```bash
# /etc/hosts.equiv (system-wide)
trusted_host
+trusted_user
-untrusted_user

# ~/.rhosts (per-user)
trusted_host trusted_user
+ +
```

### R-Service Enumeration
```bash
# Check for R-Services
nmap -p513,514 target

# Banner grabbing
nc target 513
nc target 514

# RSH access attempt
rsh target command
rsh target -l username command

# RLOGIN access attempt
rlogin target
rlogin target -l username
```

### R-Service Security Issues
1. **No Encryption**: All communication in plain text
2. **Weak Authentication**: Host-based authentication only
3. **Information Disclosure**: Verbose error messages
4. **Privilege Escalation**: Potential for root access
5. **Network Sniffing**: Credentials transmitted in clear text

## Advanced Enumeration Techniques

### SSH Advanced Enumeration
```bash
# SSH user enumeration
nmap -p22 --script ssh-enum-users target

# SSH host key fingerprinting
ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub

# SSH configuration analysis
ssh -T -o StrictHostKeyChecking=no target

# SSH tunneling detection
netstat -tlnp | grep :22
```

### SSH Brute Force
```bash
# Hydra SSH brute force
hydra -l username -P passwords.txt ssh://target

# Patator SSH brute force
patator ssh_login host=target user=username password=FILE0 0=passwords.txt

# Custom SSH brute force
#!/bin/bash
for pass in $(cat passwords.txt); do
    sshpass -p $pass ssh username@target "echo success" 2>/dev/null && echo "Password found: $pass"
done
```

### Rsync Advanced Enumeration
```bash
# Comprehensive rsync enumeration
rsync --list-only target::
rsync --list-only rsync://target/

# Recursive directory listing
rsync -r --list-only target::module/

# Test write permissions
echo "test" | rsync --partial - target::module/test.txt
```

### R-Service Exploitation
```bash
# RSH command execution
rsh target "id; whoami; uname -a"

# RCP file transfer
rcp localfile target:remotefile
rcp target:remotefile localfile

# RLOGIN session
rlogin target
# If successful, you get a shell
```

## Practical Examples

### HTB Academy Style SSH Enumeration
```bash
# Step 1: Service detection
nmap -p22 -sV -sC target

# Step 2: SSH version and algorithms
nmap -p22 --script ssh-hostkey,ssh2-enum-algos target

# Step 3: User enumeration (if possible)
nmap -p22 --script ssh-enum-users --script-args userdb=users.txt target

# Step 4: Brute force (if permitted)
hydra -l admin -P passwords.txt ssh://target

# Step 5: Key-based authentication testing
ssh-keygen -t rsa -b 2048 -f testkey
ssh-copy-id -i testkey.pub user@target
```

### HTB Academy Style Rsync Enumeration
```bash
# Step 1: Service detection
nmap -p873 target

# Step 2: List available modules
rsync target::
# Example output:
# backup          Backup files
# public          Public files

# Step 3: Enumerate module contents
rsync target::backup/
rsync target::public/

# Step 4: Download interesting files
rsync -av target::backup/passwords.txt ./
rsync -av target::public/config/ ./config/
```

### HTB Academy Lab Questions Examples
```bash
# Question 1: "Which version of SSH is running on the target?"
nmap -p22 -sV target
# Look for: ssh OpenSSH 7.6p1
# Answer: 7.6p1

# Question 2: "What rsync modules are available?"
rsync target::
# Look for module names in output
# Answer: backup, public

# Question 3: "What files are in the backup module?"
rsync target::backup/
# Look for file listings
# Answer: passwords.txt, config.bak

# Question 4: "Extract the flag from the rsync share"
rsync -av target::backup/flag.txt ./
cat flag.txt
# Answer: HTB{...}
```

## Security Assessment

### SSH Security Assessment
```bash
# Check SSH configuration
ssh -T -o StrictHostKeyChecking=no target 2>&1 | grep -E "debug|config"

# Test weak authentication
ssh user@target
ssh root@target

# Check for SSH vulnerabilities
nmap -p22 --script ssh-vuln* target
```

### Rsync Security Assessment
```bash
# Test anonymous access
rsync target::

# Check for write permissions
echo "test" | rsync - target::module/test.txt

# Enumerate sensitive files
rsync target::module/ | grep -E "passwd|shadow|key|config"
```

### R-Service Security Assessment
```bash
# Test R-Service access
rsh target "id"
rlogin target

# Check for trusted hosts
rsh target "cat /etc/hosts.equiv"
rsh target "cat ~/.rhosts"
```

## Enumeration Checklist

### SSH Enumeration
- [ ] Port scan for SSH (22/tcp)
- [ ] Version detection and banner grabbing
- [ ] Algorithm enumeration
- [ ] User enumeration
- [ ] Authentication method testing
- [ ] Configuration analysis
- [ ] Vulnerability scanning

### Rsync Enumeration
- [ ] Port scan for rsync (873/tcp)
- [ ] Module enumeration
- [ ] Anonymous access testing
- [ ] Directory listing
- [ ] File download testing
- [ ] Write permission testing
- [ ] Sensitive file identification

### R-Service Enumeration
- [ ] Port scan for R-Services (513,514/tcp)
- [ ] Service availability testing
- [ ] Authentication bypass attempts
- [ ] Command execution testing
- [ ] File transfer testing
- [ ] Configuration file analysis

## Common Vulnerabilities

### SSH Vulnerabilities
- **CVE-2018-15473**: OpenSSH user enumeration
- **CVE-2016-10009**: OpenSSH privilege escalation
- **CVE-2008-5161**: OpenSSH client vulnerability

### Rsync Vulnerabilities
- **CVE-2014-9512**: Rsync path traversal
- **CVE-2011-1097**: Rsync daemon security bypass

### R-Service Vulnerabilities
- **Inherent Design Flaws**: No encryption, weak authentication
- **CVE-1999-0651**: R-Services buffer overflow
- **CVE-1999-0025**: R-Services authentication bypass

## Tools and Techniques

### SSH Tools
```bash
# Connection tools
ssh                  # SSH client
scp                  # Secure copy
sftp                 # SSH file transfer
ssh-keygen          # Key generation
ssh-copy-id         # Key deployment

# Enumeration tools
nmap                 # Network scanning
hydra                # Brute force
patator              # Authentication testing
```

### Rsync Tools
```bash
# Basic tools
rsync                # Rsync client
nmap                 # Service detection

# Custom enumeration
#!/bin/bash
# Rsync enumerator
target=$1
modules=$(rsync $target:: 2>/dev/null | awk '{print $1}')
for module in $modules; do
    echo "=== Module: $module ==="
    rsync $target::$module/ 2>/dev/null
done
```

### R-Service Tools
```bash
# R-Service clients
rsh                  # Remote shell
rcp                  # Remote copy
rlogin               # Remote login
```

## Defensive Measures

### SSH Hardening
```bash
# Secure SSH configuration
# /etc/ssh/sshd_config
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers normaluser
DenyUsers root
```

### Rsync Security
```bash
# Secure rsync configuration
# /etc/rsyncd.conf
uid = nobody
gid = nobody
use chroot = yes
max connections = 10
timeout = 300
refuse options = delete
reverse lookup = no

[secure_backup]
    path = /backup
    read only = true
    hosts allow = 192.168.1.0/24
    hosts deny = *
    auth users = backup_user
    secrets file = /etc/rsyncd.secrets
```

### R-Service Mitigation
```bash
# Disable R-Services (recommended)
systemctl stop rsh
systemctl stop rlogin
systemctl disable rsh
systemctl disable rlogin

# Remove R-Service packages
apt remove rsh-client rsh-server
apt remove rlogin
```

## Best Practices

### SSH Best Practices
1. **Use key-based authentication only**
2. **Disable root login**
3. **Change default port**
4. **Use fail2ban for brute force protection**
5. **Regular security updates**
6. **Monitor SSH logs**

### Rsync Best Practices
1. **Use authentication and encryption**
2. **Restrict network access**
3. **Use read-only shares when possible**
4. **Monitor rsync logs**
5. **Regular security audits**

### R-Service Recommendations
1. **Do not use R-Services in production**
2. **Replace with SSH**
3. **Disable all R-Services**
4. **Use secure alternatives**
5. **Regular security assessments**
