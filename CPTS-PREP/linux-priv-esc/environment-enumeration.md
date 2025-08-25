# Linux Privilege Escalation - Environment Enumeration

## 🎯 Overview

Environment enumeration is the foundation of successful Linux privilege escalation. After gaining initial access to a Linux host, systematic enumeration helps identify potential attack vectors, misconfigurations, and valuable information that can lead to privilege escalation.

> **"Enumeration is the key to privilege escalation. Understanding what pieces of information to look for and being able to perform enumeration manually is crucial for success."**

## 🚀 Initial Situational Awareness

### Fundamental Orientation Commands

Before diving deep into enumeration, establish basic situational awareness:

```bash
# Current user context
whoami                 # What user are we running as?
id                     # What groups does our user belong to?

# System identification  
hostname               # Server name and naming conventions
uname -a              # Kernel and system information

# Network position
ifconfig              # Network interfaces and subnets
ip a                  # Alternative network interface command

# Privilege check
sudo -l               # Can we run anything with sudo without password?
```

**Why This Matters:**
- **Documentation**: Screenshots provide evidence of successful RCE
- **System Identification**: Clearly identify the affected system
- **Quick Wins**: `sudo -l` can sometimes provide immediate escalation paths

## 🔍 Operating System Enumeration

### System Version Detection

**Check OS Distribution and Version:**
```bash
cat /etc/os-release
```

**Example Output:**
```bash
NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

**Analysis Points:**
- **Distribution Type**: Ubuntu, CentOS, Debian, SUSE, etc.
- **Version Currency**: Is the system maintained or end-of-life?
- **LTS Status**: Long Term Support versions typically more secure
- **Release Lifecycle**: Check if version has known vulnerabilities

### Alternative OS Detection Methods

```bash
# Additional OS information sources
cat /etc/issue
cat /etc/redhat-release    # Red Hat/CentOS systems
cat /etc/debian_version    # Debian-based systems
lsb_release -a            # LSB information (if available)
```

## ⚙️ System Environment Analysis

### PATH Variable Examination

**Check Current PATH:**
```bash
echo $PATH
```

**Typical Output:**
```bash
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

**Security Implications:**
- **PATH Hijacking**: Writable directories in PATH can be exploited
- **Custom Paths**: Non-standard paths may contain vulnerable binaries
- **Order Matters**: Earlier directories take precedence

### Environment Variables

**Enumerate All Environment Variables:**
```bash
env
```

**Look for Sensitive Information:**
```bash
env | grep -i pass
env | grep -i key
env | grep -i secret
env | grep -i token
```

**Common Sensitive Variables:**
- Database passwords
- API keys
- Service credentials
- Custom application secrets

## 🔧 Kernel and Hardware Information

### Kernel Version Analysis

**Get Kernel Information:**
```bash
uname -a
cat /proc/version
```

**Example Output:**
```bash
Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

**Key Information:**
- **Kernel Version**: 5.4.0-122-generic
- **Build Date**: Wed Jun 22 15:00:31 UTC 2022
- **Architecture**: x86_64
- **Distribution**: Ubuntu

### CPU and Hardware Details

**CPU Information:**
```bash
lscpu
```

**Memory Information:**
```bash
free -h
cat /proc/meminfo
```

**Hardware Details:**
```bash
lshw -short          # Hardware overview
dmidecode -t system  # System information (requires root)
```

## 🐚 Available Shells and Interpreters

### Login Shell Enumeration

**Available Shells:**
```bash
cat /etc/shells
```

**Example Output:**
```bash
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen
```

**Security Considerations:**
- **Shell Vulnerabilities**: Older bash versions vulnerable to Shellshock
- **Restricted Shells**: rbash may limit command execution
- **Session Management**: tmux/screen available for persistence
- **Interpreter Versions**: Check for vulnerable versions

**Shell Version Checking:**
```bash
bash --version
/bin/sh --version
which python python3 perl ruby
```

## 🛡️ Security Controls Detection

### Identify Active Security Mechanisms

**Common Security Tools to Check:**

```bash
# Firewall Status
iptables -L 2>/dev/null
ufw status 2>/dev/null
firewall-cmd --state 2>/dev/null

# SELinux Status  
sestatus 2>/dev/null
getenforce 2>/dev/null

# AppArmor Status
apparmor_status 2>/dev/null
aa-status 2>/dev/null

# Fail2Ban
systemctl status fail2ban 2>/dev/null
fail2ban-client status 2>/dev/null

# Process monitoring
ps aux | grep -E "(snort|aide|tripwire|rkhunter|chkrootkit)"
```

**Why This Matters:**
- **Attack Vector Selection**: Avoid triggering active defenses
- **Stealth Considerations**: Understand monitoring capabilities
- **Privilege Requirements**: Some enumeration requires elevated privileges

## 💾 Storage and File System Analysis

### Block Device Enumeration

**List Block Devices:**
```bash
lsblk
```

**Example Output:**
```bash
NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda                         8:0    0   20G  0 disk 
├─sda1                      8:1    0    1M  0 part 
├─sda2                      8:2    0    1G  0 part /boot
└─sda3                      8:3    0   19G  0 part 
  └─ubuntu--vg-ubuntu--lv 253:0    0   18G  0 lvm  /
sr0                        11:0    1  908M  0 rom 
loop0                       7:0    0   55M  1 loop /snap/core18/1705
```

**Analysis Points:**
- **Additional Drives**: Unmounted drives may contain sensitive data
- **LVM Configuration**: Logical volume management
- **Loop Devices**: Snap packages and containers
- **USB/External**: Removable media

### Mounted File Systems

**Current Mounts:**
```bash
mount
df -h
```

**File System Table:**
```bash
cat /etc/fstab
```

**Look for:**
- **Credentials in fstab**: Embedded passwords for network shares
- **Unusual Mounts**: NFS, SMB shares with interesting permissions
- **Temporary Mounts**: Recently mounted drives

**Network Shares:**
```bash
cat /etc/fstab | grep -E "(cifs|nfs|smbfs)"
```

### Unmounted File Systems

**Check for Unmounted Devices:**
```bash
cat /etc/fstab | grep -v "#" | column -t
fdisk -l 2>/dev/null
```

**Potential Findings:**
- **Backup Drives**: May contain sensitive historical data
- **Development Partitions**: Source code and credentials
- **Hidden Partitions**: Deliberately concealed data

## 🌐 Network Configuration Analysis

### Network Interface Information

**Interface Configuration:**
```bash
ifconfig -a
ip addr show
ip link show
```

**Routing Information:**
```bash
route -n
ip route show
netstat -rn
```

**Example Routing Table:**
```bash
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         _gateway        0.0.0.0         UG    0      0        0 ens192
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192
```

### Network Reconnaissance

**ARP Table Analysis:**
```bash
arp -a
ip neigh show
```

**DNS Configuration:**
```bash
cat /etc/resolv.conf
```

**Network Connections:**
```bash
netstat -tulpn
ss -tulpn
lsof -i
```

**Why Network Info Matters:**
- **Internal Networks**: Identify additional network segments
- **Domain Environment**: DNS servers may indicate Active Directory
- **Communication Patterns**: ARP table shows recent host interactions
- **Service Discovery**: Listening services and their processes

## 👥 User and Group Enumeration

### User Account Analysis

**All System Users:**
```bash
cat /etc/passwd
```

**Extract Usernames:**
```bash
cat /etc/passwd | cut -f1 -d:
```

**Users with Shell Access:**
```bash
grep "sh$" /etc/passwd
```

**Password Hash Formats:**
| Algorithm | Hash Format |
|-----------|-------------|
| Salted MD5 | `$1$...` |
| SHA-256 | `$5$...` |
| SHA-512 | `$6$...` |
| BCrypt | `$2a$...` |
| Scrypt | `$7$...` |
| Argon2 | `$argon2i$...` |

**User Analysis Examples:**
```bash
# Check for users with login shells
grep -E "/bin/(bash|sh|zsh|csh|tcsh|fish)$" /etc/passwd

# Look for service accounts
grep -E "daemon|www-data|nginx|apache|mysql|postgres" /etc/passwd

# Find recently created users (high UID numbers)
awk -F: '$3 >= 1000 {print $1":"$3}' /etc/passwd
```

### Group Membership Analysis

**All Groups:**
```bash
cat /etc/group
```

**High-Privilege Groups:**
```bash
# sudo group members
getent group sudo

# admin group members  
getent group admin

# wheel group (on some systems)
getent group wheel

# docker group (container access)
getent group docker
```

**Current User Groups:**
```bash
groups
id
```

## 🏠 Home Directory Investigation

### User Home Directories

**List Home Directories:**
```bash
ls -la /home
```

**Search for Interesting Files:**
```bash
# Configuration files
find /home -name ".*rc" -type f 2>/dev/null
find /home -name "*.conf" -type f 2>/dev/null

# History files
find /home -name "*history*" -type f 2>/dev/null

# SSH keys
find /home -name "id_*" -type f 2>/dev/null
find /home -name "authorized_keys" -type f 2>/dev/null

# Scripts and automation
find /home -name "*.sh" -type f 2>/dev/null
find /home -name "*.py" -type f 2>/dev/null
```

**Common Sensitive Files:**
```bash
# Check readable bash history
ls -la /home/*/.bash_history

# Look for notes and documentation
find /home -name "*note*" -type f 2>/dev/null
find /home -name "*password*" -type f 2>/dev/null
find /home -name "*cred*" -type f 2>/dev/null
```

## 🔍 Hidden Files and Directories

### Comprehensive Hidden File Search

**All Hidden Files:**
```bash
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | head -20
```

**Hidden Directories:**
```bash
find / -type d -name ".*" -ls 2>/dev/null
```

**User-Specific Hidden Files:**
```bash
find /home -type f -name ".*" -exec ls -l {} \; 2>/dev/null
```

**Common Hidden Configuration Files:**
- `.bashrc`, `.bash_profile`, `.profile`
- `.vimrc`, `.nanorc`  
- `.ssh/config`, `.ssh/known_hosts`
- `.mysql_history`, `.lesshst`
- `.wget-hsts`, `.gitconfig`

## 📁 Temporary Files and Directories

### Temporary File Analysis

**Standard Temporary Directories:**
```bash
ls -la /tmp
ls -la /var/tmp
ls -la /dev/shm
```

**File Retention Policies:**
- **`/tmp`**: Files deleted after 10 days or on reboot
- **`/var/tmp`**: Files retained up to 30 days
- **`/dev/shm`**: In-memory filesystem, lost on reboot

**Search for Interesting Temporary Files:**
```bash
# Recently created files
find /tmp -type f -mtime -1 2>/dev/null
find /var/tmp -type f -mtime -1 2>/dev/null

# Files containing sensitive keywords
grep -r -i "password\|secret\|key" /tmp/ 2>/dev/null
grep -r -i "password\|secret\|key" /var/tmp/ 2>/dev/null
```

**Process-Specific Temp Files:**
```bash
# Look for application-specific temp directories
ls -la /tmp/ | grep -E "(apache|nginx|mysql|postgres|ssh)"
ls -la /var/tmp/ | grep -E "(systemd|service)"
```

## 📋 Systematic Enumeration Checklist

### Phase 1: Basic Orientation
- [ ] Run `whoami`, `id`, `hostname`
- [ ] Check `sudo -l` for immediate privilege escalation
- [ ] Document network position with `ifconfig`
- [ ] Screenshot basic system info

### Phase 2: System Information
- [ ] OS version and distribution (`/etc/os-release`)
- [ ] Kernel version (`uname -a`)
- [ ] Available shells (`/etc/shells`)
- [ ] CPU and memory information (`lscpu`, `free -h`)

### Phase 3: Environment Analysis
- [ ] PATH variable enumeration (`echo $PATH`)
- [ ] Environment variables (`env`)
- [ ] Security controls detection
- [ ] Network configuration (`route`, `arp -a`)

### Phase 4: User and Permission Analysis
- [ ] User enumeration (`/etc/passwd`)
- [ ] Group analysis (`/etc/group`)
- [ ] Home directory investigation
- [ ] SSH key discovery

### Phase 5: File System Analysis
- [ ] Mounted file systems (`df -h`, `mount`)
- [ ] Hidden files and directories
- [ ] Temporary file analysis
- [ ] Block device enumeration (`lsblk`)

### Phase 6: Documentation and Analysis
- [ ] Compile sensitive findings
- [ ] Test discovered credentials
- [ ] Plan privilege escalation approach
- [ ] Document attack vectors

## 💡 Key Findings to Look For

### High-Impact Discoveries

**Immediate Privilege Escalation:**
- `sudo -l` showing passwordless commands
- SUID binaries with known exploits
- Writable files in PATH
- Kernel version with public exploits

**Credential Discovery:**
- Passwords in configuration files
- SSH private keys
- Database credentials
- API keys and tokens

**Attack Vector Identification:**
- Vulnerable services running as root
- Misconfigured file permissions
- Unpatched software versions
- Interesting cron jobs

**Network Pivot Opportunities:**
- Multiple network interfaces
- SSH keys for other systems
- Database connections
- Internal service discovery

## ⚠️ Common Pitfalls and Considerations

### Enumeration Best Practices

**Stealth Considerations:**
- Some commands may generate logs
- Avoid running as root unless necessary
- Be mindful of file access times
- Consider detection mechanisms

**System Stability:**
- Kernel exploits can crash systems
- Be careful with production environments
- Test in controlled settings first
- Have backup access methods

**Thoroughness vs. Speed:**
- Balance comprehensive enumeration with time constraints
- Prioritize high-impact areas first
- Use automation tools as supplements
- Develop efficient manual workflows

## 🛠️ Automation and Tools

### Manual vs. Automated Enumeration

**When to Use Manual Enumeration:**
- Learning and understanding system internals
- Customized searches based on findings
- Stealth requirements
- Limited tool availability

**Complementary Automated Tools:**
- **LinPEAS**: Comprehensive Linux enumeration
- **LinEnum**: Classic enumeration script  
- **linux-smart-enumeration**: Selective enumeration
- **PEASS-ng**: Advanced privilege escalation

**Integration Strategy:**
1. Perform initial manual enumeration
2. Run automated tools for comprehensive coverage
3. Cross-reference findings
4. Focus manual investigation on promising vectors

## 📚 Next Steps

After completing environment enumeration, proceed to:

1. **Permissions-based Privilege Escalation**: File permissions, SUID/SGID
2. **Service-based Privilege Escalation**: Running services and processes  
3. **Configuration-based Attacks**: Misconfigurations and weak settings
4. **Kernel Exploitation**: Operating system vulnerabilities
5. **Application-specific Attacks**: Vulnerable installed software

---

*Environment enumeration provides the foundation for all subsequent privilege escalation attempts. Thorough initial reconnaissance significantly increases the likelihood of successful privilege escalation and helps identify the most efficient attack paths.* 