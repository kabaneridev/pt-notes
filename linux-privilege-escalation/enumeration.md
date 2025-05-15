# Linux System Enumeration

This document covers basic system enumeration techniques for Linux systems during penetration testing, focusing on techniques covered in the OSCP curriculum.

## Table of Contents

- [System Information](#system-information)
- [User Enumeration](#user-enumeration)
- [Network Enumeration](#network-enumeration)
- [Running Services](#running-services)
- [File System Enumeration](#file-system-enumeration)
- [Scheduled Tasks](#scheduled-tasks)
- [Installed Software](#installed-software)
- [Basic Privilege Escalation Checks](#basic-privilege-escalation-checks)
- [Automated Enumeration Tools](#automated-enumeration-tools)

## System Information

### Basic System Information

```bash
# Kernel and distribution information
uname -a
cat /proc/version
cat /etc/issue
cat /etc/*-release
lsb_release -a

# Hardware information
cat /proc/cpuinfo
free -h
df -h

# System uptime
uptime
```

### Environment Variables

```bash
# View all environment variables
env
set

# View specific variables
echo $PATH
echo $HOME
echo $USER
```

## User Enumeration

### User Accounts

```bash
# Current user information
whoami
id
groups

# All users on the system
cat /etc/passwd
cut -d: -f1 /etc/passwd

# Users with valid shells
grep -v '/nologin\|/false' /etc/passwd
```

### User Activities

```bash
# Login history
last
lastlog

# Command history
history
cat ~/.bash_history
```

### Sudo Access

```bash
# Check sudo privileges
sudo -l

# Check sudoers file (requires root)
cat /etc/sudoers
```

## Network Enumeration

### Network Interfaces

```bash
# Interface information
ifconfig -a
ip a
```

### Routing Information

```bash
# Routing tables
route
ip route
netstat -r

# ARP cache
arp -a
ip neigh
```

### Open Ports and Connections

```bash
# Listening ports
netstat -tuln
ss -tuln

# Established connections
netstat -tunap
ss -tunap
```

### Network Services

```bash
# DNS settings
cat /etc/resolv.conf
cat /etc/hosts

# Firewall rules (may require root)
iptables -L
```

## Running Services

### Service Status

```bash
# Running services
service --status-all
ps aux

# Specific service status
service service_name status
```

### Startup Scripts

```bash
# SysV init scripts
ls -la /etc/init.d/

# RC scripts
ls -la /etc/rc*.d/
```

## File System Enumeration

### Sensitive Files

```bash
# Configuration files
find / -name "*.conf" -o -name "*.config" 2>/dev/null

# Hidden files and directories
find /home -name ".*" -type f 2>/dev/null
```

### File Permissions

```bash
# World-writable files
find / -type f -perm -o+w -not -path "/proc/*" 2>/dev/null

# World-writable directories
find / -type d -perm -o+w -not -path "/proc/*" 2>/dev/null

# SUID binaries
find / -type f -perm -u=s 2>/dev/null

# SGID binaries
find / -type f -perm -g=s 2>/dev/null
```

### Recently Modified Files

```bash
# Files modified in the last day
find / -type f -mtime -1 2>/dev/null
```

## Scheduled Tasks

### Cron Jobs

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

## Installed Software

### Package Management

```bash
# Debian/Ubuntu
dpkg -l

# Red Hat/CentOS
rpm -qa

# General
which command_name
```

### Web Servers and Applications

```bash
# Apache configuration
cat /etc/apache2/apache2.conf
cat /etc/httpd/conf/httpd.conf

# Web roots
ls -la /var/www/
ls -la /srv/www/
```

## Basic Privilege Escalation Checks

### SUID Files Check

```bash
# Find SUID binaries
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

### Writeable /etc/passwd Check

```bash
# Check if /etc/passwd is writeable
ls -la /etc/passwd
```

### Sudo Rights Check

```bash
# Check what commands can be run with sudo
sudo -l
```

### Path Injection Check

```bash
# Check for writeable directories in PATH
echo $PATH | tr ':' '\n' | xargs -I {} ls -ld {} 2>/dev/null
```

### Cron Jobs with Weak Permissions

```bash
# Find world-writeable cron files
find /etc/cron* -type f -perm -o+w 2>/dev/null
```

## Automated Enumeration Tools

### Basic Scripts

```bash
# LinPEAS (a script to search for possible paths to escalate privileges on Linux)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash

# LinEnum (a script that performs common Linux privilege escalation checks)
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

## Resources

- [OSCP PWK Notes](https://github.com/Optixal/OSCP-PWK-Notes-Public)
- [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [OSCP/PWK PEN-200 OSCP Course Tools](https://www.kali.org/tools/) 