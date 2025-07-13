# NFS (Network File System) Enumeration

## Overview
Network File System (NFS) is a network file system developed by Sun Microsystems with the same purpose as SMB - to access file systems over a network as if they were local. However, it uses an entirely different protocol and is primarily used between Linux and Unix systems.

**Key Characteristics:**
- Uses ONC-RPC/SUN-RPC protocol on TCP/UDP port 111
- Main service runs on TCP/UDP port 2049
- Uses External Data Representation (XDR) for system-independent data exchange
- No built-in authentication mechanism (relies on RPC protocol options)
- Authorization derived from file system information

## NFS Versions

| Version | Features |
|---------|----------|
| **NFSv2** | Older version supported by many systems, initially operated entirely over UDP |
| **NFSv3** | More features including variable file size and better error reporting, not fully compatible with NFSv2 clients |
| **NFSv4** | Includes Kerberos, works through firewalls, no longer requires portmappers, supports ACLs, state-based operations, performance improvements and high security. First stateful protocol version |
| **NFSv4.1** | Protocol support for cluster server deployments, scalable parallel access (pNFS extension), session trunking/NFS multipathing |

**NFSv4 Advantages:**
- Only uses one port (2049) - simplifies firewall configuration
- Stateful protocol
- Better security features
- Kerberos authentication support

## Default Configuration

NFS configuration is managed through the `/etc/exports` file, which contains a table of physical filesystems accessible by clients.

**Example /etc/exports:**
```bash
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

## NFS Configuration Options

| Option | Description |
|--------|-------------|
| `rw` | Read and write permissions |
| `ro` | Read only permissions |
| `sync` | Synchronous data transfer (slower but safer) |
| `async` | Asynchronous data transfer (faster but less safe) |
| `secure` | Ports above 1024 will not be used |
| `insecure` | Ports above 1024 will be used |
| `no_subtree_check` | Disables subdirectory tree checking |
| `root_squash` | Maps root UID/GID 0 to anonymous, prevents root access |
| `no_root_squash` | All files created by root keep UID/GID 0 |
| `nohide` | Exports mounted subdirectories with their own entries |

## Dangerous Settings

⚠️ **High-Risk Configurations:**

| Option | Risk Level | Description |
|--------|------------|-------------|
| `rw` | High | Allows write access to shares |
| `insecure` | High | Allows ports above 1024 (non-root ports) |
| `no_root_squash` | Critical | Preserves root privileges - allows root access |
| `nohide` | Medium | Exports mounted subdirectories separately |

## Enumeration Techniques

### 1. Port Scanning
```bash
# Scan essential NFS ports
nmap -p111,2049 -sV -sC <target>

# Comprehensive NFS scan
nmap -p- --script nfs* <target> -sV
```

### 2. RPC Information Gathering
```bash
# Get RPC service information
nmap -p111 --script rpcinfo <target>

# Alternative RPC enumeration
rpcinfo -p <target>
```

### 3. NFS-Specific Enumeration
```bash
# Discover NFS shares
showmount -e <target>

# Use Nmap NFS scripts
nmap --script nfs-ls,nfs-showmount,nfs-statfs <target> -p2049
```

### 4. NFS Share Mounting
```bash
# Create mount point
mkdir /mnt/nfs-share

# Mount NFS share
mount -t nfs <target>:/path/to/share /mnt/nfs-share -o nolock

# Alternative mounting options
mount -t nfs <target>:/path/to/share /mnt/nfs-share -o nolock,vers=3
```

### 5. Content Analysis
```bash
# List contents with permissions
ls -la /mnt/nfs-share/

# List with numeric UIDs/GIDs
ls -n /mnt/nfs-share/

# Check file ownership and permissions
stat /mnt/nfs-share/filename
```

## Advanced Enumeration

### Using Nmap NSE Scripts
```bash
# Comprehensive NFS enumeration
nmap --script nfs-ls,nfs-showmount,nfs-statfs -p2049 <target>

# NFS vulnerability scanning
nmap --script nfs* -p2049 <target>
```

### Manual RPC Enumeration
```bash
# Query RPC services
rpcinfo -p <target>

# Specific service queries
rpcinfo -u <target> nfs
rpcinfo -t <target> nfs
```

## Security Issues and Attack Vectors

### 1. Authentication Bypass
- **Issue**: NFS relies on UID/GID mapping without proper authentication
- **Impact**: Access to files based on numeric user IDs
- **Exploitation**: Create local users with matching UIDs

### 2. Privilege Escalation
- **Issue**: `no_root_squash` configuration preserves root privileges
- **Impact**: Root access to NFS shares
- **Exploitation**: Upload SUID binaries, access sensitive files

### 3. Information Disclosure
- **Issue**: World-readable shares or misconfigured permissions
- **Impact**: Unauthorized access to sensitive data
- **Exploitation**: Mount shares and browse contents

### 4. File System Manipulation
- **Issue**: Write permissions on critical directories
- **Impact**: Modify system files, plant backdoors
- **Exploitation**: Upload malicious files, modify configurations

## Exploitation Examples

### UID/GID Manipulation
```bash
# Check file ownership
ls -n /mnt/nfs-share/

# Create local user with matching UID
useradd -u 1000 nfsuser

# Switch to created user
su nfsuser

# Access files with proper permissions
cat /mnt/nfs-share/sensitive-file.txt
```

### SUID Binary Upload (when no_root_squash is set)
```bash
# Create SUID binary
cp /bin/bash /mnt/nfs-share/rootbash
chmod +s /mnt/nfs-share/rootbash

# Execute from target system
./rootbash -p
```

## Enumeration Checklist

### Initial Discovery
- [ ] Port scan for 111 and 2049
- [ ] RPC service enumeration
- [ ] NFS version identification
- [ ] Share discovery with showmount

### Share Analysis
- [ ] Mount accessible shares
- [ ] Check file permissions and ownership
- [ ] Identify sensitive files
- [ ] Test write permissions
- [ ] Check for SUID/SGID binaries

### Security Assessment
- [ ] Verify authentication mechanisms
- [ ] Check for no_root_squash setting
- [ ] Test UID/GID manipulation
- [ ] Assess file system permissions
- [ ] Document configuration weaknesses

## Defensive Measures

### Secure Configuration
```bash
# Example secure exports entry
/secure/share 192.168.1.0/24(ro,sync,no_subtree_check,root_squash,secure)
```

### Best Practices
1. **Use root_squash**: Always enable root squashing
2. **Restrict networks**: Limit access to specific subnets
3. **Read-only when possible**: Use ro for shares that don't need write access
4. **Use secure option**: Prevent use of high-numbered ports
5. **Enable sync**: Use synchronous writes for data integrity
6. **Regular audits**: Monitor NFS configurations and access logs

### Monitoring
```bash
# Check current NFS connections
netstat -an | grep :2049

# Monitor NFS statistics
nfsstat -s

# Check mounted shares
df -t nfs
```

## Cleanup
```bash
# Unmount NFS share
umount /mnt/nfs-share

# Remove mount point
rmdir /mnt/nfs-share
```
