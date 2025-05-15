# Linux Security Bypass Techniques

This document covers basic techniques to bypass security mechanisms in Linux systems during penetration testing engagements within the OSCP scope.

## Table of Contents

- [Firewall Evasion](#firewall-evasion)
- [Log Evasion](#log-evasion)
- [Traffic Tunneling](#traffic-tunneling)
- [Port Redirection](#port-redirection)
- [Additional Resources](#additional-resources)

## Firewall Evasion

### Alternative Ports

Common services often run on non-standard ports to bypass firewall restrictions:

```bash
# SSH on non-standard port
ssh user@target -p 2222

# HTTP/HTTPS on alternative ports
curl -vk https://target:8443
nc -nvz target 8080
```

### Source Port Manipulation

Many firewalls allow traffic from trusted ports:

```bash
# Source port manipulation using nmap
nmap -g 53 target
nmap -g 88 target

# Using netcat to specify source port
nc -p 53 target 80
```

## Log Evasion

### Basic Log Cleanup

Simple techniques to reduce traces in system logs:

```bash
# Clear bash history
history -c
rm ~/.bash_history

# Disable history recording for current session
export HISTSIZE=0
unset HISTFILE
```

### File Timestomping

Modify file timestamps to match surrounding files:

```bash
# Change access and modification time
touch -a -m -t 202001010101.01 file.txt

# Use timestamps from another file
touch -r reference.txt file.txt
```

## Traffic Tunneling

### SSH Tunneling

Basic SSH tunneling techniques:

```bash
# Local port forwarding (access remote service through local port)
ssh -L 8080:internal-server:80 user@pivot-host

# Remote port forwarding (expose local service to remote host)
ssh -R 8080:localhost:80 user@remote-host

# Dynamic SOCKS proxy
ssh -D 9050 user@pivot-host
```

### Proxychains

Using proxychains to tunnel traffic through a proxy:

```bash
# Configure /etc/proxychains.conf to use your SOCKS proxy
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf

# Run commands through the proxy
proxychains nmap -sT -Pn target
proxychains firefox
```

## Port Redirection

### Simple Port Redirection

Using netcat for basic port redirection:

```bash
# Listen on local port and forward to remote
mkfifo /tmp/pipe
nc -l -p 4444 < /tmp/pipe | nc target 22 > /tmp/pipe
```

### Using Socat

Socat is more stable for port forwarding:

```bash
# TCP port forwarding
socat TCP-LISTEN:8080,fork TCP:internal-server:80

# Forward with some encryption
socat OPENSSL-LISTEN:443,cert=cert.pem,fork TCP:internal-server:80
```

## Additional Resources

- [OSCP PWK Notes](https://github.com/Optixal/OSCP-PWK-Notes-Public)
- [SANS SEC560 Cheat Sheet](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
- [OSCP/PWK PEN-200 OSCP Course Tools](https://www.kali.org/tools/)
