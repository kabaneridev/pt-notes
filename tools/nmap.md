# Nmap

Nmap ("Network Mapper") is a free and open-source utility for network discovery and security auditing. It's one of the most essential tools in a penetration tester's arsenal.

## Basic Usage

### Simple Scan
```bash
nmap target.example.com
```

### Scan Specific Ports
```bash
nmap -p 22,80,443 target.example.com
```

### Scan Port Range
```bash
nmap -p 1-1000 target.example.com
```

### Scan All Ports
```bash
nmap -p- target.example.com
```

## Advanced Scanning Techniques

### SYN Scan (Stealth Scan)
```bash
sudo nmap -sS target.example.com
```

### UDP Scan
```bash
sudo nmap -sU target.example.com
```

### OS Detection
```bash
sudo nmap -O target.example.com
```

### Version Detection
```bash
nmap -sV target.example.com
```

### Comprehensive Scan
```bash
sudo nmap -sS -sV -sC -A -O -p- target.example.com
```

## Network Scanning

### Scan a Subnet
```bash
nmap 192.168.1.0/24
```

### Scan Multiple Targets
```bash
nmap 192.168.1.1 192.168.1.2 192.168.1.3
```

### Scan from a File
```bash
nmap -iL targets.txt
```

## Output Options

### Save Output to a File
```bash
nmap -oN scan_results.txt target.example.com
```

### Save in XML Format
```bash
nmap -oX scan_results.xml target.example.com
```

### Save in All Formats
```bash
nmap -oA scan_results target.example.com
```

## Performance Options

### Timing Templates
```bash
# Paranoid (0) - Very slow, used for IDS evasion
nmap -T0 target.example.com

# Sneaky (1) - Quite slow, used for IDS evasion
nmap -T1 target.example.com

# Polite (2) - Slows down to consume less bandwidth
nmap -T2 target.example.com

# Normal (3) - Default timing template
nmap -T3 target.example.com

# Aggressive (4) - Assumes you're on a reasonably fast and reliable network
nmap -T4 target.example.com

# Insane (5) - Very aggressive; may overwhelm targets or miss open ports
nmap -T5 target.example.com
```

### Parallel Host Scan
```bash
nmap --min-parallelism 100 target.example.com
```

## Evasion Techniques

### Fragmentation
```bash
sudo nmap -f target.example.com
```

### Decoy Scan
```bash
sudo nmap -D decoy1.example.com,decoy2.example.com,ME target.example.com
```

### Spoof MAC Address
```bash
sudo nmap --spoof-mac 00:11:22:33:44:55 target.example.com
```

## NSE Scripts

Nmap Scripting Engine (NSE) provides additional functionality:

### Vulnerability Scanning
```bash
nmap --script vuln target.example.com
```

### Default Scripts
```bash
nmap -sC target.example.com
```

### Specific Script
```bash
nmap --script http-title target.example.com
```

### Multiple Scripts
```bash
nmap --script "http-*" target.example.com
```

## Practical Examples

### Basic Network Enumeration
```bash
nmap -sV -sC -oA network_enum 192.168.1.0/24
```

### Web Server Scan
```bash
nmap -p 80,443 --script "http-*" target.example.com
```

### Find All Open SMB Shares
```bash
nmap -p 445 --script smb-enum-shares 192.168.1.0/24
```

### Check for EternalBlue Vulnerability
```bash
nmap -p 445 --script smb-vuln-ms17-010 target.example.com
```

### Stealthy Scan for Firewall Evasion
```bash
sudo nmap -sS -T2 -f -D 192.168.1.101,192.168.1.102,ME target.example.com
```

## Cheat Sheet

| Command | Description |
|---------|-------------|
| `nmap -sS target` | TCP SYN scan |
| `nmap -sT target` | TCP connect scan |
| `nmap -sU target` | UDP scan |
| `nmap -sV target` | Service/version detection |
| `nmap -sC target` | Default script scan |
| `nmap -O target` | OS detection |
| `nmap -A target` | Aggressive scan (OS + version + scripts + traceroute) |
| `nmap -p 1-65535 target` | Scan all ports |
| `nmap -p- target` | Scan all ports (shorthand) |
| `nmap -p http,https target` | Scan named ports |
| `nmap -F target` | Fast scan (top 100 ports) |
| `nmap -T0-5 target` | Timing templates (higher is faster) |
| `nmap -oN results.txt target` | Save output to text file |
| `nmap -oX results.xml target` | Save output to XML |
| `nmap -oG results.gnmap target` | Save output in grepable format |
| `nmap -oA results target` | Save in all formats |

## Resources

- [Official Nmap Documentation](https://nmap.org/docs.html)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/) 