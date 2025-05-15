# Gobuster

Gobuster is a tool used to brute-force:
- URIs (directories and files) in web sites
- DNS subdomains
- Virtual Host names on target web servers 
- Open Amazon S3 buckets

## Basic Usage

Gobuster has several modes:
- `dir` - Directory/file bruteforcing mode
- `dns` - DNS subdomain bruteforcing mode
- `vhost` - Virtual host bruteforcing mode
- `s3` - Amazon S3 bucket bruteforcing mode

### Command Line Options

#### General Options
- `-z` - Don't display progress
- `-o filename` - Output file to write results to
- `-q` - Don't print the banner and other noise
- `-t threads` - Number of concurrent threads (default 10)
- `-v` - Verbose output
- `-w wordlist` - Path to the wordlist

## Directory Mode

Directory mode is used to brute force directories and files in websites.

### Basic Directory Scan
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt
```

### With File Extensions
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
```

### Handle Different Status Codes
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307,401,403"
```

### Exclude Status Codes
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -b "404,500"
```

### With Basic Authentication
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -U username -P password
```

### Follow Redirects
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -r
```

### With Cookies
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -c "PHPSESSID=abc123"
```

### With Custom Headers
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -H "X-Custom-Header: value"
```

### Specify User-Agent
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -a "Mozilla/5.0"
```

### Case-insensitive
```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -f
```

## DNS Mode

DNS mode is used to brute force subdomains.

### Basic DNS Scan
```bash
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt
```

### Show IPs
```bash
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -i
```

### Use Specific Resolver
```bash
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -r 8.8.8.8
```

### Subdomain Wildcard Detection
```bash
gobuster dns -d example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -i -w
```

## Virtual Host Mode

Virtual host mode is used for brute forcing virtual host names.

### Basic VHost Scan
```bash
gobuster vhost -u https://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Append Domain
```bash
gobuster vhost -u https://example.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -a
```

## Amazon S3 Bucket Mode

S3 mode is used to enumerate open Amazon S3 buckets.

### Basic S3 Scan
```bash
gobuster s3 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

## Tips and Tricks

### Use SecLists
The SecLists repository contains many wordlists useful for enumeration:
```bash
sudo apt-get install seclists
```

### Custom Wordlists
For more targeted scans, create custom wordlists:
```bash
cewl https://target-website.com -m 5 -w wordlist.txt
```

### Faster Scanning
Increase the number of threads for faster scanning (may cause errors or missed results):
```bash
gobuster dir -u https://example.com -w wordlist.txt -t 50
```

### Combine with Other Tools
Pipe Gobuster output to other tools:
```bash
gobuster dir -u https://example.com -w wordlist.txt -o output.txt
grep -i "interesting" output.txt
```

## Practical Examples

### Web Application Assessment
```bash
# Discover directories
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -o directories.txt

# Check for config files
gobuster dir -u https://target.com -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common-config-files.txt -o config-files.txt

# Look for backup files
gobuster dir -u https://target.com -w /usr/share/wordlists/SecLists/Discovery/Web-Content/Common-DB-Backups.txt -o backups.txt
```

### Subdomain Enumeration
```bash
# Find subdomains
gobuster dns -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o subdomains.txt

# Test discovered subdomains as virtual hosts
cat subdomains.txt | cut -d ' ' -f 2 > vhosts.txt
gobuster vhost -u https://target.com -w vhosts.txt -o valid-vhosts.txt
```

## Cheat Sheet

| Command | Description |
|---------|-------------|
| `gobuster dir -u URL -w WORDLIST` | Directory bruteforce |
| `gobuster dir -u URL -w WORDLIST -x EXTENSIONS` | With file extensions |
| `gobuster dir -u URL -w WORDLIST -c COOKIE` | With cookie |
| `gobuster dir -u URL -w WORDLIST -U USERNAME -P PASSWORD` | With Basic Auth |
| `gobuster dir -u URL -w WORDLIST -r` | Follow redirects |
| `gobuster dns -d DOMAIN -w WORDLIST` | DNS subdomain bruteforce |
| `gobuster dns -d DOMAIN -w WORDLIST -i` | Show IP addresses |
| `gobuster vhost -u URL -w WORDLIST` | Virtual host bruteforce |
| `gobuster s3 -w WORDLIST` | S3 bucket bruteforce |

## Resources

- [GitHub Repository](https://github.com/OJ/gobuster)
- [Gobuster Documentation](https://github.com/OJ/gobuster/blob/master/README.md)
- [SecLists Repository](https://github.com/danielmiessler/SecLists) 