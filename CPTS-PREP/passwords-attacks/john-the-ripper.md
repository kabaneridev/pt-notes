# John the Ripper (JtR)

## Basic Usage
```bash
john <hash_file>
john --show <hash_file>  # Show cracked passwords
```

## Cracking Modes

### Single Crack Mode
- Rule-based, uses username/GECOS info
- Best for Linux credentials
```bash
john --single passwd
```

### Wordlist Mode
- Dictionary attack with wordlist
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt <hash_file>
john --wordlist=<wordlist> --rules <hash_file>  # With rules
```

### Incremental Mode
- Brute-force with statistical model (Markov chains)
- Most exhaustive but slowest
```bash
john --incremental <hash_file>
john --incremental=ASCII <hash_file>  # Custom charset
```

## Hash Format Detection
```bash
hashid -j <hash>  # Identify hash format
john --format=<format> <hash_file>
```

## Common Hash Formats
- `raw-md5` - MD5 hashes
- `raw-sha1` - SHA1 hashes
- `nt` - Windows NT hashes
- `mscash/mscash2` - Windows cached credentials
- `crypt` - Unix crypt(3) hashes
- `mysql` - MySQL password hashes

## File Cracking Tools
```bash
# Convert files to JtR format
zip2john archive.zip > zip.hash
ssh2john id_rsa > ssh.hash
pdf2john document.pdf > pdf.hash
keepass2john database.kdbx > keepass.hash
office2john document.docx > office.hash

# Then crack
john zip.hash
```

## Key Options
- `--format=<format>` - Specify hash format
- `--rules` - Apply transformation rules
- `--show` - Display cracked passwords
- `--wordlist=<file>` - Use specific wordlist
- `--incremental` - Brute-force mode
- `--single` - Single crack mode

## Configuration
- Main config: `/etc/john/john.conf`
- Custom charsets and rules can be defined
- Incremental modes with different character sets (ASCII, UTF8, etc.) 