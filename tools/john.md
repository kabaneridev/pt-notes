# John the Ripper

John the Ripper is a free and open-source password security auditing and password recovery tool available for many operating systems. It is designed to detect weak passwords in Unix/Linux and Windows systems.

## Basic Usage

```bash
# Basic usage with automatic format detection
john hash.txt

# Specify a format
john --format=raw-md5 hash.txt

# Use wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Show cracked passwords
john --show hash.txt
```

## Extracting Hashes

### Shadow File (Linux)

```bash
# First, combine /etc/passwd and /etc/shadow
unshadow /etc/passwd /etc/shadow > hashes.txt

# Then crack with John
john hashes.txt
```

### Windows NTLM Hashes

```bash
# Using pwdump or similar tools to extract
john --format=NT hash.txt
```

### Zip Files

```bash
# Extract hash from password-protected zip
zip2john file.zip > zip.hash

# Crack the hash
john zip.hash
```

### RAR Files

```bash
# Extract hash from password-protected rar
rar2john file.rar > rar.hash

# Crack the hash
john rar.hash
```

### PDF Files

```bash
# Extract hash from password-protected PDF
pdf2john file.pdf > pdf.hash

# Crack the hash
john pdf.hash
```

### SSH Keys

```bash
# Extract hash from encrypted SSH private key
ssh2john id_rsa > ssh.hash

# Crack the hash
john ssh.hash
```

## Attack Modes

### Dictionary Attack

```bash
# Basic dictionary attack
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# With rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt
```

### Incremental Mode (Brute Force)

```bash
# Brute force attack (slower but tries all possibilities)
john --incremental hash.txt

# Limit to certain character sets
john --incremental=Digits hash.txt  # Only digits
john --incremental=Alpha hash.txt   # Only letters
```

### Rules-Based Attack

```bash
# Apply rules to transform words from wordlist
john --wordlist=/usr/share/wordlists/rockyou.txt --rules hash.txt

# Use specific rule set
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Jumbo hash.txt
```

## Common Hash Formats

```bash
# MD5
john --format=raw-md5 hash.txt

# SHA1
john --format=raw-sha1 hash.txt

# SHA256
john --format=raw-sha256 hash.txt

# SHA512
john --format=raw-sha512 hash.txt

# Windows NTLM
john --format=NT hash.txt

# Linux /etc/shadow (SHA512CRYPT)
john --format=sha512crypt hash.txt

# MySQL
john --format=mysql-sha1 hash.txt

# PostgreSQL
john --format=postgres hash.txt
```

## Advanced Options

```bash
# Set maximum execution time
john --max-run-time=3600 hash.txt  # Run for 1 hour

# Use multiple cores
john --fork=4 hash.txt  # Use 4 cores

# Session management
john --session=mysession hash.txt  # Start a named session
john --restore=mysession           # Restore a session

# Show statistics during cracking
john --status=mysession

# Automatically detect hash type
john --format=auto hash.txt
```

## Custom Rules

John's custom rules allow you to create complex password transformations. Add these to the `john.conf` file:

```
# Example rule to append years
$[append_year] $[l] [0-9][0-9]

# Example rule to replace characters
$[replace_chars] s $s0 $i1 $e3 $a4 $t7
```

## Integration in Pentesting Workflow

1. **Extract hashes** from the target system
2. **Identify hash types** (`hashid` or `hash-identifier` can help)
3. **Select appropriate attack method** based on hash type and context
4. **Begin with quick wordlist attacks** using common passwords
5. **Move to rule-based attacks** if simple wordlists fail
6. **Use incremental (brute force) mode** as a last resort for short passwords

## Tips for Effective Usage

- Always start with the most likely password patterns for your target
- Use the `--pot` option to save cracked passwords for future reference
- Leverage session management for long-running cracks
- Use custom rules based on the target organization (company name, founding year, etc.)
- For Linux shadow files, target lower-privileged users first as they often have weaker passwords
- Use `--show` to display already cracked passwords without rerunning the attack

## Real-World Example: Cracking Linux Passwords

```bash
# Step 1: Extract shadow and passwd files from target
# Assuming you have both files

# Step 2: Combine them
unshadow passwd shadow > linux_hashes.txt

# Step 3: Crack with wordlist first
john --wordlist=/usr/share/wordlists/rockyou.txt linux_hashes.txt

# Step 4: If that fails, try with rules
john --wordlist=/usr/share/wordlists/rockyou.txt --rules linux_hashes.txt

# Step 5: Show cracked passwords
john --show linux_hashes.txt
```

## Additional Resources

- [Official John the Ripper website](https://www.openwall.com/john/)
- [John the Ripper GitHub repository](https://github.com/openwall/john)
- [Wordlists collection](https://github.com/danielmiessler/SecLists) 