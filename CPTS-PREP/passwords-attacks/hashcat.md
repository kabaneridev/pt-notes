# Hashcat

## Basic Usage
```bash
hashcat -a <attack_mode> -m <hash_type> <hash_file> [wordlist/mask/etc]
hashcat --show <hash_file>  # Show cracked passwords
hashcat --help  # List all hash types
```

## Attack Modes
- `-a 0` - Dictionary attack
- `-a 1` - Combinator attack  
- `-a 3` - Mask attack (brute-force)
- `-a 6` - Hybrid wordlist + mask
- `-a 7` - Hybrid mask + wordlist

## Hash Type Detection
```bash
hashid -m <hash>  # Get hashcat mode number
```

## Common Hash Types
- `0` - MD5
- `100` - SHA1
- `1400` - SHA256
- `1700` - SHA512
- `1000` - NTLM
- `3000` - LM
- `1100` - Domain Cached Credentials (DCC)
- `2100` - DCC2
- `500` - MD5 Crypt
- `1800` - sha512crypt
- `3200` - bcrypt

## Dictionary Attack
```bash
# Basic dictionary attack
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -a 0 -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

## Mask Attack (Brute-force)
### Built-in Charsets
- `?l` - lowercase letters (a-z)
- `?u` - uppercase letters (A-Z)
- `?d` - digits (0-9)
- `?h` - lowercase hex (0-9a-f)
- `?H` - uppercase hex (0-9A-F)
- `?s` - special characters
- `?a` - all characters (?l?u?d?s)
- `?b` - all bytes (0x00-0xff)

### Custom Charsets
```bash
# Define custom charset
hashcat -a 3 -m 0 hash.txt -1 ?l?d "?1?1?1?1?1?1?1?1"  # lowercase + digits, 8 chars
hashcat -a 3 -m 0 hash.txt -1 ?u?l -2 ?d?s "?1?1?1?1?2?2"  # mixed case + digits/symbols
```

### Common Mask Examples
```bash
# 8 characters, all lowercase
hashcat -a 3 -m 0 hash.txt "?l?l?l?l?l?l?l?l"

# Uppercase + 4 lowercase + digit + symbol
hashcat -a 3 -m 0 hash.txt "?u?l?l?l?l?d?s"

# 6-8 character passwords, increment mode
hashcat -a 3 -m 0 hash.txt --increment --increment-min=6 --increment-max=8 "?a?a?a?a?a?a?a?a"
```

## Common Rule Files
- `best64.rule` - 64 common transformations
- `rockyou-30000.rule` - Popular rule set
- `T0XlC.rule` - Advanced rule set
- `dive.rule` - Comprehensive rule set
- `generated.rule` - Generated rules
- `leetspeak.rule` - Leet speak transformations

## Useful Options
- `--show` - Display cracked passwords
- `--left` - Show uncracked hashes
- `--increment` - Use incremental mask length
- `--increment-min=N` - Minimum length for incremental
- `--increment-max=N` - Maximum length for incremental
- `-r <rulefile>` - Apply rules
- `-o <outfile>` - Output results to file
- `--status` - Show status during attack
- `--force` - Force run (ignore warnings)

## Performance
- Uses GPU acceleration by default
- Much faster than CPU-based tools
- Monitor with `--status` for progress
- Can pause/resume sessions 