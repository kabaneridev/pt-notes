# Hydra - Fast Password Cracking

Hydra is a powerful password cracking tool that can perform brute force attacks against numerous protocols. It's often used for credential brute forcing during penetration tests and is particularly useful during the OSCP exam.

## Basic Usage

```bash
hydra -l <username> -P <wordlist> <ip> <protocol>
```

Where:
- `-l <username>`: Specifies a single username
- `-L <username_list>`: Specifies a list of usernames
- `-p <password>`: Specifies a single password
- `-P <password_list>`: Specifies a list of passwords
- `<ip>`: Target IP address
- `<protocol>`: Protocol to attack (ssh, ftp, http-post-form, etc.)

## Common Options

- `-v`: Verbose mode, displays login attempts
- `-V`: Very verbose, displays even more information
- `-t <number>`: Number of parallel connections (default: 16)
- `-f`: Stop on first valid credential pair found
- `-u`: Loop through usernames, then passwords (default is to loop through passwords, then usernames)
- `-e nsr`: Additional password checks (n=null, s=same as username, r=reversed username)

## Example Commands

### Basic Protocol Attacks

```bash
# FTP attack
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10

# SSH attack
hydra -l username -P /usr/share/wordlists/rockyou.txt 10.10.10.10 ssh

# SMB attack
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 10.10.10.10 smb

# RDP attack with throttling (1 thread)
hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.10
```

### HTTP Form-Based Attacks

```bash
# WordPress login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username"

# Basic Auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-get /admin
```

### Advanced Example - WordPress Login

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```

### Multiple Usernames and Passwords

```bash
hydra -L users.txt -P passwords.txt 10.10.10.10 ssh
```

## OSCP-Specific Tips

1. **Throttling**: Always use `-t 1` or `-t 4` for services like SSH/RDP to avoid account lockouts
2. **Output Files**: Use `-o results.txt` to save results for your report
3. **Login Attempt Monitoring**: Start with `-v` to monitor progress
4. **Protocol-Specific Notes**:
   - For HTTP form attacks, identify the correct failure message
   - For SSH, ensure you don't trigger account lockouts
   - For SMB, try both with and without domain names

## Handling Specific Error Messages

For HTTP form attacks, you need to specify a failure condition. Common options:

- `F=Login failed`: Look for "Login failed" text in the response
- `F=Authentication failed`: Look for "Authentication failed" text
- `S=Location`: Success if a redirect occurs (S=success condition)

## When to Use Hydra in OSCP

- After finding valid usernames through enumeration
- When you've exhausted other methods (default credentials, password reuse)
- On services where brute forcing is practical (not protected by lockouts)
- When you've found a password policy that limits the keyspace

## Common Wordlists

- `/usr/share/wordlists/rockyou.txt`: Common passwords
- `/usr/share/seclists/Passwords/`: Various password lists in SecLists
- `/usr/share/seclists/Usernames/`: Username lists in SecLists

## Prevention Measures

1. **Account Lockout Policies**: Prevent multiple failed attempts
2. **Rate Limiting**: Slow down authentication attempts
3. **Multi-Factor Authentication**: Add additional verification layer
4. **Strong Password Policies**: Enforce complex passwords
5. **Failed Login Monitoring**: Detect brute force attempts 