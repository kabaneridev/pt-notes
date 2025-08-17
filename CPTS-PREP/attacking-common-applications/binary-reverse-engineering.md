# 🔍 Binary Reverse Engineering - Connection String Extraction

> **🎯 Objective:** Extract database connection strings and credentials from compiled applications using reverse engineering techniques.

## Overview

Applications often contain **hardcoded connection strings** with database credentials. Two main approaches: **ELF binary analysis** using GDB and **.NET DLL examination** using dnSpy for credential extraction.

---

## HTB Academy Lab Solution

### Lab: Database Credentials Discovery
**Question:** "What credentials were found for the local database instance while debugging the octopus_checker binary?"

**SSH Access:** `htb-student:HTB_@cademy_stdnt!` → `10.129.205.20`

#### Method 1: ELF Binary Analysis (GDB)
```bash
# Connect to target
ssh htb-student@10.129.205.20

# Navigate to binary location
find / -name "octopus_checker" 2>/dev/null

# Run initial examination
./octopus_checker
# Expected: SQL connection attempt with driver error

# Debug with GDB
gdb ./octopus_checker

# Set disassembly style
set disassembly-flavor intel

# Disassemble main function
disas main

# Set breakpoint at SQLDriverConnect call
b *0x5555555551b0

# Run program
run

# Examine RDX register for connection string
# Expected: "DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost,1401;UID=username;PWD=password;"
```

**Answer:** `SA:N0tS3cr3t!`

---

## Reverse Engineering Techniques

### 1. ELF Binary Analysis
```bash
# GDB debugging process
gdb ./binary_name

# Common GDB commands for credential hunting
set disassembly-flavor intel     # Set assembly style
disas main                       # Disassemble main function
b *address                       # Set breakpoint
run                             # Execute program
info registers                  # View register contents
x/s $rdx                        # Examine string at RDX
```

### 2. .NET Assembly Analysis
```bash
# Using dnSpy (.NET decompiler)
# 1. Load DLL in dnSpy
# 2. Navigate to Controllers/Classes
# 3. Look for connection strings in:
#    - Configuration sections
#    - Database context classes
#    - Connection string variables

# Alternative: strings command
strings MultimasterAPI.dll | grep -i "server\|password\|connection"
```

### 3. Connection String Patterns
```bash
# Common database connection string formats
"Server=server;Database=db;User Id=user;Password=pass;"
"DRIVER={SQL Server};SERVER=host;UID=user;PWD=pass;"
"Data Source=server;Initial Catalog=db;User ID=user;Password=pass;"
```

---

## Technical Details

### ELF Binary Analysis
- **GDB breakpoints** at database function calls
- **Register examination** for connection strings
- **Memory dumps** for credential discovery
- **Assembly code analysis** for hardcoded values

### .NET DLL Examination
- **dnSpy decompiler** for source code access
- **Configuration sections** examination
- **Connection string constants** identification
- **Database context analysis**

### Common Locations
```bash
# ELF binaries
/usr/local/bin/
/opt/applications/
/home/user/apps/

# .NET assemblies
C:\Program Files\App\
C:\inetpub\wwwroot\bin\
Application directories
```

---

## Impact & Exploitation

**Credential Discovery:**
- 🔑 **Database credentials** for lateral movement
- 🎯 **Service accounts** for privilege escalation  
- 📊 **Connection strings** revealing infrastructure
- 🔐 **API keys** and secrets in compiled code

**Attack Escalation:**
- **Database access** using extracted credentials
- **Password spraying** with discovered passwords
- **Service enumeration** using connection details
- **Lateral movement** through database networks

**Common Findings:**
- **SQL Server credentials** (sa, admin accounts)
- **Database names** and server information
- **Network topology** from connection strings
- **Development/production** environment details

---

## Detection & Defense

**Prevention:**
- **Configuration files** instead of hardcoded strings
- **Environment variables** for sensitive data
- **Encrypted connection strings**
- **Secret management systems** (Azure Key Vault, etc.)

**Monitoring:**
- **Binary analysis attempts** detection
- **Unauthorized GDB usage** monitoring
- **File access logging** for sensitive executables

**💡 Pro Tip:** Always check compiled applications for hardcoded credentials - developers often leave database connection strings with production credentials in binaries, especially in legacy enterprise applications. 