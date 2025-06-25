# Windows Privilege Escalation Checklist

This checklist helps you avoid rabbit holes by systematically verifying prerequisites for various privilege escalation techniques. Before spending time on a potential vector, check if the necessary conditions are met.

## Initial Enumeration Checklist

- [ ] Identify current user and privileges (`whoami /all`)
- [ ] Check operating system version (`systeminfo`)
- [ ] Check installed patches (`wmic qfe list brief`)
- [ ] Identify installed applications (`wmic product get name,version,vendor`)
- [ ] Check for running services (`net start` or `sc query`)
- [ ] Check network connections (`netstat -ano`)
- [ ] Identify scheduled tasks (`schtasks /query /fo LIST /v`)

## Privilege Abuse Prerequisites

### Token Privileges

- [ ] **SeBackupPrivilege**
  - Current user has this privilege
  - You can read sensitive files (SAM, SYSTEM)
  - You have a way to transfer files off the system

- [ ] **SeRestorePrivilege**
  - Current user has this privilege
  - You can write to system directories
  - You know which files to modify for privilege escalation

- [ ] **SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege**
  - Current user has one of these privileges
  - For "Potato" attacks: Windows version is susceptible
  - For RogueWinRM: Not patched against this technique

- [ ] **SeTakeOwnershipPrivilege**
  - Current user has this privilege
  - Target system file is not protected by additional mechanisms

- [ ] **SeLoadDriverPrivilege**
  - Current user has this privilege
  - You have a malicious driver ready to load
  - Driver signing enforcement can be bypassed

- [ ] **SeDebugPrivilege**
  - Current user has this privilege
  - Target processes are running
  - Memory protection mechanisms can be bypassed

## Service Exploitation Prerequisites

- [ ] **Unquoted Service Paths**
  - Service path contains spaces but no quotes
  - You have write permissions to one of the parent directories
  - Service runs as SYSTEM or elevated account
  - Service can be restarted or system can be rebooted

- [ ] **Weak Service Permissions**
  - You have permission to modify service configuration (`sc qc <service>`)
  - Service runs as SYSTEM or elevated account
  - Service can be restarted or system can be rebooted

- [ ] **Weak Service Binary Permissions**
  - You have write permission to the service executable
  - Service runs as SYSTEM or elevated account
  - Service can be restarted or system can be rebooted

- [ ] **DLL Hijacking**
  - Application/service loads DLLs without specifying full path
  - You have write permissions to a directory in the search path
  - Target application runs with elevated privileges
  - You can restart the application or service

## Registry Exploits Prerequisites

- [ ] **AlwaysInstallElevated**
  - Both registry keys are set to 1:
    - HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    - HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
  - You can create and execute a malicious MSI package

- [ ] **Autorun Programs**
  - You have write access to an autorun registry key
  - You can create a malicious executable
  - You can wait for or trigger a reboot or user login

- [ ] **Stored Credentials**
  - Registry contains saved credentials
  - Credentials are for a high-privilege account

## Credential Hunting Prerequisites

- [ ] **Stored Credentials**
  - Identified potential locations for credential storage
  - You have read access to these locations
  - Credentials are not encrypted or can be decrypted

- [ ] **Memory Dumping**
  - You have permission to create memory dumps
  - Target process (e.g., LSASS) is running
  - You have a way to extract credentials from the dump

- [ ] **Configuration Files**
  - You've identified potential configuration files
  - Files contain credentials in plaintext or weak encoding

## Kernel Exploits Prerequisites

- [ ] **Missing Patches**
  - You've identified missing patches (`systeminfo`)
  - Kernel version is vulnerable to a known exploit
  - You have a compiled exploit for this specific version
  - Exploit is stable and won't crash the system
  - System doesn't have mitigations (e.g., ASLR, DEP) that prevent the exploit

## Misconfiguration Prerequisites

- [ ] **Weak File Permissions**
  - You've found writable system files
  - These files are executed by high-privilege processes
  - You can modify the file without triggering security alerts

- [ ] **Scheduled Tasks**
  - You've identified interesting scheduled tasks
  - Task runs with high privileges
  - You can modify the task or its target executable

## Software-Specific Exploits

- [ ] **Installed Software Vulnerabilities**
  - You've identified vulnerable software versions
  - Exploit is available for these specific versions
  - Software runs with elevated privileges
  - You can trigger the vulnerable functionality

## Avoiding Common Rabbit Holes

1. **Don't waste time on kernel exploits first**
   - They're riskier and can crash the system
   - Exhaust other methods before attempting these
   - Verify the exact OS version and patches before attempting

2. **Don't try exploits without checking prerequisites**
   - Verify all checklist items before investing time in an exploit
   - Test exploits in a similar environment if possible

3. **Don't ignore the "low-hanging fruit"**
   - Always check basic misconfigurations first
   - Look for stored credentials before complex exploits
   - Check user privileges immediately (`whoami /priv`)

4. **Don't forget to document attempts**
   - Keep track of what you've tried
   - Note partial successes for later combination attacks
   - Document why certain approaches failed

## Time Management Tips

1. Set a time limit for each potential vector (15-30 minutes)
2. If a technique is taking too long, move on and come back later
3. Prioritize techniques based on:
   - Reliability (less likely to crash the system)
   - Simplicity (fewer steps means fewer potential failures)
   - Prerequisites you've already confirmed

Remember: The goal is to find the easiest path to privilege escalation, not to try every possible technique. 