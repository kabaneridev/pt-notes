# Hyper-V Administrators Privilege Escalation

## 🎯 Overview

**Hyper-V Administrators** have full access to all Hyper-V features. If **Domain Controllers are virtualized**, members should be considered **Domain Admins** due to their ability to clone VMs and extract **NTDS.dit** offline.

## 🖥️ Virtual Machine Attack Vectors

### Domain Controller VM Compromise
```cmd
# Attack scenario:
1. Create clone of live Domain Controller VM
2. Mount virtual disk (.vhdx) offline
3. Extract NTDS.dit from mounted filesystem
4. Use secretsdump.py for credential extraction
```

**Risk Assessment:**
- **Virtualized DCs** = Full domain compromise potential
- **VM cloning** bypasses all online protections
- **Offline analysis** undetectable by security tools

## 🔗 Hard Link Exploitation

### Attack Mechanism
```cmd
# CVE-2018-0952 / CVE-2019-0841 exploitation:
1. vmms.exe restores permissions as NT AUTHORITY\SYSTEM
2. Delete target .vhdx file
3. Create hard link to protected SYSTEM file
4. Gain full permissions on SYSTEM file
```

### Target File Example
```cmd
# Mozilla Maintenance Service target
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
```

### Exploitation Steps
```cmd
# 1. Run PowerShell hard link exploit
# 2. Take ownership of target file
takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

# 3. Replace with malicious executable
# 4. Start service for SYSTEM execution
sc.exe start MozillaMaintenance
```

## ⚠️ Limitations

### Patching Status
```cmd
# MITIGATED: March 2020 Windows security updates
# Changed hard link behavior
# Technique no longer effective on patched systems
```

### Alternative Vectors
```cmd
# Focus on:
- VM-based attacks (still viable)
- Service exploitation requiring SYSTEM context
- Application services startable by unprivileged users
```

## 🔍 Detection & Defense

### Monitoring
```cmd
# Watch for:
- Hyper-V VM cloning activities
- Unexpected VM creation/deletion
- Hard link creation attempts
- Service file modifications
```

### Hardening
```cmd
# Mitigation strategies:
- Regular Windows updates (March 2020+)
- Restrict Hyper-V Administrators membership
- Monitor VM operations
- Implement VM integrity checking
```

## 💡 Key Takeaways

1. **Hyper-V Administrators** = potential Domain Admin access on virtualized DCs
2. **VM cloning attack** most reliable vector
3. **Hard link exploitation** patched since March 2020
4. **Virtualization security** critical for domain protection

---

*Hyper-V Administrators group represents significant risk in virtualized environments, particularly when Domain Controllers are virtualized.* 