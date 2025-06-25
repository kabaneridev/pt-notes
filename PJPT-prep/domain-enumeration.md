# Domain Enumeration

## Overview
Domain enumeration is a critical phase in Active Directory penetration testing that involves gathering information about the domain structure, users, groups, computers, and relationships. This information is essential for identifying attack paths and privilege escalation opportunities.

## Essential Domain Enumeration Tools

### 1. ldapdomaindump
A tool for dumping domain information via LDAP and creating HTML reports for analysis.

#### Installation
```bash
# Install via pip
pip3 install ldapdomaindump

# Or install from source
git clone https://github.com/dirkjanm/ldapdomaindump.git
cd ldapdomaindump
python3 setup.py install
```

#### Basic Usage
```bash
# Basic domain dump with credentials
ldapdomaindump -u 'DOMAIN\username' -p 'password' dc_ip

# Using NTLM hash
ldapdomaindump -u 'DOMAIN\username' --hashes :ntlm_hash dc_ip

# Specify output directory
ldapdomaindump -u 'DOMAIN\username' -p 'password' -o /tmp/ldap_dump dc_ip

# Use different authentication methods
ldapdomaindump -u 'username@domain.local' -p 'password' dc_ip
```

#### Advanced Options
```bash
# Resolve all SIDs to names
ldapdomaindump -u 'DOMAIN\username' -p 'password' --resolve dc_ip

# Specify custom LDAP port
ldapdomaindump -u 'DOMAIN\username' -p 'password' --port 636 dc_ip

# Use LDAPS (SSL)
ldapdomaindump -u 'DOMAIN\username' -p 'password' --ssl dc_ip

# Verbose output
ldapdomaindump -u 'DOMAIN\username' -p 'password' -v dc_ip
```

#### Output Analysis
```bash
# Generated HTML files:
# - domain_computers.html - Computer accounts
# - domain_users.html - User accounts  
# - domain_groups.html - Group memberships
# - domain_policy.html - Domain policies
# - domain_trusts.html - Trust relationships

# Open in browser for analysis
firefox domain_users.html
```

### 2. BloodHound
A tool for analyzing Active Directory trust relationships and finding attack paths.

#### Installation
```bash
# Install BloodHound (GUI)
# Download from: https://github.com/BloodHoundAD/BloodHound/releases

# Install Neo4j database
sudo apt install neo4j

# Or use Docker
docker run -d -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/bloodhound neo4j:4.4-community
```

#### Data Collection with SharpHound
```bash
# Download SharpHound
wget https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound-v1.1.0.zip

# Run SharpHound on target (Windows)
.\SharpHound.exe -c All -d domain.local

# Specify domain controller
.\SharpHound.exe -c All -d domain.local --domaincontroller dc01.domain.local

# Use specific credentials
.\SharpHound.exe -c All -d domain.local --ldapusername user --ldappassword pass

# Stealth collection (slower but quieter)
.\SharpHound.exe -c All --stealth
```

#### Data Collection with BloodHound.py
```bash
# Install BloodHound.py
pip3 install bloodhound

# Collect data remotely
bloodhound-python -d domain.local -u username -p password -gc dc01.domain.local -c all

# Using NTLM hash
bloodhound-python -d domain.local -u username --hashes :ntlm_hash -gc dc01.domain.local -c all

# Specify name server
bloodhound-python -d domain.local -u username -p password -gc dc01.domain.local -c all --dns-tcp -ns 192.168.1.10
```

#### BloodHound Analysis
```bash
# Common queries in BloodHound:
# 1. Find all Domain Admins
# 2. Find Shortest Paths to Domain Admins
# 3. Find Principals with DCSync Rights
# 4. Find Computers with Unconstrained Delegation
# 5. Find ASREPRoastable Users
# 6. Find Kerberoastable Users
# 7. Find Computers where Domain Users are Local Admin
# 8. Find Shortest Paths from Kerberoastable Users
```

### 3. PlumHound
A tool that extends BloodHound by creating additional reports and analysis.

#### Installation
```bash
# Install PlumHound
git clone https://github.com/PlumHound/PlumHound.git
cd PlumHound
pip3 install -r requirements.txt
```

#### Usage with BloodHound Data
```bash
# Generate all default reports
python3 PlumHound.py --server bolt://localhost:7687 -u neo4j -p bloodhound

# Generate specific report types
python3 PlumHound.py --server bolt://localhost:7687 -u neo4j -p bloodhound --TaskList tasks/default.tasks

# Custom output directory
python3 PlumHound.py --server bolt://localhost:7687 -u neo4j -p bloodhound -o /tmp/plumhound_reports

# Generate specific queries
python3 PlumHound.py --server bolt://localhost:7687 -u neo4j -p bloodhound --QuerySingle "MATCH (u:User {enabled:true}) RETURN u.name"
```

#### Custom Report Generation
```bash
# Create custom task file
cat > custom.tasks << EOF
["Domain Admins","MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}) RETURN u.name as Username","List of Domain Administrators"]
["High Value Targets","MATCH (u:User {highvalue:true}) RETURN u.name as Username","High Value User Accounts"]
["Unconstrained Delegation","MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name as Computer","Computers with Unconstrained Delegation"]
EOF

# Run custom tasks
python3 PlumHound.py --server bolt://localhost:7687 -u neo4j -p bloodhound --TaskList custom.tasks
```

### 4. PingCastle
A Windows-based tool for Active Directory security assessment and health check.

#### Installation and Usage
```bash
# Download PingCastle from: https://www.pingcastle.com/download/
# Run on Windows domain-joined machine or with credentials

# Basic health check
PingCastle.exe --healthcheck --server dc01.domain.local

# Generate report for specific domain
PingCastle.exe --healthcheck --server dc01.domain.local --domain domain.local

# Advanced scan with all modules
PingCastle.exe --healthcheck --level Full --server dc01.domain.local

# Export results
PingCastle.exe --healthcheck --server dc01.domain.local --xmls
```

## Comprehensive Domain Enumeration Workflow

### Phase 1: Initial LDAP Enumeration
```bash
# Step 1: Basic LDAP dump
ldapdomaindump -u 'DOMAIN\username' -p 'password' -o ldap_output dc_ip

# Step 2: Analyze HTML reports
firefox ldap_output/domain_users.html
firefox ldap_output/domain_groups.html
firefox ldap_output/domain_computers.html

# Step 3: Extract key information
grep -i "admin" ldap_output/domain_users.html
grep -i "service" ldap_output/domain_users.html
```

### Phase 2: BloodHound Data Collection
```bash
# Option A: Remote collection with BloodHound.py
bloodhound-python -d domain.local -u username -p password -gc dc01.domain.local -c all -ns dc_ip

# Option B: On-target collection (if you have access)
# Upload and run SharpHound.exe
.\SharpHound.exe -c All --zipfilename domain_bloodhound.zip
```

### Phase 3: BloodHound Analysis
```bash
# Start Neo4j database
sudo neo4j start

# Import data into BloodHound
# Drag and drop .zip files into BloodHound interface

# Run pre-built queries:
# 1. Find all Domain Admins
# 2. Shortest Paths to Domain Admins  
# 3. Find Computers with Unconstrained Delegation
# 4. Find ASREPRoastable Users (no pre-auth)
# 5. Find Kerberoastable Users (SPN set)
```

### Phase 4: Extended Analysis with PlumHound
```bash
# Generate comprehensive reports
python3 PlumHound.py --server bolt://localhost:7687 -u neo4j -p bloodhound -o plumhound_reports

# Review generated reports
ls plumhound_reports/
# - Domain_Admins.html
# - Kerberoastable_Users.html  
# - ASREPRoastable_Users.html
# - Computers_Local_Admin_Rights.html
```

## Advanced Enumeration Techniques

### LDAP Queries with ldapsearch
```bash
# Enumerate all users
ldapsearch -x -H ldap://dc_ip -D "username@domain.local" -w password -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName

# Find service accounts
ldapsearch -x -H ldap://dc_ip -D "username@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Find computers  
ldapsearch -x -H ldap://dc_ip -D "username@domain.local" -w password -b "DC=domain,DC=local" "(objectClass=computer)" sAMAccountName

# Find groups
ldapsearch -x -H ldap://dc_ip -D "username@domain.local" -w password -b "DC=domain,DC=local" "(objectClass=group)" sAMAccountName member
```

### PowerShell AD Enumeration (if on Windows)
```powershell
# Import Active Directory module
Import-Module ActiveDirectory

# Get all domain users
Get-ADUser -Filter * -Properties *

# Find service accounts
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Get domain admins
Get-ADGroupMember "Domain Admins"

# Find computers
Get-ADComputer -Filter * -Properties *

# Get domain trusts
Get-ADTrust -Filter *
```

### Impacket Tools for Domain Enumeration
```bash
# GetADUsers.py - Enumerate domain users
GetADUsers.py domain.local/username:password -dc-ip dc_ip -all

# GetUserSPNs.py - Find Kerberoastable users
GetUserSPNs.py domain.local/username:password -dc-ip dc_ip

# GetNPUsers.py - Find ASREPRoastable users  
GetNPUsers.py domain.local/username:password -dc-ip dc_ip

# secretsdump.py - Extract secrets (if admin)
secretsdump.py domain.local/username:password@dc_ip
```

## Key Information to Extract

### User Accounts
- Domain administrators
- Service accounts (SPNs)
- Privileged users
- Inactive accounts
- Accounts with passwords that don't expire
- ASREPRoastable users (no pre-auth)

### Groups
- Administrative groups
- Nested group memberships
- Custom security groups
- Distribution groups with security implications

### Computers
- Domain controllers
- Servers with specific roles
- Workstations with local admin rights
- Computers with unconstrained delegation
- Inactive computer accounts

### Permissions and Rights
- Users with DCSync rights
- Accounts with delegation permissions
- Users with admin rights on multiple systems
- Service accounts with excessive privileges

## Attack Path Identification

### Common Attack Paths
1. **Kerberoasting** → Service account compromise → Lateral movement
2. **ASREPRoasting** → User account compromise → Privilege escalation
3. **Unconstrained Delegation** → Computer compromise → Domain admin
4. **Local Admin Rights** → Credential harvesting → Domain escalation
5. **Group Policy Abuse** → System compromise → Domain control

### BloodHound Queries for Attack Paths
```cypher
// Find shortest path to Domain Admins
MATCH (u:User {name:"USERNAME@DOMAIN.LOCAL"}), (g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), p=shortestPath((u)-[*1..]->(g)) RETURN p

// Find computers where domain users have local admin
MATCH (g:Group {name:"DOMAIN USERS@DOMAIN.LOCAL"})-[:AdminTo]->(c:Computer) RETURN c.name

// Find users with DCSync rights
MATCH (u:User)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN u.name

// Find Kerberoastable users with admin rights
MATCH (u:User {hasspn:true})-[:AdminTo]->(c:Computer) RETURN u.name, c.name
```

## Defensive Considerations

### Detection Indicators
- Multiple LDAP queries from single source
- Unusual BloodHound/SharpHound activity
- Large data transfers from domain controllers
- Non-standard LDAP bind attempts
- Kerberos ticket requests for service accounts

### Mitigation Strategies
- Monitor LDAP query patterns
- Implement least privilege principles
- Regular audit of privileged groups
- Disable unused accounts
- Implement proper delegation controls
- Monitor for BloodHound indicators

## Reporting and Documentation

### Key Findings to Document
- Domain structure and topology
- Privileged user accounts identified
- Attack paths discovered
- Misconfigurations found
- Recommendations for hardening

### Evidence Collection
```bash
# Save all enumeration outputs
mkdir domain_enum_$(date +%Y%m%d)
cp -r ldap_output domain_enum_$(date +%Y%m%d)/
cp *.zip domain_enum_$(date +%Y%m%d)/  # BloodHound data
cp -r plumhound_reports domain_enum_$(date +%Y%m%d)/

# Create summary report
echo "Domain Enumeration Summary - $(date)" > domain_enum_$(date +%Y%m%d)/summary.txt
echo "Users found: $(wc -l < users.txt)" >> domain_enum_$(date +%Y%m%d)/summary.txt
echo "Computers found: $(wc -l < computers.txt)" >> domain_enum_$(date +%Y%m%d)/summary.txt
```

## Tools Comparison

| Tool | Purpose | Output Format | Best For |
|------|---------|---------------|----------|
| ldapdomaindump | LDAP enumeration | HTML reports | Initial reconnaissance |
| BloodHound | Attack path analysis | Graph database | Visual attack paths |
| PlumHound | Extended reporting | HTML/CSV reports | Detailed analysis |
| PingCastle | Security assessment | HTML reports | Compliance checking |

---

**Note**: Always ensure proper authorization before conducting domain enumeration. These techniques should only be used in authorized penetration testing scenarios or controlled lab environments. 