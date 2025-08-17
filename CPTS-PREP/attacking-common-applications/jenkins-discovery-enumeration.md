# 🔧 Jenkins Discovery & Enumeration

> **🎯 Objective:** Master the identification, enumeration, and reconnaissance techniques for Jenkins CI/CD automation servers to uncover development infrastructure attack surfaces, authentication mechanisms, and administrative interfaces in enterprise environments.

## Overview

Jenkins represents a **critical attack surface** in enterprise development environments, serving as the **central automation hub** for **continuous integration and continuous deployment (CI/CD)** pipelines. With **over 86,000 companies** using Jenkins and **widespread deployment** across internal networks, Jenkins often provides **high-privilege access** to development infrastructure and **SYSTEM/root level execution context**.

**Key Jenkins Statistics:**
- **86,000+ companies** actively using Jenkins globally
- **Original name:** Hudson (2005) → renamed Jenkins (2011) after Oracle dispute
- **Major enterprise users:** Facebook, Netflix, Udemy, Robinhood, LinkedIn
- **300+ plugins** for build and test project automation
- **Java-based architecture** - runs in servlet containers like Tomcat

**Enterprise Attack Significance:**
- **Development Infrastructure Access** - Central hub for source code, build processes, deployment credentials
- **SYSTEM/Root Execution** - Jenkins often runs with highest privileges for system integration
- **Active Directory Integration** - Domain-joined Windows servers with elevated service accounts
- **Supply Chain Impact** - Compromise can inject malicious code into production deployments
- **Credential Repository** - Access to database passwords, API keys, cloud credentials

---

## Jenkins Architecture & Components

### Core System Structure

#### Jenkins Installation Components
```
/var/lib/jenkins/ (Linux) or C:\Program Files\Jenkins\ (Windows)
├── config.xml                # Main configuration file
├── users/                     # User account configurations
│   ├── admin/                # User-specific directories
│   │   └── config.xml        # User configuration
│   └── [username]/
├── jobs/                      # Job and pipeline configurations
│   ├── [job-name]/
│   │   ├── config.xml        # Job-specific configuration
│   │   ├── builds/           # Build history and artifacts
│   │   └── workspace/        # Job workspace directory
├── plugins/                   # Installed plugins and extensions
│   ├── [plugin-name].jpi     # Plugin files
│   └── [plugin-name]/        # Plugin data directories
├── secrets/                   # Encrypted credentials and secrets
│   ├── master.key           # Master encryption key
│   ├── hudson.util.Secret   # Secret encryption
│   └── initialAdminPassword # Initial setup password
├── logs/                     # Jenkins application logs
├── workspace/                # Global workspace directory
└── war/                      # Jenkins web application files
```

#### Network Architecture
```
Standard Jenkins Deployment:
┌─────────────────────────────────────────────────┐
│                Jenkins Master                   │
│  Port 8080 (HTTP) / 8443 (HTTPS)              │
│  - Web Interface                               │
│  - REST API                                    │
│  - Script Console                              │
│  - Job Management                              │
└─────────────────┬───────────────────────────────┘
                  │ Port 5000 (JNLP)
                  │ Jenkins Remoting Protocol
                  ▼
┌─────────────────────────────────────────────────┐
│              Jenkins Agents/Slaves              │
│  - Build Execution                             │
│  - Distributed Processing                      │
│  - Isolated Environments                       │
└─────────────────────────────────────────────────┘

Integration Points:
├── Source Control (Git, SVN, Mercurial)
├── Artifact Repositories (Nexus, Artifactory)
├── Container Registries (Docker Hub, Harbor)
├── Cloud Platforms (AWS, Azure, GCP)
├── Testing Frameworks (JUnit, TestNG)
├── Notification Systems (Email, Slack, Teams)
└── Deployment Targets (Kubernetes, VMs, Cloud)
```

### Default Network Configuration

#### Standard Port Usage
```bash
# Primary Jenkins services
8080/tcp    # HTTP web interface (default)
8443/tcp    # HTTPS web interface (if SSL configured)
5000/tcp    # JNLP agent communication (Jenkins Remoting)
50000/tcp   # Alternative JNLP port (some configurations)

# Additional ports (environment dependent)
9000/tcp    # Alternative HTTP port
8000/tcp    # Development/testing instances
8180/tcp    # When running alongside Tomcat
```

#### Service Identification Commands
```bash
# Port scanning for Jenkins services
nmap -sV -p 8080,8443,5000,50000,9000,8000,8180 target.com

# Jenkins-specific Nmap scripts
nmap --script http-enum -p 8080 target.com
nmap --script http-title -p 8080 target.com

# Service banner analysis
curl -I http://target.com:8080/
curl -s http://target.com:8080/ | grep -i jenkins
```

---

## Discovery & Fingerprinting Techniques

### HTTP-Based Discovery

#### Web Interface Identification
```bash
# Primary Jenkins detection methods
curl -s http://target.com:8080/ | grep -i jenkins
curl -s http://target.com:8080/login | grep -i jenkins

# Jenkins-specific headers and responses
curl -I http://target.com:8080/
# Look for: Server: Jetty, X-Jenkins headers

# Distinctive Jenkins endpoints
jenkins_endpoints=(
    "/"
    "/login"
    "/configureSecurity/"
    "/script"
    "/systemInfo"
    "/manage"
    "/cli"
    "/api/json"
    "/asynchPeople/"
    "/build"
)

echo "[+] Testing Jenkins-specific endpoints:"
for endpoint in "${jenkins_endpoints[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com:8080$endpoint")
    echo "$endpoint: HTTP $response"
done
```

#### Version Detection Techniques
```bash
# Method 1: Login page analysis
curl -s "http://target.com:8080/login" | grep -oP 'Jenkins ver\. \K[0-9.]+'

# Method 2: API endpoint version detection
curl -s "http://target.com:8080/api/json" | jq -r '.version'

# Method 3: System information page (if accessible)
curl -s "http://target.com:8080/systemInfo" | grep -i version

# Method 4: Manage Jenkins page
curl -s "http://target.com:8080/manage" | grep -oP 'Jenkins \K[0-9.]+'

# Method 5: Footer analysis
curl -s "http://target.com:8080/" | grep -oP 'Jenkins \K[0-9.]+'

# Method 6: CLI interface version
curl -s "http://target.com:8080/cli" | grep -i version
```

#### Authentication Mechanism Detection
```bash
# Detect authentication requirements
auth_response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com:8080/manage")
if [[ $auth_response == "403" ]]; then
    echo "[+] Authentication required"
elif [[ $auth_response == "200" ]]; then
    echo "[!] No authentication required - CRITICAL FINDING"
else
    echo "[?] Unexpected response: $auth_response"
fi

# Check for anonymous access
curl -s "http://target.com:8080/asynchPeople/" | grep -i "anonymous\|user"

# Detect authentication methods
curl -s "http://target.com:8080/configureSecurity/" | grep -E "(ldap|database|unix|matrix)"
```

### Advanced Reconnaissance

#### Plugin and Extension Discovery
```bash
# Plugin enumeration via API
curl -s "http://target.com:8080/pluginManager/api/json?depth=1" | \
  jq -r '.plugins[] | "\(.shortName): \(.version)"'

# Common plugin endpoints
plugin_endpoints=(
    "/pluginManager/"
    "/updateCenter/"
    "/pluginManager/installed"
    "/pluginManager/available"
)

# Security-relevant plugins to identify
security_plugins=(
    "matrix-auth"           # Matrix-based security
    "ldap"                 # LDAP authentication
    "active-directory"     # Active Directory integration
    "role-strategy"        # Role-based access control
    "saml"                 # SAML authentication
    "github-oauth"         # GitHub OAuth
)

echo "[+] Checking for security-related plugins:"
for plugin in "${security_plugins[@]}"; do
    curl -s "http://target.com:8080/pluginManager/api/json" | grep -q "$plugin" && \
      echo "[+] $plugin plugin detected"
done
```

#### Job and Pipeline Discovery
```bash
# Job enumeration via API
curl -s "http://target.com:8080/api/json" | jq -r '.jobs[] | .name'

# Build history analysis
curl -s "http://target.com:8080/api/json?tree=jobs[name,builds[number,url]]" | \
  jq -r '.jobs[] | .name + ": " + (.builds | length | tostring) + " builds"'

# Workspace content discovery
curl -s "http://target.com:8080/job/[JOB_NAME]/ws/" | grep -oP 'href="[^"]*"'

# Build artifact enumeration
curl -s "http://target.com:8080/job/[JOB_NAME]/[BUILD_NUMBER]/artifact/"
```

#### Credential and Secret Discovery
```bash
# Credential store enumeration (if accessible)
curl -s "http://target.com:8080/credentials/" | grep -i credential

# Environment variable exposure
curl -s "http://target.com:8080/env-vars.html/" | grep -E "(password|secret|key|token)"

# Build environment analysis
curl -s "http://target.com:8080/job/[JOB_NAME]/[BUILD_NUMBER]/console" | \
  grep -E "(password|secret|key|token)" | head -10

# Git repository credentials
curl -s "http://target.com:8080/job/[JOB_NAME]/config.xml" | \
  grep -E "(username|password|credentialsId)"
```

---

## Authentication & Authorization Assessment

### Default Credential Testing

#### Common Jenkins Credentials
```bash
# Standard default credentials to test
jenkins_creds=(
    "admin:admin"
    "jenkins:jenkins"
    "admin:password"
    "admin:jenkins"
    "admin:"
    "jenkins:admin"
    "admin:123456"
    "root:root"
    "administrator:administrator"
)

# Automated credential testing
for cred in "${jenkins_creds[@]}"; do
    username=$(echo $cred | cut -d':' -f1)
    password=$(echo $cred | cut -d':' -f2)
    
    response=$(curl -s -u "$username:$password" \
        -c cookies.txt \
        "http://target.com:8080/me/api/json" \
        -w "%{http_code}")
    
    if [[ $response == *"200"* ]]; then
        echo "[+] Valid credentials found: $username:$password"
        break
    fi
done
```

#### Authentication Bypass Testing
```bash
# Test for anonymous access
curl -s "http://target.com:8080/script" | grep -q "Script Console" && \
  echo "[!] CRITICAL: Anonymous Script Console access!"

curl -s "http://target.com:8080/manage" | grep -q "Manage Jenkins" && \
  echo "[!] CRITICAL: Anonymous administrative access!"

# Authentication method analysis
curl -s "http://target.com:8080/configureSecurity/" | \
  grep -oP 'name="_.*(realm|security)"[^>]*value="[^"]*"'

# Session management testing
curl -s -c session.txt "http://target.com:8080/login"
curl -s -b session.txt "http://target.com:8080/manage" | \
  grep -q "Manage Jenkins" && echo "[+] Session-based access possible"
```

### Authorization Level Enumeration

#### Permission Matrix Analysis
```bash
# User permission enumeration (if authenticated)
curl -s -u "username:password" \
  "http://target.com:8080/whoAmI/api/json" | jq -r '.authorities[]'

# Role-based access control analysis
curl -s -u "username:password" \
  "http://target.com:8080/configureSecurity/" | \
  grep -A 10 -B 10 "authorization"

# Administrative privilege testing
admin_endpoints=(
    "/manage"
    "/configureSecurity/"
    "/script"
    "/systemInfo"
    "/pluginManager/"
)

echo "[+] Testing administrative access:"
for endpoint in "${admin_endpoints[@]}"; do
    response=$(curl -s -u "username:password" \
        -o /dev/null -w "%{http_code}" \
        "http://target.com:8080$endpoint")
    echo "$endpoint: HTTP $response"
done
```

---

## Build System Analysis

### Job Configuration Assessment

#### Build Process Enumeration
```bash
# Job configuration analysis
job_config_analysis() {
    local job_name=$1
    
    echo "[+] Analyzing job: $job_name"
    
    # Get job configuration XML
    curl -s -u "username:password" \
      "http://target.com:8080/job/$job_name/config.xml" > job_config.xml
    
    # Extract sensitive information
    echo "[+] Build triggers:"
    grep -oP '<triggers[^>]*>.*?</triggers>' job_config.xml
    
    echo "[+] Source control configuration:"
    grep -oP '<scm[^>]*>.*?</scm>' job_config.xml
    
    echo "[+] Build steps:"
    grep -oP '<builders>.*?</builders>' job_config.xml
    
    echo "[+] Post-build actions:"
    grep -oP '<publishers>.*?</publishers>' job_config.xml
    
    # Look for hardcoded credentials
    echo "[+] Potential credentials:"
    grep -iE "(password|secret|key|token|credential)" job_config.xml
}

# List all jobs and analyze each
jobs=$(curl -s -u "username:password" \
  "http://target.com:8080/api/json" | jq -r '.jobs[] | .name')

for job in $jobs; do
    job_config_analysis "$job"
done
```

#### Pipeline Security Analysis
```bash
# Pipeline script analysis (Jenkinsfile)
pipeline_analysis() {
    local job_name=$1
    
    # Get pipeline script
    curl -s -u "username:password" \
      "http://target.com:8080/job/$job_name/1/replay/" | \
      grep -oP 'name="_.script"[^>]*value="[^"]*"' | \
      sed 's/.*value="\([^"]*\)".*/\1/' | \
      base64 -d > pipeline_script.groovy
    
    # Analyze for security issues
    echo "[+] Pipeline security analysis for $job_name:"
    
    # Command execution detection
    grep -n "sh \|bat \|powershell \|cmd " pipeline_script.groovy && \
      echo "[!] Direct command execution found"
    
    # Credential usage
    grep -n "withCredentials\|usernamePassword\|string" pipeline_script.groovy && \
      echo "[+] Credential usage detected"
    
    # File system access
    grep -n "writeFile\|readFile\|deleteDir" pipeline_script.groovy && \
      echo "[+] File system operations detected"
    
    # Network operations
    grep -n "httpRequest\|wget\|curl" pipeline_script.groovy && \
      echo "[+] Network operations detected"
}

# Analyze pipeline jobs
pipeline_jobs=$(curl -s -u "username:password" \
  "http://target.com:8080/api/json" | \
  jq -r '.jobs[] | select(.color != null) | .name')

for job in $pipeline_jobs; do
    pipeline_analysis "$job"
done
```

### Build Artifact Analysis

#### Artifact Security Assessment
```bash
# Build artifact enumeration and analysis
artifact_analysis() {
    local job_name=$1
    local build_number=$2
    
    echo "[+] Analyzing artifacts for $job_name build $build_number:"
    
    # List artifacts
    artifacts=$(curl -s -u "username:password" \
      "http://target.com:8080/job/$job_name/$build_number/api/json" | \
      jq -r '.artifacts[] | .fileName')
    
    for artifact in $artifacts; do
        echo "[+] Artifact: $artifact"
        
        # Download and analyze
        curl -s -u "username:password" \
          "http://target.com:8080/job/$job_name/$build_number/artifact/$artifact" \
          -o "$artifact"
        
        # Basic security analysis
        case "$artifact" in
            *.jar|*.war)
                echo "[+] Java archive - checking for credentials:"
                unzip -l "$artifact" | grep -i "config\|properties\|xml"
                ;;
            *.zip|*.tar.gz)
                echo "[+] Archive file - checking contents:"
                if [[ "$artifact" == *.zip ]]; then
                    unzip -l "$artifact" | head -20
                else
                    tar -tzf "$artifact" | head -20
                fi
                ;;
            *.log)
                echo "[+] Log file - checking for sensitive data:"
                grep -iE "(password|secret|key|token)" "$artifact" | head -5
                ;;
        esac
    done
}

# Find recent builds with artifacts
recent_builds=$(curl -s -u "username:password" \
  "http://target.com:8080/api/json" | \
  jq -r '.jobs[] | .name + ":" + (.lastBuild.number // "N/A" | tostring)')

for build_info in $recent_builds; do
    job_name=$(echo $build_info | cut -d':' -f1)
    build_number=$(echo $build_info | cut -d':' -f2)
    
    if [[ "$build_number" != "N/A" ]]; then
        artifact_analysis "$job_name" "$build_number"
    fi
done
```

---

## HTB Academy Lab Solutions

### Lab 1: Jenkins Version Detection
**Question:** "Log in to the Jenkins instance at http://jenkins.inlanefreight.local:8000. Browse around and submit the version number when you are ready to move on."

**Solution Methodology:**

#### Step 1: Environment Setup
```bash
# Add VHost entry to /etc/hosts
echo "TARGET_IP jenkins.inlanefreight.local" >> /etc/hosts

# Verify Jenkins accessibility
curl -I http://jenkins.inlanefreight.local:8000/
```

#### Step 2: Authentication
```bash
# Login with provided credentials: admin:admin
curl -c cookies.txt -d "j_username=admin&j_password=admin" \
  http://jenkins.inlanefreight.local:8000/j_security_check

# Verify authentication success
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/manage | grep -q "Manage Jenkins"
```

#### Step 3: Version Detection Methods
```bash
# Method 1: Login page footer analysis
curl -s http://jenkins.inlanefreight.local:8000/login | \
  grep -oP 'Jenkins ver\. \K[0-9.]+'

# Method 2: Management interface
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/manage | \
  grep -oP 'Jenkins \K[0-9.]+'

# Method 3: API endpoint (authenticated)
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/api/json | \
  jq -r '.version'

# Method 4: System information page
curl -b cookies.txt http://jenkins.inlanefreight.local:8000/systemInfo | \
  grep -i "Jenkins version"

# Method 5: Browser-based approach
# Navigate to: http://jenkins.inlanefreight.local:8000/
# Login with: admin / admin
# Check footer or go to Manage Jenkins -> System Information
```

#### Step 4: Version Verification
```bash
# HTB Academy expected version: 2.303.1
# This version can typically be found in:
# 1. Login page footer: "Jenkins ver. 2.303.1"
# 2. Manage Jenkins page header
# 3. System Information under "Jenkins version"
# 4. API response in version field

# HTB Answer: 2.303.1
```

---

## Enterprise Deployment Patterns

### Internal Network Recognition

#### CI/CD Infrastructure Mapping
```bash
# Jenkins in enterprise environments commonly found:
# 1. Development networks (internal CI/CD)
# 2. Build servers (dedicated infrastructure)
# 3. Integration environments (staging/testing)
# 4. Cloud deployments (AWS/Azure/GCP)

# Network reconnaissance for Jenkins clusters
nmap -sS -p 8080,8443,5000 10.10.0.0/16 | grep -B 2 -A 2 "8080/tcp.*open"

# Jenkins master-agent architecture detection
nmap -sV -p 5000 target-range | grep -i "jenkins\|jnlp"

# Load balancer detection
curl -I http://jenkins.internal.com:8080/ | grep -i "x-forwarded\|load-balancer"
```

#### Development Tool Integration
```bash
# Common Jenkins integrations to identify:
integration_indicators=(
    "git"                  # Source control
    "docker"              # Containerization
    "kubernetes"          # Orchestration
    "aws"                 # Cloud deployment
    "ansible"             # Configuration management
    "terraform"           # Infrastructure as code
    "sonarqube"           # Code quality
    "nexus"               # Artifact repository
)

echo "[+] Checking for development tool integrations:"
for tool in "${integration_indicators[@]}"; do
    curl -s -b cookies.txt "http://jenkins.inlanefreight.local:8000/configure" | \
      grep -qi "$tool" && echo "[+] $tool integration detected"
done
```

### Security Configuration Analysis

#### Authentication Method Assessment
```bash
# Security realm analysis
curl -s -b cookies.txt "http://jenkins.inlanefreight.local:8000/configureSecurity/" | \
  grep -A 5 -B 5 "securityRealm"

# Authorization strategy detection
curl -s -b cookies.txt "http://jenkins.inlanefreight.local:8000/configureSecurity/" | \
  grep -A 10 "authorizationStrategy"

# Anonymous access configuration
curl -s "http://jenkins.inlanefreight.local:8000/configureSecurity/" | \
  grep -i "anonymous" && echo "[!] Anonymous access may be enabled"

# CSRF protection status
curl -s -b cookies.txt "http://jenkins.inlanefreight.local:8000/configureSecurity/" | \
  grep -i "csrf" && echo "[+] CSRF protection configured"
```

---

## Intelligence Gathering Workflow

### Systematic Jenkins Assessment

#### Phase 1: Discovery & Identification
- [ ] **Service Detection** - Port scanning and service identification
- [ ] **Version Fingerprinting** - Login pages, API endpoints, headers
- [ ] **Authentication Analysis** - Default credentials, anonymous access
- [ ] **Plugin Enumeration** - Security plugins and extensions

#### Phase 2: Access Control Assessment
- [ ] **Authentication Bypass** - Anonymous access testing
- [ ] **Default Credential Testing** - Common username/password combinations
- [ ] **Authorization Analysis** - Permission matrix and role evaluation
- [ ] **Session Management** - Cookie analysis and session security

#### Phase 3: Build System Analysis
- [ ] **Job Configuration** - Build processes and trigger mechanisms
- [ ] **Pipeline Security** - Groovy script analysis and command execution
- [ ] **Artifact Assessment** - Build outputs and sensitive data exposure
- [ ] **Credential Discovery** - Hardcoded secrets and credential stores

#### Phase 4: Infrastructure Mapping
- [ ] **Agent Discovery** - Build slave identification and configuration
- [ ] **Integration Analysis** - Third-party tool connections and APIs
- [ ] **Network Architecture** - Master-agent communication and clustering
- [ ] **Supply Chain Assessment** - Deployment targets and production impact

---

## Risk Assessment Framework

### Jenkins Security Priorities

#### Critical Findings
```bash
# Immediate security concerns to identify:
critical_checks=(
    "Anonymous Script Console access"
    "Anonymous administrative access"
    "Default credentials (admin:admin)"
    "Exposed credential stores"
    "Unauthenticated build triggering"
    "Pipeline privilege escalation"
    "Hardcoded secrets in job configs"
    "Unrestricted agent registration"
)

# Risk assessment automation
for check in "${critical_checks[@]}"; do
    case "$check" in
        "Anonymous Script Console access")
            curl -s "http://jenkins.inlanefreight.local:8000/script" | \
              grep -q "Script Console" && echo "[!] CRITICAL: $check"
            ;;
        "Anonymous administrative access")
            curl -s "http://jenkins.inlanefreight.local:8000/manage" | \
              grep -q "Manage Jenkins" && echo "[!] CRITICAL: $check"
            ;;
        # Add other checks as needed
    esac
done
```

---

## Next Steps

After Jenkins enumeration, proceed to:
1. **[Jenkins Attacks & Exploitation](jenkins-attacks.md)** - Script Console abuse and RCE
2. **[CI/CD Pipeline Security](cicd-security.md)** - Build process manipulation
3. **[GitLab Discovery](gitlab-discovery.md)** - Source code management reconnaissance

**💡 Key Takeaway:** Jenkins enumeration focuses on **CI/CD infrastructure reconnaissance**, **authentication bypass discovery**, and **build system analysis**. Enterprise environments frequently contain **Jenkins instances with weak security configurations**, making systematic enumeration crucial for identifying **development infrastructure attack vectors** and **supply chain compromise opportunities**. 