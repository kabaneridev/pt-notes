# ☕ Tomcat Discovery & Enumeration

> **🎯 Objective:** Master the identification, enumeration, and intelligence gathering techniques for Apache Tomcat servlet containers to uncover Java-based application attack surfaces and administrative interfaces in enterprise environments.

## Overview

Apache Tomcat represents a critical attack surface in enterprise environments, serving as the **open-source servlet container** for Java applications including **Spring Framework**, **Gradle builds**, and custom enterprise applications. With **over 220,000 live websites** and **904,000+ historical deployments**, Tomcat often provides **high-value targets** for internal network penetration and **external footholds** into corporate infrastructure.

**Key Tomcat Statistics:**
- **220,000+ active Tomcat websites** globally (BuiltWith data)
- **904,000+ historical deployments** across internet infrastructure
- **1.22% of top 1 million websites** use Tomcat (3.8% of top 100k)
- **Position #13** in web server market share rankings
- **Major users:** Alibaba, USPTO, American Red Cross, LA Times

**Enterprise Deployment Patterns:**
- **External exposure:** Less common but high-impact when discovered
- **Internal prevalence:** Multiple instances per environment (common)
- **EyeWitness priority:** First position under "High Value Targets"
- **Configuration issues:** Frequent weak/default credential usage

---

## Tomcat Architecture & Components

### Core Directory Structure

#### Standard Tomcat Installation Layout
```
/opt/tomcat/ (or /usr/local/tomcat/)
├── bin/                    # Scripts and binaries for server management
│   ├── startup.sh         # Server startup script
│   ├── shutdown.sh        # Server shutdown script  
│   ├── catalina.sh        # Main control script
│   └── setenv.sh          # Environment configuration
├── conf/                   # Configuration files
│   ├── catalina.policy    # Security policy configuration
│   ├── catalina.properties # Engine configuration properties
│   ├── context.xml        # Default context configuration
│   ├── server.xml         # Main server configuration
│   ├── tomcat-users.xml   # User credentials and roles
│   ├── tomcat-users.xsd   # User configuration schema
│   └── web.xml            # Default web application descriptor
├── lib/                    # JAR files and libraries
│   ├── catalina.jar       # Core Tomcat functionality
│   ├── servlet-api.jar    # Servlet API implementation
│   └── [various JARs]     # Additional libraries
├── logs/                   # Log files and runtime information
│   ├── catalina.out       # Main application log
│   ├── access.log         # HTTP access logs
│   └── manager.log        # Management interface logs
├── temp/                   # Temporary files and cache
├── webapps/               # Web application deployment directory
│   ├── ROOT/             # Default web application
│   ├── manager/          # Tomcat management interface
│   ├── host-manager/     # Virtual host management
│   ├── docs/             # Documentation
│   ├── examples/         # Sample applications
│   └── [custom apps]/    # Deployed applications
└── work/                  # Runtime compilation and cache
    └── Catalina/         # Engine-specific work directory
        └── localhost/    # Host-specific compiled JSPs
```

### Web Application Structure

#### Standard WAR Application Layout
```
webapps/customapp/
├── images/                # Static image resources
├── css/                   # Stylesheets
├── js/                    # JavaScript files
├── index.jsp             # Main application entry point
├── META-INF/             # Application metadata
│   ├── context.xml       # Application-specific context
│   └── MANIFEST.MF       # JAR manifest information
├── status.xsd            # Application status schema
└── WEB-INF/              # Protected application internals
    ├── jsp/              # JavaServer Pages
    │   ├── admin.jsp     # Administrative pages
    │   └── user.jsp      # User interface pages
    ├── classes/          # Compiled Java classes
    │   └── com/
    │       └── company/
    │           └── AdminServlet.class
    ├── lib/              # Application-specific libraries
    │   ├── jdbc_drivers.jar
    │   └── custom_libs.jar
    └── web.xml           # Deployment descriptor (CRITICAL)
```

### Critical Configuration Files

#### web.xml - Deployment Descriptor
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Web Application 2.3//EN" 
  "http://java.sun.com/dtd/web-app_2_3.dtd">

<web-app>
  <!-- Servlet Definitions -->
  <servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
    <init-param>
      <param-name>debug</param-name>
      <param-value>true</param-value>
    </init-param>
  </servlet>

  <!-- URL Mappings -->
  <servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
  </servlet-mapping>

  <!-- Security Constraints -->
  <security-constraint>
    <web-resource-collection>
      <web-resource-name>Admin Pages</web-resource-name>
      <url-pattern>/admin/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
      <role-name>admin</role-name>
    </auth-constraint>
  </security-constraint>

  <!-- Login Configuration -->
  <login-config>
    <auth-method>FORM</auth-method>
    <form-login-config>
      <form-login-page>/login.jsp</form-login-page>
      <form-error-page>/login-error.jsp</form-error-page>
    </form-login-config>
  </login-config>
</web-app>
```

#### tomcat-users.xml - User Authentication
```xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

<!-- Built-in Tomcat Manager Roles -->
<!-- manager-gui    - HTML GUI and status pages access -->
<!-- manager-script - HTTP API and status pages access -->
<!-- manager-jmx    - JMX proxy and status pages access -->
<!-- manager-status - Status pages only access -->

<!-- Role Definitions -->
<role rolename="manager-gui" />
<role rolename="admin-gui" />

<!-- User Accounts (OFTEN WEAK IN PRACTICE) -->
<user username="tomcat" password="tomcat" roles="manager-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />

<!-- Common Default/Weak Credentials Found: -->
<!-- tomcat:tomcat, admin:admin, manager:manager -->
<!-- admin:password, tomcat:password, admin:tomcat -->
</tomcat-users>
```

---

## Discovery & Fingerprinting Techniques

### HTTP Header Analysis

#### Method 1: Server Header Detection
```bash
# Basic server header analysis
curl -I http://target.com:8080/

# Example output revealing Tomcat:
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Content-Type: text/html;charset=UTF-8
Date: Mon, 11 Aug 2024 10:00:00 GMT

# Alternative header patterns:
Server: Apache Tomcat/9.0.30
Server: Apache Tomcat
Server: Apache/2.4.41 (Ubuntu) # (reverse proxy - check further)
```

#### Method 2: Error Page Fingerprinting
```bash
# Request invalid/non-existent pages to trigger error responses
curl -s http://app-dev.inlanefreight.local:8080/invalid

# Typical Tomcat error page indicators:
# - "Apache Tomcat/X.X.X" version strings
# - Distinctive error page styling
# - Java stack traces in error responses
# - "HTTP Status 404 – Not Found" format

# Example version extraction:
curl -s http://target.com:8080/nonexistent | grep -oP 'Apache Tomcat/\K[0-9.]+'
```

#### Method 3: Standard Application Detection
```bash
# Check for default Tomcat applications
default_apps=(
    "/docs"
    "/manager" 
    "/host-manager"
    "/examples"
    "/ROOT"
)

for app in "${default_apps[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com:8080$app")
    echo "$app: HTTP $response"
done
```

### Documentation Page Analysis

#### /docs Directory Enumeration
```bash
# Tomcat documentation often reveals version information
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep -i tomcat

# Common patterns in docs:
# <title>Apache Tomcat 9 (9.0.30) - Documentation Index</title>
# Version extraction:
curl -s http://target.com:8080/docs/ | grep -oP 'Apache Tomcat \K[0-9.]+'

# Additional documentation endpoints:
curl -I http://target.com:8080/docs/config/
curl -I http://target.com:8080/docs/api/
curl -I http://target.com:8080/docs/architecture/
```

#### Examples Application Analysis
```bash
# Examples application provides version and configuration insights
curl -s http://target.com:8080/examples/ | grep -i version

# Servlet examples revealing capabilities:
curl -s http://target.com:8080/examples/servlets/
curl -s http://target.com:8080/examples/jsp/

# Extract Java/servlet version information:
curl -s http://target.com:8080/examples/servlets/servlet/RequestInfoExample | grep -i "server\|version"
```

### Advanced Fingerprinting Methods

#### JSP Engine Detection
```bash
# Test JSP functionality and version
curl -X POST http://target.com:8080/examples/jsp/jsp2/misc/config.jsp

# Look for JSP compilation errors revealing paths:
curl -s http://target.com:8080/test.jsp | grep -i "compilation\|jasper"

# Jasper (JSP engine) version detection:
curl -s http://target.com:8080/ | grep -i jasper
```

#### JVM Information Gathering
```bash
# Attempt to gather JVM information via manager app
curl -s http://target.com:8080/manager/text/serverinfo

# Look for Java version in error messages:
curl -s http://target.com:8080/manager/ | grep -i "java\|jvm"

# Alternative methods for JVM detection:
curl -s http://target.com:8080/examples/servlets/servlet/RequestInfoExample | grep -i java
```

---

## Administrative Interface Discovery

### Manager Application Enumeration

#### /manager Interface Discovery
```bash
# Test for Tomcat Manager accessibility
curl -I http://target.com:8080/manager/

# Common manager endpoints:
manager_endpoints=(
    "/manager"
    "/manager/"
    "/manager/html"
    "/manager/text"
    "/manager/jmxproxy"
    "/manager/status"
)

echo "[+] Testing Manager Application endpoints:"
for endpoint in "${manager_endpoints[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "http://target.com:8080$endpoint")
    echo "$endpoint: HTTP $response"
    
    # 401 = Authentication required (manager exists)
    # 404 = Endpoint not found
    # 403 = Access forbidden
done
```

#### Manager Application Functionality
```bash
# Manager application capabilities (when accessible):
# /manager/html     - Web-based GUI for application management
# /manager/text     - Text-based API for scripting
# /manager/jmxproxy - JMX monitoring and management
# /manager/status   - Server status information

# Text interface commands (if authenticated):
# /manager/text/list              - List deployed applications
# /manager/text/deploy?war=...    - Deploy WAR file
# /manager/text/undeploy?path=... - Remove application
# /manager/text/reload?path=...   - Reload application
# /manager/text/sessions?path=... - Session information
```

#### Host Manager Discovery
```bash
# Host Manager for virtual host administration
curl -I http://target.com:8080/host-manager/
curl -I http://target.com:8080/host-manager/html

# Host manager capabilities:
# - Virtual host management
# - SSL certificate management  
# - Context configuration
# - Less commonly accessible than regular manager
```

### Default Credential Testing

#### Common Tomcat Credentials
```bash
# Standard default credentials (often unchanged):
credentials=(
    "tomcat:tomcat"
    "admin:admin"
    "manager:manager"
    "admin:password"
    "tomcat:password"
    "admin:tomcat"
    "admin:"
    "tomcat:"
    "manager:admin"
    "admin:manager"
)

# Basic authentication testing:
for cred in "${credentials[@]}"; do
    username=$(echo $cred | cut -d':' -f1)
    password=$(echo $cred | cut -d':' -f2)
    
    response=$(curl -s -u "$username:$password" \
        "http://target.com:8080/manager/html" \
        -w "%{http_code}")
    
    if [[ $response == *"200"* ]]; then
        echo "[+] Valid credentials found: $username:$password"
    fi
done
```

#### Automated Credential Testing
```bash
# Hydra-based brute force attack
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt \
  target.com -s 8080 http-get /manager/html

# Custom wordlist creation for Tomcat:
cat > tomcat_creds.txt << 'EOF'
admin:admin
admin:password
admin:tomcat
admin:manager
admin:
tomcat:tomcat
tomcat:admin
tomcat:password
tomcat:
manager:manager
manager:admin
manager:password
manager:tomcat
manager:
root:root
root:admin
root:password
EOF

# Burp Intruder compatible testing:
# Use cluster bomb attack on /manager/html with credential pairs
```

---

## Application and Service Enumeration

### Directory and File Discovery

#### Gobuster Enumeration
```bash
# Comprehensive directory enumeration
gobuster dir -u http://web01.inlanefreight.local:8180/ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt \
  -t 50 -x jsp,html,xml,txt

# Expected findings:
# /docs (Status: 302)     - Documentation
# /examples (Status: 302) - Sample applications  
# /manager (Status: 302)  - Management interface
# /ROOT (Status: 200)     - Default application
# /host-manager (Status: 401) - Virtual host management

# Tomcat-specific wordlist:
cat > tomcat_paths.txt << 'EOF'
admin
manager
host-manager
docs
examples
ROOT
server-info
server-status
balancer-manager
jkstatus
status
test
api
webdav
axis
axis2
soap
services
xmlrpc
dwr
struts
spring
hibernate
cxf
EOF
```

#### Application-Specific Discovery
```bash
# Discover deployed applications
curl -s http://target.com:8080/ | grep -oP 'href="[^"]*"' | grep -v http | sort -u

# Test for common Java application frameworks:
frameworks=(
    "/spring"
    "/struts"
    "/hibernate"
    "/axis"
    "/axis2"
    "/cxf"
    "/jaxws"
    "/restlet"
)

for framework in "${frameworks[@]}"; do
    curl -I "http://target.com:8080$framework" 2>/dev/null | head -n 1
done
```

### WAR File and JSP Discovery

#### JSP Page Enumeration
```bash
# Common JSP file extensions and paths
jsp_extensions=(
    "jsp"
    "jspx"
    "jsw" 
    "jsv"
    "jspf"
)

# Fuzz for JSP files
gobuster dir -u http://target.com:8080/ \
  -w /usr/share/seclists/Discovery/Web-Content/Common-JSP-Filenames.txt \
  -x jsp,jspx

# Look for admin/management JSPs:
admin_jsps=(
    "/admin.jsp"
    "/login.jsp"
    "/manager.jsp"
    "/console.jsp"
    "/dashboard.jsp"
    "/config.jsp"
)
```

#### WAR File Analysis
```bash
# If WAR files are accessible, download and analyze:
wget http://target.com:8080/applications/app.war

# Extract and examine WAR contents:
unzip app.war -d app_extracted/
cd app_extracted/

# Key files to examine:
cat WEB-INF/web.xml              # Deployment descriptor
ls -la WEB-INF/classes/          # Compiled Java classes
ls -la WEB-INF/lib/              # JAR dependencies
cat META-INF/MANIFEST.MF         # Manifest information

# Look for hardcoded credentials:
grep -r -i "password\|secret\|key" .
grep -r -i "jdbc\|database\|conn" .
```

---

## Configuration File Analysis

### tomcat-users.xml Reconnaissance

#### User and Role Analysis
```bash
# If accessible via LFI or directory traversal:
curl -s http://target.com:8080/../../conf/tomcat-users.xml

# Common role permissions breakdown:
# manager-gui    - Full HTML interface access + status pages
# manager-script - HTTP API access + status pages (automation)
# manager-jmx    - JMX proxy access + status pages (monitoring)
# manager-status - Status pages only (limited access)
# admin-gui      - Host manager access (virtual host management)

# Parse users and roles from tomcat-users.xml:
curl -s http://target.com:8080/conf/tomcat-users.xml | \
  grep -oP 'username="[^"]*"' | cut -d'"' -f2

curl -s http://target.com:8080/conf/tomcat-users.xml | \
  grep -oP 'roles="[^"]*"' | cut -d'"' -f2
```

#### Security Constraint Analysis
```bash
# Analyze web.xml for security configurations:
curl -s http://target.com:8080/WEB-INF/web.xml | grep -A 10 -B 5 "security-constraint"

# Look for authentication methods:
curl -s http://target.com:8080/WEB-INF/web.xml | grep -A 5 "auth-method"

# Identify protected resources:
curl -s http://target.com:8080/WEB-INF/web.xml | grep -A 5 "url-pattern"
```

### server.xml Analysis

#### Connector and Port Configuration
```bash
# Analyze server configuration if accessible:
curl -s http://target.com:8080/../../conf/server.xml | grep -i connector

# Common connector configurations:
# HTTP Connector (8080, 8443)
# AJP Connector (8009) - Apache integration
# HTTPS Connector (8443) - SSL/TLS

# Extract listening ports:
curl -s http://target.com:8080/conf/server.xml | \
  grep -oP 'port="[^"]*"' | cut -d'"' -f2 | sort -u
```

#### Virtual Host Enumeration
```bash
# Identify configured virtual hosts:
curl -s http://target.com:8080/conf/server.xml | grep -A 5 -B 5 "Host name"

# Test discovered virtual hosts:
vhosts=$(curl -s http://target.com:8080/conf/server.xml | \
  grep -oP 'Host name="[^"]*"' | cut -d'"' -f2)

for vhost in $vhosts; do
    curl -H "Host: $vhost" http://target_ip:8080/
done
```

---

## HTB Academy Lab Solutions

### Lab 1: Tomcat Version Detection
**Question:** "What version of Tomcat is running on the application located at http://web01.inlanefreight.local:8180?"

**Solution Methodology:**

#### Step 1: Environment Setup
```bash
# Add VHost entry to /etc/hosts
echo "10.129.201.58 web01.inlanefreight.local" >> /etc/hosts

# Verify connectivity
curl -I http://web01.inlanefreight.local:8180/
```

#### Step 2: Version Detection Methods
```bash
# Method 1: Error page analysis (most reliable)
curl -s http://web01.inlanefreight.local:8180/invalid | grep -i tomcat

# Method 2: Documentation page analysis
curl -s http://web01.inlanefreight.local:8180/docs/ | grep -i tomcat

# Method 3: Server header analysis  
curl -I http://web01.inlanefreight.local:8180/ | grep -i server

# Method 4: Examples application
curl -s http://web01.inlanefreight.local:8180/examples/ | grep -i version
```

#### Step 3: Expected Answer Extraction
```bash
# Version format expected: X.X.X (e.g., 10.0.10)
# Primary method - error page:
curl -s http://web01.inlanefreight.local:8180/invalid | \
  grep -oP 'Apache Tomcat/\K[0-9.]+'

# Alternative - docs page:
curl -s http://web01.inlanefreight.local:8180/docs/ | \
  grep -oP 'Apache Tomcat [0-9.]+ \(\K[0-9.]+'

# HTB Answer: 10.0.10
```

### Lab 2: Admin User Role Analysis  
**Question:** "What role does the admin user have in the configuration example?"

**Solution Methodology:**

#### Step 1: Configuration File Analysis
```bash
# The question refers to the configuration example shown in the HTB Academy content
# From the tomcat-users.xml example provided:

<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />

<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```

#### Step 2: Role Analysis
```bash
# Admin user roles breakdown:
# username="admin" has roles="manager-gui,admin-gui"

# Specific question asks for "the role" (singular)
# Primary/distinctive role for admin user: admin-gui
# This role provides host-manager access (virtual host management)

# HTB Answer: admin-gui
```

#### Step 3: Role Functionality Understanding
```bash
# Role hierarchy and capabilities:
# manager-gui  - Tomcat Manager HTML interface
# admin-gui    - Host Manager interface (admin-specific)
# manager-script - API access for automation
# manager-jmx    - JMX monitoring access
# manager-status - Status pages only

# The admin-gui role is the distinguishing characteristic of the admin user
```

---

## Intelligence Gathering Workflow

### Systematic Tomcat Assessment

#### Phase 1: Discovery & Fingerprinting
- [ ] **Service Detection** - Port scanning and service identification
- [ ] **Version Fingerprinting** - Error pages, documentation, headers
- [ ] **Application Discovery** - Default apps, custom deployments
- [ ] **Directory Enumeration** - Hidden paths and administrative interfaces

#### Phase 2: Administrative Interface Assessment
- [ ] **Manager Application Access** - /manager, /host-manager testing
- [ ] **Default Credential Testing** - Common username/password combinations
- [ ] **Authentication Mechanism Analysis** - HTTP Basic, Form-based, LDAP
- [ ] **Role and Permission Mapping** - User capabilities and access levels

#### Phase 3: Application Analysis
- [ ] **WAR File Discovery** - Deployed applications identification
- [ ] **JSP Enumeration** - Server-side page discovery
- [ ] **Configuration File Access** - web.xml, tomcat-users.xml analysis
- [ ] **Framework Identification** - Spring, Struts, custom applications

#### Phase 4: Vulnerability Research
- [ ] **Version-Specific CVEs** - Known vulnerability research
- [ ] **Configuration Weaknesses** - Security misconfigurations
- [ ] **Application Vulnerabilities** - Custom code analysis
- [ ] **Privilege Escalation Vectors** - Manager interface abuse

---

## Enterprise Deployment Patterns

### Internal Network Reconnaissance

#### Multi-Instance Discovery
```bash
# Tomcat commonly runs on multiple ports in enterprise environments:
common_ports=(8080 8443 8009 8180 8280 8380 8480 8580 8680 8780 8880 8980)

for port in "${common_ports[@]}"; do
    echo "Testing port $port:"
    curl -I "http://target.com:$port/" 2>/dev/null | head -n 1
done

# AJP connector detection (port 8009):
nmap -sV -p 8009 target.com
```

#### Load Balancer Detection
```bash
# Identify load-balanced Tomcat instances:
curl -I http://target.com:8080/ | grep -i "x-forwarded\|load-balancer\|cluster"

# Session affinity testing:
curl -c cookies.txt http://target.com:8080/
curl -b cookies.txt http://target.com:8080/ | grep -i jsessionid
```

### Development vs Production Discrimination

#### Environment Identification
```bash
# Look for development/staging indicators:
dev_indicators=(
    "dev"
    "test"
    "staging"  
    "uat"
    "debug"
    "localhost"
)

for indicator in "${dev_indicators[@]}"; do
    curl -s http://target.com:8080/ | grep -i "$indicator" && \
      echo "Development indicator found: $indicator"
done

# Check for debug/development features:
curl -s http://target.com:8080/examples/ | grep -i "example\|test\|debug"
```

---

## Security Assessment Priorities

### High-Value Target Identification

#### EyeWitness Integration
```bash
# Tomcat typically appears first in EyeWitness "High Value Targets"
# Automated screenshot and service identification:
eyewitness --web -f tomcat_targets.txt

# Generate target list for EyeWitness:
cat > tomcat_targets.txt << 'EOF'
http://target1.com:8080
http://target2.com:8180
https://target3.com:8443
EOF
```

#### Risk Prioritization
```bash
# High-risk Tomcat configurations:
1. Default credentials (tomcat:tomcat, admin:admin)
2. Exposed manager applications (/manager, /host-manager)
3. Directory listing enabled on /webapps
4. Outdated versions with known CVEs
5. Development features in production
6. Weak authentication mechanisms
7. Excessive user privileges (admin-gui roles)
```

---

## Next Steps

After Tomcat enumeration, proceed to:
1. **[Tomcat Attacks & Exploitation](tomcat-attacks.md)** - WAR file uploads and manager abuse
2. **[Java Application Security](java-application-security.md)** - Servlet and JSP vulnerabilities
3. **[Jenkins Discovery](jenkins-discovery.md)** - CI/CD infrastructure enumeration

**💡 Key Takeaway:** Tomcat enumeration focuses on **administrative interface discovery**, **version identification**, and **configuration analysis**. Enterprise environments frequently contain **multiple Tomcat instances** with **weak default credentials**, making systematic enumeration crucial for identifying **high-value attack vectors** and **internal network footholds**. 