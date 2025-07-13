# 🕷️ Web Application Information Gathering

## **Overview**

Web Application Information Gathering is a specialized phase of reconnaissance that focuses on web applications and their underlying technologies. Unlike infrastructure enumeration, this phase targets the application layer to identify technologies, frameworks, hidden files, parameters, and potential attack vectors.

**This guide is organized into two comprehensive sections:**

---

## **📋 Table of Contents**

### **🌐 [Subdomain Enumeration & DNS Discovery](./subdomain-enumeration.md)**
*Comprehensive guide to discovering subdomains and DNS infrastructure*

**Topics Covered:**
- **Manual DNS Enumeration** - dig, zone transfers, advanced techniques
- **Automated DNS Tools** - dnsenum, fierce, dnsrecon with HTB examples
- **Advanced Subdomain Discovery** - amass, puredns for high-performance enumeration
- **Passive Discovery** - Certificate transparency, subfinder, assetfinder
- **Tool Selection Guide** - When to use what tool and performance comparison
- **Security Considerations** - Rate limiting, stealth techniques, defensive measures

**Key Tools:**
- `dig` - Manual DNS queries and analysis
- `dnsenum` - Comprehensive DNS enumeration with zone transfers
- `amass` - Advanced subdomain discovery with 30+ data sources
- `puredns` - High-performance DNS brute-forcing with wildcard filtering
- `subfinder` - Passive subdomain enumeration
- `fierce` - User-friendly subdomain scanner

### **🔧 [Web Application Enumeration](./web-application-enumeration.md)**
*Detailed guide to enumerating web applications and their components*

**Topics Covered:**
- **Technology Stack Identification** - whatweb, Wappalyzer, header analysis
- **Directory & File Enumeration** - gobuster, ffuf, dirb for hidden content
- **Virtual Host Discovery** - Finding additional applications on same server
- **Parameter Discovery** - ffuf, arjun, paramspider for hidden parameters
- **API Enumeration** - REST, GraphQL, OpenAPI documentation discovery
- **JavaScript Analysis** - LinkFinder, endpoint extraction, sensitive data
- **CMS-Specific Enumeration** - WordPress, Joomla, Drupal specialized tools
- **Security Analysis** - Headers, SSL/TLS, WAF detection and bypass

**Key Tools:**
- `whatweb` - Technology stack identification
- `gobuster` - Directory and file discovery
- `ffuf` - Fast web fuzzing for parameters and vhosts
- `wpscan` - WordPress security scanner
- `arjun` - Parameter discovery tool
- `wafw00f` - WAF detection and fingerprinting

---

## **🎯 Quick Start Guide**

### **Phase 1: Subdomain Discovery**
```bash
# Quick subdomain enumeration
subfinder -d example.com
assetfinder example.com

# Comprehensive active enumeration
amass enum -active -d example.com -brute
```

### **Phase 2: Technology Identification**
```bash
# Identify web technologies
whatweb https://example.com
curl -I https://example.com
```

### **Phase 3: Content Discovery**
```bash
# Directory enumeration
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# Parameter discovery
ffuf -u https://example.com/page?FUZZ=value -w parameters.txt
```

---

## **🛠️ Essential Tools Summary**

| Category | Tool | Purpose | Best Use Case |
|----------|------|---------|--------------|
| **DNS** | `dig` | Manual DNS queries | Zone transfers, detailed analysis |
| **DNS** | `dnsenum` | Automated DNS enumeration | Comprehensive reconnaissance |
| **DNS** | `amass` | Advanced subdomain discovery | Maximum coverage with 30+ sources |
| **DNS** | `puredns` | High-performance brute-forcing | Massive wordlist handling |
| **Web** | `whatweb` | Technology detection | Initial reconnaissance |
| **Web** | `gobuster` | Directory discovery | Finding hidden content |
| **Web** | `ffuf` | Web fuzzing | Parameter/vhost discovery |
| **Web** | `wpscan` | WordPress security | CMS-specific testing |

---

## **📚 HTB Academy Integration**

Both guides include practical **HTB Academy lab examples** with:
- Real-world reconnaissance scenarios
- Command-line examples with expected outputs
- Step-by-step methodology for CPTS exam preparation
- Analysis of results and next steps

---

## **🔒 Security Considerations**

### **Rate Limiting & Stealth**
- Use passive enumeration when possible
- Implement delays between requests
- Distribute queries across multiple DNS servers
- Monitor for detection and blocking

### **Legal & Ethical**
- Obtain proper authorization before testing
- Respect rate limits and server resources
- Follow responsible disclosure practices
- Document all reconnaissance activities

---

## **🎓 Learning Path**

1. **Start with** [Subdomain Enumeration](./subdomain-enumeration.md) to understand DNS infrastructure
2. **Progress to** [Web Application Enumeration](./web-application-enumeration.md) for application-level discovery
3. **Practice with** HTB Academy labs for hands-on experience
4. **Combine techniques** for comprehensive reconnaissance methodology

---

## **🔍 WHOIS Information Gathering**

### **Basic WHOIS Lookup**
```bash
# Basic WHOIS query
whois example.com

# Extract key information
whois example.com | grep -E "(Registrar|Creation Date|Registry Expiry|Updated Date)"

# Name servers
whois example.com | grep -i "name server"

# Contact information
whois example.com | grep -E "(Registrant|Admin|Tech)" -A 5
```

### **Intelligence Extraction**
```bash
# Extract email addresses
whois example.com | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Check domain age
whois example.com | grep -i "creation date"

# Privacy protection detection
whois example.com | grep -iE "(whoisguard|privacy|proxy|domains by proxy)"
```

**Key Information to Extract:**
- Domain registration details and timeline
- Registrant contact information
- Name server configuration
- Domain age and transfer history
- Privacy protection status

---

## **📖 References**

- HTB Academy: Information Gathering - Web Edition
- OWASP Web Security Testing Guide
- RFC 1034, 1035: Domain Names - Concepts and Facilities
- SecLists: https://github.com/danielmiessler/SecLists
- Burp Suite Documentation
- FFUF Documentation: https://github.com/ffuf/ffuf
- Amass Documentation: https://github.com/OWASP/Amass

---

## **🚀 Next Steps**

After completing web information gathering:

1. **Infrastructure Enumeration** - Port scanning and service detection
2. **Vulnerability Assessment** - Identify specific security weaknesses
3. **Exploitation Planning** - Develop attack vectors based on findings
4. **Reporting** - Document discoveries and recommendations

**Related CPTS Guides:**
- [Infrastructure Enumeration](./footprinting.md)
- [Service-Specific Enumeration](./services/)
- [Database Enumeration](./databases/)
- [Remote Management](./remote-management/) 