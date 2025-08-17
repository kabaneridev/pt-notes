# 🎫 osTicket Attacks

> **🎯 Objective:** Exploit osTicket support system for information disclosure and credential harvesting through ticket data access and social engineering vectors.

## Overview

osTicket is an open-source PHP-based support ticketing system with MySQL backend. Often exposed externally, it can provide valuable intelligence including **user credentials**, **email addresses**, and **internal system information** through ticket conversations.

---

## HTB Academy Lab Solution

### Lab: Credential Extraction from Support Tickets
**Question:** "Find your way into the osTicket instance and submit the password sent from the Customer Support Agent to the customer Charles Smithson."

**Target:** `support.inlanefreight.local` (add to `/etc/hosts`)

#### Step 1: Setup vHost Resolution
```bash
# Add target to hosts file
echo "10.129.201.88 support.inlanefreight.local" >> /etc/hosts
```

#### Step 2: Access osTicket Interface
```bash
# Navigate to: http://support.inlanefreight.local/scp/login.php
# osTicket login page (staff control panel)
```

#### Step 3: Credential Testing
Based on discovered credentials from OSINT/data breaches:
- **Email:** `kevin@inlanefreight.local`
- **Password:** `Fish1ng_s3ason!`

```bash
# Login to osTicket staff panel with kevin's credentials
# URL: http://support.inlanefreight.local/scp/login.php
```

#### Step 4: Ticket Investigation
1. **Access ticket queue** (may show no open tickets)
2. **Check closed tickets** for sensitive information
3. **Look for Charles Smithson** ticket conversation
4. **Review agent-customer communication**

#### Step 5: Password Extraction
In the ticket conversation between:
- **Customer:** Charles Smithson (VPN lockout issue)
- **Agent:** Kevin Grimes (password reset)

**Extracted Password:** Found in agent's message to customer

**Answer:** `[PASSWORD_FROM_TICKET]` *(extract from actual ticket content)*

---

## Attack Vectors

### 1. Information Disclosure
- **Email harvesting** from address books
- **Credential exposure** in ticket conversations  
- **Internal system details** from support communications
- **Employee names/usernames** for OSINT

### 2. Email Address Generation
- **Create support ticket** → get temporary company email
- **Use for service registration** (Slack, GitLab, etc.)
- **Email verification bypass** via ticket system access

### 3. Social Engineering
- **Staff impersonation** through ticket system knowledge
- **Standard password discovery** (new joiner passwords)
- **Password spraying targets** from user lists

---

## Common Findings

**Sensitive Data in Tickets:**
- 🔑 **Default/temporary passwords**
- 📧 **Email addresses and usernames** 
- 🏢 **Internal system information**
- 🔐 **Password reset procedures**
- 👥 **Staff contact details**

**Attack Chain Example:**
1. **OSINT** → Find leaked credentials
2. **Access osTicket** → Staff panel login
3. **Ticket mining** → Extract passwords/info
4. **Lateral movement** → VPN/other services
5. **Password spraying** → Standard passwords

---

## Key Techniques

**Credential Sources:**
- **Data breach dumps** (DeHashed, etc.)
- **Password reuse** across services
- **Default credentials** testing

**Reconnaissance:**
- **Subdomain enumeration** for support portals
- **Staff email identification** 
- **Service discovery** for attack vectors

**💡 Pro Tip:** Support systems often contain the most sensitive internal communications - always check closed tickets for credential leakage and password reset conversations. 