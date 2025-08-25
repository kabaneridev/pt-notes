# 🛡️ Firewall and IDS/IPS Evasion - CPTS

## **Overview**

Firewalls and IDS/IPS systems are designed to detect and block malicious traffic. Understanding how to evade these systems is crucial for penetration testing.

## **Common Evasion Techniques**

### **1. Source Port Manipulation**

**Why it works:**
- Many firewalls allow traffic from "trusted" ports (53, 80, 443, 25)
- Port 53 (DNS) is often allowed both inbound and outbound
- Administrators rarely block DNS traffic

**Basic Usage:**
```bash
# Scan using DNS source port
sudo nmap -g53 --max-retries=1 -Pn -p- --disable-arp-ping <target>

# Alternative syntax
sudo nmap --source-port 53 -p- <target>
```

### **2. Decoy Scanning**

**Purpose:** Hide your real IP among fake ones

```bash
# Random decoys
nmap -D RND:10 <target>

# Specific decoys
nmap -D 192.168.1.5,192.168.1.10,ME,192.168.1.15 <target>
```

### **3. Packet Fragmentation**

**Purpose:** Split packets to evade signature-based detection

```bash
# Basic fragmentation
nmap -f <target>

# More aggressive fragmentation
nmap -ff <target>

# Custom MTU
nmap --mtu 24 <target>
```

### **4. Timing Manipulation**

**Purpose:** Avoid rate-based detection

```bash
# Paranoid timing (very slow)
nmap -T0 <target>

# Sneaky timing
nmap -T1 <target>

# Custom delays
nmap --scan-delay 2s <target>
nmap --max-parallelism 1 <target>
```

## **Lab Example: HTB Academy Hard**

**Scenario:** Target has restrictive firewall that blocks most scans

**Solution:**
```bash
# Step 1: Discover open ports using DNS source port
sudo nmap -g53 --max-retries=1 -Pn -p- --disable-arp-ping 10.129.142.113

# Expected output:
# PORT      STATE SERVICE
# 22/tcp    open  ssh
# 80/tcp    open  http
# 50000/tcp open  ibm-db2

# Step 2: Connect to discovered service using source port 53
sudo nc -s 10.10.14.87 -p53 10.129.142.113 50000

# Result: Access to IBM Db2 service that returns flag
# 220 HTB{...
```

## **Advanced Evasion Techniques**

### **1. IPv6 Evasion**
```bash
# Scan using IPv6 (often less monitored)
nmap -6 <target>
```

### **2. Idle Scan (Zombie Scan)**
```bash
# Use another host as a zombie
nmap -sI <zombie_ip> <target>
```

### **3. Custom Packet Crafting**
```bash
# Invalid checksums
nmap --badsum <target>

# Custom TTL
nmap --ttl 64 <target>

# Append random data
nmap --data-length 25 <target>
```

## **Firewall Detection**

### **Identify Firewall Presence**
```bash
# ACK scan to detect firewall
nmap -sA <target>

# Check for filtered ports
nmap -sS <target> | grep filtered
```

### **Firewall Fingerprinting**
```bash
# Identify firewall type
nmap --script firewall-bypass <target>
nmap --script firewalk <target>
```

## **Best Practices**

1. **Start with stealth techniques**
2. **Combine multiple evasion methods**
3. **Monitor for detection**
4. **Document successful techniques**
5. **Respect scope and permissions**

## **Common Mistakes to Avoid**

- Using predictable decoy IPs
- Ignoring timing considerations
- Over-fragmenting packets
- Not testing evasion effectiveness
- Forgetting to use appropriate source ports

## **Tools and Resources**

- **Nmap:** Primary scanning tool
- **Netcat:** Connection testing
- **Hping3:** Custom packet crafting
- **Scapy:** Python packet manipulation
- **Firewalk:** Firewall analysis

## **References**

- HTB Academy: Firewall and IDS/IPS Evasion
- Nmap Network Scanning Guide
- Penetration Testing Execution Standard (PTES) 