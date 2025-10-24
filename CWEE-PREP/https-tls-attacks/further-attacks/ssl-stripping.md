# SSL Stripping

Instead of directly attacking TLS, an attacker can attempt to force a victim to not use HTTPS at all and instead fall back to unencrypted and insecure HTTP. This can be achieved with an SSL Stripping attack (also known as an HTTP downgrade attack). To execute such an attack, the attacker must be in a Man-in-the-Middle (MitM) position, meaning the attacker can intercept and inject messages between the client and server.

## ARP Spoofing

The Address Resolution Protocol (ARP) is responsible for resolving physical addresses (such as MAC addresses) from network addresses (such as IP addresses). ARP poisoning or ARP spoofing is an attack that manipulates the normal ARP process to obtain a MitM position.

When two computers in a local network want to communicate, they need to know each other's MAC addresses. While they can obtain their corresponding IP addresses via DNS, ARP is responsible for obtaining the MAC addresses. Let's consider a basic example:

If Computer A wants to send a packet to Computer B, and both are in the same local network, Computer A knows Computer B's IP address (e.g., 192.168.178.2). To get its MAC address, Computer A broadcasts an ARP request message (e.g., "Who is 192.168.178.2?"). All computers in the local network, including B, receive this message. Computer B then responds with an ARP response message, containing its IP and MAC address (e.g., "I'm 192.168.178.2 and my MAC address is AA:BB:CC:DD:EE:FF"). Computer A then uses this MAC address to transmit the packet to B and stores the IP-MAC address pair in a local cache for future communication.

In ARP spoofing, an attacker sends a forged ARP response message to an ARP request intended for a different target. By doing so, the attacker impersonates the target. The victim stores the attacker's MAC address in its ARP cache instead of the intended target's MAC address. Consequently, the victim transmits all data meant for the target to the attacker, who now holds a MitM position between the victim and the target. ARP spoofing attacks can be difficult to detect because they do not involve changes to the network infrastructure or devices.

An ARP spoof attack can be executed using the `arpspoof` command from the `dsniff` package:

```bash
sudo apt install dsniff
```

The program needs to be run as root. You must specify the network interface and the IP address you want to impersonate. For example, to fool a Docker container at `172.17.0.2` into thinking that you (running at `172.17.0.1`) are the target `172.17.0.5`, you can spoof the ARP response:

```bash
sudo arpspoof -i docker0 172.17.0.5
```

This command periodically broadcasts ARP responses claiming to be `172.17.0.5`. If the victim Docker container then tries to contact `172.17.0.5`, the ARP request is successfully spoofed, and the victim is tricked into thinking the attacker is the target. This can be verified by checking the ARP cache on the victim using the `arp` command:

```bash
arp
```

If the cached MAC address of `172.17.0.5` is the attacker's MAC address, the attack was successful.

Another tool for ARP spoofing is `bettercap`. It can be run in a Docker container:

```bash
docker run -it --privileged --net=host bettercap/bettercap --version
```

For attacking another Docker container, you can omit the `--privileged --net=host` arguments. To start an interactive `bettercap` shell:

```bash
docker run -it bettercap/bettercap
```

If the target is `172.17.0.4` and `bettercap` excludes internal IP addresses by default, you need to set an extra option and start the ARP spoofer:

```bash
set arp.spoof.targets 172.17.0.4
set arp.spoof.internal true
arp.spoof on
```

`bettercap` will then send spoofed ARP responses to the victim for all IP addresses in the target range to poison the victim's ARP cache. After stopping the attack with `arp.spoof off`, `bettercap` automatically restores the victim's ARP cache.

## SSL Stripping Attack

After obtaining a MitM position, an attacker can execute an SSL stripping attack to prevent the victim from establishing a secure TLS connection with the target web server. Instead, the victim is forced to use an insecure HTTP connection. Because the attacker is in a MitM position, they can read and manipulate all data transmitted by the victim.

However, simply holding a MitM position and forwarding all data is not enough. Most web servers redirect HTTP requests to HTTPS to ensure encrypted communication. In an SSL Stripping attack, the MitM attacker forwards the initial HTTP request from the victim to the web server. When the web server responds with a redirect to HTTPS, the attacker intercepts this response. Instead of forwarding it, the attacker establishes the HTTPS connection to the web server themselves. After doing so, the attacker accesses the requested resource via their HTTPS connection and then transmits it to the victim via HTTP. This creates two separate connections: an HTTP connection from the victim to the attacker, and an HTTPS connection from the attacker to the web server. From the web server's perspective, all requests arrive via a TLS-encrypted tunnel, making the connection appear secure. However, the victim communicates with the attacker via unencrypted HTTP, allowing the attacker to access all sensitive information (e.g., credentials, payment details) transmitted by the victim.

## Prevention

The HTTP header `Strict-Transport-Security (HSTS)` can prevent SSL Stripping attacks. This header instructs the browser to access the target site only through HTTPS. Any attempt to access the site via HTTP is rejected by the browser or automatically converted to HTTPS requests. This prevents SSL Stripping attacks for all websites that have been visited at least once in the past. If the HSTS header is set, the browser prevents all HTTP communication with the web server, making it impossible for a MitM attacker to perform the attack.

Note: HSTS does not prevent attacks during the first visit to a site. This initial connection can still be sent via insecure HTTP, leaving it vulnerable to an SSL Stripping attack.

The HSTS header is set with a value in seconds, indicating how long the browser should remember that the site can only be accessed via HTTPS. For example, when accessing `https://www.google.com`, the response might include `Strict-Transport-Security: max-age=31536000`, meaning HTTP access is prevented for one year after the first visit.

Additionally, websites can protect subdomains using the `includeSubDomains` directive. This tells the web browser to automatically connect to all subdomains using HTTPS, even if they have not been visited before. An example would be `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
