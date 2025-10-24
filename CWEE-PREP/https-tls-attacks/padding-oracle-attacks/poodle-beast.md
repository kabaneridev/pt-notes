# POODLE & BEAST

Certain attacks specifically target the implementation of padding in TLS, such as POODLE (Padding Oracle On Downgraded Legacy Encryption) and BEAST (Browser Exploit Against SSL/TLS).

## Padding in SSL 3.0

POODLE and BEAST are padding oracle attacks that target encrypted data transmitted using SSL 3.0. Successful exploitation allows an attacker to decrypt network traffic and compromise confidential data, including credentials. These attacks require the attacker to intercept ciphertexts and communicate with the target server.

SSL 3.0 uses a specific padding scheme:

*   The last byte indicates the length of the padding (excluding the length byte itself).
*   All other padding bytes can have an arbitrary value.

For example, with an 8-byte block length and a 4-byte plaintext (`DE AD BE EF`), 4 bytes of padding are needed. The last byte would be `03` (representing 3 bytes of padding, excluding itself), making the padded plaintext `DE AD BE EF 00 00 00 03` (where `00` represents arbitrary padding bytes). If the plaintext size is already a multiple of the block length, a full block of padding must be appended.

## POODLE Attack

Discovered in 2014, the POODLE attack effectively broke SSL 3.0. An attacker exploits this by forcing a victim to send a specially crafted request containing a full block of padding. Knowing the last byte (padding size) of this block, the attacker intercepts the ciphertext and modifies data in the last block. If this modification results in an incorrect padding size, the server registers a MAC (Message Authentication Code) error, as SSL 3.0 uses MACs for integrity protection. However, if the padding size remains correct, no MAC error is thrown.

This differential behavior (MAC error vs. no MAC error) leaks an intermediate result of the CBC-mode decryption to the attacker, enabling them to deduce one byte of the plaintext. By recursively applying this attack, entire ciphertext blocks can be decrypted. The vulnerability stems from the arbitrary nature of padding bytes (except the length field) and the server's distinct behavior for incorrect padding lengths.

## BEAST Attack

The BEAST attack, discovered in 2011, operates similarly. An attacker intercepts a valid ciphertext and sends a crafted ciphertext to the target server to deduce information about a plaintext block. To overcome the challenge of brute-forcing an entire block (which can be large), BEAST uses a technique to subtly alter the original plaintext by injecting characters, ensuring that only one byte in the resulting plaintext block remains unknown. This allows the attacker to brute-force the plaintext byte by byte.

However, BEAST is primarily a theoretical attack due to its practical exploitation difficulties. It requires bypassing the Same-Origin Policy implemented by modern web browsers, necessitating a separate attack (a Same-Origin Policy bypass) for real-world scenarios, thus making the risk of practical exploitation small.

## Tools & Prevention

To execute a POODLE attack against a target web server supporting SSL 3.0, the tool TLS-Breaker can be used. It requires Java and can be installed as follows:

```bash
sudo apt install maven
git clone https://github.com/tls-attacker/TLS-Breaker
cd TLS-Breaker/
mvn clean install -DskipTests=true
```

The POODLE detection tool within TLS-Breaker can then be run:

```bash
java -jar apps/poodle-1.0.1.jar -connect 127.0.0.1:30001
```

A server vulnerable to POODLE will show a "VULNERABILITY_POSSIBLE" status, while a secure server will indicate "NOT_VULNERABLE" or a handshake failure.

**Prevention:**

POODLE can be prevented by entirely disabling SSL 3.0. Even if a web server supports newer TLS versions, clients might be able to force a downgrade to SSL 3.0 through handshake manipulation. Therefore, SSL 3.0 should be completely disabled and not supported, even for legacy compatibility. For example, in Apache2, this can be achieved with the `SSLProtocol all -SSlv3` directive.
