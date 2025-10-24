# TLS 1.3

TLS 1.3 introduces significant improvements over TLS 1.2, including simplified handshake procedures for faster session establishment and the removal of support for insecure cryptographic parameters.

## Cipher Suites and Cryptography

TLS 1.3 brings several cryptographic enhancements, dropping older, less secure techniques and integrating newer, more robust ones. It features improved key exchange algorithms and supports post-quantum cryptography. Crucially, TLS 1.3 exclusively supports key exchange algorithms that provide Perfect Forward Secrecy (PFS).

Unlike TLS 1.2 cipher suites, a TLS 1.3 cipher suite is much shorter, for example: `TLS_AES_128_GCM_SHA256`. This brevity is because it only specifies the encryption algorithm and mode, along with the hash function for the HMAC algorithm. TLS 1.3 cipher suites no longer explicitly state the server authentication method or the key exchange algorithm, as PFS-supporting key exchange is mandatory.

## Handshake

The TLS 1.3 handshake process has been streamlined for efficiency, with some messages redesigned and others eliminated to reduce latency and overhead, leading to faster connection establishment.

Similar to TLS 1.2, the TLS 1.3 handshake begins with the `ClientHello` message. However, in TLS 1.3, this message now includes the client's key share in addition to the supported cipher suites. This innovation removes the need for a separate `ClientKeyExchange` message later in the handshake. The key share is embedded within an extension sent with the `ClientHello` message.

The server responds with a `ServerHello` message, confirming the key agreement protocol and specifying the chosen cipher suite, consistent with TLS 1.2. This message also contains the server's key share. A fresh key share is always transmitted to guarantee PFS, effectively replacing the `ServerKeyExchange` message that was required in TLS 1.2 when PFS cipher suites were used. The server's certificate is also included within the `ServerHello` message.

The handshake concludes with a `ServerFinished` and `ClientFinished` message.

All messages after the `ServerHello` are encrypted, making the TLS 1.3 handshake significantly shorter and more secure than its TLS 1.2 counterpart.

Diagram of a 3-step communication process between client and server. Step 1: Client Hello, supported cipher suites, key agreement protocol, key share. Step 2: Server Hello, key agreement protocol, key share, server finished. Step 3: Client checks certificate, generates keys, client finished.
