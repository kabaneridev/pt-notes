# Introduction to HTTPS/TLS

HTTPS (Hypertext Transfer Protocol Secure) is an application layer protocol used for secure communication over the internet. It addresses the shortcomings of HTTP by providing confidentiality, integrity, and authenticity of transmitted data through the use of Transport Layer Security (TLS).

## Encryption Levels

Encryption can be applied at different levels:

*   **Encryption-at-rest:** Data is stored in an encrypted form (e.g., hard drive encryption).
*   **Encryption-in-transit:** Data is encrypted before transmission and decrypted after reception (e.g., TLS).
*   **End-to-end encryption:** Data is encrypted by the sender and decrypted only by the final recipient, with no intermediaries having access to plaintext.

This module focuses on **encryption-in-transit** as applied by TLS.

## TLS Overview and Version History

TLS (Transport Layer Security), and its predecessor SSL (Secure Sockets Layer), are cryptographic protocols that secure communication over networks. TLS operates between the TCP layer and the application layer, transparently handling cryptographic operations for protocols like HTTP, SMTP, or FTP.

### SSL Version History (Deprecated)

*   **SSL 1.0:** Never released due to serious security flaws.
*   **SSL 2.0:** Released in 1995, suffered from significant specification flaws and cryptographic vulnerabilities.
*   **SSL 3.0:** A redesign of 2.0, but relies on deprecated cryptographic algorithms and is vulnerable to various attacks.

### TLS Version History

*   **TLS 1.0 (1999):** First version of TLS, based on SSL 3.0 with security enhancements.
*   **TLS 1.1 (2006):** Introduced improvements like new cryptographic algorithms and protection against man-in-the-middle attacks.
*   **TLS 1.2 (2008):** Further security enhancements, stronger algorithms, and negotiation of compression.
*   **TLS 1.3 (2018):** Latest version with faster performance, stronger encryption, simplified handshake, and handshake encryption.

This module will discuss attacks that completely broke older SSL/TLS protocol versions (e.g., SSL 2.0 and SSL 3.0).

## What is HTTPS?

HTTPS is HTTP traffic encapsulated within TLS. It provides encrypted and integrity-protected communication, preventing eavesdropping and data manipulation. While HTTP uses `http://` and port 80, HTTPS uses `https://` and port 443. There are no dedicated HTTPS versions, as it simply indicates HTTP over TLS.

## Introduction to TLS Attacks

TLS utilizes symmetric encryption, asymmetric encryption, and Message Authentication Codes (MACs) to provide confidentiality, integrity, and authenticity. This module will cover TLS security vulnerabilities, misconfigurations, and how to detect, exploit, and prevent related attacks. Security issues in TLS are often implementation flaws rather than specification flaws.

### Padding Oracle Attacks

These attacks exploit servers that leak information about padding correctness after decryption, allowing full ciphertext decryption without the encryption key. Examples include POODLE, DROWN, and Bleichenbacher attacks.

### Compression Attacks

Compression, used to improve data transmission performance, can be exploited in misconfigured servers to leak encrypted information (e.g., session cookies, CSRF tokens). Examples include CRIME and BREACH attacks.

### Misc Attacks & Misconfigurations

This section covers other attacks and misconfigurations, such as the Heartbleed bug (exploiting missing length validation in OpenSSL to leak private keys) and misconfigurations that weaken TLS security by using insecure cryptographic primitives.
