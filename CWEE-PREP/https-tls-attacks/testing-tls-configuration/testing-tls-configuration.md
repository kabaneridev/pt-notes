# Testing TLS Configuration

TLS provides confidentiality, integrity, and authenticity only if used correctly. When conducting penetration tests on a web server, it is crucial to assess its TLS configuration. Misconfigured TLS poses a risk not only to the server but also to all clients establishing TLS sessions with it. Therefore, a web server should always be configured according to the latest TLS best practices to provide maximum security for all clients.

## Key Management Best Practices

Before delving into TLS-specific best practices, let's briefly discuss some general key management best practices that should be followed whenever cryptographic algorithms are used. For more detailed information, refer to the NIST best practices.

The first principle is that each key should ideally be used for a single purpose, whether it's encryption, signing, authentication, or another specific use case. Using a single key for multiple purposes is generally discouraged, as it limits the impact of a potential key compromise, confining an attacker to the dedicated use case of the compromised key.

Furthermore, it is important to define cryptoperiods, after which keys expire and are no longer used. This practice limits the exposure duration of a single key and ensures a finite timeframe for computationally intensive attacks such as cryptanalysis or brute-force attacks. If a key is compromised, it should immediately be treated as deprecated and replaced.

While there are many other considerations for correctly using cryptography, the following are among the most important:

*   Ensure comprehensive documentation of key management processes.
*   Ensure the key generation process produces strong, unpredictable keys.
*   Ensure keys are never stored unencrypted.
*   Ensure that expired, weakened, or compromised keys are promptly replaced and no longer used.
*   Ensure cryptographic keys are stored in a different location than the data they protect.
*   Ensure that no hardcoded cryptographic keys are used within application code.
*   Ensure that only state-of-the-art and known secure cryptographic algorithms are used; avoid custom implementations.
*   Ensure that encryption at rest and encryption in transit is used whenever possible.

## TLS Versions

Generally, only TLS 1.2 and TLS 1.3 should be offered. TLS 1.0 and 1.1 are considered deprecated, although supporting them for legacy reasons might be necessary in specific environments. However, SSL 2.0 and SSL 3.0 are completely broken and should not be offered under any circumstances.

In Apache, supported TLS versions can be configured in the `ssl.conf` file:

```
SSLProtocol +TLSv1.2 +TLSv1.3
```

The equivalent configuration in Nginx's config file looks like this:

```
ssl_protocols TLSv1.2 TLSv1.3;
```

## Cipher Suites

After the TLS version, the cipher suite is the most critical configuration for a session, as it determines all the cryptographic algorithms used. Ideally, servers should only offer the most secure cipher suites. However, this is often impractical in most scenarios, as not all clients support strong cipher suites. Consequently, weaker cipher suites sometimes must be supported to allow legacy clients to use the service, preventing them from being locked out due to an inability to establish a TLS connection.

Nonetheless, certain rules of thumb should be followed when configuring cipher suites:

*   Do not offer any NULL cipher suites, as they provide no encryption.
*   Do not offer any EXPORT cipher suites, as they only provide weak encryption.
*   Preferably use cipher suites that offer Perfect Forward Secrecy (PFS). These include all TLS 1.3 cipher suites, as well as ECDHE and DHE cipher suites in TLS 1.2.
*   Preferably use cipher suites in GCM mode over cipher suites in CBC mode.

In Apache, you can limit the offered cipher suites to those with at least a 128-bit key length in the `ssl.conf` file:

```
SSLCipherSuite HIGH
```

Alternatively, you can explicitly specify a list of cipher suites in your preferred order:

```
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305
```

The same configuration in Nginx's config file looks like this:

```
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305;
```

## Best Practices & Tools

To assess a web server's TLS configuration and determine its vulnerability to common TLS issues, the `testssl.sh` tool can be used. It can be downloaded from GitHub:

```bash
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh/
bash testssl.sh
```

All default tests can be run against a server by simply specifying its URL:

```bash
bash testssl.sh https://hackthebox.com
```

The output of `testssl.sh` automatically details the entire TLS configuration, including cipher suites, offered TLS versions, the server's certificate, and the presence of common vulnerabilities. It also assigns a grade and explains the reasons for that grading. For example, if a server still offers TLS 1.0 and TLS 1.1, or lacks the HSTS header, these findings would be highlighted. In a penetration test, these would be documented as low-risk findings, though a lower overall grade might lead to a higher severity rating for misconfigured TLS in a real-life engagement.
