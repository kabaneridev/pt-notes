# Public Key Infrastructure

TLS utilizes both symmetric and asymmetric cryptography, with asymmetric cryptography relying on Public Key Infrastructure (PKI). To understand TLS fully, it's essential to grasp basic PKI concepts, including certificates and Certificate Authorities (CAs).

## Public Key Infrastructure (PKI)

A PKI encompasses the roles and processes involved in managing digital certificates, including their distribution, creation, and revocation. It is fundamental to the practical application of public key cryptography.

In public key (asymmetric) cryptography, distinct keys are used for encryption and decryption. Each participant holds a key pair: a public key for encryption (shared openly) and a private key (kept secret) for decryption. Messages encrypted with a public key can only be decrypted by its corresponding private key, ensuring confidentiality.

Here's an overview of common encryption algorithms and their types:

| Algorithm  | Type      |
| :--------- | :-------- |
| RSA        | asymmetric|
| DSA        | asymmetric|
| AES        | symmetric |
| DES        | symmetric |
| 3DES       | symmetric |
| Blowfish   | symmetric |

A key challenge in public key cryptography is verifying the authenticity of a public key. For example, if Alice wants to communicate securely with `hackthebox.com`, she needs its public key. Without a reliable way to verify this key, an attacker could intercept her request, substitute their own public key, and impersonate `hackthebox.com`, thereby gaining access to Alice's encrypted messages. Certificates solve this problem.

## Certificates

Certificates bind public keys to an identity, proving the owner's authenticity. They contain information about the subject, most importantly the Common Name (the domain name the public key belongs to), and an expiry date. Additional domain names can be specified in the Subject Alternative Names section.

The certificate also includes the public key itself. For instance, a certificate for `hackthebox.com` would specify that a given public key belongs to `hackthebox.com`.

## Certificate Authorities (CAs)

Certificate Authorities (CAs) are trusted entities authorized to issue certificates. They do this by cryptographically signing a certificate. The CA's identity is verified by a CA Certificate, which, in turn, is signed by another CA, forming a chain that ultimately leads to a root CA. This is known as the certificate chain.

When a website is accessed, the browser validates the entire certificate chain. If any certificate in the chain is invalid or insecure, the browser displays a warning. Root CA identities are checked against a hardcoded list of trusted CAs in the browser's certificate store to prevent forgery of root CA certificates.

## OpenSSL

OpenSSL is a widely used cryptographic library and toolkit that implements cryptographic algorithms for secure communication. It is crucial for encrypted communication on the internet, and vulnerabilities in OpenSSL can affect millions of web servers. The OpenSSL client, often preinstalled on Linux distributions, allows users to generate keys and certificates, convert them between formats, and perform encryption.

### Key Generation & Certificate Conversion

An RSA key-pair (e.g., 2048-bit length) can be generated and stored in a file:

```bash
openssl genrsa -out key.pem 2048
```

The private key can be viewed by `cat`ing the `key.pem` file. The public key can be extracted and displayed:

```bash
openssl rsa -in key.pem -pubout
```

Certificates of web servers can be downloaded (e.g., from `hackthebox.com`) and stored in PEM format:

```bash
openssl s_client -connect hackthebox.com:443 | openssl x509 > hackthebox.pem
```

These certificates can be converted to other formats like DER or PKCS#7 using OpenSSL commands:

```bash
# PEM to DER
openssl x509 -outform der -in hackthebox.pem -out hackthebox.der

# PEM to PKCS#7
openssl crl2pkcs7 -nocrl -certfile hackthebox.pem -out hackthebox.p7
```

### Creating a Self-Signed Certificate

Self-signed certificates can be created without a CA's signature, specifying key type, algorithm, and expiry date. This process involves entering a passphrase and subject information (e.g., Common Name):

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out selfsigned.pem -sha256 -days 365
```

However, self-signed certificates are not trusted by web browsers, which display security warnings (e.g., `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT`). If an attacker were to obtain a CA's private key, they could sign certificates with arbitrary subjects, effectively impersonating any domain. Thus, CA private keys are among the most protected resources in online communication.

### Performing Encryption

OpenSSL can also be used to perform encryption. First, a new key-pair is created, and the public key is extracted:

```bash
# create new keypair
openssl genrsa -out rsa.pem 2048

# extract public key
openssl rsa -in rsa.pem -pubout > rsa_pub.pem
```

The extracted public key can then encrypt a file, resulting in a binary ciphertext:

```bash
openssl pkeyutl -encrypt -inkey rsa_pub.pem -pubin -in msg.txt -out msg.enc
```

Finally, the encrypted file can be decrypted using the corresponding private key:

```bash
openssl pkeyutl -decrypt -inkey rsa.pem -in msg.enc > decrypted.txt
```
