# Cryptographic Attacks

Beyond padding oracle and compression-based attacks on TLS, some attacks directly target cryptographic algorithms. Here, we discuss three such attacks for comprehensive understanding.

## LUCKY13 Attack

The Lucky13 attack, reported in 2013, exploits a timing difference during the Message Authentication Code (MAC) computation when the Cipher Block Chaining (CBC) mode is used. This attack is conceptually similar to padding oracle attacks.

To counter padding oracle vulnerabilities, TLS servers typically avoid leaking verbose error messages for incorrect padding. Additionally, they compute a MAC even if the padding is incorrect to prevent discernible timing differences that could enable padding oracle attacks. The Lucky13 attack, however, leverages a subtle timing difference: the MAC computation, when including incorrect padding bytes, takes slightly longer in certain scenarios. This minute timing variation can be sufficient to infer the validity of the padding, potentially leading to full plaintext recovery.

Most cryptographic libraries patched this attack in 2013, rendering up-to-date libraries a sufficient countermeasure. Consequently, Lucky13 attacks no longer pose a significant threat in real-world engagements.

## SWEET32 Attack

The Sweet32 attack is a birthday attack targeting block ciphers in TLS. The objective of birthday attacks is to discover collisions in block ciphers that use short block lengths, specifically 64 bits. Older TLS versions, for instance, utilized such block ciphers like Triple-DES.

Successfully finding a collision requires capturing several hundred gigabytes of traffic, meaning the attack can last multiple days. The TLS connection must be maintained throughout the attack's duration. This attack was reported in 2016, and similar to Lucky13, most libraries have patched the underlying issues. The most effective countermeasure is to use TLS 1.3, as it has eliminated all weak block ciphers with short block lengths.

## FREAK Attack

The Factoring RSA Export Keys (FREAK) attack exploits weak encryption supported in older TLS versions. SSL 3.0 and TLS 1.0 included "export cipher suites," which were intentionally weakened to comply with US regulations restricting the export of strong cryptographic software. Since these algorithms were already considered weak in the 1990s, their short key lengths make them easily breakable with today's computational power.

Servers vulnerable to the FREAK attack still support these `RSA_EXPORT` cipher suites, which are considered weak by current standards and can be compromised. As export cipher suites were removed in TLS 1.2, a sufficient countermeasure is to disable support for TLS 1.1 and older versions.
