# Padding Oracles

Padding Oracle attacks are cryptographic attacks that are the result of verbose leakage of information about the decryption process. They are not specific to TLS but can be present in any application that handles encryption or decryption incorrectly.

## What is Padding?

To understand Padding Oracle attacks, we first have to take a look at what exactly padding is and why it is required.

Block ciphers, a type of symmetric encryption algorithm, operate by splitting the input into blocks and encrypting the input block by block, hence the name. To do so, it is required that the input length is divisible by the block size. Padding is the data added to the input to reach such a correct length. For instance, AES has a block size of 16 bytes, so if we want to encrypt a string of 30 bytes, we need to add 2 bytes of padding to reach a multiple of the block size.

When padding is added to the plaintext before encryption, it must be removed from the result of the decryption operation to reconstruct the original plaintext. In particular, the padding needs to be reversible. This sounds intuitive but might not be trivial. Consider the following example padding:

*   We are using a block cipher with a block size of 8 bytes
*   Our padding scheme works by appending the byte FF until a multiple of the block size is reached

Now consider that we want to encrypt the plaintext byte stream `DE AD BE EF FF`. Since the length of this plaintext is 5 bytes, we need to append 3 bytes of padding such that the plaintext becomes `DE AD BE EF FF FF FF FF`. Now we can encrypt this plaintext using our block cipher and transmit it to the target. After the target received the encrypted message, they decrypt it, resulting in the same plaintext `DE AD BE EF FF FF FF FF`. To reverse the padding, all trailing bytes `FF` are removed, resulting in the plaintext `DE AD BE EF`. However, compared to the original message, this decryption is incorrect. That is because the trailing byte `FF` of the original plaintext is identical to the padding byte. Therefore, there is no way of knowing how many padding bytes have to be stripped after decryption. Most padding schemes solve this problem by not simply appending a fixed byte to the end of the plaintext, but encoding the length of the padding as well. That way, the target can compute the padding length after decryption and remove the padding bytes accordingly.

## Padding Oracles

Padding Oracle attacks are the result of verbose leakage of error messages regarding the padding when the CBC encryption mode is used. They are the result of improper implementation or usage of cryptographic protocols and are not specific to TLS but apply to any situation when padding is handled improperly under these circumstances.

More specifically, a padding oracle attack exploits the fact that information about improper padding of a decrypted ciphertext is verbosely leaked, hence the name padding oracle. Since the applied padding scheme is generally known in advance, an attacker might be able to forge ciphertexts and brute force the correct padding byte which can lead to plaintext leakage. This allows an attacker to decrypt ciphertexts without access to the decryption key. In some cases, an attacker might even be able to encrypt his own plaintexts without knowledge of the key.

Decryption in CBC mode works by computing an intermediate result from the current ciphertext block and XORing it with the previous ciphertext block to form the current plaintext block. We are assuming that we are working on the last ciphertext block, so the resulting plaintext contains padding bytes. The attack works by modifying the previous block until a valid padding is reached in the current block. This leaks the intermediate result of the current block. Combining this intermediate result with the knowledge of the unmodified previous block leaks a plaintext byte of the current block. Applying this attack recursively byte-wise leads to the complete decryption of the last plaintext block. The attack can then be applied block-wise to decrypt the complete plaintext without knowledge of the decryption key.

Diagram of Cipher Block Chaining (CBC) mode decryption. Shows ciphertext blocks being decrypted with a key, using block cipher decryption, and combined with an Initialization Vector (IV) to produce plaintext.

We can identify servers vulnerable to padding oracle attacks by observing their behavior when they receive incorrect padding. Any difference in behavior to a correctly padded message can indicate a vulnerability. That includes verbose error messages, differences in the HTTP status code, differences in the HTTP body, or timing differences.

## Tools

To identify and exploit a padding oracle vulnerability in practice, you can use the tool PadBuster. It can be installed via the package manager:

```bash
sudo apt install padbuster
```

To display the help, you can just type `padbuster` into a terminal:

```bash
padbuster
```

### Exploitation with PadBuster

PadBuster requires the URL, an encrypted sample, and the block size. For example, if the encrypted sample is in a user cookie and the data is base64 encoded, the command would look like this:

```bash
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -encoding 0 -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0="
```

If the application provides a specific error message for invalid padding (e.g., "Invalid Padding"), you can specify it with the `-error` flag:

```bash
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -encoding 0 -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" -error 'Invalid Padding'
```

To encrypt a custom value (e.g., `user=admin`) and forge a cookie, use the `-plaintext` flag:

```bash
padbuster http://127.0.0.1:1337/admin "AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" 16 -encoding 0 -cookies "user=AAAAAAAAAAAAAAAAAAAAAJQB/nhNEuPuNC8ox7cN1z0=" -plaintext "user=admin"
```

## Prevention

Padding Oracle attacks exist because of the improper use of cryptographic algorithms. Even if the encryption algorithm is secure, it may still be vulnerable if used incorrectly. Therefore it is important to know what you are doing when implementing anything related to encryption. In particular, padding oracle attacks can be prevented by not letting the user know that the padding was invalid. Instead of displaying a specific error message about invalid padding, a generic error message should be displayed when the decryption fails. The application has to behave the exact same way whether the expected padding was correct or not. Most importantly, remember that you should "Never Roll-Your-Own Crypto", and instead try to use common encryption libraries.
