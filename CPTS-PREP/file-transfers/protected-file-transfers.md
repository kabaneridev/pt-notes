# Protected File Transfers

## Introduction

As penetration testers, we often gain access to highly sensitive data such as user lists, credentials (i.e., downloading the NTDS.dit file for offline password cracking), and enumeration data that can contain critical information about the organization's network infrastructure, and Active Directory (AD) environment, etc. Therefore, it is essential to encrypt this data or use encrypted data connections such as SSH, SFTP, and HTTPS. However, sometimes these options are not available to us, and a different approach is required.

**⚠️ Note:** Unless specifically requested by a client, we do not recommend exfiltrating data such as Personally Identifiable Information (PII), financial data (i.e., credit card numbers), trade secrets, etc., from a client environment. Instead, if attempting to test Data Loss Prevention (DLP) controls/egress filtering protections, create a file with dummy data that mimics the data that the client is trying to protect.

Therefore, encrypting the data or files before a transfer is often necessary to prevent the data from being read if intercepted in transit.

**Data leakage during a penetration test could have severe consequences for the penetration tester, their company, and the client. As information security professionals, we must act professionally and responsibly and take all measures to protect any data we encounter during an assessment.**

## File Encryption on Windows

Many different methods can be used to encrypt files and information on Windows systems. One of the simplest methods is the `Invoke-AESEncryption.ps1` PowerShell script. This script is small and provides encryption of files and strings.

### Invoke-AESEncryption.ps1 Script

**Download or create the script:**
```powershell
# The script can be downloaded or created manually
# Save as Invoke-AESEncryption.ps1
```

**Script functionality examples:**
- Encrypt string: `Invoke-AESEncryption -Mode Encrypt -Key "test123" -Text "Secret Text"`
- Decrypt string: `Invoke-AESEncryption -Mode Decrypt -Key "test123" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="`
- Encrypt file: `Invoke-AESEncryption -Mode Encrypt -Key "test123" -Path file.bin`
- Decrypt file: `Invoke-AESEncryption -Mode Decrypt -Key "test123" -Path file.bin.aes`

### PowerShell AES Encryption Script

```powershell
function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}
                
                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
                
                if ($Path) {
                    [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                    (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    return "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
```

### Using the AES Encryption Script

**Import the Module:**
```powershell
Import-Module .\Invoke-AESEncryption.ps1
```

**File Encryption Example:**
```powershell
# Encrypt a file
Invoke-AESEncryption -Mode Encrypt -Key "test123" -Path .\scan-results.txt
# Output: File encrypted to C:\htb\scan-results.txt.aes

# List files to verify
ls
```

**String Encryption Examples:**
```powershell
# Encrypt a string
$encrypted = Invoke-AESEncryption -Mode Encrypt -Key "test123" -Text "Sensitive data here"
Write-Host "Encrypted: $encrypted"

# Decrypt the string
$decrypted = Invoke-AESEncryption -Mode Decrypt -Key "test123" -Text $encrypted
Write-Host "Decrypted: $decrypted"
```

**File Decryption Example:**
```powershell
# Decrypt a file
Invoke-AESEncryption -Mode Decrypt -Key "test123" -Path .\scan-results.txt.aes
# Output: File decrypted to C:\htb\scan-results.txt
```

### Alternative Windows Encryption Methods

#### Using 7-Zip with Password

**Encrypt with 7-Zip:**
```cmd
7z a -p"test123" encrypted_archive.7z sensitive_file.txt
```

**Decrypt with 7-Zip:**
```cmd
7z x encrypted_archive.7z -p"test123"
```

#### Using Windows Built-in Cipher

**Encrypt folder with EFS:**
```cmd
cipher /e /s:C:\SensitiveFolder
```

**Check encryption status:**
```cmd
cipher /u /n
```

## File Encryption on Linux

OpenSSL is frequently included in Linux distributions, with sysadmins using it to generate security certificates, among other tasks. OpenSSL can be used to send files "nc style" to encrypt files.

### OpenSSL Encryption

**Encrypting /etc/passwd with openssl:**
```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
# Enter password when prompted
```

**Decrypt passwd.enc with openssl:**
```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
# Enter password when prompted
```

### OpenSSL Advanced Options

**Different cipher algorithms:**
```bash
# AES-128
openssl enc -aes128 -iter 100000 -pbkdf2 -in file.txt -out file.txt.enc

# AES-192
openssl enc -aes192 -iter 100000 -pbkdf2 -in file.txt -out file.txt.enc

# ChaCha20
openssl enc -chacha20 -iter 100000 -pbkdf2 -in file.txt -out file.txt.enc
```

**Base64 encoding with encryption:**
```bash
# Encrypt and base64 encode
openssl enc -aes256 -iter 100000 -pbkdf2 -in file.txt -base64 -out file.txt.enc

# Decrypt base64 encoded file
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in file.txt.enc -base64 -out file.txt
```

**Using password from file:**
```bash
# Create password file (be careful with permissions)
echo "test123" > password.txt
chmod 600 password.txt

# Encrypt using password file
openssl enc -aes256 -iter 100000 -pbkdf2 -in file.txt -out file.txt.enc -pass file:password.txt

# Decrypt using password file
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in file.txt.enc -out file.txt -pass file:password.txt
```

### GPG Encryption

**Symmetric encryption with GPG:**
```bash
# Encrypt file
gpg --symmetric --cipher-algo AES256 --compress-algo 1 --s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65536 file.txt

# Decrypt file
gpg --decrypt file.txt.gpg > file.txt
```

**Generate GPG key pair:**
```bash
gpg --gen-key
```

**Encrypt for specific recipient:**
```bash
gpg --encrypt --recipient user@example.com file.txt
```

**Decrypt file:**
```bash
gpg --decrypt file.txt.gpg > file.txt
```

### Archive Encryption

**Create encrypted tar archive:**
```bash
tar czf - sensitive_folder/ | openssl enc -aes256 -iter 100000 -pbkdf2 -out encrypted_archive.tar.gz.enc
```

**Extract encrypted tar archive:**
```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in encrypted_archive.tar.gz.enc | tar xzf -
```

**Using 7-Zip on Linux:**
```bash
# Install 7-Zip
sudo apt-get install p7zip-full

# Encrypt archive
7z a -p"test123" encrypted_archive.7z sensitive_file.txt

# Decrypt archive
7z x encrypted_archive.7z -p"test123"
```

## Advanced Protection Methods

### Steganography

**Hide data in images using steghide:**
```bash
# Install steghide
sudo apt-get install steghide

# Hide file in image
steghide embed -cf cover_image.jpg -ef secret_file.txt -p "test123"

# Extract file from image
steghide extract -sf cover_image.jpg -p "test123"
```

**Hide data using LSB (Least Significant Bit):**
```python
# Python example for LSB steganography
from PIL import Image
import numpy as np

def hide_data_in_image(image_path, data, output_path):
    image = Image.open(image_path)
    image_array = np.array(image)
    
    # Convert data to binary
    binary_data = ''.join(format(ord(char), '08b') for char in data)
    
    # Hide data in LSB of image pixels
    data_index = 0
    for i in range(image_array.shape[0]):
        for j in range(image_array.shape[1]):
            for k in range(image_array.shape[2]):
                if data_index < len(binary_data):
                    image_array[i][j][k] = (image_array[i][j][k] & 0xFE) | int(binary_data[data_index])
                    data_index += 1
    
    # Save modified image
    modified_image = Image.fromarray(image_array)
    modified_image.save(output_path)

# Usage
hide_data_in_image('cover.png', 'secret message', 'stego.png')
```

### Split and Encrypt

**Split large files before encryption:**
```bash
# Split file into 1MB chunks
split -b 1M large_file.txt chunk_

# Encrypt each chunk
for file in chunk_*; do
    openssl enc -aes256 -iter 100000 -pbkdf2 -in "$file" -out "$file.enc"
    rm "$file"  # Remove original chunk
done
```

**Reassemble and decrypt:**
```bash
# Decrypt each chunk
for file in chunk_*.enc; do
    openssl enc -d -aes256 -iter 100000 -pbkdf2 -in "$file" -out "${file%.enc}"
done

# Reassemble file
cat chunk_* > large_file_restored.txt

# Clean up chunks
rm chunk_*
```

## Secure Transfer Protocols

### HTTPS File Transfer

**Upload via HTTPS with curl:**
```bash
curl -X POST -F "file=@encrypted_file.enc" https://secure-server.com/upload
```

**Download via HTTPS with wget:**
```bash
wget --no-check-certificate https://secure-server.com/encrypted_file.enc
```

### SFTP (SSH File Transfer Protocol)

**Upload encrypted file via SFTP:**
```bash
sftp user@remote-server
# sftp> put encrypted_file.enc
# sftp> exit
```

**Batch SFTP operations:**
```bash
echo "put encrypted_file.enc" > sftp_commands.txt
sftp -b sftp_commands.txt user@remote-server
```

### SCP over SSH

**Upload encrypted file via SCP:**
```bash
scp encrypted_file.enc user@remote-server:/tmp/
```

**SCP with compression:**
```bash
scp -C encrypted_file.enc user@remote-server:/tmp/
```

## Best Practices for Protected File Transfers

### Password Security

1. **Use strong, unique passwords** for each engagement
2. **Minimum 16 characters** with mixed case, numbers, and symbols
3. **Never reuse passwords** across different clients
4. **Store passwords securely** in a password manager
5. **Use different passwords** for each encrypted file

### Key Management

1. **Generate strong encryption keys** using cryptographically secure methods
2. **Use key derivation functions** (like PBKDF2) with high iteration counts
3. **Rotate encryption keys** regularly
4. **Securely delete keys** after use
5. **Never hardcode keys** in scripts or documentation

### File Handling

1. **Encrypt before transfer** whenever possible
2. **Verify file integrity** after transfer using checksums
3. **Securely delete original files** after encryption
4. **Use secure deletion tools** (like `shred` on Linux)
5. **Document encryption methods** used for each file

### Network Security

1. **Prefer encrypted transport protocols** (HTTPS, SFTP, SSH)
2. **Avoid unencrypted protocols** (HTTP, FTP, Telnet)
3. **Use VPN connections** when possible
4. **Monitor network traffic** for anomalies
5. **Implement proper firewall rules**

## Compliance and Legal Considerations

### Data Protection Regulations

1. **GDPR compliance** - Encrypt personal data
2. **HIPAA requirements** - Protect health information
3. **PCI DSS standards** - Secure payment card data
4. **SOX compliance** - Financial data protection
5. **Industry-specific regulations** - Follow sector requirements

### Documentation Requirements

1. **Document encryption methods** used
2. **Maintain key management logs**
3. **Record file transfer activities**
4. **Track data handling procedures**
5. **Report security incidents** promptly

## Troubleshooting Encrypted File Transfers

### Common Issues

**Incorrect password:**
```bash
# Verify password before transfer
echo "test data" | openssl enc -aes256 -iter 100000 -pbkdf2 -pass pass:"test123" | openssl enc -d -aes256 -iter 100000 -pbkdf2 -pass pass:"test123"
```

**Corrupted encrypted files:**
```bash
# Check file integrity
md5sum original_file.txt
md5sum decrypted_file.txt
```

**Encoding issues:**
```bash
# Verify base64 encoding
base64 encrypted_file.enc | base64 -d > test_decrypt.enc
diff encrypted_file.enc test_decrypt.enc
```

### Verification Methods

**File size comparison:**
```bash
# Original file size
ls -la original_file.txt

# Encrypted file size (will be larger)
ls -la original_file.txt.enc

# Decrypted file size (should match original)
ls -la decrypted_file.txt
```

**Checksum verification:**
```bash
# Create checksum before encryption
sha256sum original_file.txt > original.sha256

# Verify after decryption
sha256sum -c original.sha256
```

## Key Takeaways

1. **Always encrypt sensitive data** before transfer during penetration tests
2. **Use strong, unique passwords** for each encryption operation
3. **Prefer secure transport protocols** when available
4. **Document encryption methods** and key management procedures
5. **Verify file integrity** after encryption and transfer
6. **Follow legal and compliance requirements** for data protection
7. **Implement proper key management** practices
8. **Securely delete original files** after encryption
9. **Test encryption/decryption** before critical transfers
10. **Have backup encryption methods** available

## References

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [GPG Manual](https://gnupg.org/documentation/manuals/gnupg/)
- [PowerShell Cryptography](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/protect-cmsmessage)
- [NIST Encryption Guidelines](https://csrc.nist.gov/publications/detail/sp/800-175b/rev-1/final)
- [GDPR Data Protection](https://gdpr.eu/data-protection/)
- [PCI DSS Requirements](https://www.pcisecuritystandards.org/) 