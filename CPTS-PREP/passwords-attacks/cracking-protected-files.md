# Cracking Protected Files

## Overview
- Encrypted files can contain sensitive information
- Common in corporate environments (GDPR compliance)
- Often use AES-256 symmetric encryption
- Can be cracked with right wordlists and tools

## Hunting for Encrypted Files

### Common File Extensions
```bash
# Search for common encrypted file types
for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*")
do 
    echo -e "\nFile extension: " $ext
    find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done
```

### Common Protected File Types
- **.docx, .xlsx, .pptx** - Microsoft Office documents
- **.pdf** - Adobe PDF documents
- **.zip, .rar, .7z** - Compressed archives
- **.kdbx** - KeePass databases
- **.p12, .pfx** - Certificate files
- **.ssh keys** - SSH private keys
- **.gpg** - GPG encrypted files

## Finding SSH Keys

### Search for SSH Private Keys
```bash
# Search for SSH private key headers
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

# Common locations
find / -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null
```

### Check if SSH Key is Encrypted
```bash
# Try to read key - will prompt for password if encrypted
ssh-keygen -yf ~/.ssh/id_rsa

# Check for encryption in PEM format
head -5 private_key.pem | grep "ENCRYPTED"
```

## File Cracking Tools

### Available 2john Tools
```bash
# List all 2john conversion tools
locate *2john*

# Common tools:
# - ssh2john.py - SSH private keys
# - office2john.py - Office documents
# - pdf2john.py - PDF files
# - zip2john - ZIP archives
# - rar2john - RAR archives
# - keepass2john - KeePass databases
# - gpg2john - GPG files
```

## Cracking SSH Keys

### Extract and Crack SSH Key
```bash
# Extract hash from SSH private key
ssh2john.py SSH.private > ssh.hash

# Crack with John
john --wordlist=rockyou.txt ssh.hash

# Show results
john ssh.hash --show
```

### With Hashcat
```bash
# Convert SSH key to hashcat format
ssh2john.py SSH.private | cut -d: -f2 > ssh.hashcat

# Crack with hashcat
hashcat -a 0 -m 22931 ssh.hashcat /usr/share/wordlists/rockyou.txt
```

## Cracking Office Documents

### Microsoft Office Files
```bash
# Extract hash from Office document
office2john.py Protected.docx > protected-docx.hash

# Crack with John
john --wordlist=rockyou.txt protected-docx.hash

# Show results
john protected-docx.hash --show
```

### With Hashcat
```bash
# Office 2007-2013 (hashcat mode 9400)
hashcat -a 0 -m 9400 office.hash /usr/share/wordlists/rockyou.txt

# Office 2016-2019 (hashcat mode 9500)
hashcat -a 0 -m 9500 office.hash /usr/share/wordlists/rockyou.txt
```

## Cracking PDF Files

### Extract and Crack PDF
```bash
# Extract hash from PDF
pdf2john.py PDF.pdf > pdf.hash

# Crack with John
john --wordlist=rockyou.txt pdf.hash

# Show results
john pdf.hash --show
```

### With Hashcat
```bash
# PDF 1.4-1.6 (hashcat mode 10400)
hashcat -a 0 -m 10400 pdf.hash /usr/share/wordlists/rockyou.txt

# PDF 1.7 Level 3 (hashcat mode 10500)
hashcat -a 0 -m 10500 pdf.hash /usr/share/wordlists/rockyou.txt
```

## Cracking Archive Files

### ZIP Archives
```bash
# Extract hash from ZIP
zip2john archive.zip > zip.hash

# Crack with John
john --wordlist=rockyou.txt zip.hash

# With hashcat (mode 13600)
hashcat -a 0 -m 13600 zip.hash /usr/share/wordlists/rockyou.txt
```

### RAR Archives
```bash
# Extract hash from RAR
rar2john archive.rar > rar.hash

# Crack with John
john --wordlist=rockyou.txt rar.hash

# With hashcat (mode 12500)
hashcat -a 0 -m 12500 rar.hash /usr/share/wordlists/rockyou.txt
```

### 7-Zip Archives
```bash
# Extract hash from 7z
7z2john.pl archive.7z > 7z.hash

# Crack with John
john --wordlist=rockyou.txt 7z.hash

# With hashcat (mode 11600)
hashcat -a 0 -m 11600 7z.hash /usr/share/wordlists/rockyou.txt
```

## Other Protected Files

### KeePass Databases
```bash
# Extract hash from KeePass
keepass2john Database.kdbx > keepass.hash

# Crack with John
john --wordlist=rockyou.txt keepass.hash

# With hashcat (mode 13400)
hashcat -a 0 -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```

### GPG Files
```bash
# Extract hash from GPG
gpg2john encrypted.gpg > gpg.hash

# Crack with John
john --wordlist=rockyou.txt gpg.hash
```

## Common Hashcat Hash Modes

| File Type | Mode | Description |
|-----------|------|-------------|
| PDF 1.4-1.6 | 10400 | PDF (Portable Document Format) |
| PDF 1.7 Level 3 | 10500 | PDF 1.7 Level 3 (Acrobat 9) |
| MS Office 2007 | 9400 | Office 2007 |
| MS Office 2010 | 9500 | Office 2010 |
| MS Office 2013 | 9600 | Office 2013 |
| ZIP | 13600 | WinZip |
| RAR3 | 12500 | RAR3-hp |
| 7-Zip | 11600 | 7-Zip |
| KeePass | 13400 | KeePass 1 (AES/Twofish) |
| SSH Private Key | 22931 | RSA/DSA/EC/OPENSSH |

## Tips for Success

1. **Use targeted wordlists** - Include company names, dates, common passwords
2. **Try common patterns** - company123, Company2024!, etc.
3. **Check file metadata** - May contain hints about creator/purpose
4. **Multiple attack methods** - Dictionary, rules, mask attacks
5. **Be patient** - Some files take significant time to crack
6. **Check for weak passwords** - Many users still use simple passwords
7. **Corporate patterns** - Often follow predictable formats

## Cracking Protected Archives

### ZIP Files (Extended)
```bash
# Extract hash from ZIP
zip2john ZIP.zip > zip.hash

# Check hash format
cat zip.hash

# Crack with John
john --wordlist=rockyou.txt zip.hash

# Show results
john zip.hash --show
```

### OpenSSL Encrypted GZIP Files
```bash
# Check if file is OpenSSL encrypted
file GZIP.gzip

# Direct brute force with OpenSSL
for i in $(cat rockyou.txt); do 
    openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz
done
```

### BitLocker Encrypted Drives
```bash
# Extract hashes from BitLocker VHD
bitlocker2john -i Backup.vhd > backup.hashes

# Get password hash (first hash)
grep "bitlocker\$0" backup.hashes > backup.hash

# Crack with hashcat (mode 22100)
hashcat -a 0 -m 22100 backup.hash /usr/share/wordlists/rockyou.txt

# Show results
hashcat -m 22100 backup.hash --show
```

### Mounting BitLocker Drives

#### Windows
1. Double-click the .vhd file
2. Double-click the BitLocker volume
3. Enter the cracked password

#### Linux/macOS
```bash
# Install dislocker
sudo apt-get install dislocker

# Create mount directories
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount

# Set up loop device
sudo losetup -f -P Backup.vhd

# Decrypt with dislocker
sudo dislocker /dev/loop0p2 -u<password> -- /media/bitlocker

# Mount the decrypted volume
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# Browse files
cd /media/bitlockermount/
ls -la

# Unmount when done
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
```

### Practical BitLocker Example

**Complete workflow for cracking and mounting a BitLocker VHD:**

```bash
# Step 1: Download and extract the VHD
wget http://target:port/download -O download.zip
unzip download.zip

# Step 2: Extract BitLocker hash and crack password
bitlocker2john -i Private.vhd > private.hashes
grep "bitlocker\$0" private.hashes > private.hash
hashcat -a 0 -m 22100 private.hash /usr/share/wordlists/rockyou.txt

# Step 3: Create mount directories
sudo mkdir -p /media/bitlocker
sudo mkdir -p /media/bitlockermount

# Step 4: Set up loop device
sudo losetup -f -P Private.vhd

# Step 5: Verify loop device
losetup --all
# Output: /dev/loop0: []: (/home/user/Private.vhd)

# Step 6: Install dislocker (if not already installed)
sudo apt-get install dislocker -y

# Step 7: Decrypt with cracked password
sudo dislocker /dev/loop0p1 -u<cracked_password> -- /media/bitlocker

# Step 8: Verify decryption
sudo ls -la /media/bitlocker
# Should show dislocker-file

# Step 9: Mount the decrypted volume
sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

# Step 10: Access files
cd /media/bitlockermount
cat flag.txt

# Step 11: Cleanup when done
sudo umount /media/bitlockermount
sudo umount /media/bitlocker
sudo losetup -d /dev/loop0
```

**Key Points:**
- Use `losetup --all` to verify loop device assignment
- BitLocker partitions are usually `p1` or `p2` (e.g., `/dev/loop0p1`)
- The `dislocker-file` is created in the first mount point
- Always unmount and detach loop devices when finished

### Common Archive Types
- **.zip** - ZIP archives
- **.rar** - RAR archives 
- **.7z** - 7-Zip archives
- **.tar.gz** - Tarball with gzip
- **.tar.bz2** - Tarball with bzip2
- **.vhd/.vhdx** - Virtual Hard Disk (often BitLocker)
- **.vmdk** - VMware Virtual Disk
- **.truecrypt** - TrueCrypt volumes
- **.luks** - Linux Unified Key Setup

### Additional Archive Hash Modes
| Archive Type | Tool | Hashcat Mode |
|-------------|------|--------------|
| BitLocker | bitlocker2john | 22100 |
| TrueCrypt | truecrypt_volume2john | 6211 |
| LUKS | luks2john | 14600 |
| VMware VMDK | vmware2john | 20300 |

## Automation Script Example
```bash
#!/bin/bash
# Auto-crack common protected files and archives

for file in $(find . -name "*.pdf" -o -name "*.docx" -o -name "*.zip" -o -name "*.vhd"); do
    echo "Processing: $file"
    
    case "$file" in
        *.pdf)
            pdf2john.py "$file" > "${file}.hash"
            john --wordlist=rockyou.txt "${file}.hash"
            ;;
        *.docx)
            office2john.py "$file" > "${file}.hash"
            john --wordlist=rockyou.txt "${file}.hash"
            ;;
        *.zip)
            zip2john "$file" > "${file}.hash"
            john --wordlist=rockyou.txt "${file}.hash"
            ;;
        *.vhd)
            bitlocker2john -i "$file" > "${file}.hashes"
            grep "bitlocker\$0" "${file}.hashes" > "${file}.hash"
            hashcat -a 0 -m 22100 "${file}.hash" /usr/share/wordlists/rockyou.txt
            ;;
    esac
done
``` 