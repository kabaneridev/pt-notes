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