# Tools of the Trade

## Fuzzing

- **Fuzzing** means using wordlists of common NoSQLi payloads to check for injection points by observing differences in server responses.
- Recommended wordlists:
  - `SecLists/Fuzzing/Databases/NoSQL.txt`
  - `nosqlinjection_wordlists/mongodb_nosqli.txt`
- Example wfuzz usage (for blind or error-based NoSQLi finding):

```bash
wfuzz -z file,/usr/share/seclists/Fuzzing/Databases/NoSQL.txt \
      -u http://127.0.0.1/index.php \
      -d '{"trackingNum": FUZZ}'
```
- Analyze the length/structure of responses to highlight interesting payloads.

## Automated Tools

- **NoSQLMap** (open source Python2 tool):
    - Automated probing and exploitation of NoSQL endpoints (injection, RCE, file read etc)
    - https://github.com/codingo/NoSQLMap

- Example install steps:
  ```bash
  git clone https://github.com/codingo/NoSQLMap.git
  cd NoSQLMap
  sudo apt install python2.7
  wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
  python2 get-pip.py
  pip2 install -r requirements.txt
  # add modules as needed (pymongo, etc)
  ```
- Example use:
  ```bash
  python2 nosqlmap.py --attack 2 --victim 127.0.0.1 --webPort 80 \
    --uri /index.php --httpMethod POST \
    --postData email,admin@mangomail.com,password,qwerty \
    --injectedParameter 1 --injectSize 4
  ```
- It will report vulnerable parameters and suggest exploitation vectors.

- **Burp Suite extensions:**
    - *Burp-NoSQLiScanner* can scan forms for NoSQLi (requires Burp Pro)
    - https://github.com/PortSwigger/nosqli-scanner

## Tips
- Response length and structure is the easiest low-effort indicator of successful injection.
- Always manually confirm with a browser/Burp if fuzzing suggests interesting behavior.
- Custom scripts using `requests/wfuzz` are effective for chaining creative payloads and conditions.
