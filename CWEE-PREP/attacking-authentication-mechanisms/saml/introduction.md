# Introduction to SAML

Secure Assertion Markup Language (SAML) is an XML-based standard for authentication and authorization — most often used for Single Sign-On (SSO) in web/enterprise applications.

## Core SAML Components
- **Identity Provider (IdP):** Authenticates users, issues SAML assertions (identity statements)
- **Service Provider (SP):** SAML-relying app ('acceptor'), grants access to resources for authenticated users
- **SAML Assertion:** Digitally signed piece of XML describing an authenticated user and their attributes/roles

## Abstract SAML Authentication Flow
1. User accesses a resource on the SP
2. SP detects user is unauthenticated, redirects to IdP with a SAML AuthnRequest (XML)
3. User logs in at IdP
4. IdP generates a SAML Assertion, signs it, sends it (typically via auto-submitted form POST) to the SP
5. SP validates the assertion (checks signature, audience, etc)
6. User is allowed access to the protected resource

## Example SAML AuthnRequest (from SP to IdP)
```xml
<samlp:AuthnRequest
  ID="ONELOGIN_809707f0..."
  Version="2.0"
  Destination="https://idp.htb/idp/SSOService.php"
  AssertionConsumerServiceURL="https://sp.htb/index.php">
  <saml:Issuer>https://sp.htb/index.php</saml:Issuer>
</samlp:AuthnRequest>
```

## Example SAML Assertion (from IdP to SP)
```xml
<saml:Assertion ...>
  <saml:Issuer>https://idp.htb/idp/</saml:Issuer>
  <saml:Subject>
    <saml:NameID>johndoe@htb.htb</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="username">
      <saml:AttributeValue>john</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

## Real-World Usage
- SAML enables organizations to centralize identity/auth management (IdP) and let users access many platforms/services (SPs) with one login — e.g., "Login with your company SSO".

The next sections will detail how SAML assertions and flows can be abused, and what implementation mistakes are most dangerous.
