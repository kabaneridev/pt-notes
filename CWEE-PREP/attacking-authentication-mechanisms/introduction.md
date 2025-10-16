# Introduction to Authentication Mechanisms

Modern applications use advanced authentication & authorization standards to manage access and improve user experience. Frameworks such as JWT, OAuth, and SAML centralize access and help enforce organizational policies.

- **Authentication** confirms a user's identity (e.g., login with username/password)
- **Authorization** determines what resources a user can access (e.g., RBAC, ABAC, DAC, MAC policies)

Common standards in focus of this module:
- **JWT** — JSON Web Tokens, widely used for stateless authentication/session management
- **OAuth** — Authorization framework for delegated access ("Login via Google/Facebook", API scopes etc.)
- **SAML** — Extensible authentication & SSO protocol, commonly used in enterprises

Misconfigurations or poor practices in these mechanisms can lead to critical vulnerabilities — including privilege escalation, account takeover, and unauthorized data access.

This module teaches how these mechanisms work, how they're attacked, and how to avoid classic security pitfalls.
