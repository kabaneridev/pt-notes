# Prevention of PDF Generation Vulnerabilities

Most issues stem from untrusted HTML fed to PDF engines and insecure defaults. Combine strict input handling with hardened renderer configuration.

## Secure Configuration (examples by library)

- Disable JavaScript execution in the renderer.
- Block local file access (no `file://`).
- Disable remote fetching or restrict to an allow-list.
- dompdf:
  - `enable_remote = false` (or restrict via allow-list)
  - `isPhpEnabled = false`
- wkhtmltopdf:
  - Avoid `--enable-local-file-access` in untrusted flows
  - Prefer `--disable-javascript` if feasible
- General:
  - Run renderer in a sandbox (container/AppArmor/SELinux), read-only templates, no network egress by default.

## Input Handling

- Default: HTML-entity encode user input (e.g., PHP `htmlentities`) so tags are not interpreted.
- If limited formatting is required, use an allow-list sanitizer (e.g., only `<b>`, `<i>`, `<u>`, controlled `<img>` with data URIs or vetted hosts).
- Strip dangerous elements/attributes: `<script>`, `<iframe>`, `<object>`, `<embed>`, event handlers (`onload`...), CSS `url()`.

## Resource Strategy

- Vendor static assets (images, CSS) locally and reference local copies.
- Enforce egress firewall: deny all by default; allow specific hosts only if absolutely needed.

## Operational Hardening

- Least privilege filesystem access; render to a dedicated temp directory with strict perms.
- Keep libraries updated; review security notes of chosen engine.
- Log and rate-limit PDF generation requests; cap output size and render time.

> Principle: Do not process untrusted HTML. If business needs require HTML, strictly sanitize and sandbox the renderer with minimal capabilities.
