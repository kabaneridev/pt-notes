# Introduction to PDF Generation Vulnerabilities

Many apps generate PDFs (invoices, reports) using libraries that accept HTML/CSS input (e.g., TCPDF, mPDF, DomPDF, wkhtmltopdf, PDFKit, PD4ML). Unsanitized user HTML can lead to code execution, SSRF, file read, or data exfiltration during rendering.

## Why vulnerable?

- Engines fetch external resources (HTTP/HTTPS/file://) and execute render-time features (e.g., URL fetch, image decoding, sometimes JS or shell via converters).
- Misconfigurations (enabling remote, allowing local file access) and outdated versions increase risk.

## Common Libraries

- TCPDF, html2pdf, mPDF, DomPDF
- wkhtmltopdf (Qt-based), PDFKit, PD4ML

## Quick Start: wkhtmltopdf

- Install (Debian):

```bash
sudo dpkg -i wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
```

- Basics:

```bash
wkhtmltopdf https://example.com out.pdf
wkhtmltopdf ./index.html out.pdf
```

## Identify Generator via Metadata

Obtain a generated PDF and check metadata to identify the library/version:

- exiftool:

```bash
exiftool invoice.pdf
```

- pdfinfo:

```bash
pdfinfo invoice.pdf
```

Look for `Creator`/`Producer` fields (e.g., `wkhtmltopdf 0.12.6.1`, `Qt 4.8.7`, or `dompdf 2.0.3 + CPDF`). Use version to research known issues.

## Simple HTML Input Example

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>Hello World!</h1>
    <p>This is some text.</p>
  </body>
</html>
```

Render locally to replicate app behavior and test payloads.

> Security notice (wkhtmltopdf): Do not use with untrusted HTML without strict sanitization; untrusted input can fully compromise the host.
