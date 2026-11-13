# Security Policy

## Supported Versions

Logihertz Systems actively maintains and provides security updates for the following releases of `lh-audit-report-gen`:

| Version | Supported          | Security Maintenance Status |
|:-------:|:------------------:|:----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported Pre-release     |

## Threat Model & Audit Governance Security

`lh-audit-report-gen` aggregates security findings across multi-tool SARIF v2.1.0 runs, generates executive audit reports in native PDF 1.4 and Markdown, crosswalks technical vulnerabilities to ISO/IEC 27001:2022 Annex A and CERT-In directions, and audits organizational compliance posture.

The threat model addresses critical risk vectors in security reporting and evidence management:
1. **Document Stream & PDF Injection (CWE-74)**:
   - Malicious finding descriptions or tool outputs could attempt to inject PDF stream operators, raw PostScript directives, or embedded executable JavaScript (`/JS`, `/JavaScript`, `/Launch`).
   - `lh-audit-report-gen` strictly compiles native `%PDF-1.4` binary objects without third-party rendering engines, escapes all literal string delimiters (`\(` and `\)`), and forbids active scripting objects.
2. **Evidence Sanitization & Secret Redaction (CWE-532)**:
   - Vulnerability scanners frequently capture raw HTTP authorization headers, cloud API keys (`AKIA...`), database connection strings, or customer Personally Identifiable Information (PII) in proof-of-concept evidence snippets.
   - `lh-audit-report-gen` automatically applies regex-based redaction filters to mask sensitive tokens before embedding evidence in exported PDF or Markdown documents.
3. **Audit Report Tampering & Non-Repudiation (CWE-353)**:
   - Post-audit alterations of findings or compliance scores undermine regulatory reporting.
   - `lh-audit-report-gen` computes and embeds a deterministic cryptographic SHA-256 evidence manifest seal across all ingested findings, ensuring integrity verification.
4. **Statutory Incident Escalation**:
   - The engine identifies reportable cyber incidents requiring mandatory notification within **6 hours** under CERT-In Directions (April 2022) and safeguards personal data under the India Digital Personal Data Protection (DPDP) Act, 2023.

## Reporting a Vulnerability

If you discover a security vulnerability, evidence-redaction bypass, or document-injection flaw in `lh-audit-report-gen`:

1. **Email**: Send your disclosure to `ops@logihertz.com` and `security@logihertz.com` with the subject line `[SECURITY] lh-audit-report-gen Vulnerability Report`.
2. **Include**:
   - Technical description of the issue and affected components.
   - Minimal reproduction fixture (e.g. sample SARIF payload or audit policy).
   - Analysis of potential impact on report integrity or compliance determination.
3. **Timeline**:
   - Initial acknowledgement within 24 hours.
   - Vulnerability assessment and triage within 48 hours.
   - Security advisory and patch release within 7 business days for critical issues.

Please do not open public GitHub issues for security vulnerabilities.
