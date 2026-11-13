# Changelog

All notable changes to `lh-audit-report-gen` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-13

### Added
- **Multi-Tool SARIF v2.1.0 & JSON Ingestion Engine**:
  - Deterministic SHA-256 finding fingerprint deduplication across multi-tool scans.
  - Severity taxonomy normalization (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Automated regex-based secret and PII redaction (`Bearer`, `AKIA`, passwords, private keys).
  - Remediation SLA calculation (`24h`, `7d`, `30d`, `90d`) and CERT-In 6-hour incident flagging.
  - Fleet security posture score ($S_{\text{fleet}}$) and ISO control compliance pass ratio calculation.
- **ISO/IEC 27001:2022 & CERT-In Compliance Crosswalk**:
  - CWE mappings to ISO/IEC 27001:2022 Annex A controls (`A.5.15`, `A.8.5`, `A.8.7`, `A.8.8`, `A.8.15`, `A.8.20`, `A.8.24`, `A.8.28`).
  - CERT-In Directions (April 2022) compliance checks (`CERT-IN-DIR-01` NTP sync, `CERT-IN-DIR-02` 6-hr incident reporting, `CERT-IN-DIR-04` 180-day log retention).
  - India Digital Personal Data Protection (DPDP) Act 2023 Section 8(5) safeguard verification.
  - Automated Statement of Applicability (SoA) matrix generation.
- **Zero-Dependency Native `%PDF-1.4` Binary Compiler**:
  - Self-contained ISO 32000-1 binary buffer generation with `/Catalog`, `/Pages`, `/Page`, Type 1 standard fonts (`/Helvetica`, `/Helvetica-Bold`, `/Courier`), text stream operators, and strict string escaping.
  - Byte-accurate 10-digit zero-padded `xref` cross-reference table and trailer generation.
  - Executive report rendering with TLP classification banners, scorecards, SoA tables, finding breakdowns, and cryptographic SHA-256 evidence seals.
- **Executive Markdown & HTML Builder**:
  - Publication-ready GitHub Flavored Markdown and print-optimized HTML executive summary and technical appendices.
- **10-Rule Audit Governance Posture Auditor**:
  - Normative rules `LH-RPT-001` through `LH-RPT-010` covering evidence sealing, CERT-In compliance, secret redaction, ISO SoA mapping, NTP synchronization, PDF sanitization, TLP markings, SLA enforcement, SARIF deduplication, and auditor sign-off.
  - Standardized 0--100 posture scoring with weighted severity deductions.
- **Multi-Format Exporters & CLI (`bin/lh-report-gen`)**:
  - Subcommands: `scan`, `build-pdf`, `build-md`, `map-controls`, `--version`, `--help`.
  - Exporters: ANSI Colored Terminal Table, Canonical RFC 8259 JSON, and OASIS SARIF v2.1.0.
