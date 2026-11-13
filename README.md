# lh-audit-report-gen (`lh-report-gen`)

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-audit-report-gen/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-audit-report-gen/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](package.json)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/typescript-strict-blue.svg)](tsconfig.json)
[![Dependencies](https://img.shields.io/badge/runtime%20dependencies-zero-brightgreen.svg)](package.json)
[![Node](https://img.shields.io/badge/node->=%2020.0.0-darkgreen.svg)](package.json)

> **Production-grade, zero-runtime-dependency TypeScript Automated ISO/IEC 27001:2022 & CERT-In PDF 1.4 & Markdown Security Audit Report Generator, Multi-SARIF v2.1.0 Aggregator, and 10-Rule Compliance Governance Posture Auditor.**

---

## Table of Contents

- [Overview & Problem Statement](#overview--problem-statement)
- [Architectural Principles & Zero-Dependency Mandate](#architectural-principles--zero-dependency-mandate)
- [Native %PDF-1.4 Binary Document Compiler](#native-pdf-14-binary-document-compiler)
- [Statutory Compliance Frameworks](#statutory-compliance-frameworks)
  - [1. ISO/IEC 27001:2022 Annex A Controls](#1-isoiec-270012022-annex-a-controls)
  - [2. CERT-In Cyber Security Directions (April 2022)](#2-cert-in-cyber-security-directions-april-2022)
  - [3. India Digital Personal Data Protection (DPDP) Act 2023](#3-india-digital-personal-data-protection-dpdp-act-2023)
- [Multi-SARIF Ingestion & Deduplication Math](#multi-sarif-ingestion--deduplication-math)
- [10-Rule Audit Governance Posture Auditor](#10-rule-audit-governance-posture-auditor)
- [CLI Reference & Subcommands](#cli-reference--subcommands)
  - [`scan`](#lh-report-gen-scan)
  - [`build-pdf`](#lh-report-gen-build-pdf)
  - [`build-md`](#lh-report-gen-build-md)
  - [`map-controls`](#lh-report-gen-map-controls)
- [Verification & Test Suite](#verification--test-suite)
- [License & Corporate Governance](#license--corporate-governance)

---

## Overview & Problem Statement

In enterprise, sovereign, and defense computing environments, automated vulnerability scanning across multiple software, firmware, and infrastructure layers creates fragmented findings. Engineering and compliance teams face four major audit bottlenecks:
1. **Finding Duplication & Inflation**: Multiple static analysis, software composition, and dynamic tools report the same underlying flaw, distorting executive risk metrics.
2. **Framework Fragmentation**: Raw CWE IDs must be mapped to formal compliance clauses across **ISO/IEC 27001:2022 Annex A**, the **Indian Computer Emergency Response Team (CERT-In) Cyber Security Directions** (under Section 70B of the IT Act, 2000), and the **India Digital Personal Data Protection (DPDP) Act, 2023**.
3. **Heavy External Document Engines**: Traditional PDF generators rely on massive headless browser dependencies (Chromium, Puppeteer) or complex native C++ bindings that introduce severe supply chain vulnerabilities.
4. **Audit Evidence Tampering & Leakage**: Reports often contain unredacted secrets (API keys, authorization tokens) and lack cryptographic proof of non-repudiation.

`lh-audit-report-gen` (`lh-report-gen`) solves these challenges by providing a 100% zero-runtime-dependency TypeScript engine that ingests OASIS SARIF v2.1.0 data, deduplicates findings using SHA-256 fingerprints, maps vulnerabilities to statutory frameworks, compiles byte-accurate native `%PDF-1.4` and Markdown reports, redacts credentials, and audits reporting governance against 10 normative rules.

---

## Architectural Principles & Zero-Dependency Mandate

`lh-audit-report-gen` is built under rigorous engineering constraints:

- **100% Zero External Runtime Dependencies**: `"dependencies": {}` in `package.json`. All document generation, binary serialization, cross-reference calculation, cryptography, and string escaping utilize native Node.js core modules (`fs`, `path`, `crypto`, `child_process`).
- **Strict TypeScript & CommonJS Output**: Developed in TypeScript 5.x under strict mode (`noImplicitAny`, `strictNullChecks`, `noUnusedLocals`) and compiled to clean CommonJS in `dist/`.
- **Statutory Incident Timelines**: Enforces the **CERT-In 6-Hour Mandatory Reporting Window** for critical security events and the **180-Day ICT Log Retention Mandate** within Indian jurisdiction.

---

## Native %PDF-1.4 Binary Document Compiler

The PDF generator implements the ISO 32000-1 / PDF 1.4 binary specification directly using Node.js `Buffer`:

```
+---------------------------------------------------------------------------------+
|                       NATIVE %PDF-1.4 DOCUMENT STRUCTURE                        |
|                                                                                 |
|  %PDF-1.4                                                                       |
|  %\xE2\xE3\xCF\xD3  (8-bit binary transport marker)                             |
|                                                                                 |
|  1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj                               |
|  2 0 obj << /Type /Pages /Kids [ 6 0 R 8 0 R 10 0 R ] /Count 3 >> endobj        |
|  3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj          |
|  4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj     |
|  5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj            |
|                                                                                 |
|  [Page 1: 6 0 obj] ---> [Content Stream 1: 7 0 obj] (Cover & Scorecard)        |
|  [Page 2: 8 0 obj] ---> [Content Stream 2: 9 0 obj] (ISO 27001 SoA & CERT-In)   |
|  [Page 3: 10 0 obj] --> [Content Stream 3: 11 0 obj] (Findings & Evidence Seal) |
|                                                                                 |
|  xref                                                                           |
|  0 12                                                                           |
|  0000000000 65535 f                                                             |
|  0000000015 00000 n  (Exact 10-digit zero-padded byte offsets)                  |
|  ...                                                                            |
|  trailer << /Size 12 /Root 1 0 R >>                                             |
|  startxref                                                                      |
|  <byte_offset>                                                                  |
|  %%EOF                                                                          |
+---------------------------------------------------------------------------------+
```

### Document Security Guarantees:
1. **Zero Active Scripting (CWE-74)**: Strictly omits `/JS`, `/JavaScript`, `/Launch`, or interactive form actions.
2. **Operator Escaping**: Escapes literal string delimiters `\(` and `\)`, backslashes `\\`, and strips non-printable ASCII characters.
3. **Byte-Accurate Cross-Reference Table**: Calculates exact object offsets to satisfy strict PDF viewers without repair warnings.

---

## Statutory Compliance Frameworks

### 1. ISO/IEC 27001:2022 Annex A Controls

| Clause | Control Title | Category | Mapped CWEs |
|:---|:---|:---:|:---|
| **A.5.15** | Access Control | Organizational | CWE-284, CWE-285, CWE-732, CWE-639 |
| **A.5.24** | Incident Management Planning | Organizational | CWE-778, CWE-779 |
| **A.8.5** | Secure Authentication | Technological | CWE-290, CWE-306, CWE-307, CWE-798 |
| **A.8.6** | Capacity Management | Technological | CWE-400, CWE-770 |
| **A.8.7** | Protection Against Malware | Technological | CWE-502, CWE-94, CWE-434 |
| **A.8.8** | Technical Vulnerability Management | Technological | CWE-682, CWE-693, CWE-1188, CWE-1300 |
| **A.8.9** | Configuration Management | Technological | CWE-16, CWE-1004 |
| **A.8.15** | Logging | Technological | CWE-778, CWE-532, CWE-117 |
| **A.8.16** | Monitoring Activities | Technological | CWE-778, CWE-353 |
| **A.8.20** | Networks Security | Technological | CWE-319, CWE-923, CWE-200 |
| **A.8.24** | Use of Cryptography | Technological | CWE-312, CWE-326, CWE-328, CWE-345 |
| **A.8.26** | Application Security Requirements | Technological | CWE-20, CWE-74, CWE-693 |
| **A.8.28** | Secure Coding | Technological | CWE-119, CWE-125, CWE-787, CWE-89 |

### 2. CERT-In Cyber Security Directions (April 2022)

- **`CERT-IN-DIR-01` (NTP Synchronization)**: Mandatory synchronization of all ICT system clocks to NTP servers of the National Physical Laboratory (NPL) or National Informatics Centre (NIC), with UTC ISO 8601 timestamps.
- **`CERT-IN-DIR-02` (6-Hour Incident Notification)**: Mandatory reporting of specified cyber incidents to CERT-In within **6 hours** of noticing or being brought to notice (Section 70B(6) of IT Act 2000).
- **`CERT-IN-DIR-04` (180-Day ICT Log Retention)**: Mandatory maintenance of all system logs securely within Indian jurisdiction for a rolling period of **180 days**.

### 3. India Digital Personal Data Protection (DPDP) Act 2023

- **`DPDP-SEC-8-5`**: Requirement for Data Fiduciaries to implement reasonable technical security safeguards to prevent personal data breaches.
- **`DPDP-SEC-8-6`**: Statutory duty to intimate the Data Protection Board of India and affected Data Principals in the event of a personal data breach.

---

## Multi-SARIF Ingestion & Deduplication Math

### Finding Fingerprint Deduplication
For each ingested finding $f$, a deterministic SHA-256 fingerprint is computed:

$$K_{\text{dedup}}(f) = \text{SHA-256}\left(\text{tool} \parallel \text{rule\_id} \parallel \text{artifact\_uri} \parallel \text{line\_number}\right)$$

Duplicate findings across repeated scans or overlapping scanners are collapsed into a single normalized record, preventing risk inflation.

### Fleet Security Posture Score ($S_{\text{fleet}}$)
Given deduplicated finding counts $(c_{\text{CRIT}}, c_{\text{HIGH}}, c_{\text{MED}}, c_{\text{LOW}})$ across $N_{\text{tools}}$ audited toolchains:

$$S_{\text{fleet}} = \max\left(0, \; 100 - \frac{25 \cdot c_{\text{CRIT}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MED}} + 1 \cdot c_{\text{LOW}}}{\max(1, N_{\text{tools}})}\right)$$

### Statement of Applicability Pass Ratio ($R_{\text{compliance}}$)

$$R_{\text{compliance}}(\%) = \frac{N_{\text{controls, passed}}}{N_{\text{controls, total}}} \times 100.0$$

### Remediation SLA Schedule
- **`CRITICAL`**: **24 Hours** (Immediate operational escalation)
- **`HIGH`**: **7 Days** (168 Hours)
- **`MEDIUM`**: **30 Days** (720 Hours)
- **`LOW`**: **90 Days** (2160 Hours)

---

## 10-Rule Audit Governance Posture Auditor

The engine audits audit policies and reporting configurations against 10 normative governance rules ($S_{\text{posture}} = \max\left(0, 100 - \sum \text{Deductions}\right)$):

| Rule ID | Severity | CWE | Weight | Failure Condition | Remediation |
|:---|:---:|:---:|:---:|:---|:---|
| **`LH-RPT-001`** | CRITICAL | CWE-353 | 25 | `!cryptographic_report_signature \|\| !embed_sha256_evidence_manifest` | Enable cryptographic evidence signing and SHA-256 manifest embedding |
| **`LH-RPT-002`** | CRITICAL | CWE-778 | 25 | `!certin_6hr_incident_workflow \|\| !certin_180d_log_retention_verified` | Configure CERT-In 6-hour reporting and verify 180-day Indian log retention |
| **`LH-RPT-003`** | CRITICAL | CWE-532 | 25 | `!redact_pii_and_secrets_in_evidence` | Enable automated credential, token, and customer PII regex redaction |
| **`LH-RPT-004`** | HIGH | CWE-693 | 10 | `!iso27001_soa_mapping_enabled \|\| !cwe_crosswalk_enabled` | Enable ISO 27001:2022 Annex A SoA matrix and CWE mapping crosswalk |
| **`LH-RPT-005`** | HIGH | CWE-682 | 10 | `!ntp_npl_nic_sync_verified \|\| !utc_iso8601_timestamps_enforced` | Verify Stratum-1 NPL/NIC NTP clock sync and enforce UTC timestamps |
| **`LH-RPT-006`** | HIGH | CWE-74 | 10 | `!disallow_pdf_javascript_and_actions \|\| !sanitize_report_strings` | Strictly forbid PDF `/JS` actions and sanitize string delimiter characters |
| **`LH-RPT-007`** | HIGH | CWE-284 | 10 | `!enforce_tlp_classification \|\| !encrypt_confidential_distribution` | Enforce Traffic Light Protocol (TLP) banners and encrypt distribution |
| **`LH-RPT-008`** | MEDIUM | CWE-693 | 4 | `!enforce_remediation_sla_deadlines \|\| max_risk_exception_days > 90` | Enforce severity-based remediation SLAs and cap risk exceptions at 90 days |
| **`LH-RPT-009`** | MEDIUM | CWE-20 | 4 | `!sarif_fingerprint_deduplication` | Enable SHA-256 finding fingerprint deduplication across toolchains |
| **`LH-RPT-010`** | LOW | CWE-778 | 1 | `!require_auditor_signoff_metadata \|\| archive_worm_retention_years < 3` | Require Lead Auditor sign-off metadata and ensure $\ge 3\text{ years}$ WORM retention |

---

## CLI Reference & Subcommands

### `lh-report-gen scan`

Audits an organizational audit policy JSON file against the 10 governance rules.

```bash
# ANSI Colored Terminal Table
lh-report-gen scan fixtures/hardened_audit_policy.json

# Machine-Readable JSON Output
lh-report-gen scan fixtures/hardened_audit_policy.json --format json

# OASIS SARIF v2.1.0 for CI/CD Integration
lh-report-gen scan fixtures/vulnerable_audit_policy.json --format sarif
```

### `lh-report-gen build-pdf`

Compiles a native ISO 32000-1 / PDF 1.4 binary report from multi-tool SARIF or JSON findings.

```bash
lh-report-gen build-pdf fixtures/sample_multi_tool_findings.json --output /tmp/audit_report.pdf --tlp TLP:AMBER
```

### `lh-report-gen build-md`

Generates an executive GitHub Flavored Markdown audit report.

```bash
lh-report-gen build-md fixtures/sample_multi_tool_findings.json --output /tmp/audit_report.md --tlp TLP:GREEN
```

### `lh-report-gen map-controls`

Crosswalks findings to ISO/IEC 27001:2022 Annex A, CERT-In Directions, and the DPDP Act 2023.

```bash
lh-report-gen map-controls fixtures/sample_multi_tool_findings.json --format table
```

---

## Verification & Test Suite

The test suite contains **170 deterministic assertions** verifying SARIF ingestion, secret redaction, ISO/CERT-In crosswalks, native PDF binary streams, the 10-rule posture auditor, and CLI subprocess exit codes:

```bash
# Compile and run test suite
npm test

# Direct build
npm run build
```

---

## License & Corporate Governance

`lh-audit-report-gen` is open-source software licensed under the **Apache License, Version 2.0**.

**Logihertz Systems (OPC) Private Limited**  
Corporate Identity Number (CIN): `U72100MH2025OPC463857`  
Authored by **Sameer Tawade** `<ops@logihertz.com>` / `<security@logihertz.com>`  
Website: [https://logihertz.com/](https://logihertz.com/)
