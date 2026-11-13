"use strict";
/**
 * 10-Rule Audit Governance & Compliance Posture Auditor (LH-RPT-001..010).
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUDIT_RULES = void 0;
exports.evaluateAuditPolicy = evaluateAuditPolicy;
exports.AUDIT_RULES = [
    {
        id: 'LH-RPT-001',
        title: 'Cryptographic Evidence Manifest Seal Required',
        severity: 'CRITICAL',
        weight: 25,
        cwe: 'CWE-353',
        description: 'Audit report cryptographic SHA-256 evidence seal disabled, permitting post-audit evidence tampering.',
        remediation: 'Enable cryptographic_report_signature and embed_sha256_evidence_manifest in audit configuration.',
    },
    {
        id: 'LH-RPT-002',
        title: 'CERT-In 6-Hour Reporting Workflow & 180-Day ICT Log Retention',
        severity: 'CRITICAL',
        weight: 25,
        cwe: 'CWE-778',
        description: 'Mandatory CERT-In 6-hour incident reporting workflow or 180-day Indian jurisdiction ICT log retention verification disabled.',
        remediation: 'Configure certin_6hr_incident_workflow and verify certin_180d_log_retention_verified under April 2022 Directions.',
    },
    {
        id: 'LH-RPT-003',
        title: 'Automated PII & Secret Redaction in Evidence Snippets',
        severity: 'CRITICAL',
        weight: 25,
        cwe: 'CWE-532',
        description: 'Unredacted cleartext secrets, API keys, or raw customer PII present in exported audit evidence.',
        remediation: 'Enable redact_pii_and_secrets_in_evidence to filter high-entropy credentials, tokens, and PII.',
    },
    {
        id: 'LH-RPT-004',
        title: 'ISO/IEC 27001:2022 Annex A SoA & CWE Crosswalk Enforced',
        severity: 'HIGH',
        weight: 10,
        cwe: 'CWE-693',
        description: 'Missing ISO/IEC 27001:2022 Annex A Statement of Applicability (SoA) mapping or CWE crosswalk.',
        remediation: 'Enable iso27001_soa_mapping_enabled and cwe_crosswalk_enabled for formal compliance tracing.',
    },
    {
        id: 'LH-RPT-005',
        title: 'CERT-In NPL/NIC Stratum-1 NTP Clock Sync & UTC Timestamps',
        severity: 'HIGH',
        weight: 10,
        cwe: 'CWE-682',
        description: 'Missing CERT-In NPL/NIC Stratum-1 NTP clock synchronization verification or non-UTC audit timestamps.',
        remediation: 'Synchronize ICT clocks to NPL or NIC NTP servers and enforce ISO 8601 UTC timestamps.',
    },
    {
        id: 'LH-RPT-006',
        title: 'Disallow Active PDF JavaScript & Sanitize Stream Characters',
        severity: 'HIGH',
        weight: 10,
        cwe: 'CWE-74',
        description: 'Unescaped PDF content stream operators, active PDF JavaScript (/JS), or unsanitized strings in report generator.',
        remediation: 'Enforce disallow_pdf_javascript_and_actions and sanitize_report_strings to prevent document injection.',
    },
    {
        id: 'LH-RPT-007',
        title: 'Traffic Light Protocol (TLP) Classification & Distribution Guard',
        severity: 'HIGH',
        weight: 10,
        cwe: 'CWE-284',
        description: 'Missing Traffic Light Protocol (TLP:RED/AMBER/GREEN/CLEAR) classification markings or unencrypted confidential distribution.',
        remediation: 'Enforce enforce_tlp_classification and encrypt_confidential_distribution for sensitive audit reports.',
    },
    {
        id: 'LH-RPT-008',
        title: 'Remediation SLA Deadlines & Risk Acceptance Limits Enforced',
        severity: 'MEDIUM',
        weight: 4,
        cwe: 'CWE-693',
        description: 'Missing severity-based remediation SLA deadlines or excessive risk-acceptance expiration (> 90 days).',
        remediation: 'Enable enforce_remediation_sla_deadlines and cap max_risk_exception_days to <= 90 days.',
    },
    {
        id: 'LH-RPT-009',
        title: 'SARIF Finding Fingerprint Deduplication Across Scanners',
        severity: 'MEDIUM',
        weight: 4,
        cwe: 'CWE-20',
        description: 'Duplicate finding inflation across multi-tool SARIF ingestion distorting true risk posture.',
        remediation: 'Enable sarif_fingerprint_deduplication to merge duplicate issues by tool, rule ID, URI, and line.',
    },
    {
        id: 'LH-RPT-010',
        title: 'Lead Auditor Sign-off Metadata & WORM Archive Retention',
        severity: 'LOW',
        weight: 1,
        cwe: 'CWE-778',
        description: 'Missing Lead Auditor sign-off block or immutable WORM archive retention under 3 years.',
        remediation: 'Require require_auditor_signoff_metadata and set archive_worm_retention_years to >= 3 years.',
    },
];
/**
 * Evaluates an audit policy against the 10 normative governance rules.
 */
function evaluateAuditPolicy(policy) {
    const evaluations = [];
    let totalDeductions = 0;
    for (const rule of exports.AUDIT_RULES) {
        let passed = false;
        let observed = '';
        switch (rule.id) {
            case 'LH-RPT-001':
                passed =
                    Boolean(policy.cryptographic_report_signature) &&
                        Boolean(policy.embed_sha256_evidence_manifest);
                observed = `sig=${policy.cryptographic_report_signature}, sha256_manifest=${policy.embed_sha256_evidence_manifest}`;
                break;
            case 'LH-RPT-002':
                passed =
                    Boolean(policy.certin_6hr_incident_workflow) &&
                        Boolean(policy.certin_180d_log_retention_verified);
                observed = `certin_6hr=${policy.certin_6hr_incident_workflow}, 180d_logs=${policy.certin_180d_log_retention_verified}`;
                break;
            case 'LH-RPT-003':
                passed = Boolean(policy.redact_pii_and_secrets_in_evidence);
                observed = `redact_secrets=${policy.redact_pii_and_secrets_in_evidence}`;
                break;
            case 'LH-RPT-004':
                passed =
                    Boolean(policy.iso27001_soa_mapping_enabled) && Boolean(policy.cwe_crosswalk_enabled);
                observed = `iso_soa=${policy.iso27001_soa_mapping_enabled}, cwe_crosswalk=${policy.cwe_crosswalk_enabled}`;
                break;
            case 'LH-RPT-005':
                passed =
                    Boolean(policy.ntp_npl_nic_sync_verified) &&
                        Boolean(policy.utc_iso8601_timestamps_enforced);
                observed = `ntp_npl_nic=${policy.ntp_npl_nic_sync_verified}, utc_timestamps=${policy.utc_iso8601_timestamps_enforced}`;
                break;
            case 'LH-RPT-006':
                passed =
                    Boolean(policy.disallow_pdf_javascript_and_actions) &&
                        Boolean(policy.sanitize_report_strings);
                observed = `disallow_pdf_js=${policy.disallow_pdf_javascript_and_actions}, sanitize_strings=${policy.sanitize_report_strings}`;
                break;
            case 'LH-RPT-007':
                passed =
                    Boolean(policy.enforce_tlp_classification) &&
                        Boolean(policy.encrypt_confidential_distribution);
                observed = `tlp_enforced=${policy.enforce_tlp_classification}, encrypt_dist=${policy.encrypt_confidential_distribution}`;
                break;
            case 'LH-RPT-008':
                passed =
                    Boolean(policy.enforce_remediation_sla_deadlines) &&
                        Number(policy.max_risk_exception_days || 0) <= 90;
                observed = `sla_enforced=${policy.enforce_remediation_sla_deadlines}, max_risk_days=${policy.max_risk_exception_days}`;
                break;
            case 'LH-RPT-009':
                passed = Boolean(policy.sarif_fingerprint_deduplication);
                observed = `sarif_dedup=${policy.sarif_fingerprint_deduplication}`;
                break;
            case 'LH-RPT-010':
                passed =
                    Boolean(policy.require_auditor_signoff_metadata) &&
                        Number(policy.archive_worm_retention_years || 0) >= 3;
                observed = `auditor_signoff=${policy.require_auditor_signoff_metadata}, worm_retention_years=${policy.archive_worm_retention_years}`;
                break;
            default:
                passed = false;
                observed = 'unknown rule';
        }
        const deduction = passed ? 0 : rule.weight;
        totalDeductions += deduction;
        evaluations.push({
            rule,
            passed,
            deduction,
            observed,
        });
    }
    const score = Math.max(0, 100 - totalDeductions);
    const passedRulesCount = evaluations.filter((e) => e.passed).length;
    const failedRulesCount = evaluations.length - passedRulesCount;
    const isCompliant = score === 100 && failedRulesCount === 0;
    return {
        score,
        totalDeductions,
        passedRulesCount,
        failedRulesCount,
        isCompliant,
        evaluations,
    };
}
