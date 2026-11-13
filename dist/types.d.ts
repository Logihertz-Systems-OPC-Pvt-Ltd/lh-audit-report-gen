/**
 * Core type definitions for lh-audit-report-gen.
 *
 * Covers OASIS SARIF v2.1.0 ingestion, ISO/IEC 27001:2022 Annex A,
 * CERT-In Directions, PDF 1.4 compiler objects, and Posture Auditor rules.
 */
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type TlpClassification = 'TLP:RED' | 'TLP:AMBER' | 'TLP:GREEN' | 'TLP:CLEAR';
export interface RawFinding {
    tool: string;
    ruleId: string;
    ruleTitle?: string;
    severity: SeverityLevel | string;
    cwe?: string;
    message: string;
    artifactUri: string;
    lineNumber?: number;
    snippet?: string;
    properties?: Record<string, unknown>;
}
export interface NormalizedFinding {
    id: string;
    fingerprint: string;
    tool: string;
    ruleId: string;
    ruleTitle: string;
    severity: SeverityLevel;
    weight: number;
    cwe: string;
    message: string;
    artifactUri: string;
    lineNumber: number;
    snippet: string;
    remediationSlaHours: number;
    certInReportable: boolean;
    mappedIsoControls: string[];
    mappedCertInDirections: string[];
}
export interface IsoControlMapping {
    clause: string;
    title: string;
    category: 'Organizational' | 'People' | 'Physical' | 'Technological';
    description: string;
    status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
    violationCount: number;
    associatedCwes: string[];
}
export interface CertInClauseMapping {
    directiveId: string;
    title: string;
    legalReference: string;
    mandateDescription: string;
    status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
    incidentCount: number;
    timelineHours?: number;
}
export interface DpdpMapping {
    section: string;
    title: string;
    obligation: string;
    status: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
    breachExposure: boolean;
}
export interface StatementOfApplicability {
    totalControls: number;
    passedControls: number;
    failedControls: number;
    complianceRatio: number;
    isoControls: IsoControlMapping[];
    certInClauses: CertInClauseMapping[];
    dpdpClauses: DpdpMapping[];
}
export interface FleetPostureMetrics {
    totalFindings: number;
    rawFindingsCount: number;
    deduplicatedCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    toolsAudited: string[];
    fleetPostureScore: number;
    controlPassRatio: number;
    certInReportableCount: number;
    evidenceManifestSha256: string;
}
export interface AuditReportData {
    reportId: string;
    generatedAt: string;
    organization: string;
    cin: string;
    leadAuditor: string;
    tlp: TlpClassification;
    metrics: FleetPostureMetrics;
    soa: StatementOfApplicability;
    findings: NormalizedFinding[];
    evidenceSignature: string;
}
export interface AuditPolicyInput {
    policy_name?: string;
    organization_name?: string;
    cryptographic_report_signature: boolean;
    embed_sha256_evidence_manifest: boolean;
    certin_6hr_incident_workflow: boolean;
    certin_180d_log_retention_verified: boolean;
    redact_pii_and_secrets_in_evidence: boolean;
    iso27001_soa_mapping_enabled: boolean;
    cwe_crosswalk_enabled: boolean;
    ntp_npl_nic_sync_verified: boolean;
    utc_iso8601_timestamps_enforced: boolean;
    disallow_pdf_javascript_and_actions: boolean;
    sanitize_report_strings: boolean;
    enforce_tlp_classification: boolean;
    encrypt_confidential_distribution: boolean;
    enforce_remediation_sla_deadlines: boolean;
    max_risk_exception_days: number;
    sarif_fingerprint_deduplication: boolean;
    require_auditor_signoff_metadata: boolean;
    archive_worm_retention_years: number;
}
export interface AuditRuleMeta {
    id: string;
    title: string;
    severity: SeverityLevel;
    weight: number;
    cwe: string;
    description: string;
    remediation: string;
}
export interface RuleEvaluation {
    rule: AuditRuleMeta;
    passed: boolean;
    deduction: number;
    observed: string;
}
export interface PostureAuditReport {
    score: number;
    totalDeductions: number;
    passedRulesCount: number;
    failedRulesCount: number;
    isCompliant: boolean;
    evaluations: RuleEvaluation[];
}
//# sourceMappingURL=types.d.ts.map