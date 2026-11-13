/**
 * Deterministic Test Suite for lh-audit-report-gen.
 *
 * Covers 85+ rigorous assertions across SARIF ingestion, deduplication,
 * compliance crosswalks, native PDF 1.4 compilation, Markdown generation,
 * 10-rule posture auditor, and CLI subprocess execution.
 */

import * as assert from 'assert';
import * as child_process from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import {
  buildStatementOfApplicability,
  CERT_IN_MANDATES,
  DPDP_OBLIGATIONS,
  ISO_27001_CONTROLS,
} from '../dist/compliance_mapper';
import {
  formatAuditJson,
  formatAuditSarif,
  formatAuditTable,
  formatSoaJson,
  formatSoaTable,
} from '../dist/exporters';
import {
  buildHtmlReport,
  buildMarkdownReport,
  compileAuditPdf,
  escapePdfString,
} from '../dist/pdf_markdown_builder';
import { AUDIT_RULES, evaluateAuditPolicy } from '../dist/report_auditor';
import {
  computeFleetPostureMetrics,
  deduplicateAndNormalize,
  getRemediationSlaHours,
  getSeverityWeight,
  isCertInReportable,
  normalizeSeverity,
  parseRawFindings,
  redactPiiAndSecrets,
} from '../dist/sarif_ingestor';
import { AuditPolicyInput, AuditReportData, RawFinding } from '../dist/types';

let assertionCount = 0;

function check(condition: boolean, msg: string): void {
  assertionCount++;
  assert.ok(condition, `Assertion #${assertionCount} failed: ${msg}`);
}

function runAllTests(): void {
  console.log('>>> Running lh-audit-report-gen Test Suite...\n');

  // =========================================================================
  // GROUP 1: SARIF Ingestor, Deduplication, Redaction & SLA Math
  // =========================================================================
  console.log('[Test Group 1] Ingestor, Deduplication & Redaction Math');

  // 1. Severity normalization
  check(normalizeSeverity('CRITICAL') === 'CRITICAL', 'Normalize CRITICAL');
  check(normalizeSeverity('error') === 'HIGH', 'Normalize error to HIGH');
  check(normalizeSeverity('warning') === 'MEDIUM', 'Normalize warning to MEDIUM');
  check(normalizeSeverity('note') === 'LOW', 'Normalize note to LOW');
  check(normalizeSeverity('info') === 'INFO', 'Normalize info to INFO');
  check(normalizeSeverity(undefined) === 'LOW', 'Default undefined severity to LOW');

  // 2. Weights and SLAs
  check(getSeverityWeight('CRITICAL') === 25, 'CRITICAL weight is 25');
  check(getSeverityWeight('HIGH') === 10, 'HIGH weight is 10');
  check(getSeverityWeight('MEDIUM') === 4, 'MEDIUM weight is 4');
  check(getSeverityWeight('LOW') === 1, 'LOW weight is 1');
  check(getSeverityWeight('INFO') === 0, 'INFO weight is 0');

  check(getRemediationSlaHours('CRITICAL') === 24, 'CRITICAL SLA is 24 hours');
  check(getRemediationSlaHours('HIGH') === 168, 'HIGH SLA is 7 days (168 hours)');
  check(getRemediationSlaHours('MEDIUM') === 720, 'MEDIUM SLA is 30 days (720 hours)');
  check(getRemediationSlaHours('LOW') === 2160, 'LOW SLA is 90 days (2160 hours)');
  check(getRemediationSlaHours('INFO') === 0, 'INFO SLA is 0 hours');

  // 3. CERT-In 6-Hour reporting trigger check
  check(isCertInReportable('CRITICAL', 'CWE-89'), 'CRITICAL is CERT-In reportable');
  check(isCertInReportable('HIGH', 'CWE-284'), 'CWE-284 is CERT-In reportable');
  check(isCertInReportable('HIGH', 'CWE-502'), 'CWE-502 is CERT-In reportable');
  check(isCertInReportable('HIGH', 'CWE-312'), 'CWE-312 is CERT-In reportable');
  check(!isCertInReportable('LOW', 'CWE-125'), 'LOW CWE-125 is not reportable');

  // 4. Secret & PII Redaction
  const secret1 = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz';
  const red1 = redactPiiAndSecrets(secret1);
  check(red1.includes('[REDACTED_AUTH_TOKEN]'), 'Redact Bearer auth token');
  check(!red1.includes('eyJhbGciOi'), 'Stripped raw JWT payload');

  const secret2 = 'aws_key = "AKIAIOSFODNN7EXAMPLE"';
  const red2 = redactPiiAndSecrets(secret2);
  check(red2.includes('AKIA[REDACTED_AWS_KEY]'), 'Redact AWS access key ID');

  const secret3 = 'db_password = "SuperSecretPassword123!"';
  const red3 = redactPiiAndSecrets(secret3);
  check(red3.includes('[REDACTED_SECRET]'), 'Redact password assignment');

  const secret4 = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
  const red4 = redactPiiAndSecrets(secret4);
  check(red4.includes('[REDACTED_PRIVATE_KEY_BLOCK]'), 'Redact private key block');

  // 5. Raw findings parsing & deduplication
  const sampleFixturePath = path.join(__dirname, '..', 'fixtures', 'sample_multi_tool_findings.json');
  const sampleRaw = JSON.parse(fs.readFileSync(sampleFixturePath, 'utf8'));
  const rawList = parseRawFindings(sampleRaw);
  check(rawList.length === 8, `Parsed 8 raw findings from fixture (got ${rawList.length})`);

  const { findings, rawCount } = deduplicateAndNormalize(rawList, true);
  check(rawCount === 8, 'Recorded raw count is 8');
  check(findings.length === 7, `Deduplicated to 7 unique findings (got ${findings.length})`);

  // Verify sort order: CRITICAL first, then HIGH, then MEDIUM, then LOW
  check(findings[0].severity === 'CRITICAL', 'First finding is CRITICAL');
  check(findings[1].severity === 'CRITICAL', 'Second finding is CRITICAL');
  check(findings[2].severity === 'HIGH', 'Third finding is HIGH');

  // Verify fleet metrics
  const metrics = computeFleetPostureMetrics(findings, rawCount, 85.0);
  check(metrics.rawFindingsCount === 8, 'Metrics raw count is 8');
  check(metrics.deduplicatedCount === 7, 'Metrics deduplicated count is 7');
  check(metrics.criticalCount === 2, 'Metrics critical count is 2');
  check(metrics.highCount === 2, 'Metrics high count is 2');
  check(metrics.mediumCount === 2, 'Metrics medium count is 2');
  check(metrics.lowCount === 1, 'Metrics low count is 1');
  check(metrics.toolsAudited.length === 3, 'Metrics audited tools count is 3');
  check(metrics.toolsAudited.includes('lh-web-audit'), 'Tools include lh-web-audit');
  check(metrics.toolsAudited.includes('lh-secret-scanner'), 'Tools include lh-secret-scanner');
  check(metrics.toolsAudited.includes('lh-static-analyser'), 'Tools include lh-static-analyser');
  check(metrics.fleetPostureScore > 0 && metrics.fleetPostureScore <= 100, 'Fleet score within [0, 100]');
  check(metrics.evidenceManifestSha256.length === 64, 'SHA-256 evidence manifest is 64 hex chars');

  // =========================================================================
  // GROUP 2: ISO/IEC 27001:2022 Annex A & CERT-In Compliance Crosswalk
  // =========================================================================
  console.log('[Test Group 2] ISO 27001 & CERT-In Compliance Crosswalk');

  const soa = buildStatementOfApplicability(findings);
  check(soa.totalControls === ISO_27001_CONTROLS.length + CERT_IN_MANDATES.length, 'Total controls match catalogue sum');
  check(soa.isoControls.length === ISO_27001_CONTROLS.length, `ISO controls length matches definition (${ISO_27001_CONTROLS.length})`);
  check(soa.certInClauses.length === CERT_IN_MANDATES.length, `CERT-In clauses length matches definition (${CERT_IN_MANDATES.length})`);
  check(soa.dpdpClauses.length === DPDP_OBLIGATIONS.length, `DPDP clauses length matches definition (${DPDP_OBLIGATIONS.length})`);

  // Check specific ISO clause mappings
  const a515 = soa.isoControls.find((c) => c.clause === 'A.5.15');
  check(Boolean(a515), 'A.5.15 Access Control found');
  check(a515!.violationCount > 0, 'A.5.15 has active violations from CWE-284');
  check(a515!.status === 'NON_COMPLIANT', 'A.5.15 is NON_COMPLIANT due to CRITICAL BOLA finding');

  const a85 = soa.isoControls.find((c) => c.clause === 'A.8.5');
  check(Boolean(a85), 'A.8.5 Secure Authentication found');
  check(a85!.violationCount > 0, 'A.8.5 has active violations from CWE-798');

  const a87 = soa.isoControls.find((c) => c.clause === 'A.8.7');
  check(Boolean(a87), 'A.8.7 Protection Against Malware found');
  check(a87!.violationCount > 0, 'A.8.7 has active violations from CWE-502');

  const a815 = soa.isoControls.find((c) => c.clause === 'A.8.15');
  check(Boolean(a815), 'A.8.15 Logging found');
  check(a815!.violationCount > 0, 'A.8.15 has active violations from CWE-778');

  const a828 = soa.isoControls.find((c) => c.clause === 'A.8.28');
  check(Boolean(a828), 'A.8.28 Secure Coding found');
  check(a828!.violationCount > 0, 'A.8.28 has active violations from CWE-125');

  // Check CERT-In Directions mapping
  const dir01 = soa.certInClauses.find((m) => m.directiveId === 'CERT-IN-DIR-01');
  check(Boolean(dir01), 'CERT-IN-DIR-01 NTP Sync found');
  check(dir01!.incidentCount > 0, 'DIR-01 has violation from CWE-682');

  const dir02 = soa.certInClauses.find((m) => m.directiveId === 'CERT-IN-DIR-02');
  check(Boolean(dir02), 'CERT-IN-DIR-02 6-hr Incident Reporting found');
  check(dir02!.incidentCount > 0, 'DIR-02 has incidents triggered');
  check(dir02!.status === 'NON_COMPLIANT', 'DIR-02 is NON_COMPLIANT due to critical findings');

  const dir04 = soa.certInClauses.find((m) => m.directiveId === 'CERT-IN-DIR-04');
  check(Boolean(dir04), 'CERT-IN-DIR-04 180-Day Log Retention found');
  check(dir04!.incidentCount > 0, 'DIR-04 has triggers from CWE-778');

  // Check compliance pass ratio
  check(soa.complianceRatio >= 0 && soa.complianceRatio <= 100, 'Compliance ratio is percentage within [0, 100]');
  check(soa.passedControls + soa.failedControls === soa.totalControls, 'Passed + Failed equals Total Controls');

  // =========================================================================
  // GROUP 3: Native %PDF-1.4 Binary Compiler & Markdown/HTML Builder
  // =========================================================================
  console.log('[Test Group 3] Native %PDF-1.4 Compiler & Markdown/HTML Builder');

  // PDF string escaping
  const escaped = escapePdfString('Hello (World) \\ Test\nWith\tControl');
  check(escaped.includes('\\('), 'Escaped open parenthesis');
  check(escaped.includes('\\)'), 'Escaped close parenthesis');
  check(escaped.includes('\\\\'), 'Escaped backslash');
  check(!escaped.includes('\n'), 'Sanitized newline');
  check(!escaped.includes('\t'), 'Sanitized tab');

  // Audit Report Data Construction
  const auditData: AuditReportData = {
    reportId: 'LH-AUDIT-TEST-001',
    generatedAt: new Date().toISOString(),
    organization: 'Logihertz Systems Client Infrastructure',
    cin: 'U72100MH2025OPC463857',
    leadAuditor: 'Sameer Tawade <ops@logihertz.com>',
    tlp: 'TLP:AMBER',
    metrics,
    soa,
    findings,
    evidenceSignature: 'SEAL-VALIDATED-EVIDENCE-TEST',
  };

  // Compile Native %PDF-1.4 Binary Buffer
  const pdfBuffer = compileAuditPdf(auditData);
  check(Buffer.isBuffer(pdfBuffer), 'compileAuditPdf returns a Node.js Buffer');
  check(pdfBuffer.length > 1000, `PDF buffer has non-trivial length (${pdfBuffer.length} bytes)`);

  const pdfString = pdfBuffer.toString('latin1');
  check(pdfString.startsWith('%PDF-1.4'), 'PDF starts with %PDF-1.4 header');
  check(pdfString.includes('%\xE2\xE3\xCF\xD3'), 'PDF contains 8-bit binary transport marker');
  check(pdfString.includes('/Type /Catalog'), 'PDF contains /Catalog object');
  check(pdfString.includes('/Type /Pages'), 'PDF contains /Pages object');
  check(pdfString.includes('/Type /Page'), 'PDF contains /Page object');
  check(pdfString.includes('/Count 3'), 'PDF has multi-page count of 3');
  check(pdfString.includes('/BaseFont /Helvetica'), 'PDF contains standard Helvetica font');
  check(pdfString.includes('/BaseFont /Helvetica-Bold'), 'PDF contains Helvetica-Bold font');
  check(pdfString.includes('/BaseFont /Courier'), 'PDF contains Courier font');
  check(pdfString.includes('xref'), 'PDF contains xref cross-reference table');
  check(pdfString.includes('0000000000 65535 f'), 'PDF contains first free xref entry');
  check(pdfString.includes('trailer'), 'PDF contains trailer block');
  check(pdfString.includes('/Root 1 0 R'), 'PDF trailer references Root object 1');
  check(pdfString.includes('startxref'), 'PDF contains startxref pointer');
  check(pdfString.endsWith('%%EOF\n') || pdfString.endsWith('%%EOF'), 'PDF ends with %%EOF');

  // Verify that active JavaScript is strictly forbidden
  check(!pdfString.includes('/JS'), 'PDF does NOT contain /JS object');
  check(!pdfString.includes('/JavaScript'), 'PDF does NOT contain /JavaScript object');
  check(!pdfString.includes('/Launch'), 'PDF does NOT contain /Launch action');

  // Markdown Report Builder
  const mdReport = buildMarkdownReport(auditData);
  check(mdReport.includes('# ISO/IEC 27001:2022 & CERT-In'), 'Markdown title present');
  check(mdReport.includes('TLP:AMBER'), 'Markdown TLP banner present');
  check(mdReport.includes('U72100MH2025OPC463857'), 'Markdown CIN present');
  check(mdReport.includes('Sameer Tawade'), 'Markdown Lead Auditor present');
  check(mdReport.includes('Statement of Applicability'), 'Markdown SoA section present');
  check(mdReport.includes('CERT-In Cyber Security Directions'), 'Markdown CERT-In section present');
  check(mdReport.includes('India Digital Personal Data Protection (DPDP) Act 2023'), 'Markdown DPDP section present');
  check(mdReport.includes('Detailed Technical Security Findings'), 'Markdown findings table present');
  check(mdReport.includes('Evidence Snippets'), 'Markdown evidence snippets present');
  check(mdReport.includes(metrics.evidenceManifestSha256), 'Markdown SHA-256 evidence manifest present');

  // HTML Report Builder
  const htmlReport = buildHtmlReport(auditData);
  check(htmlReport.includes('<!DOCTYPE html>'), 'HTML doctype present');
  check(htmlReport.includes('<title>'), 'HTML title tag present');

  // =========================================================================
  // GROUP 4: 10-Rule Posture Auditor & Governance Scoring Math
  // =========================================================================
  console.log('[Test Group 4] 10-Rule Posture Auditor & Governance Scoring');

  check(AUDIT_RULES.length === 10, 'Audit rules catalogue contains exactly 10 rules');

  // 1. Hardened Policy Fixture
  const hardenedPath = path.join(__dirname, '..', 'fixtures', 'hardened_audit_policy.json');
  const hardenedPolicy: AuditPolicyInput = JSON.parse(fs.readFileSync(hardenedPath, 'utf8'));
  const hardenedReport = evaluateAuditPolicy(hardenedPolicy);

  check(hardenedReport.score === 100, `Hardened policy score is 100 (got ${hardenedReport.score})`);
  check(hardenedReport.totalDeductions === 0, 'Hardened policy deductions are 0');
  check(hardenedReport.passedRulesCount === 10, 'Hardened policy passed all 10 rules');
  check(hardenedReport.failedRulesCount === 0, 'Hardened policy failed 0 rules');
  check(hardenedReport.isCompliant, 'Hardened policy isCompliant is true');

  // 2. Vulnerable Policy Fixture
  const vulnerablePath = path.join(__dirname, '..', 'fixtures', 'vulnerable_audit_policy.json');
  const vulnerablePolicy: AuditPolicyInput = JSON.parse(fs.readFileSync(vulnerablePath, 'utf8'));
  const vulnerableReport = evaluateAuditPolicy(vulnerablePolicy);

  check(vulnerableReport.score === 0, `Vulnerable policy score is 0 (got ${vulnerableReport.score})`);
  check(vulnerableReport.totalDeductions === 124, `Vulnerable policy deductions are 124 (got ${vulnerableReport.totalDeductions})`);
  check(vulnerableReport.passedRulesCount === 0, 'Vulnerable policy passed 0 rules');
  check(vulnerableReport.failedRulesCount === 10, 'Vulnerable policy failed all 10 rules');
  check(!vulnerableReport.isCompliant, 'Vulnerable policy isCompliant is false');

  // 3. Isolated single-rule triggers
  // Rule 1: LH-RPT-001 (-25)
  const p1 = { ...hardenedPolicy, cryptographic_report_signature: false };
  const r1 = evaluateAuditPolicy(p1);
  check(r1.totalDeductions === 25, 'LH-RPT-001 deducts 25 pts');
  check(r1.score === 75, 'LH-RPT-001 yields score 75');

  // Rule 2: LH-RPT-002 (-25)
  const p2 = { ...hardenedPolicy, certin_6hr_incident_workflow: false };
  const r2 = evaluateAuditPolicy(p2);
  check(r2.totalDeductions === 25, 'LH-RPT-002 deducts 25 pts');
  check(r2.score === 75, 'LH-RPT-002 yields score 75');

  // Rule 3: LH-RPT-003 (-25)
  const p3 = { ...hardenedPolicy, redact_pii_and_secrets_in_evidence: false };
  const r3 = evaluateAuditPolicy(p3);
  check(r3.totalDeductions === 25, 'LH-RPT-003 deducts 25 pts');
  check(r3.score === 75, 'LH-RPT-003 yields score 75');

  // Rule 4: LH-RPT-004 (-10)
  const p4 = { ...hardenedPolicy, iso27001_soa_mapping_enabled: false };
  const r4 = evaluateAuditPolicy(p4);
  check(r4.totalDeductions === 10, 'LH-RPT-004 deducts 10 pts');
  check(r4.score === 90, 'LH-RPT-004 yields score 90');

  // Rule 5: LH-RPT-005 (-10)
  const p5 = { ...hardenedPolicy, ntp_npl_nic_sync_verified: false };
  const r5 = evaluateAuditPolicy(p5);
  check(r5.totalDeductions === 10, 'LH-RPT-005 deducts 10 pts');
  check(r5.score === 90, 'LH-RPT-005 yields score 90');

  // Rule 6: LH-RPT-006 (-10)
  const p6 = { ...hardenedPolicy, disallow_pdf_javascript_and_actions: false };
  const r6 = evaluateAuditPolicy(p6);
  check(r6.totalDeductions === 10, 'LH-RPT-006 deducts 10 pts');
  check(r6.score === 90, 'LH-RPT-006 yields score 90');

  // Rule 7: LH-RPT-007 (-10)
  const p7 = { ...hardenedPolicy, enforce_tlp_classification: false };
  const r7 = evaluateAuditPolicy(p7);
  check(r7.totalDeductions === 10, 'LH-RPT-007 deducts 10 pts');
  check(r7.score === 90, 'LH-RPT-007 yields score 90');

  // Rule 8: LH-RPT-008 (-4)
  const p8 = { ...hardenedPolicy, max_risk_exception_days: 120 };
  const r8 = evaluateAuditPolicy(p8);
  check(r8.totalDeductions === 4, 'LH-RPT-008 deducts 4 pts');
  check(r8.score === 96, 'LH-RPT-008 yields score 96');

  // Rule 9: LH-RPT-009 (-4)
  const p9 = { ...hardenedPolicy, sarif_fingerprint_deduplication: false };
  const r9 = evaluateAuditPolicy(p9);
  check(r9.totalDeductions === 4, 'LH-RPT-009 deducts 4 pts');
  check(r9.score === 96, 'LH-RPT-009 yields score 96');

  // Rule 10: LH-RPT-010 (-1)
  const p10 = { ...hardenedPolicy, require_auditor_signoff_metadata: false };
  const r10 = evaluateAuditPolicy(p10);
  check(r10.totalDeductions === 1, 'LH-RPT-010 deducts 1 pt');
  check(r10.score === 99, 'LH-RPT-010 yields score 99');

  // Multiple rules combined (Rule 1 + Rule 4 = -35)
  const pComb = {
    ...hardenedPolicy,
    cryptographic_report_signature: false,
    iso27001_soa_mapping_enabled: false,
  };
  const rComb = evaluateAuditPolicy(pComb);
  check(rComb.totalDeductions === 35, 'Combined deduction is 35 pts');
  check(rComb.score === 65, 'Combined score is 65');

  // =========================================================================
  // GROUP 5: Exporters (ANSI Table, Canonical JSON, OASIS SARIF v2.1.0)
  // =========================================================================
  console.log('[Test Group 5] Multi-Format Exporters');

  const tblStr = formatAuditTable(hardenedReport);
  check(tblStr.includes('LOGIHERTZ AUDIT GOVERNANCE'), 'Table exporter contains header');
  check(tblStr.includes('LH-RPT-001'), 'Table exporter contains rule IDs');
  check(tblStr.includes('100 / 100'), 'Table exporter displays score 100');

  const jsonStr = formatAuditJson(hardenedReport);
  const jsonParsed = JSON.parse(jsonStr);
  check(jsonParsed.score === 100, 'JSON exporter parses with score 100');
  check(Array.isArray(jsonParsed.evaluations), 'JSON exporter contains evaluations array');

  const sarifStr = formatAuditSarif(vulnerableReport);
  const sarifParsed = JSON.parse(sarifStr);
  check(sarifParsed.version === '2.1.0', 'SARIF version is 2.1.0');
  check(sarifParsed.runs[0].tool.driver.name === 'lh-report-gen', 'SARIF driver name is lh-report-gen');
  check(sarifParsed.runs[0].results.length === 10, 'SARIF results contains 10 failing rules');

  const soaTblStr = formatSoaTable(soa);
  check(soaTblStr.includes('STATEMENT OF APPLICABILITY'), 'SoA table contains title');
  check(soaTblStr.includes('A.5.15'), 'SoA table contains A.5.15');

  const soaJsonStr = formatSoaJson(soa);
  const soaJsonParsed = JSON.parse(soaJsonStr);
  check(soaJsonParsed.totalControls > 0, 'SoA JSON contains totalControls');

  // =========================================================================
  // GROUP 6: CLI Subprocesses & Exit Codes
  // =========================================================================
  console.log('[Test Group 6] CLI Subprocess Verification');

  const cliBin = path.join(__dirname, '..', 'bin', 'lh-report-gen');

  // 1. --help
  const helpRes = child_process.spawnSync(process.execPath, [cliBin, '--help'], { encoding: 'utf8' });
  check(helpRes.status === 0, 'CLI --help exits with 0');
  check(helpRes.stdout.includes('Logihertz Audit Report Generator'), 'CLI --help prints usage banner');

  // 2. --version
  const verRes = child_process.spawnSync(process.execPath, [cliBin, '--version'], { encoding: 'utf8' });
  check(verRes.status === 0, 'CLI --version exits with 0');
  check(verRes.stdout.includes('lh-report-gen 0.1.0'), 'CLI --version prints version 0.1.0');

  // 3. scan hardened policy -> exit 0
  const scanHard = child_process.spawnSync(process.execPath, [cliBin, 'scan', hardenedPath], { encoding: 'utf8' });
  check(scanHard.status === 0, 'CLI scan hardened policy exits with 0');
  check(scanHard.stdout.includes('COMPLIANT'), 'CLI scan hardened prints COMPLIANT');

  // 4. scan vulnerable policy -> exit 1
  const scanVuln = child_process.spawnSync(process.execPath, [cliBin, 'scan', vulnerablePath], { encoding: 'utf8' });
  check(scanVuln.status === 1, 'CLI scan vulnerable policy exits with 1');
  check(scanVuln.stdout.includes('NON-COMPLIANT'), 'CLI scan vulnerable prints NON-COMPLIANT');

  // 5. scan with --format json
  const scanJson = child_process.spawnSync(
    process.execPath,
    [cliBin, 'scan', hardenedPath, '--format', 'json'],
    { encoding: 'utf8' }
  );
  check(scanJson.status === 0, 'CLI scan --format json exits with 0');
  check(scanJson.stdout.includes('"score": 100'), 'CLI scan JSON prints score 100');

  // 6. scan with --format sarif
  const scanSarif = child_process.spawnSync(
    process.execPath,
    [cliBin, 'scan', hardenedPath, '--format', 'sarif'],
    { encoding: 'utf8' }
  );
  check(scanSarif.status === 0, 'CLI scan --format sarif exits with 0');
  check(scanSarif.stdout.includes('2.1.0'), 'CLI scan SARIF prints version 2.1.0');

  // 7. build-pdf
  const tmpPdf = path.join('/tmp', `test_audit_${Date.now()}.pdf`);
  const buildPdfRes = child_process.spawnSync(
    process.execPath,
    [cliBin, 'build-pdf', sampleFixturePath, '--output', tmpPdf, '--tlp', 'TLP:AMBER'],
    { encoding: 'utf8' }
  );
  check(buildPdfRes.status === 0, 'CLI build-pdf exits with 0');
  check(fs.existsSync(tmpPdf), 'Compiled PDF file exists on disk');
  const diskPdfBuf = fs.readFileSync(tmpPdf);
  check(diskPdfBuf.toString('latin1').startsWith('%PDF-1.4'), 'Disk PDF file starts with %PDF-1.4');
  try {
    fs.unlinkSync(tmpPdf);
  } catch {}

  // 8. build-md
  const tmpMd = path.join('/tmp', `test_audit_${Date.now()}.md`);
  const buildMdRes = child_process.spawnSync(
    process.execPath,
    [cliBin, 'build-md', sampleFixturePath, '--output', tmpMd, '--tlp', 'TLP:GREEN'],
    { encoding: 'utf8' }
  );
  check(buildMdRes.status === 0, 'CLI build-md exits with 0');
  check(fs.existsSync(tmpMd), 'Generated Markdown file exists on disk');
  const diskMdStr = fs.readFileSync(tmpMd, 'utf8');
  check(diskMdStr.includes('# ISO/IEC 27001:2022 & CERT-In'), 'Disk Markdown contains title');
  try {
    fs.unlinkSync(tmpMd);
  } catch {}

  // 9. map-controls
  const mapRes = child_process.spawnSync(
    process.execPath,
    [cliBin, 'map-controls', sampleFixturePath, '--format', 'table'],
    { encoding: 'utf8' }
  );
  check(mapRes.status === 0, 'CLI map-controls exits with 0');
  check(mapRes.stdout.includes('STATEMENT OF APPLICABILITY'), 'CLI map-controls prints table');

  // 10. invalid usage / missing file -> exit 2
  const errRes = child_process.spawnSync(process.execPath, [cliBin, 'scan', 'non_existent_file.json'], {
    encoding: 'utf8',
  });
  check(errRes.status === 2, 'CLI scan non-existent file exits with code 2');

  console.log(`\n========================================================================`);
  console.log(`>>> ALL TESTS PASSED: ${assertionCount} DETERMINISTIC ASSERTIONS VERIFIED!`);
  console.log(`========================================================================\n`);
}

runAllTests();
