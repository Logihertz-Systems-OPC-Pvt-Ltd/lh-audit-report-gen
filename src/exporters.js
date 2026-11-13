"use strict";
/**
 * Multi-Format Exporters for lh-audit-report-gen.
 *
 * Supports ANSI Terminal Tables, Canonical JSON (RFC 8259), and OASIS SARIF v2.1.0.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatAuditTable = formatAuditTable;
exports.formatAuditJson = formatAuditJson;
exports.formatAuditSarif = formatAuditSarif;
exports.formatSoaTable = formatSoaTable;
exports.formatSoaJson = formatSoaJson;
/**
 * Formats the audit posture report as an ANSI colored terminal box table.
 */
function formatAuditTable(report) {
    let out = '';
    out += '========================================================================================================\n';
    out += '              LOGIHERTZ AUDIT GOVERNANCE & COMPLIANCE POSTURE REPORT (ISO 27001 / CERT-In)             \n';
    out += '========================================================================================================\n';
    out += ` Overall Score: ${report.score} / 100  |  Status: ${report.isCompliant ? '\x1b[32mCOMPLIANT\x1b[0m' : '\x1b[31mNON-COMPLIANT\x1b[0m'}  |  Deductions: -${report.totalDeductions}\n`;
    out += ` Rules Evaluated: ${report.evaluations.length}  |  Passed: \x1b[32m${report.passedRulesCount}\x1b[0m  |  Failed: \x1b[31m${report.failedRulesCount}\x1b[0m\n`;
    out += '--------------------------------------------------------------------------------------------------------\n';
    out += ' RULE ID    | SEVERITY | DEDUCT | STATUS  | DETAILS                                                     \n';
    out += '--------------------------------------------------------------------------------------------------------\n';
    for (const ev of report.evaluations) {
        const statusStr = ev.passed ? '\x1b[32mPASS\x1b[0m   ' : '\x1b[31mFAIL\x1b[0m   ';
        let sevStr = '\x1b[37mLOW     \x1b[0m';
        if (ev.rule.severity === 'CRITICAL')
            sevStr = '\x1b[31mCRITICAL\x1b[0m';
        else if (ev.rule.severity === 'HIGH')
            sevStr = '\x1b[33mHIGH    \x1b[0m';
        else if (ev.rule.severity === 'MEDIUM')
            sevStr = '\x1b[36mMEDIUM  \x1b[0m';
        const ruleIdPadded = ev.rule.id.padEnd(10);
        const deductPadded = String(ev.deduction).padStart(6);
        const obsTruncated = ev.observed.padEnd(58).substring(0, 58);
        out += ` ${ruleIdPadded} | ${sevStr} | ${deductPadded} | ${statusStr} | ${obsTruncated}\n`;
    }
    out += '========================================================================================================\n';
    return out;
}
/**
 * Formats the audit posture report as canonical JSON.
 */
function formatAuditJson(report) {
    return JSON.stringify({
        score: report.score,
        total_deductions: report.totalDeductions,
        passed_rules_count: report.passedRulesCount,
        failed_rules_count: report.failedRulesCount,
        is_compliant: report.isCompliant,
        evaluations: report.evaluations.map((ev) => ({
            rule: {
                id: ev.rule.id,
                title: ev.rule.title,
                severity: ev.rule.severity,
                weight: ev.rule.weight,
                cwe: ev.rule.cwe,
                description: ev.rule.description,
                remediation: ev.rule.remediation,
            },
            passed: ev.passed,
            deduction: ev.deduction,
            observed: ev.observed,
        })),
    }, null, 2);
}
/**
 * Formats the audit posture report as OASIS SARIF v2.1.0 for CI/CD ingestion.
 */
function formatAuditSarif(report) {
    const rulesSarif = report.evaluations.map((ev) => ({
        id: ev.rule.id,
        name: ev.rule.title,
        shortDescription: { text: ev.rule.title },
        fullDescription: { text: ev.rule.description },
        help: { text: `Remediation: ${ev.rule.remediation}\nCWE: ${ev.rule.cwe}` },
        properties: {
            tags: ['compliance', 'audit', ev.rule.cwe],
            precision: 'very-high',
        },
    }));
    const resultsSarif = report.evaluations
        .filter((ev) => !ev.passed)
        .map((ev) => {
        const level = ev.rule.severity === 'CRITICAL' || ev.rule.severity === 'HIGH'
            ? 'error'
            : ev.rule.severity === 'MEDIUM'
                ? 'warning'
                : 'note';
        return {
            ruleId: ev.rule.id,
            level,
            message: {
                text: `${ev.rule.title}: ${ev.rule.description}. Observed: ${ev.observed}`,
            },
            locations: [
                {
                    physicalLocation: {
                        artifactLocation: { uri: 'governance/audit_policy.json' },
                    },
                },
            ],
        };
    });
    const sarif = {
        version: '2.1.0',
        $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'lh-report-gen',
                        version: '0.1.0',
                        informationUri: 'https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-audit-report-gen',
                        rules: rulesSarif,
                    },
                },
                results: resultsSarif,
            },
        ],
    };
    return JSON.stringify(sarif, null, 2);
}
/**
 * Formats Statement of Applicability as an ANSI terminal table.
 */
function formatSoaTable(soa) {
    let out = '';
    out += '========================================================================================================\n';
    out += '              STATEMENT OF APPLICABILITY & CERT-In COMPLIANCE MAPPING MATRIX                            \n';
    out += '========================================================================================================\n';
    out += ` Control Pass Ratio: ${soa.complianceRatio}%  |  Passed: ${soa.passedControls}  |  Failed: ${soa.failedControls}  |  Total: ${soa.totalControls}\n`;
    out += '--------------------------------------------------------------------------------------------------------\n';
    out += ' CONTROL ID      | TITLE                           | STATUS         | VIOLATIONS | FRAMEWORK            \n';
    out += '--------------------------------------------------------------------------------------------------------\n';
    for (const c of soa.isoControls) {
        const statusStr = c.status === 'COMPLIANT'
            ? '\x1b[32mCOMPLIANT    \x1b[0m'
            : c.status === 'PARTIAL'
                ? '\x1b[33mPARTIAL      \x1b[0m'
                : '\x1b[31mNON_COMPLIANT\x1b[0m';
        out += ` ${c.clause.padEnd(15)} | ${c.title.padEnd(31).substring(0, 31)} | ${statusStr} | ${String(c.violationCount).padStart(10)} | ISO 27001 Annex A    \n`;
    }
    for (const m of soa.certInClauses) {
        const statusStr = m.status === 'COMPLIANT'
            ? '\x1b[32mCOMPLIANT    \x1b[0m'
            : '\x1b[31mNON_COMPLIANT\x1b[0m';
        out += ` ${m.directiveId.padEnd(15)} | ${m.title.padEnd(31).substring(0, 31)} | ${statusStr} | ${String(m.incidentCount).padStart(10)} | CERT-In Directions   \n`;
    }
    for (const d of soa.dpdpClauses) {
        const statusStr = d.status === 'COMPLIANT'
            ? '\x1b[32mCOMPLIANT    \x1b[0m'
            : '\x1b[31mNON_COMPLIANT\x1b[0m';
        out += ` ${d.section.padEnd(15)} | ${d.title.padEnd(31).substring(0, 31)} | ${statusStr} |          0 | India DPDP Act 2023  \n`;
    }
    out += '========================================================================================================\n';
    return out;
}
/**
 * Formats Statement of Applicability as JSON.
 */
function formatSoaJson(soa) {
    return JSON.stringify(soa, null, 2);
}
