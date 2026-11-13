"use strict";
/**
 * Command-Line Interface router for lh-report-gen.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.printUsage = printUsage;
exports.main = main;
const fs = __importStar(require("fs"));
const compliance_mapper_1 = require("./compliance_mapper");
const exporters_1 = require("./exporters");
const pdf_markdown_builder_1 = require("./pdf_markdown_builder");
const report_auditor_1 = require("./report_auditor");
const sarif_ingestor_1 = require("./sarif_ingestor");
const VERSION = '0.1.0';
function printUsage() {
    console.log(`Logihertz Audit Report Generator (lh-report-gen) v${VERSION}`);
    console.log('Automated ISO/IEC 27001:2022 & CERT-In PDF 1.4 & Markdown Report Generator\n');
    console.log('USAGE:');
    console.log('    lh-report-gen <SUBCOMMAND> [OPTIONS]\n');
    console.log('SUBCOMMANDS:');
    console.log('    scan <policy.json> [--format table|json|sarif] [--output <file>]');
    console.log('        Audit reporting governance and compliance posture against 10 rules.\n');
    console.log('    build-pdf <findings.json> --output <report.pdf> [--tlp TLP:AMBER]');
    console.log('        Compile native %PDF-1.4 binary report from multi-tool SARIF/JSON.\n');
    console.log('    build-md <findings.json> [--output <report.md>] [--tlp TLP:AMBER]');
    console.log('        Generate executive Markdown security audit report.\n');
    console.log('    map-controls <findings.json> [--format table|json]');
    console.log('        Crosswalk findings to ISO 27001:2022 Annex A, CERT-In & DPDP Act 2023.\n');
    console.log('FLAGS:');
    console.log('    -h, --help       Print help information');
    console.log('    -V, --version    Print version information');
}
function main(args) {
    if (args.length === 0) {
        printUsage();
        process.exit(2);
    }
    const sub = args[0];
    if (sub === '-h' || sub === '--help') {
        printUsage();
        process.exit(0);
    }
    if (sub === '-V' || sub === '--version') {
        console.log(`lh-report-gen ${VERSION}`);
        process.exit(0);
    }
    if (sub === 'scan') {
        handleScan(args.slice(1));
        return;
    }
    if (sub === 'build-pdf') {
        handleBuildPdf(args.slice(1));
        return;
    }
    if (sub === 'build-md') {
        handleBuildMd(args.slice(1));
        return;
    }
    if (sub === 'map-controls') {
        handleMapControls(args.slice(1));
        return;
    }
    console.error(`Error: Unknown subcommand '${sub}'\n`);
    printUsage();
    process.exit(2);
}
function handleScan(args) {
    if (args.length === 0) {
        console.error('Error: scan requires path to policy JSON file.');
        console.error('Usage: lh-report-gen scan <policy.json> [--format table|json|sarif] [--output <file>]');
        process.exit(2);
    }
    const policyPath = args[0];
    let format = 'table';
    let outputPath = null;
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--format' && i + 1 < args.length) {
            format = args[i + 1];
            i++;
        }
        else if (args[i] === '--output' && i + 1 < args.length) {
            outputPath = args[i + 1];
            i++;
        }
    }
    if (!fs.existsSync(policyPath)) {
        console.error(`Error: Policy file not found: '${policyPath}'`);
        process.exit(2);
    }
    let policy;
    try {
        const raw = fs.readFileSync(policyPath, 'utf8');
        policy = JSON.parse(raw);
    }
    catch (err) {
        console.error(`Error parsing policy JSON: ${String(err)}`);
        process.exit(2);
    }
    const report = (0, report_auditor_1.evaluateAuditPolicy)(policy);
    let outputStr = '';
    if (format === 'json') {
        outputStr = (0, exporters_1.formatAuditJson)(report);
    }
    else if (format === 'sarif') {
        outputStr = (0, exporters_1.formatAuditSarif)(report);
    }
    else {
        outputStr = (0, exporters_1.formatAuditTable)(report);
    }
    if (outputPath) {
        try {
            fs.writeFileSync(outputPath, outputStr, 'utf8');
            console.log(`Report written to ${outputPath}`);
        }
        catch (err) {
            console.error(`Error writing output file: ${String(err)}`);
            process.exit(2);
        }
    }
    else {
        console.log(outputStr);
    }
    process.exit(report.isCompliant ? 0 : 1);
}
function prepareAuditData(findingsPath, tlp) {
    if (!fs.existsSync(findingsPath)) {
        console.error(`Error: Findings file not found: '${findingsPath}'`);
        process.exit(2);
    }
    let rawPayload;
    try {
        const content = fs.readFileSync(findingsPath, 'utf8');
        rawPayload = JSON.parse(content);
    }
    catch (err) {
        console.error(`Error parsing findings JSON: ${String(err)}`);
        process.exit(2);
    }
    const rawFindings = (0, sarif_ingestor_1.parseRawFindings)(rawPayload);
    const { findings, rawCount } = (0, sarif_ingestor_1.deduplicateAndNormalize)(rawFindings, true);
    const soa = (0, compliance_mapper_1.buildStatementOfApplicability)(findings);
    const metrics = (0, sarif_ingestor_1.computeFleetPostureMetrics)(findings, rawCount, soa.complianceRatio);
    const reportId = `LH-AUDIT-${Date.now().toString(36).toUpperCase()}`;
    const generatedAt = new Date().toISOString();
    return {
        reportId,
        generatedAt,
        organization: 'Logihertz Systems Client Infrastructure',
        cin: 'U72100MH2025OPC463857',
        leadAuditor: 'Sameer Tawade <ops@logihertz.com>',
        tlp,
        metrics,
        soa,
        findings,
        evidenceSignature: `SEAL-${metrics.evidenceManifestSha256.substring(0, 24).toUpperCase()}`,
    };
}
function handleBuildPdf(args) {
    if (args.length === 0) {
        console.error('Error: build-pdf requires path to findings JSON file.');
        console.error('Usage: lh-report-gen build-pdf <findings.json> --output <report.pdf> [--tlp TLP:AMBER]');
        process.exit(2);
    }
    const findingsPath = args[0];
    let outputPath = null;
    let tlp = 'TLP:AMBER';
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--output' && i + 1 < args.length) {
            outputPath = args[i + 1];
            i++;
        }
        else if (args[i] === '--tlp' && i + 1 < args.length) {
            const val = args[i + 1].toUpperCase();
            if (val === 'TLP:RED' || val === 'TLP:AMBER' || val === 'TLP:GREEN' || val === 'TLP:CLEAR') {
                tlp = val;
            }
            i++;
        }
    }
    if (!outputPath) {
        console.error('Error: --output <report.pdf> is required for build-pdf.');
        process.exit(2);
    }
    const auditData = prepareAuditData(findingsPath, tlp);
    const pdfBuffer = (0, pdf_markdown_builder_1.compileAuditPdf)(auditData);
    try {
        fs.writeFileSync(outputPath, pdfBuffer);
        console.log(`[OK] Successfully compiled native %PDF-1.4 audit report (${pdfBuffer.length} bytes) to ${outputPath}`);
        process.exit(0);
    }
    catch (err) {
        console.error(`Error writing PDF output: ${String(err)}`);
        process.exit(2);
    }
}
function handleBuildMd(args) {
    if (args.length === 0) {
        console.error('Error: build-md requires path to findings JSON file.');
        console.error('Usage: lh-report-gen build-md <findings.json> [--output <report.md>] [--tlp TLP:AMBER]');
        process.exit(2);
    }
    const findingsPath = args[0];
    let outputPath = null;
    let tlp = 'TLP:AMBER';
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--output' && i + 1 < args.length) {
            outputPath = args[i + 1];
            i++;
        }
        else if (args[i] === '--tlp' && i + 1 < args.length) {
            const val = args[i + 1].toUpperCase();
            if (val === 'TLP:RED' || val === 'TLP:AMBER' || val === 'TLP:GREEN' || val === 'TLP:CLEAR') {
                tlp = val;
            }
            i++;
        }
    }
    const auditData = prepareAuditData(findingsPath, tlp);
    const mdReport = (0, pdf_markdown_builder_1.buildMarkdownReport)(auditData);
    if (outputPath) {
        try {
            fs.writeFileSync(outputPath, mdReport, 'utf8');
            console.log(`[OK] Successfully generated Markdown audit report to ${outputPath}`);
            process.exit(0);
        }
        catch (err) {
            console.error(`Error writing Markdown output: ${String(err)}`);
            process.exit(2);
        }
    }
    else {
        console.log(mdReport);
        process.exit(0);
    }
}
function handleMapControls(args) {
    if (args.length === 0) {
        console.error('Error: map-controls requires path to findings JSON file.');
        console.error('Usage: lh-report-gen map-controls <findings.json> [--format table|json]');
        process.exit(2);
    }
    const findingsPath = args[0];
    let format = 'table';
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--format' && i + 1 < args.length) {
            format = args[i + 1];
            i++;
        }
    }
    const auditData = prepareAuditData(findingsPath, 'TLP:AMBER');
    if (format === 'json') {
        console.log((0, exporters_1.formatSoaJson)(auditData.soa));
    }
    else {
        console.log((0, exporters_1.formatSoaTable)(auditData.soa));
    }
    process.exit(0);
}
// Invoke main when run directly
if (require.main === module) {
    main(process.argv.slice(2));
}
//# sourceMappingURL=cli.js.map