"use strict";
/**
 * Multi-Tool SARIF v2.1.0 & JSON Finding Ingestor, Deduplicator & Fleet Posture Aggregator.
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
exports.redactPiiAndSecrets = redactPiiAndSecrets;
exports.normalizeSeverity = normalizeSeverity;
exports.getSeverityWeight = getSeverityWeight;
exports.getRemediationSlaHours = getRemediationSlaHours;
exports.isCertInReportable = isCertInReportable;
exports.parseRawFindings = parseRawFindings;
exports.deduplicateAndNormalize = deduplicateAndNormalize;
exports.computeFleetPostureMetrics = computeFleetPostureMetrics;
const crypto = __importStar(require("crypto"));
/**
 * Redacts secrets, private keys, authorization tokens, and PII in evidence snippets.
 */
function redactPiiAndSecrets(text) {
    if (!text)
        return '';
    return text
        // Bearer / Token authorization headers
        .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED_AUTH_TOKEN]')
        .replace(/Token\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Token [REDACTED_AUTH_TOKEN]')
        // AWS Access Key IDs
        .replace(/\bAKIA[0-9A-Z]{16}\b/g, 'AKIA[REDACTED_AWS_KEY]')
        // JWT Tokens
        .replace(/\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g, '[REDACTED_JWT_TOKEN]')
        // Password query/assignment parameters
        .replace(/(password|passwd|pwd|secret|api_key|apikey)\s*[:=]\s*['"]?[^\s'";&]+['"]?/gi, '$1=[REDACTED_SECRET]')
        // Private Key Blocks
        .replace(/-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]+PRIVATE KEY-----/gi, '[REDACTED_PRIVATE_KEY_BLOCK]')
        // Generic high-entropy hex secrets >= 32 chars
        .replace(/\b[0-9a-fA-F]{32,64}\b/g, (match) => match.length >= 32 ? '[REDACTED_HEX_KEY]' : match);
}
/**
 * Normalizes severity levels across various SARIF and scanner formats.
 */
function normalizeSeverity(sev) {
    if (!sev)
        return 'LOW';
    const s = sev.toUpperCase().trim();
    if (s === 'CRITICAL' || s === 'FATAL')
        return 'CRITICAL';
    if (s === 'HIGH' || s === 'ERROR')
        return 'HIGH';
    if (s === 'MEDIUM' || s === 'MODERATE' || s === 'WARNING')
        return 'MEDIUM';
    if (s === 'LOW' || s === 'NOTE')
        return 'LOW';
    return 'INFO';
}
/**
 * Returns severity deduction weight for fleet posture scoring.
 */
function getSeverityWeight(sev) {
    switch (sev) {
        case 'CRITICAL':
            return 25;
        case 'HIGH':
            return 10;
        case 'MEDIUM':
            return 4;
        case 'LOW':
            return 1;
        default:
            return 0;
    }
}
/**
 * Assigns statutory remediation SLA in hours.
 * CRITICAL: 24h, HIGH: 7d (168h), MEDIUM: 30d (720h), LOW: 90d (2160h).
 */
function getRemediationSlaHours(sev) {
    switch (sev) {
        case 'CRITICAL':
            return 24;
        case 'HIGH':
            return 168;
        case 'MEDIUM':
            return 720;
        case 'LOW':
            return 2160;
        default:
            return 0;
    }
}
/**
 * Determines whether a finding constitutes a mandatory 6-hour reportable cyber incident
 * under CERT-In Directions (April 2022) / Section 70B of IT Act 2000.
 */
function isCertInReportable(sev, cwe) {
    if (sev === 'CRITICAL')
        return true;
    const criticalCwes = ['CWE-284', 'CWE-290', 'CWE-306', 'CWE-312', 'CWE-319', 'CWE-502', 'CWE-353'];
    return criticalCwes.includes(cwe.toUpperCase().trim());
}
/**
 * Ingests and extracts findings from raw SARIF v2.1.0 or JSON payload.
 */
function parseRawFindings(payload) {
    const findings = [];
    if (!payload || typeof payload !== 'object')
        return findings;
    const obj = payload;
    // Case 1: Standard OASIS SARIF v2.1.0 structure
    if (Array.isArray(obj.runs)) {
        for (const run of obj.runs) {
            if (typeof run !== 'object' || !run)
                continue;
            const toolName = run.tool?.driver?.name || 'unknown-tool';
            if (!Array.isArray(run.results))
                continue;
            for (const res of run.results) {
                if (typeof res !== 'object' || !res)
                    continue;
                const ruleId = res.ruleId || 'GEN-000';
                const ruleTitle = res.message?.text || ruleId;
                const rawLevel = res.level || 'warning';
                const cwe = res.properties?.cwe || res.properties?.tags?.[0] || 'CWE-693';
                let uri = 'source/codebase';
                let line = 1;
                let snippet = '';
                if (Array.isArray(res.locations) && res.locations[0]?.physicalLocation) {
                    const loc = res.locations[0].physicalLocation;
                    uri = loc.artifactLocation?.uri || uri;
                    line = loc.region?.startLine || 1;
                    snippet = loc.region?.snippet?.text || '';
                }
                findings.push({
                    tool: String(toolName),
                    ruleId: String(ruleId),
                    ruleTitle: String(ruleTitle),
                    severity: String(rawLevel),
                    cwe: String(cwe),
                    message: String(res.message?.text || ruleTitle),
                    artifactUri: String(uri),
                    lineNumber: Number(line),
                    snippet: String(snippet),
                });
            }
        }
        return findings;
    }
    // Case 2: Array of findings at top level
    const list = Array.isArray(payload)
        ? payload
        : Array.isArray(obj.findings)
            ? obj.findings
            : Array.isArray(obj.results)
                ? obj.results
                : [];
    for (const item of list) {
        if (typeof item !== 'object' || !item)
            continue;
        const it = item;
        findings.push({
            tool: String(it.tool || 'generic-scanner'),
            ruleId: String(it.ruleId || it.id || it.code || 'SEC-001'),
            ruleTitle: String(it.ruleTitle || it.title || it.name || it.ruleId || 'Security Finding'),
            severity: String(it.severity || it.level || 'MEDIUM'),
            cwe: String(it.cwe || 'CWE-693'),
            message: String(it.message || it.description || 'Finding description'),
            artifactUri: String(it.artifactUri || it.file || it.path || 'unknown/file'),
            lineNumber: Number(it.lineNumber || it.line || 1),
            snippet: String(it.snippet || it.evidence || ''),
            properties: it.properties,
        });
    }
    return findings;
}
/**
 * Deduplicates raw findings using a deterministic SHA-256 fingerprint:
 *   K_dedup(f) = SHA-256(tool || rule_id || artifact_uri || line_number)
 */
function deduplicateAndNormalize(rawFindings, redactSecrets = true) {
    const map = new Map();
    let count = 0;
    for (const f of rawFindings) {
        count++;
        const tool = f.tool.trim();
        const ruleId = f.ruleId.trim();
        const uri = f.artifactUri.trim();
        const line = f.lineNumber && f.lineNumber > 0 ? f.lineNumber : 1;
        const keyPayload = `${tool}|${ruleId}|${uri}|${line}`;
        const fingerprint = crypto.createHash('sha256').update(keyPayload).digest('hex');
        if (!map.has(fingerprint)) {
            const sev = normalizeSeverity(f.severity);
            const cwe = (f.cwe || 'CWE-693').trim();
            const rawSnippet = f.snippet || '';
            const snippet = redactSecrets ? redactPiiAndSecrets(rawSnippet) : rawSnippet;
            map.set(fingerprint, {
                id: `FND-${fingerprint.substring(0, 10).toUpperCase()}`,
                fingerprint,
                tool,
                ruleId,
                ruleTitle: f.ruleTitle || ruleId,
                severity: sev,
                weight: getSeverityWeight(sev),
                cwe,
                message: f.message,
                artifactUri: uri,
                lineNumber: line,
                snippet,
                remediationSlaHours: getRemediationSlaHours(sev),
                certInReportable: isCertInReportable(sev, cwe),
                mappedIsoControls: [],
                mappedCertInDirections: [],
            });
        }
    }
    const findings = Array.from(map.values()).sort((a, b) => {
        // Sort by severity descending, then by ruleId
        const order = {
            CRITICAL: 0,
            HIGH: 1,
            MEDIUM: 2,
            LOW: 3,
            INFO: 4,
        };
        if (order[a.severity] !== order[b.severity]) {
            return order[a.severity] - order[b.severity];
        }
        return a.ruleId.localeCompare(b.ruleId);
    });
    return { findings, rawCount: count };
}
/**
 * Calculates fleet-wide security posture metrics, score S_fleet, and evidence manifest hash.
 */
function computeFleetPostureMetrics(findings, rawCount, controlPassRatio = 100.0) {
    let crit = 0;
    let high = 0;
    let med = 0;
    let low = 0;
    let info = 0;
    let certIn = 0;
    const toolsSet = new Set();
    for (const f of findings) {
        toolsSet.add(f.tool);
        if (f.certInReportable)
            certIn++;
        switch (f.severity) {
            case 'CRITICAL':
                crit++;
                break;
            case 'HIGH':
                high++;
                break;
            case 'MEDIUM':
                med++;
                break;
            case 'LOW':
                low++;
                break;
            default:
                info++;
                break;
        }
    }
    const nTools = Math.max(1, toolsSet.size);
    const totalWeightedDeductions = 25 * crit + 10 * high + 4 * med + 1 * low;
    const fleetScore = Math.max(0, Math.round(100 - totalWeightedDeductions / nTools));
    // Evidence manifest seal: SHA-256 of sorted fingerprints
    const manifestData = findings.map((f) => f.fingerprint).join(':');
    const evidenceManifestSha256 = crypto
        .createHash('sha256')
        .update(manifestData.length > 0 ? manifestData : 'EMPTY_MANIFEST')
        .digest('hex');
    return {
        totalFindings: findings.length,
        rawFindingsCount: rawCount,
        deduplicatedCount: findings.length,
        criticalCount: crit,
        highCount: high,
        mediumCount: med,
        lowCount: low,
        infoCount: info,
        toolsAudited: Array.from(toolsSet).sort(),
        fleetPostureScore: fleetScore,
        controlPassRatio,
        certInReportableCount: certIn,
        evidenceManifestSha256,
    };
}
//# sourceMappingURL=sarif_ingestor.js.map