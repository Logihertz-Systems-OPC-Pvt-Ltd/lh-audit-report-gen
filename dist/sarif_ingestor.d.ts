/**
 * Multi-Tool SARIF v2.1.0 & JSON Finding Ingestor, Deduplicator & Fleet Posture Aggregator.
 */
import { FleetPostureMetrics, NormalizedFinding, RawFinding, SeverityLevel } from './types';
/**
 * Redacts secrets, private keys, authorization tokens, and PII in evidence snippets.
 */
export declare function redactPiiAndSecrets(text: string): string;
/**
 * Normalizes severity levels across various SARIF and scanner formats.
 */
export declare function normalizeSeverity(sev: string | undefined): SeverityLevel;
/**
 * Returns severity deduction weight for fleet posture scoring.
 */
export declare function getSeverityWeight(sev: SeverityLevel): number;
/**
 * Assigns statutory remediation SLA in hours.
 * CRITICAL: 24h, HIGH: 7d (168h), MEDIUM: 30d (720h), LOW: 90d (2160h).
 */
export declare function getRemediationSlaHours(sev: SeverityLevel): number;
/**
 * Determines whether a finding constitutes a mandatory 6-hour reportable cyber incident
 * under CERT-In Directions (April 2022) / Section 70B of IT Act 2000.
 */
export declare function isCertInReportable(sev: SeverityLevel, cwe: string): boolean;
/**
 * Ingests and extracts findings from raw SARIF v2.1.0 or JSON payload.
 */
export declare function parseRawFindings(payload: unknown): RawFinding[];
/**
 * Deduplicates raw findings using a deterministic SHA-256 fingerprint:
 *   K_dedup(f) = SHA-256(tool || rule_id || artifact_uri || line_number)
 */
export declare function deduplicateAndNormalize(rawFindings: RawFinding[], redactSecrets?: boolean): {
    findings: NormalizedFinding[];
    rawCount: number;
};
/**
 * Calculates fleet-wide security posture metrics, score S_fleet, and evidence manifest hash.
 */
export declare function computeFleetPostureMetrics(findings: NormalizedFinding[], rawCount: number, controlPassRatio?: number): FleetPostureMetrics;
//# sourceMappingURL=sarif_ingestor.d.ts.map