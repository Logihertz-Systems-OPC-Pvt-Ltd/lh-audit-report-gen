/**
 * Multi-Format Exporters for lh-audit-report-gen.
 *
 * Supports ANSI Terminal Tables, Canonical JSON (RFC 8259), and OASIS SARIF v2.1.0.
 */
import { PostureAuditReport, StatementOfApplicability } from './types';
/**
 * Formats the audit posture report as an ANSI colored terminal box table.
 */
export declare function formatAuditTable(report: PostureAuditReport): string;
/**
 * Formats the audit posture report as canonical JSON.
 */
export declare function formatAuditJson(report: PostureAuditReport): string;
/**
 * Formats the audit posture report as OASIS SARIF v2.1.0 for CI/CD ingestion.
 */
export declare function formatAuditSarif(report: PostureAuditReport): string;
/**
 * Formats Statement of Applicability as an ANSI terminal table.
 */
export declare function formatSoaTable(soa: StatementOfApplicability): string;
/**
 * Formats Statement of Applicability as JSON.
 */
export declare function formatSoaJson(soa: StatementOfApplicability): string;
//# sourceMappingURL=exporters.d.ts.map