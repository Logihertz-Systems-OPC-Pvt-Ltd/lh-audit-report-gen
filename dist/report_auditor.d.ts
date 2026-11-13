/**
 * 10-Rule Audit Governance & Compliance Posture Auditor (LH-RPT-001..010).
 */
import { AuditPolicyInput, AuditRuleMeta, PostureAuditReport } from './types';
export declare const AUDIT_RULES: AuditRuleMeta[];
/**
 * Evaluates an audit policy against the 10 normative governance rules.
 */
export declare function evaluateAuditPolicy(policy: AuditPolicyInput): PostureAuditReport;
//# sourceMappingURL=report_auditor.d.ts.map