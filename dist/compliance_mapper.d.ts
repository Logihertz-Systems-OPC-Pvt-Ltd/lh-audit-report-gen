/**
 * ISO/IEC 27001:2022 Annex A, CERT-In Directions & DPDP Act 2023 Compliance Crosswalk.
 */
import { NormalizedFinding, StatementOfApplicability } from './types';
interface IsoControlDefinition {
    clause: string;
    title: string;
    category: 'Organizational' | 'People' | 'Physical' | 'Technological';
    description: string;
    matchingCwes: string[];
}
export declare const ISO_27001_CONTROLS: IsoControlDefinition[];
export declare const CERT_IN_MANDATES: ({
    directiveId: string;
    title: string;
    legalReference: string;
    mandateDescription: string;
    timelineHours: undefined;
    associatedCwes: string[];
} | {
    directiveId: string;
    title: string;
    legalReference: string;
    mandateDescription: string;
    timelineHours: number;
    associatedCwes: string[];
})[];
export declare const DPDP_OBLIGATIONS: {
    section: string;
    title: string;
    obligation: string;
    associatedCwes: string[];
}[];
/**
 * Maps findings to ISO/IEC 27001:2022, CERT-In, and DPDP frameworks,
 * and compiles the Statement of Applicability (SoA) matrix.
 */
export declare function buildStatementOfApplicability(findings: NormalizedFinding[]): StatementOfApplicability;
export {};
//# sourceMappingURL=compliance_mapper.d.ts.map