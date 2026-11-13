/**
 * Zero-Dependency Native %PDF-1.4 Binary Compiler & Markdown/HTML Report Builder.
 */
import { AuditReportData } from './types';
/**
 * Escapes characters in PDF string literals: backslashes and parentheses.
 * Also strips active PostScript and forbidden JavaScript control sequences.
 */
export declare function escapePdfString(str: string): string;
/**
 * Native %PDF-1.4 binary compiler implementing ISO 32000-1 specifications.
 * Generates valid multi-page PDF documents with xref tables and trailers.
 */
export declare function compileAuditPdf(data: AuditReportData): Buffer;
/**
 * Builds a structured, publication-quality Markdown report.
 */
export declare function buildMarkdownReport(data: AuditReportData): string;
/**
 * Builds an executive print-optimized HTML report.
 */
export declare function buildHtmlReport(data: AuditReportData): string;
//# sourceMappingURL=pdf_markdown_builder.d.ts.map