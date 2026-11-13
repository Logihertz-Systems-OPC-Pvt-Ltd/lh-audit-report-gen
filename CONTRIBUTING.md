# Contributing to Logihertz Audit Report Generator

Thank you for contributing to `lh-audit-report-gen` (`lh-report-gen`), part of the Logihertz 60-Tool Open-Source Ecosystem.

## Architectural Principles & Strict Mandates

`lh-audit-report-gen` is engineered for statutory security auditing, ISO/IEC 27001:2022 certification evidence preparation, and Indian national cyber incident compliance under CERT-In Directions. All contributions must adhere to the following core tenets:

1. **Zero External Runtime Dependencies**:
   - The `"dependencies"` field in `package.json` MUST remain completely empty (`{}`).
   - All SARIF v2.1.0 ingestion, deduplication, ISO/IEC 27001:2022 control mapping, native `%PDF-1.4` binary stream generation, Markdown reporting, and SHA-256 evidence hashing must rely strictly on Node.js built-in modules (`fs`, `path`, `crypto`, `child_process`).
2. **Strict TypeScript Standards**:
   - Code must pass `tsc --noEmit` and `npm run build` under strict mode without any type errors, `any` leaks, or unused parameters.
3. **Native PDF 1.4 Binary Correctness**:
   - PDF output must strictly conform to ISO 32000-1 / PDF 1.4 specification with exact 10-digit zero-padded byte offsets in the cross-reference (`xref`) table.
   - Text operators must sanitize string literals to prevent PDF stream escape vulnerabilities (`\(` and `\)`). Active script objects (`/JS`, `/JavaScript`, `/Launch`) are forbidden.
4. **Deterministic Compliance Mapping**:
   - CWE-to-ISO-27001 and CWE-to-CERT-In crosswalks must map to official published clauses.

## Local Development Workflow

### Prerequisites
- Node.js 20 LTS or Node.js 22 LTS
- TypeScript 5.x

### Building the Project
```bash
npm run build
```

### Running the Test Suite
```bash
npm test
```

### Formatting & Code Quality
Ensure clean code formatting and strict type compliance:
```bash
npx tsc --noEmit
```

## Pull Request Guidelines

1. **Conventional Commits**: Format commit titles as `feat(pdf): ...`, `fix(sarif): ...`, `test(mapper): ...`.
2. **Test Coverage**: Every new control mapping, PDF operator, or audit rule must be accompanied by unit assertions in `tests/run_tests.ts`.
3. **Documentation**: Update `README.md` and inline JSDoc comments when adding or modifying CLI subcommands.
