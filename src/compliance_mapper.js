"use strict";
/**
 * ISO/IEC 27001:2022 Annex A, CERT-In Directions & DPDP Act 2023 Compliance Crosswalk.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DPDP_OBLIGATIONS = exports.CERT_IN_MANDATES = exports.ISO_27001_CONTROLS = void 0;
exports.buildStatementOfApplicability = buildStatementOfApplicability;
exports.ISO_27001_CONTROLS = [
    {
        clause: 'A.5.15',
        title: 'Access Control',
        category: 'Organizational',
        description: 'Rules to control physical and logical access to information and other associated assets.',
        matchingCwes: ['CWE-284', 'CWE-285', 'CWE-732', 'CWE-639'],
    },
    {
        clause: 'A.5.24',
        title: 'Incident Management Planning',
        category: 'Organizational',
        description: 'Information security incident management responsibilities and procedures.',
        matchingCwes: ['CWE-778', 'CWE-779'],
    },
    {
        clause: 'A.8.5',
        title: 'Secure Authentication',
        category: 'Technological',
        description: 'Secure authentication technologies and procedures based on information access restrictions.',
        matchingCwes: ['CWE-290', 'CWE-306', 'CWE-307', 'CWE-798', 'CWE-287'],
    },
    {
        clause: 'A.8.6',
        title: 'Capacity Management',
        category: 'Technological',
        description: 'The use of resources shall be monitored and adjusted in line with capacity requirements.',
        matchingCwes: ['CWE-400', 'CWE-770'],
    },
    {
        clause: 'A.8.7',
        title: 'Protection Against Malware',
        category: 'Technological',
        description: 'Protection against malware shall be implemented and supported by appropriate user awareness.',
        matchingCwes: ['CWE-502', 'CWE-94', 'CWE-434'],
    },
    {
        clause: 'A.8.8',
        title: 'Management of Technical Vulnerabilities',
        category: 'Technological',
        description: 'Information about technical vulnerabilities of information systems in use shall be obtained.',
        matchingCwes: ['CWE-682', 'CWE-693', 'CWE-1188', 'CWE-1300'],
    },
    {
        clause: 'A.8.9',
        title: 'Configuration Management',
        category: 'Technological',
        description: 'Configurations, including security configurations, of hardware, software, services and networks.',
        matchingCwes: ['CWE-16', 'CWE-1004'],
    },
    {
        clause: 'A.8.15',
        title: 'Logging',
        category: 'Technological',
        description: 'Logs that record activities, exceptions, faults and other relevant events shall be produced.',
        matchingCwes: ['CWE-778', 'CWE-532', 'CWE-117'],
    },
    {
        clause: 'A.8.16',
        title: 'Monitoring Activities',
        category: 'Technological',
        description: 'Networks, systems and applications shall be monitored for anomalous behavior.',
        matchingCwes: ['CWE-778', 'CWE-353'],
    },
    {
        clause: 'A.8.20',
        title: 'Networks Security',
        category: 'Technological',
        description: 'Networks and network devices shall be secured, managed and controlled.',
        matchingCwes: ['CWE-319', 'CWE-923', 'CWE-200'],
    },
    {
        clause: 'A.8.24',
        title: 'Use of Cryptography',
        category: 'Technological',
        description: 'Rules for the effective use of cryptography, including cryptographic key management.',
        matchingCwes: ['CWE-312', 'CWE-326', 'CWE-328', 'CWE-345', 'CWE-347'],
    },
    {
        clause: 'A.8.26',
        title: 'Application Security Requirements',
        category: 'Technological',
        description: 'Information security requirements shall be identified and addressed when developing applications.',
        matchingCwes: ['CWE-20', 'CWE-74', 'CWE-693'],
    },
    {
        clause: 'A.8.28',
        title: 'Secure Coding',
        category: 'Technological',
        description: 'Secure coding principles shall be applied to software development.',
        matchingCwes: ['CWE-119', 'CWE-125', 'CWE-787', 'CWE-89', 'CWE-79', 'CWE-662'],
    },
];
exports.CERT_IN_MANDATES = [
    {
        directiveId: 'CERT-IN-DIR-01',
        title: 'NTP Clock Synchronization',
        legalReference: 'Directions under Section 70B(6) of IT Act 2000, Clause 2(i)',
        mandateDescription: 'Mandatory synchronization of all ICT system clocks to NTP servers of NPL or NIC, with UTC timestamps.',
        timelineHours: undefined,
        associatedCwes: ['CWE-682'],
    },
    {
        directiveId: 'CERT-IN-DIR-02',
        title: '6-Hour Incident Notification',
        legalReference: 'Directions under Section 70B(6) of IT Act 2000, Clause 2(v)',
        mandateDescription: 'Mandatory reporting of specified cyber incidents to CERT-In within 6 hours of noticing or being brought to notice.',
        timelineHours: 6,
        associatedCwes: ['CWE-284', 'CWE-306', 'CWE-312', 'CWE-502', 'CWE-319', 'CWE-778', 'CWE-353'],
    },
    {
        directiveId: 'CERT-IN-DIR-04',
        title: '180-Day ICT Log Retention',
        legalReference: 'Directions under Section 70B(6) of IT Act 2000, Clause 2(iii)',
        mandateDescription: 'Mandatory maintenance of all ICT logs within Indian jurisdiction for a rolling period of 180 days.',
        timelineHours: undefined,
        associatedCwes: ['CWE-778', 'CWE-532'],
    },
];
exports.DPDP_OBLIGATIONS = [
    {
        section: 'DPDP-SEC-8-5',
        title: 'Reasonable Security Safeguards',
        obligation: 'Data Fiduciary shall protect personal data in its possession or control by taking reasonable security safeguards to prevent personal data breach.',
        associatedCwes: ['CWE-312', 'CWE-532', 'CWE-319', 'CWE-284', 'CWE-306'],
    },
    {
        section: 'DPDP-SEC-8-6',
        title: 'Data Breach Notification',
        obligation: 'In the event of a personal data breach, intimate the Data Protection Board of India and each affected Data Principal.',
        associatedCwes: ['CWE-312', 'CWE-284', 'CWE-532'],
    },
];
/**
 * Maps findings to ISO/IEC 27001:2022, CERT-In, and DPDP frameworks,
 * and compiles the Statement of Applicability (SoA) matrix.
 */
function buildStatementOfApplicability(findings) {
    // Map findings to matching controls
    const isoViolations = new Map();
    const certInViolations = new Map();
    const dpdpViolations = new Map();
    for (const c of exports.ISO_27001_CONTROLS) {
        isoViolations.set(c.clause, []);
    }
    for (const c of exports.CERT_IN_MANDATES) {
        certInViolations.set(c.directiveId, []);
    }
    for (const d of exports.DPDP_OBLIGATIONS) {
        dpdpViolations.set(d.section, []);
    }
    for (const f of findings) {
        const cweUpper = f.cwe.toUpperCase().trim();
        // Map to ISO 27001
        for (const ctrl of exports.ISO_27001_CONTROLS) {
            if (ctrl.matchingCwes.includes(cweUpper)) {
                isoViolations.get(ctrl.clause)?.push(f);
                if (!f.mappedIsoControls.includes(ctrl.clause)) {
                    f.mappedIsoControls.push(ctrl.clause);
                }
            }
        }
        // Map to CERT-In
        for (const mand of exports.CERT_IN_MANDATES) {
            if (mand.associatedCwes.includes(cweUpper)) {
                certInViolations.get(mand.directiveId)?.push(f);
                if (!f.mappedCertInDirections.includes(mand.directiveId)) {
                    f.mappedCertInDirections.push(mand.directiveId);
                }
            }
        }
        // Map to DPDP
        for (const dp of exports.DPDP_OBLIGATIONS) {
            if (dp.associatedCwes.includes(cweUpper)) {
                dpdpViolations.get(dp.section)?.push(f);
            }
        }
    }
    // Compile ISO Statement of Applicability
    const isoControls = exports.ISO_27001_CONTROLS.map((ctrl) => {
        const viols = isoViolations.get(ctrl.clause) || [];
        let status = 'COMPLIANT';
        if (viols.length > 0) {
            const hasCritOrHigh = viols.some((v) => v.severity === 'CRITICAL' || v.severity === 'HIGH');
            status = hasCritOrHigh ? 'NON_COMPLIANT' : 'PARTIAL';
        }
        return {
            clause: ctrl.clause,
            title: ctrl.title,
            category: ctrl.category,
            description: ctrl.description,
            status,
            violationCount: viols.length,
            associatedCwes: ctrl.matchingCwes,
        };
    });
    // Compile CERT-In Directions SoA
    const certInClauses = exports.CERT_IN_MANDATES.map((mand) => {
        const viols = certInViolations.get(mand.directiveId) || [];
        let status = 'COMPLIANT';
        if (viols.length > 0) {
            const hasCrit = viols.some((v) => v.severity === 'CRITICAL');
            status = hasCrit ? 'NON_COMPLIANT' : 'PARTIAL';
        }
        return {
            directiveId: mand.directiveId,
            title: mand.title,
            legalReference: mand.legalReference,
            mandateDescription: mand.mandateDescription,
            status,
            incidentCount: viols.length,
            timelineHours: mand.timelineHours,
        };
    });
    // Compile DPDP Act SoA
    const dpdpClauses = exports.DPDP_OBLIGATIONS.map((dp) => {
        const viols = dpdpViolations.get(dp.section) || [];
        const status = viols.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT';
        return {
            section: dp.section,
            title: dp.title,
            obligation: dp.obligation,
            status,
            breachExposure: viols.length > 0,
        };
    });
    const totalControls = isoControls.length + certInClauses.length;
    const passedControls = isoControls.filter((c) => c.status === 'COMPLIANT').length +
        certInClauses.filter((c) => c.status === 'COMPLIANT').length;
    const failedControls = totalControls - passedControls;
    const complianceRatio = Math.round((passedControls / totalControls) * 1000) / 10;
    return {
        totalControls,
        passedControls,
        failedControls,
        complianceRatio,
        isoControls,
        certInClauses,
        dpdpClauses,
    };
}
