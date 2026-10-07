const pool = require("../config/db");
const { encryptField, decryptField } = require("../utils/fieldEncryption");

const decryptReportRow = (row) => {
    if (!row) return row;
    const report_id = row.report_id;
    return {
        ...row,
        report_title: (typeof row.report_title === "string" && row.report_title.startsWith("v1:"))
            ? decryptField("forensic_reports", "report_title", report_id, row.report_title)
            : row.report_title,
        tools_used: (typeof row.tools_used === "string" && row.tools_used.startsWith("v1:"))
            ? decryptField("forensic_reports", "tools_used", report_id, row.tools_used)
            : row.tools_used,
        findings: (typeof row.findings === "string" && row.findings.startsWith("v1:"))
            ? decryptField("forensic_reports", "findings", report_id, row.findings)
            : row.findings,
        artifacts_recovered: (typeof row.artifacts_recovered === "string" && row.artifacts_recovered.startsWith("v1:"))
            ? decryptField("forensic_reports", "artifacts_recovered", report_id, row.artifacts_recovered)
            : row.artifacts_recovered,
        conclusion: (typeof row.conclusion === "string" && row.conclusion.startsWith("v1:"))
            ? decryptField("forensic_reports", "conclusion", report_id, row.conclusion)
            : row.conclusion,
        recipient_name: (typeof row.recipient_name === "string" && row.recipient_name.startsWith("v1:"))
            ? decryptField("forensic_reports", "recipient_name", report_id, row.recipient_name)
            : row.recipient_name,
        recipient_agency: (typeof row.recipient_agency === "string" && row.recipient_agency.startsWith("v1:"))
            ? decryptField("forensic_reports", "recipient_agency", report_id, row.recipient_agency)
            : row.recipient_agency,
        dispatch_notes: (typeof row.dispatch_notes === "string" && row.dispatch_notes.startsWith("v1:"))
            ? decryptField("forensic_reports", "dispatch_notes", report_id, row.dispatch_notes)
            : row.dispatch_notes,
        analyst_name: (typeof row.analyst_name === "string" && row.analyst_name.startsWith("v1:") && row.analyst_id)
            ? decryptField("users", "full_name", row.analyst_id, row.analyst_name)
            : row.analyst_name,
        recipient_user_name: (typeof row.recipient_user_name === "string" && row.recipient_user_name.startsWith("v1:") && row.recipient_id)
            ? decryptField("users", "full_name", row.recipient_id, row.recipient_user_name)
            : row.recipient_user_name,
        evidence_name: (typeof row.evidence_name === "string" && row.evidence_name.startsWith("v1:") && row.evidence_id)
            ? decryptField("evidence", "evidence_name", row.evidence_id, row.evidence_name)
            : row.evidence_name,
        case_title: (typeof row.case_title === "string" && row.case_title.startsWith("v1:") && row.case_id)
            ? decryptField("cases", "case_title", row.case_id, row.case_title)
            : row.case_title
    };
};

const decryptAutopsyRow = (row) => {
    if (!row) return row;
    const autopsy_id = row.autopsy_id;
    return {
        ...row,
        subject_name: (typeof row.subject_name === "string" && row.subject_name.startsWith("v1:"))
            ? decryptField("autopsy_records", "subject_name", autopsy_id, row.subject_name)
            : row.subject_name,
        hardware_condition: (typeof row.hardware_condition === "string" && row.hardware_condition.startsWith("v1:"))
            ? decryptField("autopsy_records", "hardware_condition", autopsy_id, row.hardware_condition)
            : row.hardware_condition,
        extraction_method: (typeof row.extraction_method === "string" && row.extraction_method.startsWith("v1:"))
            ? decryptField("autopsy_records", "extraction_method", autopsy_id, row.extraction_method)
            : row.extraction_method,
        autopsy_findings: (typeof row.autopsy_findings === "string" && row.autopsy_findings.startsWith("v1:"))
            ? decryptField("autopsy_records", "autopsy_findings", autopsy_id, row.autopsy_findings)
            : row.autopsy_findings,
        triage_summary: (typeof row.triage_summary === "string" && row.triage_summary.startsWith("v1:"))
            ? decryptField("autopsy_records", "triage_summary", autopsy_id, row.triage_summary)
            : row.triage_summary,
        dispatched_to: (typeof row.dispatched_to === "string" && row.dispatched_to.startsWith("v1:"))
            ? decryptField("autopsy_records", "dispatched_to", autopsy_id, row.dispatched_to)
            : row.dispatched_to,
        dispatch_notes: (typeof row.dispatch_notes === "string" && row.dispatch_notes.startsWith("v1:"))
            ? decryptField("autopsy_records", "dispatch_notes", autopsy_id, row.dispatch_notes)
            : row.dispatch_notes,
        examiner_name: (typeof row.examiner_name === "string" && row.examiner_name.startsWith("v1:") && row.examiner_id)
            ? decryptField("users", "full_name", row.examiner_id, row.examiner_name)
            : row.examiner_name,
        recipient_user_name: (typeof row.recipient_user_name === "string" && row.recipient_user_name.startsWith("v1:") && row.recipient_id)
            ? decryptField("users", "full_name", row.recipient_id, row.recipient_user_name)
            : row.recipient_user_name,
        evidence_name: (typeof row.evidence_name === "string" && row.evidence_name.startsWith("v1:") && row.evidence_id)
            ? decryptField("evidence", "evidence_name", row.evidence_id, row.evidence_name)
            : row.evidence_name,
        case_title: (typeof row.case_title === "string" && row.case_title.startsWith("v1:") && row.case_id)
            ? decryptField("cases", "case_title", row.case_id, row.case_title)
            : row.case_title
    };
};

// FORENSIC REPORTS
const getAllForensicReports = async () => {
    const query = `
        SELECT 
            fr.*,
            e.evidence_number,
            e.evidence_name,
            c.case_number,
            c.case_title,
            u.full_name AS analyst_name,
            rec.full_name AS recipient_user_name
        FROM forensic_reports fr
        LEFT JOIN evidence e ON fr.evidence_id = e.evidence_id
        LEFT JOIN cases c ON fr.case_id = c.case_id
        LEFT JOIN users u ON fr.analyst_id = u.user_id
        LEFT JOIN users rec ON fr.recipient_id = rec.user_id
        ORDER BY fr.created_at DESC;
    `;
    const result = await pool.query(query);
    return result.rows.map(decryptReportRow);
};

const getLatestReportNumber = async () => {
    const query = `SELECT report_number FROM forensic_reports ORDER BY report_id DESC LIMIT 1`;
    const result = await pool.query(query);
    return result.rows[0];
};

const createForensicReport = async (data) => {
    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.forensic_reports_report_id_seq') AS next_id;");
        const nextReportId = parseInt(seqRes.rows[0].next_id, 10);

        const encTitle = encryptField("forensic_reports", "report_title", nextReportId, data.report_title);
        const encTools = encryptField("forensic_reports", "tools_used", nextReportId, data.tools_used);
        const encFindings = encryptField("forensic_reports", "findings", nextReportId, data.findings);
        const encArtifacts = encryptField("forensic_reports", "artifacts_recovered", nextReportId, data.artifacts_recovered);
        const encConclusion = encryptField("forensic_reports", "conclusion", nextReportId, data.conclusion);

        const query = `
            INSERT INTO forensic_reports
            (
                report_id,
                report_number,
                case_id,
                evidence_id,
                analyst_id,
                report_title,
                report_type,
                tools_used,
                hash_verified,
                findings,
                artifacts_recovered,
                conclusion,
                status,
                old_report_title,
                old_tools_used,
                old_findings,
                old_artifacts_recovered,
                old_conclusion
            )
            OVERRIDING SYSTEM VALUE
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'DRAFT', $13, $14, $15, $16, $17)
            RETURNING *;
        `;
        const values = [
            nextReportId,
            data.report_number,
            data.case_id,
            data.evidence_id,
            data.analyst_id,
            encTitle,
            data.report_type || 'EXAMINATION_REPORT',
            encTools,
            data.hash_verified !== undefined ? data.hash_verified : true,
            encFindings,
            encArtifacts,
            encConclusion,
            data.report_title,
            data.tools_used,
            data.findings,
            data.artifacts_recovered,
            data.conclusion
        ];
        const result = await client.query(query, values);
        await client.query("COMMIT;");
        return decryptReportRow(result.rows[0]);
    } catch (err) {
        await client.query("ROLLBACK;");
        throw err;
    } finally {
        client.release();
    }
};

const dispatchForensicReport = async (reportId, dispatchData) => {
    const encRecipName = dispatchData.recipient_name ? encryptField("forensic_reports", "recipient_name", reportId, dispatchData.recipient_name) : null;
    const encRecipAgency = dispatchData.recipient_agency ? encryptField("forensic_reports", "recipient_agency", reportId, dispatchData.recipient_agency) : null;
    const encDispatchNotes = dispatchData.dispatch_notes ? encryptField("forensic_reports", "dispatch_notes", reportId, dispatchData.dispatch_notes) : null;

    const query = `
        UPDATE forensic_reports
        SET status = 'SENT',
            recipient_id = $2,
            recipient_name = $3,
            recipient_agency = $4,
            transmission_priority = $5,
            dispatch_notes = $6,
            old_recipient_name = $7,
            old_recipient_agency = $8,
            old_dispatch_notes = $9,
            sent_at = CURRENT_TIMESTAMP
        WHERE report_id = $1
        RETURNING *;
    `;
    const values = [
        reportId,
        dispatchData.recipient_id,
        encRecipName,
        encRecipAgency,
        dispatchData.transmission_priority || 'NORMAL',
        encDispatchNotes,
        dispatchData.recipient_name,
        dispatchData.recipient_agency,
        dispatchData.dispatch_notes
    ];
    const result = await pool.query(query, values);
    return decryptReportRow(result.rows[0]);
};

// AUTOPSIES
const getAllAutopsies = async () => {
    const query = `
        SELECT 
            a.*,
            e.evidence_number,
            e.evidence_name,
            c.case_number,
            c.case_title,
            u.full_name AS examiner_name,
            rec.full_name AS recipient_user_name
        FROM autopsy_records a
        LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
        LEFT JOIN cases c ON a.case_id = c.case_id
        LEFT JOIN users u ON a.examiner_id = u.user_id
        LEFT JOIN users rec ON a.recipient_id = rec.user_id
        ORDER BY a.created_at DESC;
    `;
    const result = await pool.query(query);
    return result.rows.map(decryptAutopsyRow);
};

const getLatestAutopsyNumber = async () => {
    const query = `SELECT autopsy_number FROM autopsy_records ORDER BY autopsy_id DESC LIMIT 1`;
    const result = await pool.query(query);
    return result.rows[0];
};

const createAutopsy = async (data) => {
    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.autopsy_records_autopsy_id_seq') AS next_id;");
        const nextAutopsyId = parseInt(seqRes.rows[0].next_id, 10);

        const encSubject = encryptField("autopsy_records", "subject_name", nextAutopsyId, data.subject_name);
        const encCondition = encryptField("autopsy_records", "hardware_condition", nextAutopsyId, data.hardware_condition);
        const encMethod = encryptField("autopsy_records", "extraction_method", nextAutopsyId, data.extraction_method);
        const encFindings = encryptField("autopsy_records", "autopsy_findings", nextAutopsyId, data.autopsy_findings);
        const encTriage = encryptField("autopsy_records", "triage_summary", nextAutopsyId, data.triage_summary);

        const query = `
            INSERT INTO autopsy_records
            (
                autopsy_id,
                autopsy_number,
                case_id,
                evidence_id,
                examiner_id,
                subject_name,
                device_type,
                hardware_condition,
                extraction_method,
                autopsy_findings,
                triage_summary,
                status,
                old_subject_name,
                old_hardware_condition,
                old_extraction_method,
                old_autopsy_findings,
                old_triage_summary
            )
            OVERRIDING SYSTEM VALUE
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'COMPLETED', $12, $13, $14, $15, $16)
            RETURNING *;
        `;
        const values = [
            nextAutopsyId,
            data.autopsy_number,
            data.case_id,
            data.evidence_id,
            data.examiner_id,
            encSubject,
            data.device_type,
            encCondition,
            encMethod,
            encFindings,
            encTriage,
            data.subject_name,
            data.hardware_condition,
            data.extraction_method,
            data.autopsy_findings,
            data.triage_summary
        ];
        const result = await client.query(query, values);
        await client.query("COMMIT;");
        return decryptAutopsyRow(result.rows[0]);
    } catch (err) {
        await client.query("ROLLBACK;");
        throw err;
    } finally {
        client.release();
    }
};

const dispatchAutopsy = async (autopsyId, dispatchData) => {
    const encDispatchedTo = dispatchData.dispatched_to ? encryptField("autopsy_records", "dispatched_to", autopsyId, dispatchData.dispatched_to) : null;
    const encDispatchNotes = dispatchData.dispatch_notes ? encryptField("autopsy_records", "dispatch_notes", autopsyId, dispatchData.dispatch_notes) : null;

    const query = `
        UPDATE autopsy_records
        SET status = 'DISPATCHED',
            dispatched_to = $2,
            recipient_id = $3,
            dispatch_notes = $4,
            old_dispatched_to = $5,
            old_dispatch_notes = $6,
            dispatched_at = CURRENT_TIMESTAMP
        WHERE autopsy_id = $1
        RETURNING *;
    `;
    const values = [
        autopsyId,
        encDispatchedTo,
        dispatchData.recipient_id,
        encDispatchNotes,
        dispatchData.dispatched_to,
        dispatchData.dispatch_notes
    ];
    const result = await pool.query(query, values);
    return decryptAutopsyRow(result.rows[0]);
};

// COMPREHENSIVE CASE RECORDS FOR FORENSIC REPORT
const getCaseFullDossier = async (caseId) => {
    const caseQuery = `
        SELECT 
            c.*,
            u.full_name AS officer_name,
            u.employee_id AS officer_badge,
            u.email AS officer_email,
            cr.full_name AS created_by_name
        FROM cases c
        LEFT JOIN users u ON c.investigating_officer = u.user_id
        LEFT JOIN users cr ON c.created_by = cr.user_id
        WHERE c.case_id = $1;
    `;
    const caseRes = await pool.query(caseQuery, [caseId]);
    const rawCase = caseRes.rows[0];
    if (!rawCase) return null;

    const caseData = {
        ...rawCase,
        case_title: (typeof rawCase.case_title === "string" && rawCase.case_title.startsWith("v1:"))
            ? decryptField("cases", "case_title", rawCase.case_id, rawCase.case_title)
            : rawCase.case_title,
        case_description: (typeof rawCase.case_description === "string" && rawCase.case_description.startsWith("v1:"))
            ? decryptField("cases", "case_description", rawCase.case_id, rawCase.case_description)
            : rawCase.case_description,
        officer_name: (typeof rawCase.officer_name === "string" && rawCase.officer_name.startsWith("v1:") && rawCase.investigating_officer)
            ? decryptField("users", "full_name", rawCase.investigating_officer, rawCase.officer_name)
            : rawCase.officer_name,
        officer_badge: (typeof rawCase.officer_badge === "string" && rawCase.officer_badge.startsWith("v1:") && rawCase.investigating_officer)
            ? decryptField("users", "employee_id", rawCase.investigating_officer, rawCase.officer_badge)
            : rawCase.officer_badge,
        officer_email: (typeof rawCase.officer_email === "string" && rawCase.officer_email.startsWith("v1:") && rawCase.investigating_officer)
            ? decryptField("users", "email", rawCase.investigating_officer, rawCase.officer_email)
            : rawCase.officer_email,
        created_by_name: (typeof rawCase.created_by_name === "string" && rawCase.created_by_name.startsWith("v1:") && rawCase.created_by)
            ? decryptField("users", "full_name", rawCase.created_by, rawCase.created_by_name)
            : rawCase.created_by_name
    };

    const evidenceQuery = `
        SELECT 
            e.*,
            u.full_name AS uploader_name,
            u.employee_id AS uploader_badge
        FROM evidence e
        LEFT JOIN users u ON e.uploaded_by = u.user_id
        WHERE e.case_id = $1
        ORDER BY e.evidence_id ASC;
    `;
    const evidenceRes = await pool.query(evidenceQuery, [caseId]);
    const evidenceList = evidenceRes.rows.map(ev => ({
        ...ev,
        evidence_name: (typeof ev.evidence_name === "string" && ev.evidence_name.startsWith("v1:"))
            ? decryptField("evidence", "evidence_name", ev.evidence_id, ev.evidence_name)
            : ev.evidence_name,
        description: (typeof ev.description === "string" && ev.description.startsWith("v1:"))
            ? decryptField("evidence", "description", ev.evidence_id, ev.description)
            : ev.description,
        file_name: (typeof ev.file_name === "string" && ev.file_name.startsWith("v1:"))
            ? decryptField("evidence", "file_name", ev.evidence_id, ev.file_name)
            : ev.file_name,
        file_path: (typeof ev.file_path === "string" && ev.file_path.startsWith("v1:"))
            ? decryptField("evidence", "file_path", ev.evidence_id, ev.file_path)
            : ev.file_path,
        uploader_name: (typeof ev.uploader_name === "string" && ev.uploader_name.startsWith("v1:") && ev.uploaded_by)
            ? decryptField("users", "full_name", ev.uploaded_by, ev.uploader_name)
            : ev.uploader_name,
        uploader_badge: (typeof ev.uploader_badge === "string" && ev.uploader_badge.startsWith("v1:") && ev.uploaded_by)
            ? decryptField("users", "employee_id", ev.uploaded_by, ev.uploader_badge)
            : ev.uploader_badge
    }));

    const custodyQuery = `
        SELECT 
            cl.*,
            e.evidence_number,
            e.evidence_name,
            fu.full_name AS from_user_name,
            fu.employee_id AS from_user_badge,
            tu.full_name AS to_user_name,
            tu.employee_id AS to_user_badge
        FROM custody_logs cl
        JOIN evidence e ON cl.evidence_id = e.evidence_id
        LEFT JOIN users fu ON cl.from_user = fu.user_id
        LEFT JOIN users tu ON cl.to_user = tu.user_id
        WHERE e.case_id = $1
        ORDER BY cl.created_at ASC;
    `;
    const custodyRes = await pool.query(custodyQuery, [caseId]);
    const custodyList = custodyRes.rows.map(c => ({
        ...c,
        remarks: (typeof c.remarks === "string" && c.remarks.startsWith("v1:"))
            ? decryptField("custody_logs", "remarks", c.custody_id, c.remarks)
            : c.remarks,
        evidence_name: (typeof c.evidence_name === "string" && c.evidence_name.startsWith("v1:") && c.evidence_id)
            ? decryptField("evidence", "evidence_name", c.evidence_id, c.evidence_name)
            : c.evidence_name,
        from_user_name: (typeof c.from_user_name === "string" && c.from_user_name.startsWith("v1:") && c.from_user)
            ? decryptField("users", "full_name", c.from_user, c.from_user_name)
            : c.from_user_name,
        from_user_badge: (typeof c.from_user_badge === "string" && c.from_user_badge.startsWith("v1:") && c.from_user)
            ? decryptField("users", "employee_id", c.from_user, c.from_user_badge)
            : c.from_user_badge,
        to_user_name: (typeof c.to_user_name === "string" && c.to_user_name.startsWith("v1:") && c.to_user)
            ? decryptField("users", "full_name", c.to_user, c.to_user_name)
            : c.to_user_name,
        to_user_badge: (typeof c.to_user_badge === "string" && c.to_user_badge.startsWith("v1:") && c.to_user)
            ? decryptField("users", "employee_id", c.to_user, c.to_user_badge)
            : c.to_user_badge
    }));

    const autopsyQuery = `
        SELECT 
            a.*,
            e.evidence_number,
            e.evidence_name,
            u.full_name AS examiner_name,
            rec.full_name AS recipient_user_name
        FROM autopsy_records a
        LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
        LEFT JOIN cases c ON a.case_id = c.case_id
        LEFT JOIN users u ON a.examiner_id = u.user_id
        LEFT JOIN users rec ON a.recipient_id = rec.user_id
        WHERE a.case_id = $1 OR a.evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id = $1)
        ORDER BY a.created_at DESC;
    `;
    const autopsyRes = await pool.query(autopsyQuery, [caseId]);
    const autopsyList = autopsyRes.rows.map(decryptAutopsyRow);

    const reportsQuery = `
        SELECT 
            fr.*,
            e.evidence_number,
            e.evidence_name,
            u.full_name AS analyst_name,
            rec.full_name AS recipient_user_name
        FROM forensic_reports fr
        LEFT JOIN evidence e ON fr.evidence_id = e.evidence_id
        LEFT JOIN cases c ON fr.case_id = c.case_id
        LEFT JOIN users u ON fr.analyst_id = u.user_id
        LEFT JOIN users rec ON fr.recipient_id = rec.user_id
        WHERE fr.case_id = $1 OR fr.evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id = $1)
        ORDER BY fr.created_at DESC;
    `;
    const reportsRes = await pool.query(reportsQuery, [caseId]);
    const reportsList = reportsRes.rows.map(decryptReportRow);

    const auditQuery = `
        SELECT 
            al.*,
            u.full_name AS user_name,
            u.employee_id AS user_employee_id,
            e.evidence_number,
            e.evidence_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.user_id
        LEFT JOIN evidence e ON al.evidence_id = e.evidence_id
        ORDER BY al.created_at DESC;
    `;
    const auditRes = await pool.query(auditQuery);
    const evIds = new Set(evidenceList.map(e => e.evidence_id));
    const caseNum = rawCase.case_number;

    const auditList = [];
    for (const al of auditRes.rows) {
        const plainDetails = (typeof al.details === "string" && al.details.startsWith("v1:"))
            ? decryptField("audit_logs", "details", al.audit_id, al.details)
            : al.details;

        const matchesCase = (al.evidence_id && evIds.has(al.evidence_id)) || (plainDetails && plainDetails.includes(caseNum));
        if (matchesCase) {
            auditList.push({
                ...al,
                details: plainDetails,
                user_name: (typeof al.user_name === "string" && al.user_name.startsWith("v1:") && al.user_id)
                    ? decryptField("users", "full_name", al.user_id, al.user_name)
                    : al.user_name,
                user_employee_id: (typeof al.user_employee_id === "string" && al.user_employee_id.startsWith("v1:") && al.user_id)
                    ? decryptField("users", "employee_id", al.user_id, al.user_employee_id)
                    : al.user_employee_id,
                evidence_name: (typeof al.evidence_name === "string" && al.evidence_name.startsWith("v1:") && al.evidence_id)
                    ? decryptField("evidence", "evidence_name", al.evidence_id, al.evidence_name)
                    : al.evidence_name
            });
        }
    }

    const alertsQuery = `
        SELECT 
            ta.*,
            e.evidence_number,
            e.evidence_name,
            u.full_name AS resolved_by_name
        FROM tamper_alerts ta
        LEFT JOIN evidence e ON ta.evidence_id = e.evidence_id
        LEFT JOIN users u ON ta.resolved_by = u.user_id
        WHERE ta.case_id = $1 OR ta.evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id = $1)
        ORDER BY ta.detected_at DESC;
    `;
    const alertsRes = await pool.query(alertsQuery, [caseId]);
    const alertsList = alertsRes.rows.map(ta => ({
        ...ta,
        message: (typeof ta.message === "string" && ta.message.startsWith("v1:"))
            ? decryptField("tamper_alerts", "message", ta.alert_id, ta.message)
            : ta.message,
        file_path: (typeof ta.file_path === "string" && ta.file_path.startsWith("v1:"))
            ? decryptField("tamper_alerts", "file_path", ta.alert_id, ta.file_path)
            : ta.file_path,
        resolution_notes: (typeof ta.resolution_notes === "string" && ta.resolution_notes.startsWith("v1:"))
            ? decryptField("tamper_alerts", "resolution_notes", ta.alert_id, ta.resolution_notes)
            : ta.resolution_notes,
        evidence_name: (typeof ta.evidence_name === "string" && ta.evidence_name.startsWith("v1:") && ta.evidence_id)
            ? decryptField("evidence", "evidence_name", ta.evidence_id, ta.evidence_name)
            : ta.evidence_name,
        resolved_by_name: (typeof ta.resolved_by_name === "string" && ta.resolved_by_name.startsWith("v1:") && ta.resolved_by)
            ? decryptField("users", "full_name", ta.resolved_by, ta.resolved_by_name)
            : ta.resolved_by_name
    }));

    return {
        case: caseData,
        evidence: evidenceList,
        custody: custodyList,
        autopsies: autopsyList,
        reports: reportsList,
        auditLogs: auditList,
        alerts: alertsList,
        stats: {
            evidenceCount: evidenceList.length,
            custodyEventsCount: custodyList.length,
            autopsiesCount: autopsyList.length,
            reportsCount: reportsList.length,
            auditLogsCount: auditList.length,
            alertsCount: alertsList.length,
            activeAlertsCount: alertsList.filter(a => a.status === 'ACTIVE').length
        }
    };
};

module.exports = {
    getAllForensicReports,
    getLatestReportNumber,
    createForensicReport,
    dispatchForensicReport,
    getAllAutopsies,
    getLatestAutopsyNumber,
    createAutopsy,
    dispatchAutopsy,
    getCaseFullDossier,
    decryptReportRow,
    decryptAutopsyRow
};
