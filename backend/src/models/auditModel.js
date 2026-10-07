const pool = require("../config/db");
const { decryptField } = require("../utils/fieldEncryption");

const decryptAuditRow = (row) => {
    if (!row) return row;
    const audit_id = row.audit_id;
    return {
        ...row,
        details: (typeof row.details === "string" && row.details.startsWith("v1:"))
            ? decryptField("audit_logs", "details", audit_id, row.details)
            : row.details,
        user_name: (typeof row.user_name === "string" && row.user_name.startsWith("v1:") && row.user_id)
            ? decryptField("users", "full_name", row.user_id, row.user_name)
            : row.user_name,
        employee_id: (typeof row.employee_id === "string" && row.employee_id.startsWith("v1:") && row.user_id)
            ? decryptField("users", "employee_id", row.user_id, row.employee_id)
            : row.employee_id,
        evidence_name: (typeof row.evidence_name === "string" && row.evidence_name.startsWith("v1:") && row.evidence_id)
            ? decryptField("evidence", "evidence_name", row.evidence_id, row.evidence_name)
            : row.evidence_name
    };
};

const getAllAuditLogs = async () => {
    const query = `
        SELECT 
            a.audit_id,
            a.user_id,
            COALESCE(u.full_name, 'SYSTEM') AS user_name,
            COALESCE(u.employee_id, 'SYSTEM') AS employee_id,
            a.evidence_id,
            e.evidence_number,
            e.evidence_name,
            a.action,
            a.details,
            a.created_at
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.user_id
        LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
        ORDER BY a.created_at DESC;
    `;
    const result = await pool.query(query);
    return result.rows.map(decryptAuditRow);
};

module.exports = {
    getAllAuditLogs,
    decryptAuditRow
};