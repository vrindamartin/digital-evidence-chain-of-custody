const pool = require("../config/db");
const auditService = require("./auditService");
const { encryptField, decryptField } = require("../utils/fieldEncryption");

const decryptCustodyRow = (row) => {
    if (!row) return row;
    const custody_id = row.custody_id;
    return {
        ...row,
        remarks: (typeof row.remarks === "string" && row.remarks.startsWith("v1:"))
            ? decryptField("custody_logs", "remarks", custody_id, row.remarks)
            : row.remarks,
        from_user_name: (typeof row.from_user_name === "string" && row.from_user_name.startsWith("v1:") && row.from_user)
            ? decryptField("users", "full_name", row.from_user, row.from_user_name)
            : row.from_user_name,
        to_user_name: (typeof row.to_user_name === "string" && row.to_user_name.startsWith("v1:") && row.to_user)
            ? decryptField("users", "full_name", row.to_user, row.to_user_name)
            : row.to_user_name
    };
};

const createCustodyLog = async (custodyData) => {
    const {
        evidence_id,
        from_user,
        to_user,
        action,
        remarks
    } = custodyData;

    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.custody_logs_custody_id_seq') AS next_id;");
        const nextCustodyId = parseInt(seqRes.rows[0].next_id, 10);

        const encRemarks = encryptField("custody_logs", "remarks", nextCustodyId, remarks);

        const query = `
            INSERT INTO custody_logs
            (
                custody_id,
                evidence_id,
                from_user,
                to_user,
                action,
                remarks,
                old_remarks
            )
            OVERRIDING SYSTEM VALUE
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *;
        `;

        const values = [
            nextCustodyId,
            evidence_id,
            from_user,
            to_user,
            action,
            encRemarks,
            remarks
        ];

        const result = await client.query(query, values);
        const custodyLog = decryptCustodyRow(result.rows[0]);

        await auditService.createAuditLog(
            from_user,
            evidence_id,
            action,
            `Custody action: ${action}. ${remarks || ""}`
        );

        await client.query("COMMIT;");
        return custodyLog;
    } catch (err) {
        await client.query("ROLLBACK;");
        throw err;
    } finally {
        client.release();
    }
};

const getCustodyLogs = async (evidenceId) => {
    const query = `
        SELECT
            c.custody_id,
            c.evidence_id,
            c.from_user,
            from_u.full_name AS from_user_name,
            c.to_user,
            to_u.full_name AS to_user_name,
            c.action,
            c.remarks,
            c.created_at
        FROM custody_logs c
        LEFT JOIN users from_u
            ON c.from_user = from_u.user_id
        LEFT JOIN users to_u
            ON c.to_user = to_u.user_id
        WHERE c.evidence_id = $1
        ORDER BY c.created_at ASC;
    `;

    const result = await pool.query(query, [evidenceId]);
    return result.rows.map(decryptCustodyRow);
};

module.exports = {
    createCustodyLog,
    getCustodyLogs,
    decryptCustodyRow
};