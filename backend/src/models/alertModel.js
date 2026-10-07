const pool = require("../config/db");
const { encryptField, decryptField, computeBlindIndex } = require("../utils/fieldEncryption");

const decryptAlertRow = (row) => {
    if (!row) return row;
    const alert_id = row.alert_id;
    return {
        ...row,
        message: (typeof row.message === "string" && row.message.startsWith("v1:"))
            ? decryptField("tamper_alerts", "message", alert_id, row.message)
            : row.message,
        email_last_error: (typeof row.email_last_error === "string" && row.email_last_error.startsWith("v1:"))
            ? decryptField("tamper_alerts", "email_last_error", alert_id, row.email_last_error)
            : row.email_last_error,
        file_path: (typeof row.file_path === "string" && row.file_path.startsWith("v1:"))
            ? decryptField("tamper_alerts", "file_path", alert_id, row.file_path)
            : row.file_path,
        resolution_notes: (typeof row.resolution_notes === "string" && row.resolution_notes.startsWith("v1:"))
            ? decryptField("tamper_alerts", "resolution_notes", alert_id, row.resolution_notes)
            : row.resolution_notes,
        evidence_name: (typeof row.evidence_name === "string" && row.evidence_name.startsWith("v1:") && row.evidence_id)
            ? decryptField("evidence", "evidence_name", row.evidence_id, row.evidence_name)
            : row.evidence_name,
        case_title: (typeof row.case_title === "string" && row.case_title.startsWith("v1:") && row.case_id)
            ? decryptField("cases", "case_title", row.case_id, row.case_title)
            : row.case_title,
        resolved_by_name: (typeof row.resolved_by_name === "string" && row.resolved_by_name.startsWith("v1:") && row.resolved_by)
            ? decryptField("users", "full_name", row.resolved_by, row.resolved_by_name)
            : row.resolved_by_name
    };
};

const getAllAlerts = async () => {
    const query = `
        SELECT 
            a.alert_id,
            a.evidence_id,
            a.case_id,
            a.alert_type,
            a.severity,
            a.stored_hash,
            a.detected_hash,
            a.file_path,
            a.message,
            a.status,
            a.email_status,
            a.email_attempts,
            a.email_last_error,
            a.email_sent_at,
            a.detected_at,
            a.resolved_by,
            a.resolved_at,
            a.resolution_notes,
            e.evidence_number,
            e.evidence_name,
            e.file_name,
            c.case_number,
            c.case_title,
            u.full_name AS resolved_by_name
        FROM tamper_alerts a
        LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
        LEFT JOIN cases c ON a.case_id = c.case_id
        LEFT JOIN users u ON a.resolved_by = u.user_id
        ORDER BY 
            CASE WHEN a.status = 'ACTIVE' THEN 1 ELSE 2 END,
            a.detected_at DESC;
    `;
    const result = await pool.query(query);
    return result.rows.map(decryptAlertRow);
};

const getAlertStats = async () => {
    const query = `
        SELECT 
            COUNT(*)::int AS total_alerts,
            COUNT(*) FILTER (WHERE status = 'ACTIVE')::int AS active_alerts,
            COUNT(*) FILTER (WHERE status = 'RESOLVED')::int AS resolved_alerts,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL' AND status = 'ACTIVE')::int AS critical_alerts,
            COUNT(*) FILTER (WHERE severity = 'HIGH' AND status = 'ACTIVE')::int AS high_alerts,
            COUNT(*) FILTER (WHERE status = 'ACTIVE' AND email_status IN ('PENDING', 'FAILED'))::int AS unsent_email_alerts
        FROM tamper_alerts;
    `;
    const result = await pool.query(query);
    return result.rows[0];
};

const createAlert = async (alertData) => {
    // Proactively check for existing active alert for duplicate suppression
    const existing = await findActiveAlert(alertData.evidence_id, alertData.alert_type, alertData.file_path);
    if (existing) {
        return { ...existing, is_new: false, already_exists: true };
    }

    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.tamper_alerts_alert_id_seq') AS next_id;");
        const nextAlertId = parseInt(seqRes.rows[0].next_id, 10);

        const encMsg = encryptField("tamper_alerts", "message", nextAlertId, alertData.message);
        const encFilePath = encryptField("tamper_alerts", "file_path", nextAlertId, alertData.file_path);
        const encEmailErr = encryptField("tamper_alerts", "email_last_error", nextAlertId, alertData.email_last_error);
        const filePathBidx = computeBlindIndex(alertData.file_path);

        const query = `
            INSERT INTO tamper_alerts
            (
                alert_id,
                evidence_id,
                case_id,
                alert_type,
                severity,
                stored_hash,
                detected_hash,
                file_path,
                message,
                status,
                email_status,
                email_attempts,
                email_last_error,
                email_sent_at,
                file_path_bidx,
                old_message,
                old_file_path,
                old_email_last_error
            )
            OVERRIDING SYSTEM VALUE
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ACTIVE', $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING *;
        `;
        const values = [
            nextAlertId,
            alertData.evidence_id,
            alertData.case_id,
            alertData.alert_type,
            alertData.severity || 'CRITICAL',
            alertData.stored_hash,
            alertData.detected_hash,
            encFilePath,
            encMsg,
            alertData.email_status || 'PENDING',
            alertData.email_attempts || 0,
            encEmailErr,
            alertData.email_sent_at || null,
            filePathBidx,
            alertData.message,
            alertData.file_path,
            alertData.email_last_error || null
        ];

        const result = await client.query(query, values);
        await client.query("COMMIT;");
        return { ...decryptAlertRow(result.rows[0]), is_new: true };
    } catch (err) {
        await client.query("ROLLBACK;");
        // Unique violation (Postgres error 23505): partial unique index idx_active_tamper_alerts_unique
        if (err.code === "23505") {
            const conflictExisting = await findActiveAlert(alertData.evidence_id, alertData.alert_type, alertData.file_path);
            return conflictExisting ? { ...conflictExisting, is_new: false, already_exists: true } : null;
        }
        throw err;
    } finally {
        client.release();
    }
};

const findActiveAlert = async (evidenceId, alertType, filePath = null) => {
    let query;
    let params;

    if (evidenceId !== null && evidenceId !== undefined) {
        query = `
            SELECT 
                alert_id,
                evidence_id,
                case_id,
                alert_type,
                severity,
                stored_hash,
                detected_hash,
                file_path,
                message,
                status,
                email_status,
                email_attempts,
                email_last_error,
                email_sent_at,
                detected_at
            FROM tamper_alerts 
            WHERE evidence_id = $1 AND alert_type = $2 AND status = 'ACTIVE'
            LIMIT 1;
        `;
        params = [evidenceId, alertType];
    } else if (filePath) {
        const filePathBidx = computeBlindIndex(filePath);
        query = `
            SELECT 
                alert_id,
                evidence_id,
                case_id,
                alert_type,
                severity,
                stored_hash,
                detected_hash,
                file_path,
                message,
                status,
                email_status,
                email_attempts,
                email_last_error,
                email_sent_at,
                detected_at
            FROM tamper_alerts 
            WHERE evidence_id IS NULL AND alert_type = $1 
              AND (file_path_bidx = $2 OR file_path = $3) 
              AND status = 'ACTIVE'
            LIMIT 1;
        `;
        params = [alertType, filePathBidx, filePath];
    } else {
        query = `
            SELECT 
                alert_id,
                evidence_id,
                case_id,
                alert_type,
                severity,
                stored_hash,
                detected_hash,
                file_path,
                message,
                status,
                email_status,
                email_attempts,
                email_last_error,
                email_sent_at,
                detected_at
            FROM tamper_alerts 
            WHERE evidence_id IS NULL AND alert_type = $1 AND status = 'ACTIVE'
            LIMIT 1;
        `;
        params = [alertType];
    }

    const result = await pool.query(query, params);
    return decryptAlertRow(result.rows[0]);
};

const updateAlertEmailDispatch = async (alertId, { email_status, email_attempts, email_last_error, email_sent_at }) => {
    const encEmailErr = email_last_error ? encryptField("tamper_alerts", "email_last_error", alertId, email_last_error) : null;
    const query = `
        UPDATE tamper_alerts
        SET email_status = COALESCE($2, email_status),
            email_attempts = COALESCE($3, email_attempts),
            email_last_error = $4,
            old_email_last_error = $5,
            email_sent_at = COALESCE($6, email_sent_at)
        WHERE alert_id = $1
        RETURNING *;
    `;
    const values = [
        alertId,
        email_status,
        email_attempts,
        encEmailErr,
        email_last_error || null,
        email_sent_at
    ];
    const result = await pool.query(query, values);
    return decryptAlertRow(result.rows[0]);
};

const getUnsentActiveAlerts = async (maxAttempts = 5) => {
    const query = `
        SELECT 
            a.*,
            e.evidence_number,
            e.evidence_name,
            c.case_number
        FROM tamper_alerts a
        LEFT JOIN evidence e ON a.evidence_id = e.evidence_id
        LEFT JOIN cases c ON a.case_id = c.case_id
        WHERE a.status = 'ACTIVE' 
          AND a.email_status IN ('PENDING', 'FAILED')
          AND (a.email_attempts IS NULL OR a.email_attempts < $1)
        ORDER BY a.alert_id ASC;
    `;
    const result = await pool.query(query, [maxAttempts]);
    return result.rows.map(decryptAlertRow);
};

const resolveAlert = async (alertId, userId, notes) => {
    const encNotes = notes ? encryptField("tamper_alerts", "resolution_notes", alertId, notes) : null;
    const query = `
        UPDATE tamper_alerts
        SET status = 'RESOLVED',
            resolved_by = $2,
            resolved_at = CURRENT_TIMESTAMP,
            resolution_notes = $3,
            old_resolution_notes = $4
        WHERE alert_id = $1
        RETURNING *;
    `;
    const result = await pool.query(query, [alertId, userId, encNotes, notes || 'Resolved by administrator']);
    return decryptAlertRow(result.rows[0]);
};

module.exports = {
    getAllAlerts,
    getAlertStats,
    createAlert,
    findActiveAlert,
    updateAlertEmailDispatch,
    getUnsentActiveAlerts,
    resolveAlert,
    decryptAlertRow
};
