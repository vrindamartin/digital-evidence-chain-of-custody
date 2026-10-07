const pool = require("../config/db");
const { encryptField, decryptField } = require("../utils/fieldEncryption");

const decryptEvidenceRow = (row) => {
    if (!row) return row;
    const evidence_id = row.evidence_id;
    return {
        ...row,
        evidence_name: (typeof row.evidence_name === "string" && row.evidence_name.startsWith("v1:"))
            ? decryptField("evidence", "evidence_name", evidence_id, row.evidence_name)
            : row.evidence_name,
        description: (typeof row.description === "string" && row.description.startsWith("v1:"))
            ? decryptField("evidence", "description", evidence_id, row.description)
            : row.description,
        file_name: (typeof row.file_name === "string" && row.file_name.startsWith("v1:"))
            ? decryptField("evidence", "file_name", evidence_id, row.file_name)
            : row.file_name,
        file_path: (typeof row.file_path === "string" && row.file_path.startsWith("v1:"))
            ? decryptField("evidence", "file_path", evidence_id, row.file_path)
            : row.file_path,
        case_title: (typeof row.case_title === "string" && row.case_title.startsWith("v1:") && row.case_id)
            ? decryptField("cases", "case_title", row.case_id, row.case_title)
            : row.case_title
    };
};

const getLatestEvidenceNumber = async () => {
    const query = `
        SELECT evidence_number
        FROM evidence
        ORDER BY evidence_id DESC
        LIMIT 1;
    `;
    const result = await pool.query(query);
    return result.rows[0];
};

const createEvidence = async (evidenceData) => {
    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.evidence_evidence_id_seq') AS next_id;");
        const nextEvId = parseInt(seqRes.rows[0].next_id, 10);

        const encName = encryptField("evidence", "evidence_name", nextEvId, evidenceData.evidence_name);
        const encDesc = encryptField("evidence", "description", nextEvId, evidenceData.description);
        const encFileName = encryptField("evidence", "file_name", nextEvId, evidenceData.file_name);
        const encFilePath = encryptField("evidence", "file_path", nextEvId, evidenceData.file_path);

        const query = `
            INSERT INTO evidence
            (
                evidence_id,
                evidence_number,
                case_id,
                evidence_name,
                evidence_type,
                description,
                file_name,
                file_path,
                old_evidence_name,
                old_description,
                old_file_name,
                old_file_path,
                file_hash,
                encrypted_aes_key,
                encryption_iv,
                encryption_auth_tag,
                uploaded_by
            )
            OVERRIDING SYSTEM VALUE
            VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING *;
        `;

        const values = [
            nextEvId,
            evidenceData.evidence_number,
            evidenceData.case_id,
            encName,
            evidenceData.evidence_type,
            encDesc,
            encFileName,
            encFilePath,
            evidenceData.evidence_name,
            evidenceData.description,
            evidenceData.file_name,
            evidenceData.file_path,
            evidenceData.file_hash,
            evidenceData.encrypted_aes_key,
            evidenceData.encryption_iv,
            evidenceData.encryption_auth_tag,
            evidenceData.uploaded_by
        ];

        const result = await client.query(query, values);
        await client.query("COMMIT;");
        return decryptEvidenceRow(result.rows[0]);
    } catch (err) {
        await client.query("ROLLBACK;");
        throw err;
    } finally {
        client.release();
    }
};

const getEvidenceById = async (evidenceId) => {
    const query = `
        SELECT
            evidence_id,
            evidence_number,
            file_name,
            file_path,
            file_hash,
            encrypted_aes_key,
            encryption_iv,
            encryption_auth_tag,
            is_legacy_seed
        FROM evidence
        WHERE evidence_id = $1;
    `;
    const result = await pool.query(query, [evidenceId]);
    return decryptEvidenceRow(result.rows[0]);
};

const getAllEvidence = async () => {
    const query = `
        SELECT
            e.evidence_id,
            e.evidence_number,
            e.case_id,
            c.case_number,
            c.case_title,
            e.evidence_name,
            e.evidence_type,
            e.description,
            e.file_name,
            e.file_path,
            e.file_hash,
            e.uploaded_by,
            e.uploaded_at,
            e.is_legacy_seed,
            CASE 
                WHEN e.encrypted_aes_key IS NOT NULL 
                     AND e.encrypted_aes_key LIKE '%:%' 
                     AND e.encryption_iv IS NOT NULL 
                     AND e.encryption_auth_tag IS NOT NULL 
                THEN true 
                ELSE false 
            END AS is_encrypted
        FROM evidence e
        LEFT JOIN cases c
            ON e.case_id = c.case_id
        ORDER BY e.evidence_id DESC;
    `;

    const result = await pool.query(query);
    return result.rows.map(decryptEvidenceRow);
};

module.exports = {
    createEvidence,
    getLatestEvidenceNumber,
    getEvidenceById,
    getAllEvidence,
    decryptEvidenceRow
};