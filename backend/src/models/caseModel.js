const pool = require("../config/db");
const { encryptField, decryptField } = require("../utils/fieldEncryption");

const decryptCaseRow = (row) => {
    if (!row) return row;
    const case_id = row.case_id;
    return {
        ...row,
        case_title: (typeof row.case_title === "string" && row.case_title.startsWith("v1:"))
            ? decryptField("cases", "case_title", case_id, row.case_title)
            : row.case_title,
        case_description: (typeof row.case_description === "string" && row.case_description.startsWith("v1:"))
            ? decryptField("cases", "case_description", case_id, row.case_description)
            : row.case_description
    };
};

const getLatestCaseNumber = async () => {
    const query = `
        SELECT case_number
        FROM cases
        ORDER BY case_id DESC
        LIMIT 1;
    `;
    const result = await pool.query(query);
    return result.rows[0];
};

const createCase = async (caseData) => {
    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.cases_case_id_seq') AS next_id;");
        const nextCaseId = parseInt(seqRes.rows[0].next_id, 10);

        const encTitle = encryptField("cases", "case_title", nextCaseId, caseData.case_title);
        const encDesc = encryptField("cases", "case_description", nextCaseId, caseData.case_description);

        const query = `
            INSERT INTO cases
            (
                case_id,
                case_number,
                case_title,
                case_description,
                old_case_title,
                old_case_description,
                investigating_officer,
                created_by,
                status
            )
            OVERRIDING SYSTEM VALUE
            VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *;
        `;

        const values = [
            nextCaseId,
            caseData.case_number,
            encTitle,
            encDesc,
            caseData.case_title,
            caseData.case_description,
            caseData.investigating_officer,
            caseData.created_by,
            caseData.status
        ];

        const result = await client.query(query, values);
        await client.query("COMMIT;");
        return decryptCaseRow(result.rows[0]);
    } catch (err) {
        await client.query("ROLLBACK;");
        throw err;
    } finally {
        client.release();
    }
};

const getAllCases = async () => {
    const query = `
        SELECT
            case_id,
            case_number,
            case_title,
            case_description,
            investigating_officer,
            created_by,
            status,
            created_at
        FROM cases
        ORDER BY case_id DESC;
    `;

    const result = await pool.query(query);
    return result.rows.map(decryptCaseRow);
};

module.exports = {
    getLatestCaseNumber,
    createCase,
    getAllCases,
    decryptCaseRow
};