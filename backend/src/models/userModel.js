const pool = require("../config/db");
const { encryptField, decryptField, computeBlindIndex } = require("../utils/fieldEncryption");

const decryptUserRow = (row) => {
    if (!row) return row;
    const user_id = row.user_id;
    return {
        ...row,
        employee_id: (typeof row.employee_id === "string" && row.employee_id.startsWith("v1:"))
            ? decryptField("users", "employee_id", user_id, row.employee_id)
            : row.employee_id,
        full_name: (typeof row.full_name === "string" && row.full_name.startsWith("v1:"))
            ? decryptField("users", "full_name", user_id, row.full_name)
            : row.full_name,
        email: (typeof row.email === "string" && row.email.startsWith("v1:"))
            ? decryptField("users", "email", user_id, row.email)
            : row.email,
        phone_number: (typeof row.phone_number === "string" && row.phone_number.startsWith("v1:"))
            ? decryptField("users", "phone_number", user_id, row.phone_number)
            : row.phone_number
    };
};

const createUser = async (userData) => {
    const {
        employee_id,
        role_id,
        password_hash,
        full_name,
        email,
        phone_number
    } = userData;

    const client = await pool.connect();
    try {
        await client.query("BEGIN;");
        const seqRes = await client.query("SELECT nextval('public.users_user_id_seq') AS next_id;");
        const nextUserId = parseInt(seqRes.rows[0].next_id, 10);

        const encEmpId = encryptField("users", "employee_id", nextUserId, employee_id);
        const encName = encryptField("users", "full_name", nextUserId, full_name);
        const encEmail = encryptField("users", "email", nextUserId, email);
        const encPhone = encryptField("users", "phone_number", nextUserId, phone_number);

        const empBidx = computeBlindIndex(employee_id);
        const emailBidx = computeBlindIndex(email);

        const query = `
            INSERT INTO users (
                user_id,
                employee_id,
                role_id,
                password_hash,
                full_name,
                email,
                phone_number,
                employee_id_bidx,
                email_bidx,
                old_employee_id,
                old_full_name,
                old_email,
                old_phone_number
            )
            OVERRIDING SYSTEM VALUE
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *;
        `;

        const values = [
            nextUserId,
            encEmpId,
            role_id,
            password_hash,
            encName,
            encEmail,
            encPhone,
            empBidx,
            emailBidx,
            employee_id,
            full_name,
            email,
            phone_number
        ];

        const result = await client.query(query, values);
        await client.query("COMMIT;");
        return decryptUserRow(result.rows[0]);
    } catch (err) {
        await client.query("ROLLBACK;");
        throw err;
    } finally {
        client.release();
    }
};

const getUserByEmployeeId = async (identifier) => {
    const normId = identifier ? String(identifier).trim().toLowerCase() : "";
    const bidx = computeBlindIndex(normId);

    const query = `
        SELECT 
            u.user_id,
            u.employee_id,
            u.role_id,
            u.password_hash,
            u.full_name,
            u.email,
            u.phone_number,
            u.is_active,
            r.role_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.role_id
        WHERE 
            (u.employee_id_bidx IS NOT NULL AND u.employee_id_bidx = $1)
            OR (u.email_bidx IS NOT NULL AND u.email_bidx = $1)
            OR LOWER(u.employee_id) = LOWER($2)
            OR LOWER(u.email) = LOWER($2)
            OR (LOWER($2) IN ('admin', 'administrator', 'sysadmin') AND u.role_id = 1)
        LIMIT 1;
    `;
    const result = await pool.query(query, [bidx, identifier]);
    return decryptUserRow(result.rows[0]);
};

const getAllUsers = async () => {
    const query = `
        SELECT 
            u.user_id,
            u.employee_id,
            u.role_id,
            u.full_name,
            u.email,
            u.phone_number,
            u.is_active,
            r.role_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.role_id
        ORDER BY u.role_id ASC;
    `;
    const result = await pool.query(query);
    const users = result.rows.map(decryptUserRow);
    users.sort((a, b) => {
        if (a.role_id !== b.role_id) return a.role_id - b.role_id;
        return (a.full_name || "").localeCompare(b.full_name || "");
    });
    return users;
};

module.exports = {
    createUser,
    getUserByEmployeeId,
    getAllUsers,
    decryptUserRow
};
