/**
 * DIG_EVI — Field-Level Database Encryption & Blind Index Engine
 *
 * Implements:
 *   - AES-256-GCM authenticated envelope encryption with "v1:" version prefix
 *   - Per-table and per-column subkey derivation via HKDF (RFC 5869)
 *   - Row-bound Additional Authenticated Data (AAD) preventing ciphertext swapping across rows
 *   - Deterministic HMAC-SHA256 blind indexing for exact-match database queries
 *   - Strict fail-loud security: refuses to start without valid 32-byte keys,
 *     fails loudly on authentication tag or decryption failures (never returns corrupt/silent data).
 *
 * Security: NEVER prints secrets, keys, or plaintext in logs/output.
 */

const crypto = require("crypto");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });
require("dotenv").config();

const HKDF_SALT = Buffer.from("dig_evi_data_encryption_hkdf_salt_v1", "utf8");
const subKeyCache = new Map();

/**
 * Validates and retrieves root cryptographic keys.
 * Fails loudly on missing or invalid key configurations.
 */
function getValidatedRootKeys() {
    const rawDek = process.env.DATA_ENCRYPTION_KEY;
    const rawBik = process.env.BLIND_INDEX_KEY;

    if (!rawDek || typeof rawDek !== "string") {
        throw new Error("[FieldEncryption] FATAL: DATA_ENCRYPTION_KEY environment variable is missing.");
    }
    if (!rawBik || typeof rawBik !== "string") {
        throw new Error("[FieldEncryption] FATAL: BLIND_INDEX_KEY environment variable is missing.");
    }

    let dekBuffer;
    if (rawDek.length === 64 && /^[0-9a-fA-F]+$/.test(rawDek)) {
        dekBuffer = Buffer.from(rawDek, "hex");
    } else {
        dekBuffer = Buffer.from(rawDek, "utf8");
    }

    let bikBuffer;
    if (rawBik.length === 64 && /^[0-9a-fA-F]+$/.test(rawBik)) {
        bikBuffer = Buffer.from(rawBik, "hex");
    } else {
        bikBuffer = Buffer.from(rawBik, "utf8");
    }

    if (dekBuffer.length !== 32) {
        throw new Error(`[FieldEncryption] FATAL: DATA_ENCRYPTION_KEY must be exactly 32 bytes (got ${dekBuffer.length}).`);
    }
    if (bikBuffer.length !== 32) {
        throw new Error(`[FieldEncryption] FATAL: BLIND_INDEX_KEY must be exactly 32 bytes (got ${bikBuffer.length}).`);
    }

    return { dekBuffer, bikBuffer };
}

// Immediate validation at module initialization to prevent application boot with bad keys
const { dekBuffer: ROOT_DEK, bikBuffer: ROOT_BIK } = getValidatedRootKeys();

/**
 * Derives a dedicated 32-byte AES-256 key for a specific table and column using HKDF.
 *
 * @param {string} table
 * @param {string} column
 * @returns {Buffer} 32-byte derived subkey
 */
function getDerivedSubKey(table, column) {
    const cacheKey = `${table}:${column}`;
    if (subKeyCache.has(cacheKey)) {
        return subKeyCache.get(cacheKey);
    }

    const info = Buffer.from(`${table}:${column}`, "utf8");
    const derived = crypto.hkdfSync("sha256", ROOT_DEK, HKDF_SALT, info, 32);
    const subKey = Buffer.from(derived);
    subKeyCache.set(cacheKey, subKey);
    return subKey;
}

/**
 * Encrypts a sensitive database field value using AES-256-GCM.
 *
 * @param {string} table Database table name
 * @param {string} column Database column name
 * @param {string|number} rowId Unique row identifier (bound into AAD)
 * @param {string|null} plaintext Plaintext value
 * @returns {string|null} Versioned ciphertext "v1:iv:tag:ciphertext" (base64)
 */
function encryptField(table, column, rowId, plaintext) {
    if (plaintext === null || plaintext === undefined) {
        return null;
    }
    if (plaintext === "") {
        return "";
    }

    const strValue = String(plaintext);
    const subKey = getDerivedSubKey(table, column);
    const iv = crypto.randomBytes(12);
    const aad = Buffer.from(`${table}:${column}:${rowId}`, "utf8");

    const cipher = crypto.createCipheriv("aes-256-gcm", subKey, iv);
    cipher.setAAD(aad);

    const encrypted = Buffer.concat([
        cipher.update(strValue, "utf8"),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${encrypted.toString("base64")}`;
}

/**
 * Decrypts a sensitive database field value using AES-256-GCM.
 * Fails loudly on authentication tag mismatch, tampering, or corrupted ciphertext.
 *
 * @param {string} table Database table name
 * @param {string} column Database column name
 * @param {string|number} rowId Unique row identifier (verified via AAD)
 * @param {string|null} storedValue Stored database value
 * @returns {string|null} Decrypted plaintext value
 */
function decryptField(table, column, rowId, storedValue) {
    if (storedValue === null || storedValue === undefined) {
        return null;
    }
    if (storedValue === "") {
        return "";
    }

    if (typeof storedValue !== "string" || !storedValue.startsWith("v1:")) {
        throw new Error(`[FieldEncryption] Decryption failed: invalid ciphertext format for ${table}.${column} (row ${rowId}). Expected 'v1:...' envelope.`);
    }

    const parts = storedValue.split(":");
    if (parts.length !== 4) {
        throw new Error(`[FieldEncryption] Decryption failed: malformed ciphertext envelope for ${table}.${column} (row ${rowId}).`);
    }

    const [, ivB64, tagB64, ctB64] = parts;
    const iv = Buffer.from(ivB64, "base64");
    const tag = Buffer.from(tagB64, "base64");
    const ciphertext = Buffer.from(ctB64, "base64");
    const aad = Buffer.from(`${table}:${column}:${rowId}`, "utf8");
    const subKey = getDerivedSubKey(table, column);

    try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", subKey, iv);
        decipher.setAAD(aad);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        return decrypted.toString("utf8");
    } catch (err) {
        throw new Error(`[FieldEncryption] Decryption authentication failed for ${table}.${column} (row ${rowId}): ${err.message}`);
    }
}

/**
 * Computes a normalized HMAC-SHA256 blind index for exact-match lookups.
 * Normalizes input by trimming and converting to lowercase.
 *
 * @param {string|null} value
 * @returns {string|null} 64-character hex digest blind index
 */
function computeBlindIndex(value) {
    if (value === null || value === undefined) {
        return null;
    }
    const normalized = String(value).trim().toLowerCase();
    if (!normalized) {
        return null;
    }
    return crypto.createHmac("sha256", ROOT_BIK).update(normalized, "utf8").digest("hex");
}

module.exports = {
    encryptField,
    decryptField,
    computeBlindIndex,
    getValidatedRootKeys
};

