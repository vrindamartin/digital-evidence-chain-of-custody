/**
 * DIG_EVI — Field-Level Database Encryption Migration & Verification Script
 *
 * Capabilities:
 *   1. Takes an automated pg_dump of the database and halts if it fails.
 *   2. Operates on a target database (defaults strictly to dry-run copy: digital_evidence_db_dryrun).
 *   3. Alters column types to TEXT to support "v1:iv:tag:ciphertext" envelopes.
 *   4. Preserves old plaintext in "old_<column>" backup columns for rollback safety.
 *   5. Encrypts all sensitive fields using AES-256-GCM with HKDF subkeys and row-bound AAD.
 *   6. Computes normalized HMAC-SHA256 blind indexes (employee_id_bidx, email_bidx, file_path_bidx).
 *   7. Upgrades audit_logs with hash_version and seals with a signed MIGRATION_CHECKPOINT entry.
 *   8. Performs 100% round-trip verification: decrypts every encrypted field and asserts 0 mismatches.
 *
 * Security: NEVER prints passwords, secrets, keys, or plaintext data.
 */

const { Client } = require("pg");
const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });
require("dotenv").config();

const {
    encryptField,
    decryptField,
    computeBlindIndex,
    getValidatedRootKeys
} = require("./fieldEncryption");

const { computeAuditEntryHash } = require("../services/auditService");

const crypto = require("crypto");

// Configuration
const DB_HOST = process.env.DB_HOST || "localhost";
const DB_PORT = process.env.DB_PORT || 5432;
const DB_USER = process.env.DB_USER || "postgres";
const DB_PASSWORD = String(process.env.DB_PASSWORD || "");
const LIVE_DB = "digital_evidence_db";

const TABLES_CONFIG = [
    {
        table: "users",
        idCol: "user_id",
        fields: ["employee_id", "full_name", "email", "phone_number"],
        blindIndexes: [
            { source: "employee_id", target: "employee_id_bidx", unique: true },
            { source: "email", target: "email_bidx", unique: false }
        ]
    },
    {
        table: "cases",
        idCol: "case_id",
        fields: ["case_title", "case_description"],
        blindIndexes: []
    },
    {
        table: "evidence",
        idCol: "evidence_id",
        fields: ["evidence_name", "description", "file_name", "file_path"],
        blindIndexes: []
    },
    {
        table: "custody_logs",
        idCol: "custody_id",
        fields: ["remarks"],
        blindIndexes: []
    },
    {
        table: "audit_logs",
        idCol: "audit_id",
        fields: ["details"],
        blindIndexes: [],
        hasHashVersion: true
    },
    {
        table: "tamper_alerts",
        idCol: "alert_id",
        fields: ["message", "email_last_error", "file_path", "resolution_notes"],
        blindIndexes: [
            { source: "file_path", target: "file_path_bidx", unique: false }
        ]
    },
    {
        table: "forensic_reports",
        idCol: "report_id",
        fields: [
            "report_title",
            "tools_used",
            "findings",
            "artifacts_recovered",
            "conclusion",
            "recipient_name",
            "recipient_agency",
            "dispatch_notes"
        ],
        blindIndexes: []
    },
    {
        table: "autopsy_records",
        idCol: "autopsy_id",
        fields: [
            "subject_name",
            "hardware_condition",
            "extraction_method",
            "autopsy_findings",
            "triage_summary",
            "dispatched_to",
            "dispatch_notes"
        ],
        blindIndexes: []
    }
];

function runPgDump(targetDbName) {
    console.log(`[Backup] Initiating automated pg_dump for '${targetDbName}'...`);
    const backupDir = path.resolve(__dirname, "../../../backups");
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const dumpPath = path.join(backupDir, `backup_${targetDbName}_${timestamp}.sql`);

    const env = { ...process.env, PGPASSWORD: DB_PASSWORD };
    const cmd = `pg_dump -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -F p -f "${dumpPath}" ${targetDbName}`;

    try {
        execSync(cmd, { env, stdio: "pipe" });
        console.log(`[Backup] SUCCESS: Full database backup saved to: ${dumpPath}\n`);
        return dumpPath;
    } catch (err) {
        console.error(`[Backup] FATAL ERROR: pg_dump failed! Halting migration immediately:`, err.message);
        throw new Error(`pg_dump failed: ${err.message}`);
    }
}

async function prepareSchemaColumns(client, config) {
    const { table, fields, blindIndexes, hasHashVersion } = config;

    // 1. Add plaintext backup columns old_<field>
    for (const f of fields) {
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = '${table}' AND column_name = 'old_${f}'
                ) THEN
                    ALTER TABLE ${table} ADD COLUMN old_${f} TEXT;
                END IF;
            END $$;
        `);

        // Ensure target column is TEXT to store v1: ciphertext envelope
        await client.query(`ALTER TABLE ${table} ALTER COLUMN ${f} TYPE TEXT;`);
    }

    // 2. Add blind index columns
    for (const bi of blindIndexes) {
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = '${table}' AND column_name = '${bi.target}'
                ) THEN
                    ALTER TABLE ${table} ADD COLUMN ${bi.target} VARCHAR(64);
                END IF;
            END $$;
        `);

        if (bi.unique) {
            await client.query(`
                CREATE UNIQUE INDEX IF NOT EXISTS idx_${table}_${bi.target}_unique 
                ON ${table} (${bi.target}) WHERE ${bi.target} IS NOT NULL;
            `);
        } else {
            await client.query(`
                CREATE INDEX IF NOT EXISTS idx_${table}_${bi.target} 
                ON ${table} (${bi.target});
            `);
        }
    }

    // 3. Add hash_version column if audit_logs
    if (hasHashVersion) {
        await client.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = '${table}' AND column_name = 'hash_version'
                ) THEN
                    ALTER TABLE ${table} ADD COLUMN hash_version INTEGER DEFAULT 1;
                END IF;
            END $$;
        `);
    }
}

async function migrateTableData(client, config) {
    const { table, idCol, fields, blindIndexes, hasHashVersion } = config;
    const fetchRes = await client.query(`SELECT * FROM ${table} ORDER BY ${idCol} ASC;`);
    const rows = fetchRes.rows;

    let migratedCount = 0;

    for (const row of rows) {
        const rowId = row[idCol];
        const updateSets = [];
        const updateVals = [];
        let valIndex = 1;

        // Check if row is already migrated (already starts with v1:)
        let needsUpdate = false;

        for (const f of fields) {
            const rawVal = row[f];
            const oldVal = row[`old_${f}`];

            // If old_<field> is NULL and current rawVal is not encrypted, capture rawVal as old_<field>
            if (oldVal === null && rawVal !== null && !String(rawVal).startsWith("v1:")) {
                updateSets.push(`old_${f} = $${valIndex++}`);
                updateVals.push(rawVal);
                needsUpdate = true;
            }

            // If current rawVal is not encrypted, encrypt it
            if (rawVal !== null && !String(rawVal).startsWith("v1:")) {
                const encrypted = encryptField(table, f, rowId, rawVal);
                updateSets.push(`${f} = $${valIndex++}`);
                updateVals.push(encrypted);
                needsUpdate = true;
            }
        }

        // Blind indexes
        for (const bi of blindIndexes) {
            const currentBidx = row[bi.target];
            const sourceVal = row[`old_${bi.source}`] !== null ? row[`old_${bi.source}`] : row[bi.source];
            if (sourceVal && !currentBidx) {
                const bidx = computeBlindIndex(sourceVal);
                updateSets.push(`${bi.target} = $${valIndex++}`);
                updateVals.push(bidx);
                needsUpdate = true;
            }
        }

        // Hash version for audit_logs
        if (hasHashVersion && (row.hash_version === null || row.hash_version === undefined)) {
            updateSets.push(`hash_version = $${valIndex++}`);
            updateVals.push(1);
            needsUpdate = true;
        }

        if (needsUpdate && updateSets.length > 0) {
            updateVals.push(rowId);
            const updateSql = `
                UPDATE ${table} 
                SET ${updateSets.join(", ")} 
                WHERE ${idCol} = $${valIndex};
            `;
            await client.query(updateSql, updateVals);
            migratedCount++;
        }
    }

    return { totalRows: rows.length, migratedRows: migratedCount };
}

async function verifyTableRoundTrip(client, config) {
    const { table, idCol, fields } = config;
    const fetchRes = await client.query(`SELECT * FROM ${table} ORDER BY ${idCol} ASC;`);
    const rows = fetchRes.rows;

    let checkedFields = 0;
    let mismatches = 0;

    for (const row of rows) {
        const rowId = row[idCol];
        for (const f of fields) {
            const storedCt = row[f];
            const originalPlain = row[`old_${f}`];

            if (originalPlain === null || originalPlain === undefined) {
                if (storedCt !== null) {
                    throw new Error(`Round-trip verification failure on ${table}.${f} (row ${rowId}): expected NULL, got '${storedCt}'`);
                }
                continue;
            }

            if (storedCt === "") {
                if (originalPlain !== "") {
                    throw new Error(`Round-trip verification failure on ${table}.${f} (row ${rowId}): expected empty string mismatch`);
                }
                continue;
            }

            checkedFields++;
            const decrypted = decryptField(table, f, rowId, storedCt);
            if (decrypted !== String(originalPlain)) {
                mismatches++;
                throw new Error(`Round-trip mismatch on ${table}.${f} (row ${rowId})! Decrypted text does not match preserved original value.`);
            }
        }
    }

    return { totalRows: rows.length, checkedFields, mismatches };
}

/**
 * Inserts the MIGRATION_CHECKPOINT audit log entry to establish the bridge
 * from hash_version 1 to hash_version 2.
 */
async function insertMigrationCheckpointAudit(client) {
    const latestRes = await client.query(`
        SELECT audit_id, entry_hash, hash_version 
        FROM audit_logs 
        ORDER BY audit_id DESC 
        LIMIT 1;
    `);

    if (latestRes.rows.length === 0) return null;

    const lastRow = latestRes.rows[0];
    const prevHash = lastRow.entry_hash || "0".repeat(64);

    const seqRes = await client.query("SELECT nextval('public.audit_logs_audit_id_seq') AS next_id;");
    const nextAuditId = parseInt(seqRes.rows[0].next_id, 10);
    const createdAt = new Date();

    const plainDetail = `[MIGRATION_CHECKPOINT] Field-level database encryption activated. Hash chain upgraded to ciphertext hashing (hash_version: 2). Bridge from audit_id ${lastRow.audit_id}.`;
    const encDetail = encryptField("audit_logs", "details", nextAuditId, plainDetail);

    // Compute entry_hash for hash_version 2 (hashed over ciphertext encDetail)
    const entryHash = computeAuditEntryHash(prevHash, {
        audit_id: nextAuditId,
        user_id: null,
        evidence_id: null,
        action: "MIGRATION_CHECKPOINT",
        details: encDetail,
        created_at: createdAt
    });

    const insertSql = `
        INSERT INTO audit_logs 
        (
            audit_id,
            user_id,
            evidence_id,
            action,
            details,
            old_details,
            created_at,
            prev_hash,
            entry_hash,
            hash_version
        )
        OVERRIDING SYSTEM VALUE
        VALUES ($1, NULL, NULL, $2, $3, $4, $5, $6, $7, 2)
        RETURNING *;
    `;

    const res = await client.query(insertSql, [
        nextAuditId,
        "MIGRATION_CHECKPOINT",
        encDetail,
        plainDetail,
        createdAt,
        prevHash,
        entryHash
    ]);

    return res.rows[0];
}

async function verifyAuditChainCompatibility(client) {
    const fetchRes = await client.query(`
        SELECT audit_id, user_id, evidence_id, action, details, old_details, created_at, prev_hash, entry_hash, hash_version
        FROM audit_logs
        ORDER BY audit_id ASC;
    `);
    const rows = fetchRes.rows;

    let expectedPrevHash = "0".repeat(64);

    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];

        if (row.prev_hash !== expectedPrevHash) {
            return {
                valid: false,
                reason: `Linkage broken at audit_id ${row.audit_id}: stored prev_hash does not match expected (${expectedPrevHash.substring(0, 16)}...).`,
                brokenId: row.audit_id
            };
        }

        let computedHash;
        if (row.hash_version === 2) {
            // hash_version 2: hashed over stored ciphertext
            computedHash = computeAuditEntryHash(row.prev_hash, {
                audit_id: row.audit_id,
                user_id: row.user_id,
                evidence_id: row.evidence_id,
                action: row.action,
                details: row.details,
                created_at: row.created_at
            });
        } else {
            // hash_version 1: hashed over decrypted plaintext
            let plainDetails;
            try {
                plainDetails = decryptField("audit_logs", "details", row.audit_id, row.details);
            } catch (decErr) {
                return {
                    valid: false,
                    reason: `Tampering detected at audit_id ${row.audit_id}: decryption authentication failed (${decErr.message}). Ciphertext was modified or corrupted.`,
                    brokenId: row.audit_id
                };
            }

            computedHash = computeAuditEntryHash(row.prev_hash, {
                audit_id: row.audit_id,
                user_id: row.user_id,
                evidence_id: row.evidence_id,
                action: row.action,
                details: plainDetails,
                created_at: row.created_at
            });
        }

        if (row.entry_hash !== computedHash) {
            return {
                valid: false,
                reason: `Content hash mismatch at audit_id ${row.audit_id} (hash_version: ${row.hash_version || 1}). Stored: ${row.entry_hash.substring(0, 16)}..., Computed: ${computedHash.substring(0, 16)}...`,
                brokenId: row.audit_id
            };
        }

        expectedPrevHash = row.entry_hash;
    }

    return {
        valid: true,
        totalVerified: rows.length,
        latestHash: rows.length > 0 ? rows[rows.length - 1].entry_hash : "0".repeat(64)
    };
}

async function runMigration({ targetDb, isDryRun }) {
    console.log("================================================================================");
    console.log(`FIELD-LEVEL DATABASE ENCRYPTION MIGRATION [${isDryRun ? "DRY-RUN ON COPY" : "LIVE DATABASE"}]`);
    console.log(`Target Database: ${targetDb}`);
    console.log("================================================================================\n");

    // 1. Mandatory Pre-Flight Backup
    runPgDump(targetDb);

    const client = new Client({
        host: DB_HOST,
        port: DB_PORT,
        user: DB_USER,
        password: DB_PASSWORD,
        database: targetDb
    });

    await client.connect();

    try {
        console.log("[Migration] Applying schema enhancements (TEXT types, old_* columns, blind indexes)...");
        for (const config of TABLES_CONFIG) {
            await prepareSchemaColumns(client, config);
        }
        console.log("[Migration] Schema structure prepared.\n");

        console.log("[Migration] Encrypting table records in batches...");
        const tableStats = [];
        for (const config of TABLES_CONFIG) {
            const stats = await migrateTableData(client, config);
            tableStats.push({ table: config.table, ...stats });
            console.log(`  -> ${config.table.padEnd(18)} Total Rows: ${String(stats.totalRows).padStart(4)} | Migrated Rows: ${String(stats.migratedRows).padStart(4)}`);
        }
        console.log("\n[Migration] Inserting MIGRATION_CHECKPOINT audit checkpoint...");
        const checkpointEntry = await insertMigrationCheckpointAudit(client);
        if (checkpointEntry) {
            console.log(`  -> Inserted checkpoint audit_id #${checkpointEntry.audit_id} (hash_version: 2)`);
        }

        console.log("\n[Verification] Performing 100% Round-Trip Decryption Check on every migrated field...");
        let grandTotalCheckedFields = 0;
        let grandTotalMismatches = 0;

        for (const config of TABLES_CONFIG) {
            const vStats = await verifyTableRoundTrip(client, config);
            grandTotalCheckedFields += vStats.checkedFields;
            grandTotalMismatches += vStats.mismatches;
            console.log(`  -> ${config.table.padEnd(18)} Rows: ${String(vStats.totalRows).padStart(4)} | Fields Verified: ${String(vStats.checkedFields).padStart(4)} | Mismatches: ${vStats.mismatches}`);
        }

        console.log(`\n[Verification] SUMMARY: ${grandTotalCheckedFields} sensitive values decrypted and compared vs original plaintext.`);
        if (grandTotalMismatches > 0) {
            throw new Error(`CRITICAL: Detected ${grandTotalMismatches} round-trip mismatches!`);
        }
        console.log("[Verification] SUCCESS: EXACT ZERO MISMATCHES across all tables!\n");

        console.log("[AuditChain] Verifying entire audit chain compatibility across v1 and v2 records...");
        const chainRes = await verifyAuditChainCompatibility(client);
        if (!chainRes.valid) {
            throw new Error(`Audit chain verification failed: ${chainRes.reason}`);
        }
        console.log(`[AuditChain] SUCCESS: Validated ${chainRes.totalVerified} audit records with seamless v1 -> v2 checkpoint linkage.\n`);

        return {
            success: true,
            targetDb,
            isDryRun,
            tableStats,
            totalFieldsVerified: grandTotalCheckedFields,
            auditRecordsVerified: chainRes.totalVerified
        };

    } finally {
        await client.end();
    }
}

// Execution entry point
if (require.main === module) {
    const isLive = process.argv.includes("--live");
    const targetDb = isLive ? LIVE_DB : "digital_evidence_db_dryrun";

    runMigration({ targetDb, isDryRun: !isLive })
        .then(res => {
            console.log("================================================================================");
            console.log(`MIGRATION SCRIPT FINISHED SUCCESSFULLY [${res.isDryRun ? "DRY RUN COMPLETE" : "LIVE APPLIED"}]`);
            console.log("================================================================================");
            process.exit(0);
        })
        .catch(err => {
            console.error("Migration failed:", err);
            process.exit(1);
        });
}

module.exports = {
    runMigration,
    verifyAuditChainCompatibility
};
