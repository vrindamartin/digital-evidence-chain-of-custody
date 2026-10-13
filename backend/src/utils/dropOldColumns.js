/**
 * =============================================================================
 * DIG_EVI — Safe Transactional Drop Utility for Legacy Migration Columns (old_*)
 * =============================================================================
 *
 * Pre-checks that 100% of encrypted fields decrypt correctly and match the
 * fallback old_* columns (round-trip verification) before dropping them inside
 * a single atomic PostgreSQL transaction.
 *
 * Safety Rules:
 * - Refuses to drop in dry-run mode (default).
 * - Requires explicit --execute flag to apply changes.
 * - If even a single mismatch or decryption failure occurs, rolls back immediately.
 *
 * Usage:
 *   node backend/src/utils/dropOldColumns.js            (Dry-run pre-check only)
 *   node backend/src/utils/dropOldColumns.js --dry-run  (Explicit dry-run pre-check)
 *   node backend/src/utils/dropOldColumns.js --execute  (Atomic transaction drop - requires approval)
 * =============================================================================
 */

require("dotenv").config({ path: require("path").resolve(__dirname, "../../.env") });
const pool = require("../config/db");
const { decryptField, encryptField } = require("./fieldEncryption");

const ENCRYPTED_COLUMNS_SPEC = [
    {
        table: "users",
        idCol: "user_id",
        columns: ["employee_id", "full_name", "email", "phone_number"]
    },
    {
        table: "cases",
        idCol: "case_id",
        columns: ["case_title", "case_description"]
    },
    {
        table: "evidence",
        idCol: "evidence_id",
        columns: ["evidence_name", "description", "file_name", "file_path"]
    },
    {
        table: "custody_logs",
        idCol: "custody_id",
        columns: ["remarks"]
    },
    {
        table: "audit_logs",
        idCol: "audit_id",
        columns: ["details"]
    },
    {
        table: "tamper_alerts",
        idCol: "alert_id",
        columns: ["message", "email_last_error", "file_path", "resolution_notes"]
    },
    {
        table: "forensic_reports",
        idCol: "report_id",
        columns: [
            "report_title", "tools_used", "findings",
            "artifacts_recovered", "conclusion", "recipient_name",
            "recipient_agency", "dispatch_notes"
        ]
    },
    {
        table: "autopsy_records",
        idCol: "autopsy_id",
        columns: [
            "subject_name", "hardware_condition", "extraction_method",
            "autopsy_findings", "triage_summary", "dispatched_to", "dispatch_notes"
        ]
    }
];

const DROP_STATEMENTS = [
    "ALTER TABLE audit_logs DROP COLUMN IF EXISTS old_details;",
    `ALTER TABLE autopsy_records 
        DROP COLUMN IF EXISTS old_autopsy_findings,
        DROP COLUMN IF EXISTS old_dispatch_notes,
        DROP COLUMN IF EXISTS old_dispatched_to,
        DROP COLUMN IF EXISTS old_extraction_method,
        DROP COLUMN IF EXISTS old_hardware_condition,
        DROP COLUMN IF EXISTS old_subject_name,
        DROP COLUMN IF EXISTS old_triage_summary;`,
    `ALTER TABLE cases 
        DROP COLUMN IF EXISTS old_case_description,
        DROP COLUMN IF EXISTS old_case_title;`,
    "ALTER TABLE custody_logs DROP COLUMN IF EXISTS old_remarks;",
    `ALTER TABLE evidence 
        DROP COLUMN IF EXISTS old_description,
        DROP COLUMN IF EXISTS old_evidence_name,
        DROP COLUMN IF EXISTS old_file_name,
        DROP COLUMN IF EXISTS old_file_path;`,
    `ALTER TABLE forensic_reports 
        DROP COLUMN IF EXISTS old_artifacts_recovered,
        DROP COLUMN IF EXISTS old_conclusion,
        DROP COLUMN IF EXISTS old_dispatch_notes,
        DROP COLUMN IF EXISTS old_findings,
        DROP COLUMN IF EXISTS old_recipient_agency,
        DROP COLUMN IF EXISTS old_recipient_name,
        DROP COLUMN IF EXISTS old_report_title,
        DROP COLUMN IF EXISTS old_tools_used;`,
    `ALTER TABLE tamper_alerts 
        DROP COLUMN IF EXISTS old_email_last_error,
        DROP COLUMN IF EXISTS old_file_path,
        DROP COLUMN IF EXISTS old_message,
        DROP COLUMN IF EXISTS old_resolution_notes;`,
    `ALTER TABLE users 
        DROP COLUMN IF EXISTS old_email,
        DROP COLUMN IF EXISTS old_employee_id,
        DROP COLUMN IF EXISTS old_full_name,
        DROP COLUMN IF EXISTS old_phone_number;`
];

async function verifyAllEncryptedColumnsRoundTrip(client) {
    console.log("--------------------------------------------------------------------------------");
    console.log("PHASE 1: PRE-CHECK — VERIFYING 100% ENCRYPTED COLUMN ROUND-TRIP FIDELITY");
    console.log("--------------------------------------------------------------------------------\n");

    let totalChecked = 0;
    let totalMatches = 0;
    let mismatches = [];

    for (const spec of ENCRYPTED_COLUMNS_SPEC) {
        const selectCols = [spec.idCol];
        for (const col of spec.columns) {
            selectCols.push(col);
            selectCols.push(`old_${col}`);
        }

        const query = `SELECT ${selectCols.join(", ")} FROM ${spec.table} ORDER BY ${spec.idCol} ASC;`;
        let res;
        try {
            res = await client.query(query);
        } catch (queryErr) {
            console.error(`Failed to query table ${spec.table}: ${queryErr.message}`);
            throw queryErr;
        }

        let tableCount = 0;
        for (const row of res.rows) {
            const rowId = row[spec.idCol];
            for (const col of spec.columns) {
                const cipherVal = row[col];
                const oldVal = row[`old_${col}`];

                if (cipherVal === null || cipherVal === undefined) {
                    if (oldVal !== null && oldVal !== undefined) {
                        mismatches.push({
                            table: spec.table,
                            id: rowId,
                            column: col,
                            reason: "Ciphertext is null but old_* column contains value"
                        });
                    }
                    continue;
                }

                totalChecked++;
                tableCount++;

                // 1. Decrypt ciphertext
                let decryptedVal;
                try {
                    decryptedVal = decryptField(spec.table, col, rowId, cipherVal);
                } catch (decErr) {
                    mismatches.push({
                        table: spec.table,
                        id: rowId,
                        column: col,
                        reason: `Decryption failed: ${decErr.message}`
                    });
                    continue;
                }

                // 2. Re-encrypt and verify round-trip
                try {
                    const reEnc = encryptField(spec.table, col, rowId, decryptedVal);
                    const reDec = decryptField(spec.table, col, rowId, reEnc);
                    if (reDec !== decryptedVal) {
                        mismatches.push({
                            table: spec.table,
                            id: rowId,
                            column: col,
                            reason: "Round-trip re-encryption mismatch"
                        });
                        continue;
                    }
                } catch (reEncErr) {
                    mismatches.push({
                        table: spec.table,
                        id: rowId,
                        column: col,
                        reason: `Re-encryption failed: ${reEncErr.message}`
                    });
                    continue;
                }

                // 3. Verify against old_* column if old_* exists and has value
                if (oldVal !== null && oldVal !== undefined) {
                    if (decryptedVal !== oldVal) {
                        mismatches.push({
                            table: spec.table,
                            id: rowId,
                            column: col,
                            reason: "Decrypted plaintext differs from old_* column value"
                        });
                        continue;
                    }
                }

                totalMatches++;
            }
        }

        console.log(`  [Table Checked] ${spec.table.padEnd(18)} : ${res.rows.length} rows, ${tableCount} encrypted values verified.`);
    }

    console.log(`\n[Pre-Check Summary] Total Encrypted Values Verified: ${totalChecked}`);
    console.log(`[Pre-Check Summary] 100% Round-Trip Matches:          ${totalMatches}`);
    console.log(`[Pre-Check Summary] Mismatches / Failures:           ${mismatches.length}`);

    if (mismatches.length > 0) {
        console.error("\nFATAL INTEGRITY ERROR: Pre-check detected mismatches!");
        mismatches.forEach(m => console.error(`  - ${m.table} #${m.id} (${m.column}): ${m.reason}`));
        throw new Error(`Pre-check failed with ${mismatches.length} mismatches! Transaction aborted.`);
    }

    console.log("\n>>> PRE-CHECK PASSED WITH 100% SUCCESS (ZERO MISMATCHES)\n");
    return { totalChecked, totalMatches };
}

async function runDropScript() {
    const isExecuteMode = process.argv.includes("--execute");

    console.log("================================================================================");
    console.log("       DIG_EVI — TRANSACTIONAL DROP UTILITY FOR MIGRATION COLUMNS (old_*)       ");
    console.log(`       MODE: ${isExecuteMode ? "LIVE EXECUTE (COMMITTING CHANGES)" : "DRY RUN ONLY (NO CHANGES APPLIED)"}`);
    console.log("================================================================================\n");

    const client = await pool.connect();
    try {
        await client.query("BEGIN;");

        // Step 1: Pre-check round-trip on all tables
        const verification = await verifyAllEncryptedColumnsRoundTrip(client);

        // Step 2: Show SQL statements to execute
        console.log("--------------------------------------------------------------------------------");
        console.log("PHASE 2: TRANSACTIONAL DROP STATEMENTS");
        console.log("--------------------------------------------------------------------------------\n");
        DROP_STATEMENTS.forEach((stmt, idx) => {
            console.log(`-- Statement ${idx + 1}:`);
            console.log(stmt.trim() + "\n");
        });

        if (!isExecuteMode) {
            console.log("--------------------------------------------------------------------------------");
            console.log(">>> DRY-RUN COMPLETE: ROLLING BACK TRANSACTION WITHOUT ALTERING SCHEMA.");
            console.log(">>> To execute this drop permanently, pass the --execute flag after approval.");
            console.log("--------------------------------------------------------------------------------\n");
            await client.query("ROLLBACK;");
            return { executed: false, verification };
        }

        console.log("--------------------------------------------------------------------------------");
        console.log(">>> EXECUTING ATOMIC SCHEMA DROP IN SINGLE TRANSACTION...");
        console.log("--------------------------------------------------------------------------------\n");

        for (const stmt of DROP_STATEMENTS) {
            await client.query(stmt);
        }

        await client.query("COMMIT;");
        console.log(">>> ATOMIC TRANSACTION COMMITTED SUCCESSFULLY: ALL 31 old_* COLUMNS DROPPED.\n");
        return { executed: true, verification };
    } catch (err) {
        await client.query("ROLLBACK;");
        console.error("\nFATAL ERROR DURING TRANSACTION: Rollback executed.");
        console.error(err.message);
        throw err;
    } finally {
        client.release();
    }
}

if (require.main === module) {
    runDropScript()
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
}

module.exports = {
    runDropScript,
    verifyAllEncryptedColumnsRoundTrip,
    DROP_STATEMENTS
};
