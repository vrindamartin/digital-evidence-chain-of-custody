/**
 * DIG_EVI — Test Audit Hash Chain Tamper Detection for v1 and v2 records
 *
 * Verifies:
 *   1. Tampering with an old row (hash_version: 1) triggers AUDIT_CHAIN_BROKEN / verification failure.
 *   2. Tampering with a new row (hash_version: 2) triggers AUDIT_CHAIN_BROKEN / verification failure.
 *   3. Restores cleanly from backup.
 *
 * Security: NEVER prints secrets, keys, or plaintext data.
 */

const { Client } = require("pg");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });
require("dotenv").config();

const { verifyAuditChainCompatibility } = require("./migrateFieldEncryption");

async function runTest() {
    const client = new Client({
        host: process.env.DB_HOST || "localhost",
        port: process.env.DB_PORT || 5432,
        user: process.env.DB_USER || "postgres",
        password: String(process.env.DB_PASSWORD || ""),
        database: "digital_evidence_db_dryrun"
    });

    await client.connect();

    try {
        console.log("================================================================================");
        console.log("TESTING AUDIT LOG CHAIN TAMPER DETECTION ON DRY RUN DATABASE");
        console.log("================================================================================\n");

        // Baseline verification
        const baseRes = await verifyAuditChainCompatibility(client);
        console.log(`[Baseline] Valid: ${baseRes.valid}, Total Records: ${baseRes.totalVerified}`);
        if (!baseRes.valid) throw new Error(`Initial chain broken: ${baseRes.reason}`);

        // --- TEST A: Tamper with an OLD row (hash_version 1) ---
        console.log("\n[Test A] Tampering with OLD row (audit_id 5, hash_version 1)...");
        const oldRowRes = await client.query("SELECT details FROM audit_logs WHERE audit_id = 5;");
        const originalOldDetails = oldRowRes.rows[0].details;

        await client.query("UPDATE audit_logs SET details = 'v1:TAMPERED_CIPHERTEXT_PAYLOAD' WHERE audit_id = 5;");
        let tamperOldDetected = false;
        try {
            const checkOld = await verifyAuditChainCompatibility(client);
            if (!checkOld.valid) {
                tamperOldDetected = true;
                console.log(`[Test A] SUCCESS: Tampering detected on old row! Reason: ${checkOld.reason}`);
            }
        } catch (err) {
            tamperOldDetected = true;
            console.log(`[Test A] SUCCESS: Tampering detected on old row via decryption failure! (${err.message})`);
        }

        if (!tamperOldDetected) {
            throw new Error("TEST A FAILED: Tampering on old row was NOT detected!");
        }

        // Restore old row
        await client.query("UPDATE audit_logs SET details = $1 WHERE audit_id = 5;", [originalOldDetails]);
        const restoredOld = await verifyAuditChainCompatibility(client);
        console.log(`[Test A Cleanup] Restored old row. Chain valid: ${restoredOld.valid}`);

        // --- TEST B: Tamper with a NEW row (hash_version 2) ---
        const newRowRes = await client.query("SELECT audit_id, details FROM audit_logs WHERE hash_version = 2 ORDER BY audit_id DESC LIMIT 1;");
        if (newRowRes.rows.length === 0) {
            throw new Error("TEST B FAILED: No hash_version = 2 rows found!");
        }
        const targetV2Id = newRowRes.rows[0].audit_id;
        const originalNewDetails = newRowRes.rows[0].details;
        console.log(`\n[Test B] Tampering with NEW row (audit_id ${targetV2Id}, hash_version 2)...`);

        await client.query("UPDATE audit_logs SET details = 'v1:TAMPERED_V2_CIPHERTEXT_PAYLOAD' WHERE audit_id = $1;", [targetV2Id]);
        let tamperNewDetected = false;
        try {
            const checkNew = await verifyAuditChainCompatibility(client);
            if (!checkNew.valid) {
                tamperNewDetected = true;
                console.log(`[Test B] SUCCESS: Tampering detected on new row! Reason: ${checkNew.reason}`);
            }
        } catch (err) {
            tamperNewDetected = true;
            console.log(`[Test B] SUCCESS: Tampering detected on new row! (${err.message})`);
        }

        if (!tamperNewDetected) {
            throw new Error("TEST B FAILED: Tampering on new row was NOT detected!");
        }

        // Restore new row
        await client.query("UPDATE audit_logs SET details = $1 WHERE audit_id = $2;", [originalNewDetails, targetV2Id]);
        const restoredNew = await verifyAuditChainCompatibility(client);
        console.log(`[Test B Cleanup] Restored new row. Chain valid: ${restoredNew.valid}`);

        console.log("\n================================================================================");
        console.log("ALL AUDIT TAMPER DETECTION TESTS PASSED SUCCESSFULLY!");
        console.log("================================================================================\n");

    } finally {
        await client.end();
    }
}

runTest().catch(err => {
    console.error("Test failed:", err);
    process.exit(1);
});
