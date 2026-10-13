/**
 * =============================================================================
 * DIG_EVI — Safe Demo Tamper Reset Utility
 * =============================================================================
 *
 * Restores test exhibit EV-2026-012 (evidence_id: 14) to its pristine, intact
 * state following a live tamper detection demonstration.
 *
 * Safety Guards:
 * - Refuses to execute if NODE_ENV === 'production'
 * - Hardcoded restriction strictly to test exhibit EV-2026-012 (evidence_id: 14)
 * - Restores .enc ciphertext bit-for-bit from backup
 * - Resolves any active demo alerts for EV-2026-012 via official model helper
 * - Executes post-restore cryptographic integrity check verifying status INTACT
 *
 * Usage:
 *   node backend/src/utils/resetDemoTamper.js
 * =============================================================================
 */

require("dotenv").config({ path: require("path").resolve(__dirname, "../../.env") });
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const pool = require("../config/db");
const alertService = require("../services/alertService");
const alertModel = require("../models/alertModel");
const evidenceModel = require("../models/evidenceModel");

// Production safety guard: Refuse to run in production
if (process.env.NODE_ENV === "production") {
    console.error("\n================================================================================");
    console.error("FATAL SAFETY ERROR: Refusing to execute demo reset in PRODUCTION environment!");
    console.error("NODE_ENV is set to 'production'. Demo reset aborted.");
    console.error("================================================================================\n");
    process.exit(1);
}

// Strict exhibit restriction: EV-2026-012 only
const TEST_EVIDENCE_ID = 14;
const EXPECTED_EVIDENCE_NUMBER = "EV-2026-012";

// External backup directory outside uploads/
const BACKUP_DIR = path.resolve(__dirname, "../../../scratch/backups");

async function resetDemoTamper() {
    console.log("================================================================================");
    console.log("           DIG_EVI — DEMO TAMPER RESET UTILITY                                  ");
    console.log("================================================================================\n");

    // Step 0: Fetch test exhibit and verify strict exhibit identity
    const testEvidence = await evidenceModel.getEvidenceById(TEST_EVIDENCE_ID);
    if (!testEvidence) {
        throw new Error(`Test exhibit with evidence_id ${TEST_EVIDENCE_ID} not found in database!`);
    }

    if (testEvidence.evidence_id !== TEST_EVIDENCE_ID || testEvidence.evidence_number !== EXPECTED_EVIDENCE_NUMBER) {
        console.error("\nFATAL SAFETY VIOLATION: Target record is not the verified test exhibit!");
        console.error(`Expected: #${TEST_EVIDENCE_ID} (${EXPECTED_EVIDENCE_NUMBER}), Received: #${testEvidence.evidence_id} (${testEvidence.evidence_number})`);
        process.exit(1);
    }

    const encFilePath = path.resolve(testEvidence.file_path);
    console.log(`[Target Exhibit] Exhibit: ${testEvidence.evidence_number} ("${testEvidence.evidence_name}")`);
    console.log(`[Target Exhibit] File:    ${path.basename(encFilePath)}`);
    console.log(`[Target Exhibit] Safety:  RESTRICTED TO TEST EXHIBIT ONLY\n`);

    // Step 1: Locate backup file
    console.log("--------------------------------------------------------------------------------");
    console.log("STEP 1: Locating verified backup of test exhibit ciphertext...");
    console.log("--------------------------------------------------------------------------------");
    const primaryBackupPath = path.join(BACKUP_DIR, `${path.basename(encFilePath)}.bak`);
    const alternateBackupPath = path.join(BACKUP_DIR, `${path.basename(encFilePath)}`);

    let backupSource = null;
    if (fs.existsSync(primaryBackupPath)) {
        backupSource = primaryBackupPath;
    } else if (fs.existsSync(alternateBackupPath)) {
        backupSource = alternateBackupPath;
    }

    if (!backupSource) {
        throw new Error(
            `No backup found for ${path.basename(encFilePath)} in ${BACKUP_DIR}.\n` +
            `Please ensure a backup exists at ${primaryBackupPath}.`
        );
    }

    console.log(`[Backup Found] Source: ${backupSource}`);
    const backupBytes = fs.readFileSync(backupSource);
    const backupHash = crypto.createHash("sha256").update(backupBytes).digest("hex");
    console.log(`[Backup Found] Size:   ${backupBytes.length} bytes`);
    console.log(`[Backup Found] Hash:   ${backupHash}\n`);

    // Step 2: Restore original file to destination
    console.log("--------------------------------------------------------------------------------");
    console.log("STEP 2: Restoring original ciphertext to destination...");
    console.log("--------------------------------------------------------------------------------");
    fs.copyFileSync(backupSource, encFilePath);
    const restoredBytes = fs.readFileSync(encFilePath);
    const restoredHash = crypto.createHash("sha256").update(restoredBytes).digest("hex");

    if (restoredHash !== backupHash) {
        throw new Error(`Restoration failed: Restored file hash (${restoredHash}) does not match backup (${backupHash})!`);
    }
    console.log(`[Restored] Target:     ${encFilePath}`);
    console.log(`[Restored] Size:       ${restoredBytes.length} bytes`);
    console.log(`[Restored] Integrity:  100% BIT-FOR-BIT RESTORATION CONFIRMED\n`);

    // Step 3: Resolve any active alerts for EV-2026-012 in PostgreSQL
    console.log("--------------------------------------------------------------------------------");
    console.log("STEP 3: Resolving active demo alerts in PostgreSQL...");
    console.log("--------------------------------------------------------------------------------");
    const activeAlerts = await pool.query(
        "SELECT alert_id, alert_type, status FROM tamper_alerts WHERE evidence_id = $1 AND status = 'ACTIVE' ORDER BY alert_id DESC;",
        [TEST_EVIDENCE_ID]
    );

    if (activeAlerts.rows.length === 0) {
        console.log(`[Alerts] No active demo alerts found for exhibit ${testEvidence.evidence_number}.\n`);
    } else {
        const adminRes = await pool.query(
            "SELECT user_id, full_name FROM users WHERE role_id = 1 AND is_active = TRUE ORDER BY user_id ASC LIMIT 1;"
        );
        const adminUserId = adminRes.rows[0] ? adminRes.rows[0].user_id : 6;
        const resolutionNote = `Demo reset: ${testEvidence.evidence_number} restored to intact state before presentation.`;

        for (const row of activeAlerts.rows) {
            await alertModel.resolveAlert(row.alert_id, adminUserId, resolutionNote);
            console.log(`[Alert Resolved] Alert #${row.alert_id} (${row.alert_type}) marked RESOLVED by User ID ${adminUserId}.`);
        }
        console.log(`[Alerts] All active demo alerts for ${testEvidence.evidence_number} resolved.\n`);
    }

    // Step 4: Re-verify integrity through alertService
    console.log("--------------------------------------------------------------------------------");
    console.log("STEP 4: Executing post-reset cryptographic integrity scan...");
    console.log("--------------------------------------------------------------------------------");
    const verifyResult = await alertService.checkEvidenceIntegrity(testEvidence);
    console.log(`[Verification] Exhibit:    ${verifyResult.evidence_number} (#${verifyResult.evidence_id})`);
    console.log(`[Verification] Status:     ${verifyResult.status}`);
    console.log(`[Verification] New Alerts: ${verifyResult.new_alert_created ? "YES (UNEXPECTED)" : "NONE (CLEAN)"}`);

    if (verifyResult.status !== "INTACT") {
        throw new Error(`Integrity check failed: Expected status INTACT, received ${verifyResult.status}!`);
    }

    console.log("\n================================================================================");
    console.log(">>> DEMO RESET SUCCESSFUL: EXHIBIT EV-2026-012 VERIFIED INTACT & ALERT CENTER CLEAN");
    console.log("================================================================================\n");
}

if (require.main === module) {
    resetDemoTamper()
        .then(() => {
            process.exit(0);
        })
        .catch((err) => {
            console.error("Demo reset failed with error:", err);
            process.exit(1);
        });
}

module.exports = { resetDemoTamper };
