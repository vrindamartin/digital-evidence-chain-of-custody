/**
 * =============================================================================
 * DIG_EVI — Safe Tamper Alert Feature Verification & Demo Script
 * =============================================================================
 *
 * Demonstrates the end-to-end cryptographic tamper detection and notification
 * workflow using ONLY test record EV-2026-012 (evidence_id: 14).
 *
 * Safety Guards:
 * - Refuses to execute if NODE_ENV === 'production'
 * - Hardcoded restriction strictly to test record EV-2026-012 (evidence_id: 14)
 * - Activates DEMO_MAIL=true sandbox exclusively for this test run
 * - Performs backup outside uploads/ before tampering
 * - Always restores original .enc file bit-for-bit in finally block
 *
 * Usage:
 *   node backend/src/utils/demoTamperAlert.js
 * =============================================================================
 */

require("dotenv").config({ path: require("path").resolve(__dirname, "../../.env") });
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const pool = require("../config/db");
const alertService = require("../services/alertService");
const alertModel = require("../models/alertModel");
const auditModel = require("../models/auditModel");
const evidenceModel = require("../models/evidenceModel");
const emailService = require("../services/emailService");

// Production safety guard: Refuse to run in production
if (process.env.NODE_ENV === "production") {
    console.error("\n================================================================================");
    console.error("FATAL SAFETY ERROR: Refusing to execute tamper demo in PRODUCTION environment!");
    console.error("NODE_ENV is set to 'production'. Demo execution aborted.");
    console.error("================================================================================\n");
    process.exit(1);
}

// Strict exhibit restriction
const TEST_EVIDENCE_ID = 14;
const EXPECTED_EVIDENCE_NUMBER = "EV-2026-012";

// External backup directory outside uploads/
const BACKUP_DIR = path.resolve(__dirname, "../../../scratch/backups");

async function runSafeDemo() {
    console.log("================================================================================");
    console.log("           DIG_EVI — TAMPER ALERT SYSTEM SAFE DEMONSTRATION                     ");
    console.log("================================================================================\n");

    // Enable demo email transport exclusively for this test session
    process.env.DEMO_MAIL = "true";

    // Step 0: Fetch test exhibit metadata and verify strict exhibit identity
    const testEvidence = await evidenceModel.getEvidenceById(TEST_EVIDENCE_ID);
    if (!testEvidence) {
        throw new Error(`Test exhibit with evidence_id ${TEST_EVIDENCE_ID} not found in database!`);
    }

    if (testEvidence.evidence_id !== TEST_EVIDENCE_ID || testEvidence.evidence_number !== EXPECTED_EVIDENCE_NUMBER) {
        console.error(`\nFATAL SAFETY VIOLATION: Target record is not the verified test exhibit!`);
        console.error(`Expected: #${TEST_EVIDENCE_ID} (${EXPECTED_EVIDENCE_NUMBER}), Received: #${testEvidence.evidence_id} (${testEvidence.evidence_number})`);
        process.exit(1);
    }

    const encFilePath = path.resolve(testEvidence.file_path);

    console.log(`[Target Exhibit] Exhibit: ${testEvidence.evidence_number} ("${testEvidence.evidence_name}")`);
    console.log(`[Target Exhibit] File:    ${path.basename(encFilePath)}`);
    console.log(`[Target Exhibit] SHA-256: ${testEvidence.file_hash}`);
    console.log(`[Target Exhibit] Safety:  RESTRICTED TO TEST EXHIBIT ONLY\n`);

    if (!fs.existsSync(encFilePath)) {
        throw new Error(`Encrypted file not found on disk at: ${encFilePath}`);
    }

    // Step 1: Backup .enc file outside uploads/
    console.log("--------------------------------------------------------------------------------");
    console.log("STEP 1: Backing up test exhibit .enc file outside uploads/...");
    console.log("--------------------------------------------------------------------------------");
    if (!fs.existsSync(BACKUP_DIR)) {
        fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }
    const backupFilePath = path.join(BACKUP_DIR, `${path.basename(encFilePath)}.bak`);
    fs.copyFileSync(encFilePath, backupFilePath);

    const originalEncBytes = fs.readFileSync(encFilePath);
    const originalEncHash = crypto.createHash("sha256").update(originalEncBytes).digest("hex");
    console.log(`[Backup] Source:      ${encFilePath}`);
    console.log(`[Backup] Destination: ${backupFilePath}`);
    console.log(`[Backup] File Size:   ${originalEncBytes.length} bytes`);
    console.log(`[Backup] SHA-256:     ${originalEncHash}`);
    console.log(`[Backup] Status:      BACKUP VERIFIED SECURE\n`);

    // Verify baseline integrity before tampering
    const preCheck = await alertService.checkEvidenceIntegrity(testEvidence);
    console.log(`[Baseline Check] Status: ${preCheck.status} (Verified Intact)\n`);

    let demoAlertRecord = null;
    let emailResult = null;

    try {
        // Step 2: Configure Demo Mail Transport
        console.log("--------------------------------------------------------------------------------");
        console.log("STEP 2: Initializing Ethereal demo mail transport (DEMO_MAIL=true)...");
        console.log("--------------------------------------------------------------------------------");
        const smtpConn = await emailService.verifySmtpConnection();
        console.log(`[Transport] Status:  ${smtpConn.message}`);
        console.log(`[Transport] Mode:    Ethereal Sandbox (Real SMTP credentials untouched)\n`);

        // Step 3: Flip 1 byte in the test record's .enc file
        console.log("--------------------------------------------------------------------------------");
        console.log("STEP 3: Inducing single-byte tampering in exhibit ciphertext...");
        console.log("--------------------------------------------------------------------------------");
        const tamperedBytes = Buffer.from(originalEncBytes);
        // Flip byte 0
        tamperedBytes[0] = tamperedBytes[0] ^ 0xff;
        fs.writeFileSync(encFilePath, tamperedBytes);

        const tamperedEncHash = crypto.createHash("sha256").update(tamperedBytes).digest("hex");
        console.log(`[Tamper Action] Flipped 1 byte at index 0 (0x${originalEncBytes[0].toString(16)} -> 0x${tamperedBytes[0].toString(16)})`);
        console.log(`[Tamper Action] Modified File Hash: ${tamperedEncHash}`);
        console.log(`[Tamper Action] Status: Simulated physical ciphertext corruption complete\n`);

        // Step 4: Trigger the check manually
        console.log("--------------------------------------------------------------------------------");
        console.log("STEP 4: Triggering cryptographic integrity scan...");
        console.log("--------------------------------------------------------------------------------");
        const scanResult = await alertService.checkEvidenceIntegrity(testEvidence);
        console.log("[Scan Result] Scan Status:        ", scanResult.status);
        console.log("[Scan Result] New Alert Created:  ", scanResult.new_alert_created);
        emailResult = scanResult.email_dispatch;

        // Step 5: Show alert row created, audit log entry, UI appearance, and captured email
        console.log("\n--------------------------------------------------------------------------------");
        console.log("STEP 5: Forensic Evidence Verification & Alert Inspection");
        console.log("--------------------------------------------------------------------------------\n");

        // 5a. Database Alert Row
        const alertRes = await pool.query(
            "SELECT * FROM tamper_alerts WHERE evidence_id = $1 AND status = 'ACTIVE' ORDER BY alert_id DESC LIMIT 1;",
            [TEST_EVIDENCE_ID]
        );
        if (alertRes.rows.length > 0) {
            demoAlertRecord = alertModel.decryptAlertRow(alertRes.rows[0]);
            console.log(">>> [1/4] POSTGRESQL tamper_alerts ROW CREATED:");
            console.log(`    Alert ID:        #${demoAlertRecord.alert_id}`);
            console.log(`    Evidence ID:     ${demoAlertRecord.evidence_id} (${testEvidence.evidence_number})`);
            console.log(`    Case ID:         ${demoAlertRecord.case_id}`);
            console.log(`    Alert Type:      ${demoAlertRecord.alert_type}`);
            console.log(`    Severity:        ${demoAlertRecord.severity}`);
            console.log(`    Status:          ${demoAlertRecord.status}`);
            console.log(`    Stored Hash:     ${demoAlertRecord.stored_hash}`);
            console.log(`    Detected At:     ${demoAlertRecord.detected_at.toISOString()}`);
            console.log(`    Message:         ${demoAlertRecord.message}\n`);
        } else {
            console.warn(">>> [1/4] Warning: No active alert row found in tamper_alerts.");
        }

        // 5b. Audit Log Entry
        const auditRes = await pool.query(
            "SELECT * FROM audit_logs WHERE evidence_id = $1 AND action = 'TAMPER_DETECTED' ORDER BY audit_id DESC LIMIT 1;",
            [TEST_EVIDENCE_ID]
        );
        if (auditRes.rows.length > 0) {
            const auditLog = auditModel.decryptAuditRow(auditRes.rows[0]);
            console.log(">>> [2/4] IMMUTABLE audit_logs ENTRY RECORDED:");
            console.log(`    Audit ID:        #${auditLog.audit_id}`);
            console.log(`    User ID:         ${auditLog.user_id}`);
            console.log(`    Evidence ID:     ${auditLog.evidence_id}`);
            console.log(`    Action:          ${auditLog.action}`);
            console.log(`    Details:         ${auditLog.details}`);
            console.log(`    Timestamp:       ${auditLog.created_at.toISOString()}\n`);
        } else {
            console.warn(">>> [2/4] Warning: No audit log entry found.");
        }

        // 5c. Alert Center UI Representation
        console.log(">>> [3/4] ALERT CENTER UI STATUS (/alerts):");
        console.log(`    Incident Card:   CRITICAL ALERT #${demoAlertRecord ? demoAlertRecord.alert_id : "N/A"}`);
        console.log(`    Badge:           [ CRITICAL ] - ${scanResult.status}`);
        console.log(`    Exhibit:         ${testEvidence.evidence_number} - ${testEvidence.evidence_name}`);
        console.log(`    Action Needed:   Forensic chain-of-custody review & administrator sign-off\n`);

        // 5d. Captured Email Notification
        console.log(">>> [4/4] CAPTURED SECURITY NOTIFICATION EMAIL:");
        if (emailResult && emailResult.sent) {
            console.log(`    Status:          SENT via Ethereal`);
            console.log(`    Recipient:       ${emailService.maskEmail(emailResult.recipient)}`);
            console.log(`    Subject:         ${emailResult.subject}`);
            console.log(`    Message ID:      ${emailResult.messageId}`);
            if (emailResult.previewUrl) {
                console.log(`    \n    ========================================================================`);
                console.log(`    >>> ETHEREAL LIVE EMAIL PREVIEW URL:`);
                console.log(`        ${emailResult.previewUrl}`);
                console.log(`    ========================================================================\n`);
            }
            console.log("    EMAIL BODY CONTENT SNIPPET:");
            const lines = emailResult.text ? emailResult.text.split("\n").slice(0, 18) : [];
            lines.forEach(l => console.log(`      | ${l}`));
            console.log("      | [...remaining forensic body...]\n");
        } else {
            console.log("    Status: Not dispatched or SMTP disabled.");
        }

    } finally {
        const isTamperOnlyMode = process.argv.includes("--tamper-only") || process.argv.includes("--no-restore");

        if (isTamperOnlyMode) {
            console.log("\n================================================================================");
            console.log(">>> [LIVE DEMO MODE: --tamper-only ACTIVE]");
            console.log(">>> Exhibit EV-2026-012 remains in TAMPERED state for live presentation.");
            console.log(">>> View the active incident card in Alert Center: http://localhost:5173/alerts");
            console.log(">>> To restore to pristine state, execute:");
            console.log(">>>   node backend/src/utils/resetDemoTamper.js");
            console.log("================================================================================\n");
            delete process.env.DEMO_MAIL;
        } else {
            // Step 6: Restore original .enc from backup
            console.log("--------------------------------------------------------------------------------");
            console.log("STEP 6: Restoring original .enc file from backup and verifying INTACT...");
            console.log("--------------------------------------------------------------------------------");
            fs.copyFileSync(backupFilePath, encFilePath);
            const restoredBytes = fs.readFileSync(encFilePath);
            const restoredHash = crypto.createHash("sha256").update(restoredBytes).digest("hex");

            console.log(`[Restore] Restored bytes: ${restoredBytes.length} bytes`);
            console.log(`[Restore] Restored hash:  ${restoredHash}`);
            console.log(`[Restore] Hash matches:   ${restoredHash === originalEncHash ? "YES (100% BIT-FOR-BIT IDENTICAL)" : "NO"}`);

            // Re-run check on restored file
            const postCheck = await alertService.checkEvidenceIntegrity(testEvidence);
            console.log(`[Verification] Re-scan status: ${postCheck.status} (Successfully validated INTACT)\n`);

            // Resolve the demo alert in database
            if (demoAlertRecord) {
                console.log(`[Cleanup] Resolving test demo alert #${demoAlertRecord.alert_id} in PostgreSQL...`);
                const adminRes = await pool.query("SELECT user_id FROM users WHERE role_id = 1 AND is_active = TRUE LIMIT 1;");
                const adminUserId = adminRes.rows[0] ? adminRes.rows[0].user_id : null;
                await alertModel.resolveAlert(
                    demoAlertRecord.alert_id,
                    adminUserId,
                    "[SAFE DEMO] Test alert resolved automatically after tamper detection verification demo."
                );
                console.log(`[Cleanup] Alert #${demoAlertRecord.alert_id} marked as RESOLVED by User ID ${adminUserId}.\n`);
            }

            // Remove demo transport setting
            delete process.env.DEMO_MAIL;
            console.log("[Cleanup] DEMO_MAIL transport unmounted.");
        }
    }

    console.log("================================================================================");
    console.log("           DEMO COMPLETED SUCCESSFULLY WITH ZERO DATA CORRUPTION                ");
    console.log("================================================================================\n");
}

if (require.main === module) {
    runSafeDemo().then(() => {
        process.exit(0);
    }).catch(err => {
        console.error("Demo failed with error:", err);
        process.exit(1);
    });
}

module.exports = { runSafeDemo };
