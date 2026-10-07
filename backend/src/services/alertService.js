const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const pool = require("../config/db");
const alertModel = require("../models/alertModel");
const auditService = require("./auditService");
const emailService = require("./emailService");
const manifestService = require("./manifestService");
const { decryptAESKey } = require("../utils/encryption");

// Global mutex to prevent concurrent integrity scans
let isScanRunning = false;

// In-memory cache for lightweight file verification (size and mtime)
const fileStatCache = new Map();
let lastFullScanTimestamp = 0;

const getIsScanRunning = () => isScanRunning;

/**
 * Streams unencrypted file bytes directly through SHA-256 without loading into memory buffer.
 */
const streamComputeFileSha256 = (filePath) => {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(filePath);
        stream.on("data", chunk => hash.update(chunk));
        stream.on("end", () => resolve(hash.digest("hex")));
        stream.on("error", reject);
    });
};

/**
 * Streams AES-256-GCM ciphertext from disk, decrypts on the fly, and feeds decrypted chunks
 * directly into SHA-256 digest without buffering plaintext.
 * Throws on GCM authentication failure (tampered ciphertext / auth tag).
 */
const streamDecryptAndHash = (filePath, fileKeyBuffer, ivBuffer, authTagBuffer) => {
    return new Promise((resolve, reject) => {
        let decipher;
        try {
            decipher = crypto.createDecipheriv("aes-256-gcm", fileKeyBuffer, ivBuffer);
            decipher.setAuthTag(authTagBuffer);
        } catch (initErr) {
            return reject(initErr);
        }

        const hash = crypto.createHash("sha256");
        const stream = fs.createReadStream(filePath);

        stream.on("data", (chunk) => {
            try {
                const decryptedChunk = decipher.update(chunk);
                if (decryptedChunk.length > 0) {
                    hash.update(decryptedChunk);
                }
            } catch (err) {
                stream.destroy(err);
            }
        });

        stream.on("end", () => {
            try {
                const finalChunk = decipher.final();
                if (finalChunk.length > 0) {
                    hash.update(finalChunk);
                }
                resolve(hash.digest("hex"));
            } catch (authErr) {
                reject(authErr);
            }
        });

        stream.on("error", (err) => {
            reject(err);
        });
    });
};

const getSystemAdminId = async () => {
    const res = await pool.query("SELECT user_id FROM users WHERE role_id = 1 AND is_active = TRUE ORDER BY user_id ASC LIMIT 1;");
    return res.rows[0] ? res.rows[0].user_id : null;
};

const resolveEvidenceFilePath = (filePath) => {
    if (!filePath) return null;
    if (path.isAbsolute(filePath) && fs.existsSync(filePath)) {
        return filePath;
    }
    const backendRoot = path.resolve(__dirname, "../../");
    const candidates = [
        path.resolve(backendRoot, filePath),
        path.resolve(backendRoot, "uploads", path.basename(filePath)),
        path.resolve(backendRoot, "uploads/encrypted", path.basename(filePath)),
        path.resolve(process.cwd(), filePath),
        path.resolve(process.cwd(), "uploads", path.basename(filePath)),
        path.resolve(process.cwd(), "uploads/encrypted", path.basename(filePath))
    ];
    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }
    return candidates[0];
};

/**
 * Checks integrity of a single evidence record using streaming computation.
 *
 * @param {Object} evidenceItem Database row from evidence table
 * @param {number|null} scanUserId ID of the user requesting the scan (null for background scheduler)
 * @param {number|null} preloadedAdminId Preloaded admin ID to avoid repeated DB lookups
 * @returns {Promise<Object>} Verification status object
 */
const checkEvidenceIntegrity = async (evidenceItem, scanUserId = null, preloadedAdminId = null) => {
    const {
        evidence_id,
        case_id,
        evidence_number,
        file_path,
        file_hash,
        encrypted_aes_key,
        encryption_iv,
        encryption_auth_tag,
        is_legacy_seed
    } = evidenceItem;

    // Use clear SYSTEM actor (null) when run by background scheduler
    const auditUserId = scanUserId || null;
    const absolutePath = resolveEvidenceFilePath(file_path);

    // Strictly verified legacy seed records
    const isVerifiedLegacySeed = Boolean(
        is_legacy_seed === true ||
        (Number(evidence_id) <= 3 && encrypted_aes_key === "temporary_key")
    );

    if (!fs.existsSync(absolutePath)) {
        if (isVerifiedLegacySeed) {
            return {
                status: "LEGACY_SEED",
                evidence_id,
                evidence_number,
                is_legacy_seed: true,
                message: "Catalog-only seed exhibit (no disk payload). Skipped from tamper alerts.",
                new_alert_created: false
            };
        }

        // Raise CRITICAL FILE_MISSING alert
        const alertRes = await alertModel.createAlert({
            evidence_id,
            case_id,
            alert_type: "FILE_MISSING",
            severity: "CRITICAL",
            stored_hash: file_hash,
            detected_hash: null,
            file_path,
            message: `Evidence file ${evidence_number} is missing from disk storage at ${file_path}`,
            email_status: "PENDING",
            email_attempts: 0
        });

        const isNew = alertRes && alertRes.is_new;
        if (isNew) {
            await auditService.createAuditLog(
                auditUserId,
                evidence_id,
                "TAMPER_DETECTED",
                `[SYSTEM] CRITICAL: Evidence file missing from storage: ${evidence_number}`
            );
        }

        return {
            status: "FILE_MISSING",
            evidence_id,
            evidence_number,
            new_alert_created: isNew,
            alert: alertRes
        };
    }

    try {
        let calculatedHash;

        if (encrypted_aes_key && encryption_iv && encryption_auth_tag) {
            // Step 1: Unwrap the per-file AES key
            let fileKeyHex;
            try {
                fileKeyHex = decryptAESKey(encrypted_aes_key);
            } catch (keyErr) {
                // SYSTEM ERROR: Key-unwrap failure (e.g. invalid MASTER_ENCRYPTION_KEY or corrupt wrap)
                // One system warning, NO per-record evidence alerts per requirement 3.
                return {
                    status: "KEY_UNWRAP_FAILED",
                    evidence_id,
                    evidence_number,
                    is_system_error: true,
                    error: keyErr.message,
                    new_alert_created: false
                };
            }

            // Step 2: Stream decrypt and hash
            const fileKeyBuffer = Buffer.from(fileKeyHex, "hex");
            const ivBuffer = Buffer.from(encryption_iv, "hex");
            const authTagBuffer = Buffer.from(encryption_auth_tag, "hex");

            try {
                calculatedHash = await streamDecryptAndHash(
                    absolutePath,
                    fileKeyBuffer,
                    ivBuffer,
                    authTagBuffer
                );
            } catch (gcmErr) {
                // GCM authentication failure / ciphertext corruption -> CORRUPTED_CIPHERTEXT
                const alertRes = await alertModel.createAlert({
                    evidence_id,
                    case_id,
                    alert_type: "CORRUPTED_CIPHERTEXT",
                    severity: "CRITICAL",
                    stored_hash: file_hash,
                    detected_hash: null,
                    file_path,
                    message: `Encrypted file for ${evidence_number} failed AES-256-GCM authentication or decryption: ${gcmErr.message}`,
                    email_status: "PENDING",
                    email_attempts: 0
                });

                const isNew = alertRes && alertRes.is_new;
                if (isNew) {
                    await auditService.createAuditLog(
                        auditUserId,
                        evidence_id,
                        "TAMPER_DETECTED",
                        `[SYSTEM] CRITICAL: Ciphertext corruption detected in evidence ${evidence_number}`
                    );
                }

                return {
                    status: "CORRUPTED_CIPHERTEXT",
                    evidence_id,
                    evidence_number,
                    new_alert_created: isNew,
                    alert: alertRes
                };
            }
        } else {
            // Unencrypted physical file -> streaming SHA-256
            calculatedHash = await streamComputeFileSha256(absolutePath);
        }

        // Compare calculated hash against stored hash
        if (calculatedHash !== file_hash) {
            const alertRes = await alertModel.createAlert({
                evidence_id,
                case_id,
                alert_type: "HASH_MISMATCH",
                severity: "CRITICAL",
                stored_hash: file_hash,
                detected_hash: calculatedHash,
                file_path,
                message: `SHA-256 mismatch detected for evidence ${evidence_number}. Stored: ${file_hash}, Detected: ${calculatedHash}`,
                email_status: "PENDING",
                email_attempts: 0
            });

            const isNew = alertRes && alertRes.is_new;
            if (isNew) {
                await auditService.createAuditLog(
                    auditUserId,
                    evidence_id,
                    "TAMPER_DETECTED",
                    `[SYSTEM] CRITICAL: SHA-256 hash mismatch detected for evidence ${evidence_number}`
                );
            }

            return {
                status: "HASH_MISMATCH",
                evidence_id,
                evidence_number,
                calculatedHash,
                storedHash: file_hash,
                new_alert_created: isNew,
                alert: alertRes
            };
        }

        return {
            status: "INTACT",
            evidence_id,
            evidence_number,
            hash: calculatedHash,
            new_alert_created: false
        };
    } catch (err) {
        // Unexpected scan execution error -> create SCAN_ERROR alert with duplicate suppression
        let newAlertCreated = false;
        let alertRes = null;
        try {
            alertRes = await alertModel.createAlert({
                evidence_id,
                case_id,
                alert_type: "SCAN_ERROR",
                severity: "HIGH",
                stored_hash: file_hash,
                detected_hash: null,
                file_path,
                message: `Integrity scan error for ${evidence_number}: ${err.message}`,
                email_status: "PENDING",
                email_attempts: 0
            });

            if (alertRes && alertRes.is_new) {
                newAlertCreated = true;
                await auditService.createAuditLog(
                    auditUserId,
                    evidence_id,
                    "SCAN_ERROR",
                    `[SYSTEM] Integrity scan error for evidence ${evidence_number}: ${err.message}`
                );
            }
        } catch (_) {}

        return {
            status: "ERROR",
            evidence_id,
            evidence_number,
            error: err.message,
            new_alert_created: newAlertCreated,
            alert: alertRes
        };
    }
};

/**
 * Retries dispatch of any active alerts with PENDING or FAILED email status (up to 5 attempts).
 */
const retryUnsentAlertEmails = async (auditUserId = null, excludeAlertIds = []) => {
    try {
        const rawAlerts = await alertModel.getUnsentActiveAlerts(5);
        if (!rawAlerts || rawAlerts.length === 0) {
            return { retried: 0, successful: 0 };
        }

        const unsentAlerts = Array.isArray(excludeAlertIds) && excludeAlertIds.length > 0
            ? rawAlerts.filter(a => !excludeAlertIds.includes(a.alert_id))
            : rawAlerts;

        if (unsentAlerts.length === 0) {
            return { retried: 0, successful: 0 };
        }

        let sendResult;
        if (unsentAlerts.length === 1) {
            sendResult = await emailService.sendTamperAlertEmail(unsentAlerts[0]);
        } else {
            sendResult = await emailService.sendTamperAlertDigestEmail(unsentAlerts);
        }

        let successful = 0;
        for (const alert of unsentAlerts) {
            const newAttempts = (alert.email_attempts || 0) + 1;
            if (sendResult.sent) {
                await alertModel.updateAlertEmailDispatch(alert.alert_id, {
                    email_status: "SENT",
                    email_attempts: newAttempts,
                    email_sent_at: new Date(),
                    email_last_error: null
                });
                await auditService.createAuditLog(
                    auditUserId,
                    alert.evidence_id,
                    "EMAIL_ALERT_SENT",
                    `[SYSTEM] Alert email successfully delivered on retry attempt ${newAttempts}`
                );
                successful++;
            } else {
                const newStatus = newAttempts >= 5 ? "FAILED" : "PENDING";
                const safeErr = sendResult.error || sendResult.reason || "SMTP delivery failure";
                await alertModel.updateAlertEmailDispatch(alert.alert_id, {
                    email_status: newStatus,
                    email_attempts: newAttempts,
                    email_last_error: safeErr
                });
                await auditService.createAuditLog(
                    auditUserId,
                    alert.evidence_id,
                    "EMAIL_ALERT_FAILED",
                    `[SYSTEM] Alert email delivery failed on retry attempt ${newAttempts}/5: ${safeErr}`
                );
            }
        }

        return { retried: unsentAlerts.length, successful };
    } catch (err) {
        console.warn("[AlertService] Unsent alert email retry loop failed:", err.message);
        return { retried: 0, successful: 0, error: err.message };
    }
};

const cleanEvidenceFileName = (rawFileName) => {
    if (!rawFileName) return "evidence-file";
    const base = path.basename(rawFileName);
    const cleaned = base.replace(/^\d+-/, "");
    return cleaned || base;
};

const getFullScanIntervalMs = () => {
    const mins = parseFloat(process.env.INTEGRITY_FULL_SCAN_MINUTES);
    if (!isNaN(mins) && mins > 0) {
        return Math.round(mins * 60 * 1000);
    }
    return 60 * 60 * 1000; // default 60 minutes
};

/**
 * Scans storage folders for physical files that have no corresponding database record.
 * Raises CRITICAL alert of type UNREGISTERED_FILE for stray files.
 */
const scanUnregisteredFiles = async (adminId) => {
    const newlyCreatedAlerts = [];
    const backendRoot = path.resolve(__dirname, "../../");
    const candidateDirs = [
        path.resolve(backendRoot, "uploads"),
        path.resolve(backendRoot, "uploads/encrypted"),
        path.resolve(process.cwd(), "uploads"),
        path.resolve(process.cwd(), "uploads/encrypted")
    ];

    const uniqueDirs = Array.from(new Set(candidateDirs.map(d => path.normalize(d)))).filter(d => fs.existsSync(d));

    const res = await pool.query("SELECT file_path, file_name FROM evidence;");
    const registeredNames = new Set();
    for (const r of res.rows) {
        if (r.file_name) {
            registeredNames.add(path.basename(r.file_name).toLowerCase());
            registeredNames.add(cleanEvidenceFileName(r.file_name).toLowerCase());
        }
        if (r.file_path) {
            registeredNames.add(path.basename(r.file_path).toLowerCase());
            registeredNames.add(cleanEvidenceFileName(r.file_path).toLowerCase());
        }
    }

    const ignoredNames = new Set([
        ".gitkeep", ".gitignore", "thumbs.db", ".ds_store"
    ]);

    const scannedPaths = new Set();

    for (const dir of uniqueDirs) {
        let entries = [];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (_) {
            continue;
        }

        for (const entry of entries) {
            if (!entry.isFile()) continue;
            const fileName = entry.name;
            const lowerName = fileName.toLowerCase();

            if (ignoredNames.has(lowerName) || lowerName.startsWith(".") || lowerName.endsWith(".zip")) {
                continue;
            }

            const fullPath = path.join(dir, fileName);
            const normalizedFullPath = path.normalize(fullPath);
            if (scannedPaths.has(normalizedFullPath)) continue;
            scannedPaths.add(normalizedFullPath);

            const cleanedName = cleanEvidenceFileName(fileName).toLowerCase();

            const isRegistered = registeredNames.has(lowerName) || registeredNames.has(cleanedName);
            if (!isRegistered) {
                let fileHash = null;
                try {
                    fileHash = await streamComputeFileSha256(fullPath);
                } catch (_) {}

                const alertRes = await alertModel.createAlert({
                    evidence_id: null,
                    case_id: null,
                    alert_type: "UNREGISTERED_FILE",
                    severity: "CRITICAL",
                    stored_hash: null,
                    detected_hash: fileHash,
                    file_path: fullPath,
                    message: `Unregistered file detected on storage volume with no corresponding evidence record: ${fileName}`,
                    email_status: "PENDING",
                    email_attempts: 0
                });

                if (alertRes && alertRes.is_new) {
                    await auditService.createAuditLog(
                        adminId,
                        null,
                        "TAMPER_DETECTED",
                        `[SYSTEM] CRITICAL: Unregistered file detected on storage volume: ${fileName}`
                    );
                    newlyCreatedAlerts.push(alertRes);
                }
            }
        }
    }

    return newlyCreatedAlerts;
};

/**
 * Runs integrity verification across the entire vault.
 * Supports configurable full rehashes vs lightweight checks (file size & modified timestamp).
 * Also verifies audit log hash chain, signed manifest consistency, and unregistered storage files.
 *
 * @param {number|null} scanUserId User requesting scan
 * @param {boolean} forceFull Force complete cryptographic stream rehash of all files
 */
const scanAllEvidenceIntegrity = async (scanUserId = null, forceFull = false) => {
    if (isScanRunning) {
        console.warn("[AlertService] Scan requested while previous scan is in progress. Skipping concurrent run.");
        return {
            already_running: true,
            message: "Integrity scan is already in progress. Concurrent execution prevented.",
            scanned: 0,
            intact: 0,
            legacy_seed: 0,
            compromised: 0,
            new_alerts_dispatched: 0,
            results: []
        };
    }

    isScanRunning = true;

    try {
        const adminId = scanUserId || (await getSystemAdminId());
        const newlyCreatedAlerts = [];

        // ---------------------------------------------------------------------
        // Step A: Audit Log Hash Chain Verification
        // ---------------------------------------------------------------------
        try {
            const chainCheck = await auditService.verifyAuditLogChain();
            if (!chainCheck.valid) {
                const chainAlert = await alertModel.createAlert({
                    evidence_id: null,
                    case_id: null,
                    alert_type: "AUDIT_CHAIN_BROKEN",
                    severity: "CRITICAL",
                    stored_hash: chainCheck.storedEntryHash || chainCheck.expectedPrevHash || null,
                    detected_hash: chainCheck.computedEntryHash || chainCheck.actualPrevHash || null,
                    file_path: "audit_logs",
                    message: chainCheck.reason || "Audit log cryptographic hash chain linkage broken! Row edited, reordered, or deleted.",
                    email_status: "PENDING",
                    email_attempts: 0
                });
                if (chainAlert && chainAlert.is_new) {
                    await auditService.createAuditLog(
                        adminId,
                        null,
                        "TAMPER_DETECTED",
                        `[SYSTEM] CRITICAL: Audit log hash chain broken: ${chainCheck.reason}`
                    );
                    newlyCreatedAlerts.push(chainAlert);
                }
            }
        } catch (chainErr) {
            console.warn("[AlertService] Audit chain check error:", chainErr.message);
        }

        // ---------------------------------------------------------------------
        // Step B: Compare Database with Daily Signed Integrity Manifest
        // ---------------------------------------------------------------------
        try {
            const manifestComparison = await manifestService.compareDatabaseWithManifest();
            if (!manifestComparison.valid) {
                if (manifestComparison.manifest_tampered) {
                    const mAlert = await alertModel.createAlert({
                        evidence_id: null,
                        case_id: null,
                        alert_type: "MANIFEST_TAMPERED",
                        severity: "CRITICAL",
                        stored_hash: null,
                        detected_hash: null,
                        file_path: "manifest-latest.json",
                        message: manifestComparison.message || "Signed integrity manifest signature verification failed! HMAC mismatch.",
                        email_status: "PENDING",
                        email_attempts: 0
                    });
                    if (mAlert && mAlert.is_new) {
                        await auditService.createAuditLog(
                            adminId,
                            null,
                            "TAMPER_DETECTED",
                            `[SYSTEM] CRITICAL: Signed manifest HMAC verification failed`
                        );
                        newlyCreatedAlerts.push(mAlert);
                    }
                }

                // Evidence records deleted from database
                for (const delRec of manifestComparison.deleted_records || []) {
                    const delAlert = await alertModel.createAlert({
                        evidence_id: null,
                        case_id: null,
                        alert_type: "EVIDENCE_RECORD_DELETED",
                        severity: "CRITICAL",
                        stored_hash: delRec.manifest_hash,
                        detected_hash: null,
                        file_path: `database:evidence:${delRec.evidence_id}`,
                        message: `Evidence record ${delRec.evidence_number} (ID: ${delRec.evidence_id}) previously signed in manifest was deleted from the database!`,
                        email_status: "PENDING",
                        email_attempts: 0
                    });
                    if (delAlert && delAlert.is_new) {
                        await auditService.createAuditLog(
                            adminId,
                            null,
                            "TAMPER_DETECTED",
                            `[SYSTEM] CRITICAL: Evidence record deleted from database: ${delRec.evidence_number} (ID: ${delRec.evidence_id})`
                        );
                        newlyCreatedAlerts.push(delAlert);
                    }
                }

                // Hash mismatches vs manifest
                for (const misRec of manifestComparison.mismatches || []) {
                    const misAlert = await alertModel.createAlert({
                        evidence_id: misRec.evidence_id,
                        case_id: null,
                        alert_type: "MANIFEST_HASH_MISMATCH",
                        severity: "CRITICAL",
                        stored_hash: misRec.manifest_hash,
                        detected_hash: misRec.db_hash,
                        file_path: "database:evidence",
                        message: `Evidence ${misRec.evidence_number} stored hash in database (${misRec.db_hash}) does not match signed manifest (${misRec.manifest_hash}).`,
                        email_status: "PENDING",
                        email_attempts: 0
                    });
                    if (misAlert && misAlert.is_new) {
                        await auditService.createAuditLog(
                            adminId,
                            misRec.evidence_id,
                            "TAMPER_DETECTED",
                            `[SYSTEM] CRITICAL: Evidence ${misRec.evidence_number} database hash differs from signed manifest`
                        );
                        newlyCreatedAlerts.push(misAlert);
                    }
                }
            }
        } catch (manErr) {
            console.warn("[AlertService] Manifest check error:", manErr.message);
        }

        // ---------------------------------------------------------------------
        // Step C: Scan Storage for Unregistered Files
        // ---------------------------------------------------------------------
        try {
            const unregisteredAlerts = await scanUnregisteredFiles(adminId);
            for (const unreg of unregisteredAlerts) {
                newlyCreatedAlerts.push(unreg);
            }
        } catch (unregErr) {
            console.warn("[AlertService] Unregistered files scan error:", unregErr.message);
        }

        // ---------------------------------------------------------------------
        // Step D: Scan Evidence Exhibits (Lightweight vs Full Cryptographic Rehash)
        // ---------------------------------------------------------------------
        const fullScanIntervalMs = getFullScanIntervalMs();
        const isFullScan = forceFull || (Date.now() - lastFullScanTimestamp >= fullScanIntervalMs);

        const query = `
            SELECT 
                evidence_id,
                evidence_number,
                case_id,
                evidence_name,
                description,
                file_name,
                file_path,
                file_hash,
                encrypted_aes_key,
                encryption_iv,
                encryption_auth_tag,
                is_legacy_seed
            FROM evidence
            ORDER BY evidence_id ASC;
        `;
        const result = await pool.query(query);
        const items = result.rows;
        const scanResults = [];

        for (const item of items) {
            const isVerifiedLegacySeed = Boolean(
                item.is_legacy_seed === true ||
                (Number(item.evidence_id) <= 3 && item.encrypted_aes_key === "temporary_key")
            );

            if (isVerifiedLegacySeed) {
                scanResults.push({
                    status: "LEGACY_SEED",
                    evidence_id: item.evidence_id,
                    evidence_number: item.evidence_number,
                    is_legacy_seed: true,
                    new_alert_created: false
                });
                continue;
            }

            const resolvedPath = resolveEvidenceFilePath(item.file_path);
            if (!resolvedPath || !fs.existsSync(resolvedPath)) {
                const res = await checkEvidenceIntegrity(item, scanUserId, adminId);
                scanResults.push(res);
                if (res.new_alert_created && res.alert) {
                    newlyCreatedAlerts.push({
                        ...res.alert,
                        evidence_number: item.evidence_number,
                        evidence_name: item.evidence_name
                    });
                }
                continue;
            }

            // File exists on disk: inspect file size and modified timestamp
            let stat = null;
            try {
                stat = fs.statSync(resolvedPath);
            } catch (_) {}

            const cached = fileStatCache.get(item.evidence_id);
            const statChanged = !cached || !stat || cached.size !== stat.size || cached.mtimeMs !== stat.mtimeMs;

            if (isFullScan || statChanged) {
                const res = await checkEvidenceIntegrity(item, scanUserId, adminId);
                scanResults.push(res);
                if (stat) {
                    fileStatCache.set(item.evidence_id, { size: stat.size, mtimeMs: stat.mtimeMs });
                }
                if (res.new_alert_created && res.alert) {
                    newlyCreatedAlerts.push({
                        ...res.alert,
                        evidence_number: item.evidence_number,
                        evidence_name: item.evidence_name
                    });
                }
            } else {
                // Lightweight check passed: size and mtime are identical to last verified state
                scanResults.push({
                    status: "INTACT",
                    evidence_id: item.evidence_id,
                    evidence_number: item.evidence_number,
                    hash: item.file_hash,
                    lightweight: true,
                    new_alert_created: false
                });
            }
        }

        if (isFullScan) {
            lastFullScanTimestamp = Date.now();
        }

        // Handle key unwrap failures as a single system-level warning (no per-record alerts)
        const keyUnwrapFailures = scanResults.filter(r => r.status === "KEY_UNWRAP_FAILED");
        if (keyUnwrapFailures.length > 0) {
            console.warn(`[AlertService] Master key unwrap failure detected on ${keyUnwrapFailures.length} exhibits. Check MASTER_ENCRYPTION_KEY.`);
            await auditService.createAuditLog(
                scanUserId || null,
                null,
                "SYSTEM_WARNING",
                `[SYSTEM] Master key unwrap failure detected on ${keyUnwrapFailures.length} exhibits during integrity scan: ${keyUnwrapFailures[0].error}`
            );
        }

        // Email newly created alerts: single email if 1, digest email if > 1
        if (newlyCreatedAlerts.length === 1) {
            const singleAlert = newlyCreatedAlerts[0];
            try {
                const sendResult = await emailService.sendTamperAlertEmail({
                    ...singleAlert,
                    audit_user_id: adminId
                });

                const isSent = Boolean(sendResult && sendResult.sent);
                const safeErr = isSent ? null : (sendResult.error || sendResult.reason || "Failed to dispatch email");
                await alertModel.updateAlertEmailDispatch(singleAlert.alert_id, {
                    email_status: isSent ? "SENT" : "FAILED",
                    email_attempts: 1,
                    email_sent_at: isSent ? new Date() : null,
                    email_last_error: safeErr
                });

                if (isSent) {
                    await auditService.createAuditLog(
                        adminId,
                        singleAlert.evidence_id,
                        "EMAIL_ALERT_SENT",
                        `[SYSTEM] Tamper alert notification email delivered to ${emailService.maskEmail(sendResult.recipient)} (attempt 1/5)`
                    );
                } else {
                    await auditService.createAuditLog(
                        adminId,
                        singleAlert.evidence_id,
                        "EMAIL_ALERT_FAILED",
                        `[SYSTEM] Tamper alert notification email dispatch failed (attempt 1/5): ${safeErr}`
                    );
                }
            } catch (emErr) {
                await alertModel.updateAlertEmailDispatch(singleAlert.alert_id, {
                    email_status: "FAILED",
                    email_attempts: 1,
                    email_last_error: emErr.message
                });
                await auditService.createAuditLog(
                    adminId,
                    singleAlert.evidence_id,
                    "EMAIL_ALERT_FAILED",
                    `[SYSTEM] Tamper alert notification email dispatch failed (attempt 1/5): ${emErr.message}`
                );
            }
        } else if (newlyCreatedAlerts.length > 1) {
            try {
                const digestResult = await emailService.sendTamperAlertDigestEmail(newlyCreatedAlerts);
                const isSent = Boolean(digestResult && digestResult.sent);
                const safeErr = isSent ? null : (digestResult.error || digestResult.reason || "Failed to dispatch digest");

                for (const alert of newlyCreatedAlerts) {
                    await alertModel.updateAlertEmailDispatch(alert.alert_id, {
                        email_status: isSent ? "SENT" : "FAILED",
                        email_attempts: 1,
                        email_sent_at: isSent ? new Date() : null,
                        email_last_error: safeErr
                    });

                    if (isSent) {
                        await auditService.createAuditLog(
                            adminId,
                            alert.evidence_id,
                            "EMAIL_ALERT_SENT",
                            `[SYSTEM] Digest notification delivered to ${emailService.maskEmail(digestResult.recipient)} (attempt 1/5)`
                        );
                    } else {
                        await auditService.createAuditLog(
                            adminId,
                            alert.evidence_id,
                            "EMAIL_ALERT_FAILED",
                            `[SYSTEM] Digest notification dispatch failed (attempt 1/5): ${safeErr}`
                        );
                    }
                }
            } catch (emErr) {
                for (const alert of newlyCreatedAlerts) {
                    await alertModel.updateAlertEmailDispatch(alert.alert_id, {
                        email_status: "FAILED",
                        email_attempts: 1,
                        email_last_error: emErr.message
                    });
                    await auditService.createAuditLog(
                        adminId,
                        alert.evidence_id,
                        "EMAIL_ALERT_FAILED",
                        `[SYSTEM] Digest notification dispatch failed (attempt 1/5): ${emErr.message}`
                    );
                }
            }
        }

        // Retry previously unsent/failed alert emails (excluding alerts just processed above)
        const newlyCreatedIds = newlyCreatedAlerts.map(a => a.alert_id);
        await retryUnsentAlertEmails(scanUserId || null, newlyCreatedIds);

        const scanned = scanResults.length;
        const intact = scanResults.filter(r => r.status === "INTACT").length;
        const legacy_seed = scanResults.filter(r => r.status === "LEGACY_SEED").length;
        const compromised = scanResults.filter(r => r.status !== "INTACT" && r.status !== "LEGACY_SEED" && r.status !== "KEY_UNWRAP_FAILED").length;
        const new_alerts_dispatched = newlyCreatedAlerts.length;

        return {
            results: scanResults,
            scanned,
            intact,
            legacy_seed,
            compromised,
            new_alerts_dispatched,
            is_full_scan: isFullScan
        };
    } finally {
        isScanRunning = false;
    }
};

const resolveAlert = async (alertId, userId, notes) => {
    if (!userId) {
        throw new Error("Authenticated user required to resolve alerts");
    }
    const resolved = await alertModel.resolveAlert(alertId, userId, notes);
    if (!resolved) {
        throw new Error("Alert not found or already resolved");
    }

    await auditService.createAuditLog(
        userId,
        resolved.evidence_id,
        "ALERT_RESOLVED",
        `Tamper alert #${alertId} marked as RESOLVED by User ID ${userId}. Notes: ${notes || "None provided"}`
    );

    return resolved;
};

module.exports = {
    checkEvidenceIntegrity,
    scanAllEvidenceIntegrity,
    scanUnregisteredFiles,
    retryUnsentAlertEmails,
    resolveAlert,
    getIsScanRunning,
    resolveEvidenceFilePath
};
