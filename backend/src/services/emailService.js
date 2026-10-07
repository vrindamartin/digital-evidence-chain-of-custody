const fs = require("fs");
const path = require("path");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const pool = require("../config/db");
const auditService = require("./auditService");
const { decryptField } = require("../utils/fieldEncryption");

/**
 * Escapes dynamic string values to prevent HTML injection in emails.
 */
const escapeHtml = (unsafe) => {
    if (unsafe === null || unsafe === undefined) return "";
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
};

/**
 * Dynamically reloads backend/.env so edits to credentials reflect immediately without process restart.
 */
const refreshEnv = () => {
    try {
        const envPath = path.resolve(__dirname, "../../.env");
        if (fs.existsSync(envPath)) {
            dotenv.config({ path: envPath, override: true });
        }
    } catch (_) {}
};

/**
 * Checks whether SMTP environment variables are properly populated.
 */
const isSmtpConfigured = () => {
    refreshEnv();
    const { SMTP_HOST, SMTP_USER, SMTP_PASS } = process.env;
    return Boolean(
        SMTP_HOST && SMTP_HOST.trim() &&
        SMTP_USER && SMTP_USER.trim() &&
        SMTP_PASS && SMTP_PASS.trim()
    );
};

let cachedTransporter = null;
let cachedTransporterKey = null;
let cachedEtherealTransporter = null;

/**
 * Creates or retrieves the mail transporter instance.
 * Ethereal fallback is ONLY activated when DEMO_MAIL=true or explicitly requested for testing.
 */
const getTransporter = async (forceEthereal = false) => {
    refreshEnv();
    if (isSmtpConfigured() && !forceEthereal) {
        const currentKey = `${process.env.SMTP_HOST}:${process.env.SMTP_PORT}:${process.env.SMTP_USER}:${process.env.SMTP_PASS}`;
        if (!cachedTransporter || cachedTransporterKey !== currentKey) {
            const port = parseInt(process.env.SMTP_PORT, 10) || 587;
            const isSecure = port === 465;

            cachedTransporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST.trim(),
                port: port,
                secure: isSecure,
                auth: {
                    user: process.env.SMTP_USER.trim(),
                    pass: process.env.SMTP_PASS.trim()
                },
                connectionTimeout: 10000,
                greetingTimeout: 10000,
                socketTimeout: 15000
            });
            cachedTransporterKey = currentKey;
        }
        return { transporter: cachedTransporter, isEthereal: false };
    }

    const isDemoMailEnabled = String(process.env.DEMO_MAIL || "").toLowerCase() === "true";
    if (isDemoMailEnabled || forceEthereal) {
        if (!cachedEtherealTransporter) {
            console.log("[EmailService] DEMO_MAIL=true active. Creating temporary Ethereal test inbox...");
            const testAccount = await nodemailer.createTestAccount();
            console.log(`[EmailService] Ethereal demo test account ready: ${testAccount.user}`);
            cachedEtherealTransporter = nodemailer.createTransport({
                host: testAccount.smtp.host,
                port: testAccount.smtp.port,
                secure: testAccount.smtp.secure,
                auth: {
                    user: testAccount.user,
                    pass: testAccount.pass
                }
            });
        }
        return { transporter: cachedEtherealTransporter, isEthereal: true };
    }

    return { transporter: null, isEthereal: false };
};

/**
 * Resolves the destination email address for System Administrator alerts.
 * Priority:
 * 1. SYSTEM_ADMIN_EMAIL from environment variables
 * 2. Active System Administrator (role_id = 1) email from database users table
 */
const resolveRecipientEmail = async () => {
    if (process.env.SYSTEM_ADMIN_EMAIL && process.env.SYSTEM_ADMIN_EMAIL.trim()) {
        return process.env.SYSTEM_ADMIN_EMAIL.trim();
    }

    try {
        const query = `
            SELECT user_id, email, full_name 
            FROM users 
            WHERE role_id = 1 AND is_active = TRUE AND email IS NOT NULL AND email != ''
            ORDER BY user_id ASC 
            LIMIT 1;
        `;
        const res = await pool.query(query);
        if (res.rows.length > 0 && res.rows[0].email) {
            const row = res.rows[0];
            const plainEmail = (typeof row.email === "string" && row.email.startsWith("v1:"))
                ? decryptField("users", "email", row.user_id, row.email)
                : row.email;
            return plainEmail.trim();
        }
    } catch (dbErr) {
        console.warn("[EmailService] Failed to query admin email from database:", dbErr.message);
    }

    return null;
};

/**
 * Masks an email address for safe display in logs and UI (e.g., v***@gmail.com).
 */
const maskEmail = (email) => {
    if (!email || typeof email !== "string") return null;
    return email.replace(/^(.)(.*)(@.*)$/, (_, first, middle, domain) => `${first}***${domain}`);
};

/**
 * Returns current email configuration status for frontend awareness.
 * Strictly avoids exposing passwords, tokens, or credentials.
 */
const getEmailConfigurationStatus = () => {
    const configured = isSmtpConfigured();
    const demoMail = String(process.env.DEMO_MAIL || "").toLowerCase() === "true";
    return {
        smtp_configured: configured,
        demo_mail: demoMail,
        sender: configured ? maskEmail(process.env.SMTP_USER) : null,
        host: configured ? process.env.SMTP_HOST : null,
        port: configured ? (parseInt(process.env.SMTP_PORT, 10) || 587) : null
    };
};

/**
 * Dispatches a single high-priority tamper alert notification email to the System Administrator.
 *
 * @param {Object} alertDetails Details of the newly created tamper alert
 * @param {Object} options Optional overrides (e.g. forceEthereal)
 * @returns {Promise<Object>} Status object with send result
 */
const sendTamperAlertEmail = async (alertDetails, options = {}) => {
    try {
        const forceEthereal = Boolean(options.useEthereal);
        const { transporter, isEthereal } = await getTransporter(forceEthereal);

        const {
            alert_id,
            case_id,
            case_number,
            evidence_id,
            evidence_number,
            evidence_name,
            alert_type,
            severity,
            detected_at,
            stored_hash,
            detected_hash,
            file_path,
            message,
            audit_user_id
        } = alertDetails || {};

        if (!transporter) {
            console.error(
                `[EmailService] SMTP email notifications are not configured (SMTP_HOST, SMTP_USER, or SMTP_PASS missing) and DEMO_MAIL is not set. Email alert suppressed for exhibit ${evidence_number || evidence_id}.`
            );

            try {
                await auditService.createAuditLog(
                    audit_user_id || null,
                    evidence_id || null,
                    "SYSTEM_WARNING",
                    `[SYSTEM] Email alerts unconfigured: SMTP credentials missing in environment variables. Evidence tamper alert was not emailed for exhibit ${evidence_number || evidence_id || "N/A"}.`
                );
            } catch (auditErr) {
                console.warn("[EmailService] Failed to record SYSTEM_WARNING audit log:", auditErr.message);
            }

            return {
                sent: false,
                reason: "SMTP_NOT_CONFIGURED",
                warningLogged: true
            };
        }

        const resolved = await resolveRecipientEmail();
        const recipient = resolved || (isEthereal ? "admin.sentinel@dig-evi.local" : null);
        if (!recipient) {
            console.warn("[EmailService] No recipient email address available for tamper alert. Set SYSTEM_ADMIN_EMAIL in .env or configure an active System Administrator email in the database.");
            return { sent: false, reason: "NO_RECIPIENT_EMAIL" };
        }

        const detectionTime = detected_at
            ? new Date(detected_at).toLocaleString("en-US", { timeZone: "UTC", dateStyle: "full", timeStyle: "long" }) + " (UTC)"
            : new Date().toISOString() + " (UTC)";

        const subject = `[DIG_EVI] CRITICAL DIGITAL EVIDENCE INTEGRITY ALERT — ${evidence_number || "Exhibit"}`;

        const textContent = `
================================================================================
DIG_EVI DIGITAL EVIDENCE MANAGEMENT SYSTEM — CRITICAL INTEGRITY ALERT
================================================================================

ATTENTION: System Administrator

A critical digital evidence tamper or integrity anomaly has been detected
by the DIG_EVI automated integrity monitoring system.

INCIDENT DETAILS:
--------------------------------------------------------------------------------
Alert Reference ID:  #${alert_id || "NEW"}
Case ID:             ${case_id || "N/A"}${case_number ? ` (Case #${case_number})` : ""}
Evidence ID:         ${evidence_id || "N/A"}
Evidence Number:     ${evidence_number || "N/A"}
Evidence Name:       ${evidence_name || "N/A"}
Integrity Failure:   ${alert_type || "TAMPER_DETECTED"}
Severity Level:      ${severity || "CRITICAL"}
Detection Time:      ${detectionTime}
Stored SHA-256 Hash: ${stored_hash || "Not Available"}
Detected SHA-256:    ${detected_hash || "Not Available"}
Storage Path:        ${file_path || "N/A"}
Diagnostic Message:  ${message || "Evidence integrity verification failed."}

--------------------------------------------------------------------------------
ACTION REQUIRED:
Please open the DIG_EVI Alert Center immediately to review this incident,
inspect chain of custody logs, audit system events, and initiate the formal
evidence compromise response procedure.

System: DIG_EVI Digital Evidence Chain of Custody & Management System
Sentinel Background Automated Integrity Monitor
================================================================================
`.trim();

        const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b; }
    .container { max-width: 650px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #cbd5e1; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
    .header { background: #b91c1c; color: #ffffff; padding: 20px 24px; }
    .header h1 { margin: 0; font-size: 19px; font-weight: 700; letter-spacing: 0.3px; }
    .header p { margin: 6px 0 0 0; font-size: 13px; opacity: 0.92; }
    .body { padding: 24px; }
    .lead { font-size: 14.5px; line-height: 1.55; margin-bottom: 20px; color: #334155; }
    .alert-card { background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #dc2626; padding: 12px 16px; border-radius: 4px; margin-bottom: 22px; font-size: 14px; font-weight: bold; color: #991b1b; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    th, td { text-align: left; padding: 10px 14px; font-size: 13px; border-bottom: 1px solid #e2e8f0; }
    th { width: 34%; background: #f8fafc; color: #475569; font-weight: 600; }
    td { width: 66%; color: #0f172a; word-break: break-all; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }
    .cta-box { background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 14px 18px; border-radius: 4px; font-size: 13.5px; line-height: 1.5; color: #92400e; margin-bottom: 20px; }
    .footer { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 16px 24px; font-size: 11.5px; color: #64748b; text-align: center; line-height: 1.4; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 CRITICAL DIGITAL EVIDENCE INTEGRITY ALERT</h1>
      <p>DIG_EVI Digital Evidence Chain of Custody &amp; Management System</p>
    </div>
    <div class="body">
      <p class="lead">
        A critical digital evidence integrity anomaly was detected by the automated cryptographic background monitoring system. Immediate administrative attention is recommended.
      </p>
      <div class="alert-card">
        FAILURE CLASSIFICATION: ${escapeHtml(alert_type || "TAMPER_DETECTED")} (${escapeHtml(severity || "CRITICAL")})
      </div>
      <table>
        <tr><th>Alert Reference</th><td>#${escapeHtml(alert_id || "NEW")}</td></tr>
        <tr><th>Case ID</th><td>Case ID ${escapeHtml(case_id || "N/A")}${case_number ? ` (${escapeHtml(case_number)})` : ""}</td></tr>
        <tr><th>Evidence ID</th><td>${escapeHtml(evidence_id || "N/A")}</td></tr>
        <tr><th>Evidence Number</th><td class="mono"><strong>${escapeHtml(evidence_number || "N/A")}</strong></td></tr>
        <tr><th>Evidence Name</th><td>${escapeHtml(evidence_name || "N/A")}</td></tr>
        <tr><th>Integrity Failure</th><td style="color: #b91c1c; font-weight: bold;">${escapeHtml(alert_type || "TAMPER_DETECTED")}</td></tr>
        <tr><th>Detection Timestamp</th><td>${escapeHtml(detectionTime)}</td></tr>
        <tr><th>Stored SHA-256 Hash</th><td class="mono">${escapeHtml(stored_hash || "Not Available")}</td></tr>
        <tr><th>Detected SHA-256 Hash</th><td class="mono">${escapeHtml(detected_hash || "Not Available")}</td></tr>
        <tr><th>Storage Path</th><td class="mono">${escapeHtml(file_path || "N/A")}</td></tr>
        <tr><th>Diagnostic Detail</th><td>${escapeHtml(message || "Evidence integrity verification failed.")}</td></tr>
      </table>
      <div class="cta-box">
        <strong>ACTION REQUIRED:</strong> Please log in to the DIG_EVI system, open the <strong>Alert Center</strong> dashboard, inspect the evidence exhibits and chain of custody logs, and follow the standard evidence compromise response protocols.
      </div>
    </div>
    <div class="footer">
      Automated System Notification &bull; DIG_EVI Sentinel Integrity Monitor &bull; Confidential Administrative Record
    </div>
  </div>
</body>
</html>
`;

        const fromAddress = process.env.SMTP_FROM || `"DIG_EVI Sentinel Alert" <${process.env.SMTP_USER || "sentinel@dig-evi.local"}>`;

        const sendResult = await transporter.sendMail({
            from: fromAddress,
            to: recipient,
            subject: subject,
            text: textContent,
            html: htmlContent
        });

        const previewUrl = isEthereal ? nodemailer.getTestMessageUrl(sendResult) : null;
        if (previewUrl) {
            console.log(`[EmailService] >>> Ethereal demo email preview URL: ${previewUrl}`);
        } else {
            console.log(`[EmailService] Tamper alert notification successfully sent to ${maskEmail(recipient)} (Message ID: ${sendResult.messageId})`);
        }

        return {
            sent: true,
            messageId: sendResult.messageId,
            recipient: recipient,
            previewUrl: previewUrl,
            subject: subject,
            text: textContent
        };
    } catch (err) {
        console.error("[EmailService] Failed to send tamper alert email (non-fatal):", err.message);
        return {
            sent: false,
            error: err.message
        };
    }
};

/**
 * Sends a single digest email summarizing several newly created alerts in one scan.
 * HTML escapes all dynamic values.
 *
 * @param {Array<Object>} alerts Array of alert objects
 * @param {Object} options Optional settings
 * @returns {Promise<Object>}
 */
const sendTamperAlertDigestEmail = async (alerts, options = {}) => {
    try {
        if (!Array.isArray(alerts) || alerts.length === 0) {
            return { sent: false, reason: "NO_ALERTS" };
        }

        const forceEthereal = Boolean(options.useEthereal);
        const { transporter, isEthereal } = await getTransporter(forceEthereal);

        if (!transporter) {
            console.error(`[EmailService] SMTP email notifications unconfigured. Suppressing digest email for ${alerts.length} exhibits.`);
            return { sent: false, reason: "SMTP_NOT_CONFIGURED" };
        }

        const recipient = (await resolveRecipientEmail()) || (isEthereal ? "admin.sentinel@dig-evi.local" : null);
        if (!recipient) {
            return { sent: false, reason: "NO_RECIPIENT_EMAIL" };
        }

        const subject = `[DIG_EVI DIGEST] CRITICAL: ${alerts.length} Digital Evidence Integrity Anomalies Detected`;
        const scanTime = new Date().toLocaleString("en-US", { timeZone: "UTC", dateStyle: "full", timeStyle: "long" }) + " (UTC)";

        const textTable = alerts.map((a, idx) => {
            return `[#${idx + 1}] Alert #${a.alert_id || "NEW"} | Exhibit: ${a.evidence_number || a.evidence_id} (${a.evidence_name || "N/A"})
    Anomaly Type:  ${a.alert_type} | Severity: ${a.severity || "CRITICAL"}
    Stored Hash:   ${a.stored_hash || "N/A"}
    Detected Hash: ${a.detected_hash || "N/A"}
    Message:       ${a.message || "Failed integrity verification"}`;
        }).join("\n\n");

        const textContent = `
================================================================================
DIG_EVI DIGITAL EVIDENCE MANAGEMENT SYSTEM — INTEGRITY ALERT DIGEST
================================================================================
ATTENTION: System Administrator

A cryptographic vault integrity scan detected ${alerts.length} evidence anomalies.
Scan Timestamp: ${scanTime}

INCIDENT SUMMARY:
--------------------------------------------------------------------------------
${textTable}

--------------------------------------------------------------------------------
ACTION REQUIRED:
Please open the DIG_EVI Alert Center immediately to review these incidents,
inspect chain of custody logs, and follow standard forensic response protocols.
================================================================================
`.trim();

        const rowsHtml = alerts.map(a => `
          <tr>
            <td class="mono">#${escapeHtml(a.alert_id || "NEW")}</td>
            <td class="mono"><strong>${escapeHtml(a.evidence_number || "N/A")}</strong></td>
            <td>${escapeHtml(a.evidence_name || "N/A")}</td>
            <td style="color: #b91c1c; font-weight: bold;">${escapeHtml(a.alert_type)}</td>
            <td>${escapeHtml(a.severity || "CRITICAL")}</td>
            <td style="font-size: 11.5px; color: #475569;">${escapeHtml(a.message || "Failed integrity check")}</td>
          </tr>
        `).join("");

        const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b; }
    .container { max-width: 750px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #cbd5e1; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
    .header { background: #b91c1c; color: #ffffff; padding: 20px 24px; }
    .header h1 { margin: 0; font-size: 19px; font-weight: 700; }
    .header p { margin: 6px 0 0 0; font-size: 13px; opacity: 0.92; }
    .body { padding: 24px; }
    .alert-card { background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #dc2626; padding: 12px 16px; border-radius: 4px; margin-bottom: 20px; font-size: 14px; font-weight: bold; color: #991b1b; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; }
    th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid #e2e8f0; }
    th { background: #f8fafc; color: #475569; font-weight: 600; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .cta-box { background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 14px 18px; border-radius: 4px; font-size: 13px; color: #92400e; margin-bottom: 20px; }
    .footer { background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 14px 24px; font-size: 11px; color: #64748b; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🚨 CRITICAL INTEGRITY SCAN DIGEST (${escapeHtml(alerts.length)} ANOMALIES)</h1>
      <p>DIG_EVI Digital Evidence Chain of Custody &amp; Management System</p>
    </div>
    <div class="body">
      <div class="alert-card">
        ANOMALIES DETECTED: ${escapeHtml(alerts.length)} evidence exhibit(s) failed cryptographic integrity verification during scheduled scan.
      </div>
      <table>
        <thead>
          <tr>
            <th>Ref</th>
            <th>Evidence #</th>
            <th>Exhibit Name</th>
            <th>Anomaly Type</th>
            <th>Severity</th>
            <th>Diagnostic Message</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml}
        </tbody>
      </table>
      <div class="cta-box">
        <strong>ACTION REQUIRED:</strong> Please log in to the DIG_EVI Alert Center to review these incidents, inspect chain of custody logs, and follow standard evidence compromise response protocols.
      </div>
    </div>
    <div class="footer">
      Automated Digest Notification &bull; DIG_EVI Sentinel Integrity Monitor &bull; Scan Time: ${escapeHtml(scanTime)}
    </div>
  </div>
</body>
</html>
`;

        const fromAddress = process.env.SMTP_FROM || `"DIG_EVI Sentinel Alert" <${process.env.SMTP_USER || "sentinel@dig-evi.local"}>`;
        const sendResult = await transporter.sendMail({
            from: fromAddress,
            to: recipient,
            subject: subject,
            text: textContent,
            html: htmlContent
        });

        const previewUrl = isEthereal ? nodemailer.getTestMessageUrl(sendResult) : null;
        console.log(`[EmailService] Tamper digest email sent for ${alerts.length} exhibits to ${maskEmail(recipient)} (Message ID: ${sendResult.messageId})`);

        return {
            sent: true,
            messageId: sendResult.messageId,
            recipient: recipient,
            previewUrl: previewUrl,
            subject: subject,
            text: textContent,
            isDigest: true,
            count: alerts.length
        };
    } catch (err) {
        console.error("[EmailService] Failed to send digest email:", err.message);
        return {
            sent: false,
            error: err.message
        };
    }
};

/**
 * Sends a safe administrative test email using configured SMTP settings.
 * Strictly sanitizes output so passwords and credentials are never leaked.
 *
 * @param {number} requestedByUserId The user ID of the requesting administrator
 * @returns {Promise<Object>} Safe result summary
 */
const sendTestEmail = async (requestedByUserId) => {
    try {
        const isConfigured = isSmtpConfigured();
        const isDemoMail = String(process.env.DEMO_MAIL || "").toLowerCase() === "true";

        if (!isConfigured && !isDemoMail) {
            return {
                success: false,
                configured: false,
                error: "SMTP credentials are not configured in backend/.env. Please configure SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASS."
            };
        }

        const { transporter, isEthereal } = await getTransporter();
        if (!transporter) {
            return {
                success: false,
                configured: false,
                error: "Unable to initialize mail transport."
            };
        }

        const recipient = (await resolveRecipientEmail()) || (isEthereal ? "admin.sentinel@dig-evi.local" : null);
        if (!recipient) {
            return {
                success: false,
                configured: true,
                error: "No administrator recipient email found. Configure SYSTEM_ADMIN_EMAIL in .env or set an admin user email in the database."
            };
        }

        const fromAddress = process.env.SMTP_FROM || `"DIG_EVI Sentinel" <${process.env.SMTP_USER || "sentinel@dig-evi.local"}>`;
        const testTimestamp = new Date().toUTCString();

        const info = await transporter.sendMail({
            from: fromAddress,
            to: recipient,
            subject: "[DIG_EVI] Forensic Sentinel — SMTP Configuration Test",
            text: `This is a test notification from the DIG_EVI Digital Evidence Management System sent at ${testTimestamp}. Your SMTP mail transport is operational.`,
            html: `
                <div style="font-family: sans-serif; padding: 20px; background: #f8fafc;">
                    <div style="max-width: 500px; margin: 0 auto; background: white; padding: 24px; border-radius: 8px; border: 1px solid #e2e8f0;">
                        <h3 style="color: #4f46e5; margin-top: 0;">🛡️ DIG_EVI Mail Dispatch Test</h3>
                        <p style="font-size: 14px; color: #334155;">This is an administrative test notification confirming that the DIG_EVI SMTP dispatch channel is operational.</p>
                        <p style="font-size: 12px; color: #64748b;">Timestamp: ${escapeHtml(testTimestamp)}</p>
                    </div>
                </div>
            `
        });

        const previewUrl = isEthereal ? nodemailer.getTestMessageUrl(info) : null;
        const maskedRecipient = maskEmail(recipient);

        // Record successful test in audit logs
        if (requestedByUserId) {
            try {
                await auditService.createAuditLog(
                    requestedByUserId,
                    null,
                    "EMAIL_TEST_SENT",
                    `Administrative test email sent successfully to ${maskedRecipient}`
                );
            } catch (_) {}
        }

        return {
            success: true,
            configured: true,
            isDemo: isEthereal,
            recipient: maskedRecipient,
            messageId: info.messageId,
            previewUrl: previewUrl,
            message: `Test email successfully dispatched to ${maskedRecipient}`
        };
    } catch (err) {
        // Sanitize error string so no passwords or tokens can leak
        let safeError = err.message || "Unknown SMTP dispatch error";
        if (process.env.SMTP_PASS && process.env.SMTP_PASS.trim()) {
            safeError = safeError.split(process.env.SMTP_PASS.trim()).join("[REDACTED]");
        }
        if (process.env.JWT_SECRET && process.env.JWT_SECRET.trim()) {
            safeError = safeError.split(process.env.JWT_SECRET.trim()).join("[REDACTED]");
        }

        if (safeError.includes("535") || safeError.includes("BadCredentials") || safeError.includes("Username and Password not accepted")) {
            safeError += " — Note for Gmail: Google requires a 16-character App Password (not your normal account password). Generate one at https://myaccount.google.com/apppasswords and set it in SMTP_PASS.";
        }

        if (requestedByUserId) {
            try {
                await auditService.createAuditLog(
                    requestedByUserId,
                    null,
                    "EMAIL_TEST_FAILED",
                    `Administrative test email failed: ${safeError}`
                );
            } catch (_) {}
        }

        return {
            success: false,
            configured: true,
            error: safeError
        };
    }
};

/**
 * Dispatches the daily signed integrity manifest to the system administrator via email.
 */
const sendSignedManifestEmail = async (manifestDoc) => {
    const { transporter, isEthereal } = await getTransporter();
    if (!transporter) {
        return {
            sent: false,
            configured: false,
            reason: "SMTP not configured. Manifest email suppressed."
        };
    }

    const recipient = await resolveRecipientEmail();
    const fromAddress = process.env.SMTP_FROM || `"Digital Evidence Vault" <no-reply@police.gov>`;
    const timestampStr = manifestDoc.generated_at || new Date().toISOString();
    const jsonStr = JSON.stringify(manifestDoc, null, 2);

    try {
        const info = await transporter.sendMail({
            from: fromAddress,
            to: recipient,
            subject: `[DIG_EVI] Daily Signed Evidence Integrity Manifest (${manifestDoc.total_records} exhibits)`,
            text: `Daily Signed Evidence Integrity Manifest generated at ${timestampStr}.\nTotal Exhibits: ${manifestDoc.total_records}\nLatest Audit Chain Hash: ${manifestDoc.latest_audit_hash}\nHMAC Signature: ${manifestDoc.signature?.hmac}`,
            html: `
                <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0d14; color: #e2e8f0; padding: 24px;">
                    <div style="max-width: 600px; margin: 0 auto; background-color: #121526; border: 1px solid #232942; border-radius: 8px; padding: 24px;">
                        <h2 style="color: #8b5cf6; margin-top: 0;">🛡️ Daily Signed Integrity Manifest</h2>
                        <p style="font-size: 14px; color: #94a3b8;">An automated cryptographic manifest of all evidence exhibits and the immutable audit log chain has been generated and signed with HMAC-SHA256.</p>
                        <table style="width: 100%; font-size: 13px; border-collapse: collapse; margin: 16px 0;">
                            <tr><td style="padding: 6px 0; color: #64748b;">Generated At:</td><td style="font-family: monospace; color: #f1f5f9;">${escapeHtml(timestampStr)}</td></tr>
                            <tr><td style="padding: 6px 0; color: #64748b;">Total Exhibits:</td><td style="font-weight: 600; color: #f1f5f9;">${escapeHtml(manifestDoc.total_records)}</td></tr>
                            <tr><td style="padding: 6px 0; color: #64748b;">Audit Chain Head:</td><td style="font-family: monospace; color: #a78bfa; word-break: break-all;">${escapeHtml(manifestDoc.latest_audit_hash)}</td></tr>
                            <tr><td style="padding: 6px 0; color: #64748b;">HMAC Signature:</td><td style="font-family: monospace; color: #38bdf8; word-break: break-all;">${escapeHtml(manifestDoc.signature?.hmac)}</td></tr>
                        </table>
                        <p style="font-size: 12px; color: #64748b; margin-bottom: 0;">The complete manifest JSON is attached to this dispatch.</p>
                    </div>
                </div>
            `,
            attachments: [
                {
                    filename: `manifest-${timestampStr.split("T")[0]}.json`,
                    content: jsonStr,
                    contentType: "application/json"
                }
            ]
        });

        const previewUrl = isEthereal ? nodemailer.getTestMessageUrl(info) : null;
        return {
            sent: true,
            configured: true,
            isDemo: isEthereal,
            recipient: maskEmail(recipient),
            messageId: info.messageId,
            previewUrl
        };
    } catch (err) {
        let safeError = err.message || "Failed to dispatch manifest email";
        if (process.env.SMTP_PASS && process.env.SMTP_PASS.trim()) {
            safeError = safeError.split(process.env.SMTP_PASS.trim()).join("[REDACTED]");
        }
        return {
            sent: false,
            configured: true,
            error: safeError
        };
    }
};

/**
 * Helper to verify SMTP credentials and connectivity during manual testing.
 */
const verifySmtpConnection = async () => {
    const { transporter, isEthereal } = await getTransporter();
    if (!transporter) {
        return {
            configured: false,
            message: "SMTP credentials are not configured in environment variables."
        };
    }
    try {
        await transporter.verify();
        return {
            configured: true,
            connected: true,
            isEthereal: isEthereal,
            message: isEthereal ? "Ethereal demo mail transporter active." : "SMTP connection verified successfully."
        };
    } catch (err) {
        let errMessage = err.message || "SMTP connection failed";
        if (errMessage.includes("535") || errMessage.includes("BadCredentials") || errMessage.includes("Username and Password not accepted")) {
            errMessage += " — Note for Gmail: Google requires a 16-character App Password (not your normal account password). Generate one at https://myaccount.google.com/apppasswords and set it in SMTP_PASS.";
        }
        return {
            configured: true,
            connected: false,
            error: errMessage
        };
    }
};

module.exports = {
    isSmtpConfigured,
    getTransporter,
    resolveRecipientEmail,
    maskEmail,
    escapeHtml,
    getEmailConfigurationStatus,
    sendTamperAlertEmail,
    sendTamperAlertDigestEmail,
    sendTestEmail,
    sendSignedManifestEmail,
    verifySmtpConnection
};
