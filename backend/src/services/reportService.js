const pool = require("../config/db");
const reportModel = require("../models/reportModel");
const userModel = require("../models/userModel");
const auditService = require("./auditService");

/**
 * Validates that the executing user has the authorized Forensic Officer role (role_id === 4).
 * Enforces role authorization at the service layer to prevent route bypass.
 *
 * @param {Object|number} user User object from req.user or numeric user_id
 * @param {string} actionName Descriptive action name for audit log
 * @param {number|null} evidenceId Optional associated evidence_id
 * @returns {Promise<{ userId: number, roleId: number }>}
 */
const checkReportAuthorRole = async (user, actionName = "report authoring", evidenceId = null) => {
    let roleId = null;
    let userId = null;
    let empId = "Unknown";

    if (user && typeof user === "object") {
        roleId = user.role_id;
        userId = user.user_id;
        empId = user.employee_id || user.full_name || `User #${userId}`;
    } else if (typeof user === "number") {
        userId = user;
        const u = await userModel.getUserById(userId);
        if (u) {
            roleId = u.role_id;
            empId = u.employee_id || u.full_name || `User #${userId}`;
        }
    }

    if (roleId !== 4) {
        if (userId) {
            try {
                await auditService.createAuditLog(
                    userId,
                    evidenceId || null,
                    "ACCESS_DENIED",
                    `[SECURITY] Unauthorized ${actionName} attempt by user ${empId} (Role ID: ${roleId || "Unknown"}). Write access restricted to Forensic Officer.`
                );
            } catch (auditErr) {
                console.warn("[ReportService] Failed to record access denied audit entry:", auditErr.message);
            }
        }

        const forbiddenError = new Error("Your role has view-only access to reports.");
        forbiddenError.statusCode = 403;
        forbiddenError.code = "FORBIDDEN";
        throw forbiddenError;
    }

    return { userId, roleId };
};

const generateReportNumber = async (prefix = "FAR") => {
    const latest = await reportModel.getLatestReportNumber();
    const year = new Date().getFullYear();
    if (!latest || !latest.report_number) {
        return `${prefix}-${year}-001`;
    }
    const parts = latest.report_number.split("-");
    const lastNum = parseInt(parts[parts.length - 1], 10) || 0;
    const nextNum = String(lastNum + 1).padStart(3, "0");
    return `${prefix}-${year}-${nextNum}`;
};

const generateAutopsyNumber = async () => {
    const latest = await reportModel.getLatestAutopsyNumber();
    const year = new Date().getFullYear();
    if (!latest || !latest.autopsy_number) {
        return `AUT-${year}-001`;
    }
    const parts = latest.autopsy_number.split("-");
    const lastNum = parseInt(parts[parts.length - 1], 10) || 0;
    const nextNum = String(lastNum + 1).padStart(3, "0");
    return `AUT-${year}-${nextNum}`;
};

const createForensicReport = async (reportData, user) => {
    const { userId } = await checkReportAuthorRole(user, "Forensic Report creation", reportData.evidence_id);

    if (!reportData.report_number) {
        reportData.report_number = await generateReportNumber("FAR");
    }
    reportData.analyst_id = userId;
    const report = await reportModel.createForensicReport(reportData);
    await auditService.createAuditLog(
        userId,
        reportData.evidence_id,
        "REPORT_CREATED",
        `Created forensic report ${report.report_number}: ${report.report_title}`
    );
    return report;
};

const dispatchForensicReport = async (reportId, dispatchData, user) => {
    const { userId } = await checkReportAuthorRole(user, "Forensic Report dispatch");

    const dispatched = await reportModel.dispatchForensicReport(reportId, dispatchData);
    await auditService.createAuditLog(
        userId,
        dispatched.evidence_id,
        "REPORT_DISPATCHED",
        `Dispatched forensic report ${dispatched.report_number} to ${dispatchData.recipient_agency || dispatchData.recipient_name} (${dispatchData.transmission_priority} Priority)`
    );
    return dispatched;
};

const createAutopsy = async (autopsyData, user) => {
    const { userId } = await checkReportAuthorRole(user, "Digital Autopsy creation", autopsyData.evidence_id);

    if (!autopsyData.autopsy_number) {
        autopsyData.autopsy_number = await generateAutopsyNumber();
    }
    autopsyData.examiner_id = userId;
    const autopsy = await reportModel.createAutopsy(autopsyData);
    await auditService.createAuditLog(
        userId,
        autopsyData.evidence_id,
        "AUTOPSY_LOGGED",
        `Completed autopsy ${autopsy.autopsy_number} for device ${autopsy.device_type}`
    );
    return autopsy;
};

const dispatchAutopsy = async (autopsyId, dispatchData, user) => {
    const { userId } = await checkReportAuthorRole(user, "Digital Autopsy dispatch");

    const dispatched = await reportModel.dispatchAutopsy(autopsyId, dispatchData);
    await auditService.createAuditLog(
        userId,
        dispatched.evidence_id,
        "AUTOPSY_DISPATCHED",
        `Dispatched autopsy report ${dispatched.autopsy_number} to ${dispatchData.dispatched_to}`
    );
    return dispatched;
};

module.exports = {
    createForensicReport,
    dispatchForensicReport,
    createAutopsy,
    dispatchAutopsy,
    checkReportAuthorRole
};
