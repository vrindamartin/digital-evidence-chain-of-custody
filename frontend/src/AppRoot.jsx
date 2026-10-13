import AlertCenter from "./components/AlertCenter";
import ForensicSuite from "./components/ForensicSuite";
import { useState, useEffect } from "react";
import {
  PageHeader,
  Card,
  Badge,
  Button,
  FormField,
  MetaItem,
  EmptyState,
  EvidenceCard,
  SidebarItem,
  DashboardIcon,
  VaultIcon,
  UploadIcon,
  CasesIcon,
  CustodyIcon,
  AuditIcon,
  ReportsIcon,
  AlertsIcon,
  ForensicIcon,
  LogoutIcon
} from "./components/common";
import "./App.css";
import "./layout.css";

function App() {
  // =========================
  // LOGIN STATE
  // =========================

  const [employeeId, setEmployeeId] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  // =========================
  // PAGE STATE
  // =========================

  const [currentPage, setCurrentPage] = useState("dashboard");

  // =========================
  // USER STATE
  // =========================

  const [loggedIn, setLoggedIn] = useState(
    !!localStorage.getItem("token")
  );

  const [user, setUser] = useState(() => {
    const savedUser = localStorage.getItem("user");
    return savedUser ? JSON.parse(savedUser) : null;
  });

  // =========================
  // EVIDENCE STATE
  // =========================

  const [evidence, setEvidence] = useState([]);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  // =========================
// CASE STATE
// =========================
const [cases, setCases] = useState([]);
const [casesLoading, setCasesLoading] = useState(false);
const [caseForm, setCaseForm] = useState({
  case_title: "",
  case_description: "",
  investigating_officer: ""
});

const [caseCreateLoading, setCaseCreateLoading] = useState(false);
const [caseMessage, setCaseMessage] = useState("");
const [caseError, setCaseError] = useState("");
const [selectedCaseId, setSelectedCaseId] = useState("");

const [verificationResults, setVerificationResults] = useState({});
  const [verifyingId, setVerifyingId] = useState(null);
  const [decryptingId, setDecryptingId] = useState(null);
  const [vaultNotice, setVaultNotice] = useState(null);

  // =========================
  // UPLOAD STATE
  // =========================

  const [uploadForm, setUploadForm] = useState({
    case_id: "",
    evidence_name: "",
    evidence_type: "",
    description: "",
  });

  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadLoading, setUploadLoading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState("");
  const [uploadError, setUploadError] = useState("");
    // =========================
  // CHAIN OF CUSTODY STATE
  // =========================

  const [selectedCustodyEvidence, setSelectedCustodyEvidence] = useState("");
  const [custodyLogs, setCustodyLogs] = useState([]);
  const [custodyLoading, setCustodyLoading] = useState(false);

  const [transferForm, setTransferForm] = useState({
    to_user: "7",
    action: "TRANSFERRED",
    remarks: "",
  });

  const [transferLoading, setTransferLoading] = useState(false);
  const [transferMessage, setTransferMessage] = useState("");
  const [transferError, setTransferError] = useState("");
  // =========================
// AUDIT LOG STATE
// =========================

const [auditLogs, setAuditLogs] = useState([]);
const [auditLoading, setAuditLoading] = useState(false);
// =========================
// FETCH EVIDENCE
// =========================

const fetchEvidence = async (attempt = 1) => {
  const token = localStorage.getItem("token");

  if (!token) {
    return;
  }

  setEvidenceLoading(true);

  try {
    const response = await fetch(
      "http://localhost:3000/api/evidence",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    const data = await response.json();

    // Token expired / invalid
    if (response.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");

      setUser(null);
      setLoggedIn(false);
      setEvidence([]);

      return;
    }

    if (!response.ok) {
      throw new Error(
        data.message || "Failed to fetch evidence"
      );
    }

    setEvidence(data.data || []);

  } catch (error) {
    console.error(
      `Evidence fetch attempt ${attempt} failed:`,
      error
    );

    // Retry automatically up to 3 times
    if (attempt < 3) {
      setTimeout(() => {
        fetchEvidence(attempt + 1);
      }, 1000);
    }

  } finally {
    setEvidenceLoading(false);
  }
};
// =========================
// FETCH CASES
// =========================
const fetchCases = async () => {
  const token = localStorage.getItem("token");

  if (!token) {
    return;
  }

  setCasesLoading(true);

  try {
    const response = await fetch(
      "http://localhost:3000/api/cases",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.message || "Failed to fetch cases"
      );
    }

    setCases(data.data || []);
  } catch (error) {
    console.error("Cases fetch error:", error);
    setCases([]);
  } finally {
    setCasesLoading(false);
  }
};
// =========================
// CREATE CASE
// =========================

const handleCaseChange = (e) => {
  const { name, value } = e.target;

  setCaseForm((previous) => ({
    ...previous,
    [name]: value
  }));
};

const handleCreateCase = async (e) => {
  e.preventDefault();

  setCaseMessage("");
  setCaseError("");

  const token = localStorage.getItem("token");

  if (!token) {
    setCaseError("You are not logged in.");
    return;
  }

  setCaseCreateLoading(true);

  try {
    const response = await fetch(
      "http://localhost:3000/api/cases",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          case_title: caseForm.case_title,
          case_description: caseForm.case_description,
          investigating_officer: Number(
            caseForm.investigating_officer
          )
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.message || "Failed to create case"
      );
    }

    setCaseMessage(
      `Case created successfully: ${data.data.case_number}`
    );

    setCaseForm({
      case_title: "",
      case_description: "",
      investigating_officer: ""
    });

    await fetchCases();

  } catch (error) {
    console.error("Case creation error:", error);
    setCaseError(error.message);

  } finally {
    setCaseCreateLoading(false);
  }
};
  // =========================
  // LOAD EVIDENCE AFTER LOGIN
  // =========================

useEffect(() => {
  if (loggedIn) {
    fetchEvidence();
    fetchCases();

    if (currentPage === "audit") {
      fetchAuditLogs();
    }
  }
}, [loggedIn, currentPage]);

// MANDATORY DEFAULT CASE
useEffect(() => {
  if (!selectedCaseId && cases.length > 0) {
    setSelectedCaseId(cases[0].case_id);
  }
}, [cases, selectedCaseId]);
  // =========================
  // VERIFY EVIDENCE
  // =========================

  const handleVerify = async (evidenceId) => {
    const token = localStorage.getItem("token");

    if (!token) {
      return;
    }

    setVerifyingId(evidenceId);

    try {
      const response = await fetch(
        `http://localhost:3000/api/evidence/${evidenceId}/verify`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || "Verification failed"
        );
      }

      setVerificationResults((previous) => ({
        ...previous,
        [evidenceId]: data.data,
      }));
    } catch (error) {
      console.error("Verification error:", error);

      setVerificationResults((previous) => ({
        ...previous,
        [evidenceId]: {
          integrity_status: "ERROR",
          message: error.message,
        },
      }));
    } finally {
      setVerifyingId(null);
    }
  };
  const handleDecrypt = async (evidenceId) => {
    if (decryptingId) return; // Prevent double clicks

    try {
      const token = localStorage.getItem("token");
      if (!token) {
        setVaultNotice({
          type: "error",
          message: "You must be authenticated with valid role credentials to decrypt evidence."
        });
        return;
      }

      setDecryptingId(evidenceId);
      setVaultNotice(null);

      const response = await fetch(
        `http://localhost:3000/api/evidence/${evidenceId}/decrypt`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        let errMessage = "Failed to decrypt evidence";
        try {
          const errData = await response.json();
          if (errData && errData.message) errMessage = errData.message;
        } catch (_) {}
        setVaultNotice({
          type: "error",
          message: errMessage
        });
        return;
      }

      // Robustly extract filename from Content-Disposition header
      let filename = `evidence-${evidenceId}-decrypted`;
      const disposition = response.headers.get("Content-Disposition");
      if (disposition) {
        // First check RFC 5987 / UTF-8 format: filename*=UTF-8''...
        const utf8Matches = disposition.match(/filename\*=UTF-8''([^;\n]+)/i);
        if (utf8Matches && utf8Matches[1]) {
          try {
            filename = decodeURIComponent(utf8Matches[1].trim());
          } catch (_) {
            filename = utf8Matches[1].trim();
          }
        } else {
          // Standard filename="..."
          const standardMatches = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
          if (standardMatches && standardMatches[1]) {
            filename = standardMatches[1].replace(/['"]/g, "").trim();
          }
        }
      }

      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const downloadLink = document.createElement("a");
      downloadLink.href = objectUrl;
      downloadLink.download = filename;
      document.body.appendChild(downloadLink);
      downloadLink.click();
      document.body.removeChild(downloadLink);
      window.URL.revokeObjectURL(objectUrl);

      setVaultNotice({
        type: "success",
        message: `Evidence decrypted and verified: ${filename}. File securely downloaded.`
      });
    } catch (error) {
      console.error("Decryption download error:", error);
      setVaultNotice({
        type: "error",
        message: "Failed to decrypt and download evidence: " + error.message
      });
    } finally {
      setDecryptingId(null);
    }
  };

  const handleLegacyDownload = async (evidenceId) => {
    if (decryptingId) return;

    try {
      const token = localStorage.getItem("token");
      if (!token) {
        setVaultNotice({
          type: "error",
          message: "You must be authenticated with valid role credentials to download evidence."
        });
        return;
      }

      setDecryptingId(evidenceId);
      setVaultNotice(null);

      const response = await fetch(
        `http://localhost:3000/api/evidence/${evidenceId}/legacy-download`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      if (!response.ok) {
        let errMessage = "Failed to download legacy evidence";
        try {
          const errData = await response.json();
          if (errData && errData.message) errMessage = errData.message;
        } catch (_) {}
        setVaultNotice({
          type: "error",
          message: errMessage
        });
        return;
      }

      let filename = `evidence-${evidenceId}-legacy`;
      const disposition = response.headers.get("Content-Disposition");
      if (disposition) {
        const utf8Matches = disposition.match(/filename\*=UTF-8''([^;\n]+)/i);
        if (utf8Matches && utf8Matches[1]) {
          try {
            filename = decodeURIComponent(utf8Matches[1].trim());
          } catch (_) {
            filename = utf8Matches[1].trim();
          }
        } else {
          const standardMatches = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
          if (standardMatches && standardMatches[1]) {
            filename = standardMatches[1].replace(/['"]/g, "").trim();
          }
        }
      }

      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const downloadLink = document.createElement("a");
      downloadLink.href = objectUrl;
      downloadLink.download = filename;
      document.body.appendChild(downloadLink);
      downloadLink.click();
      document.body.removeChild(downloadLink);
      window.URL.revokeObjectURL(objectUrl);

      setVaultNotice({
        type: "success",
        message: `Legacy evidence verified and downloaded: ${filename}.`
      });
    } catch (error) {
      console.error("Legacy download error:", error);
      setVaultNotice({
        type: "error",
        message: "Failed to download legacy evidence: " + error.message
      });
    } finally {
      setDecryptingId(null);
    }
  };

  // =========================
  // HANDLE UPLOAD FORM CHANGE
  // =========================

  const handleUploadChange = (e) => {
    const { name, value } = e.target;

    setUploadForm((previous) => ({
      ...previous,
      [name]: value,
    }));
  };

  // =========================
  // HANDLE FILE CHANGE
  // =========================

  const handleFileChange = (e) => {
    const file = e.target.files[0];

    setSelectedFile(file || null);
  };

  // =========================
  // UPLOAD EVIDENCE
  // =========================

  const handleUpload = async (e) => {
    e.preventDefault();

    setUploadMessage("");
    setUploadError("");

    if (!selectedFile) {
      setUploadError("Please select an evidence file.");
      return;
    }

    const token = localStorage.getItem("token");

    if (!token) {
      setUploadError("You are not logged in.");
      return;
    }

    setUploadLoading(true);

    try {
      const formData = new FormData();

      formData.append(
        "case_id",
        uploadForm.case_id
      );

      formData.append(
        "evidence_name",
        uploadForm.evidence_name
      );

      formData.append(
        "evidence_type",
        uploadForm.evidence_type
      );

      formData.append(
        "description",
        uploadForm.description
      );

      formData.append(
        "evidenceFile",
        selectedFile
      );


      const response = await fetch(
        "http://localhost:3000/api/evidence",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
          body: formData,
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || "Evidence upload failed"
        );
      }

      setUploadMessage(
        `Evidence uploaded successfully: ${data.data.evidence_number}`
      );

      // Clear form
      setUploadForm({
        case_id: "",
        evidence_name: "",
        evidence_type: "",
        description: "",
      });

      setSelectedFile(null);

      // Reset file input
      document.getElementById(
        "evidenceFile"
      ).value = "";

      // Refresh evidence
      await fetchEvidence();

    } catch (error) {
      console.error("Upload error:", error);

      setUploadError(error.message);
    } finally {
      setUploadLoading(false);
    }
  };
    // ============================================================
  // CHAIN OF CUSTODY FUNCTIONS
  // ============================================================

  const fetchCustodyLogs = async (evidenceId) => {
    const token = localStorage.getItem("token");

    if (!token || !evidenceId) {
      return;
    }

    setCustodyLoading(true);
    setTransferMessage("");
    setTransferError("");

    try {
      const response = await fetch(
        `http://localhost:3000/api/custody/${evidenceId}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || "Failed to fetch custody history"
        );
      }

      setCustodyLogs(data.data || []);
    } catch (error) {
      console.error("Custody fetch error:", error);

      setCustodyLogs([]);
      setTransferError(error.message);
    } finally {
      setCustodyLoading(false);
    }
  };


  const handleCustodyEvidenceChange = (e) => {
    const evidenceId = e.target.value;

    setSelectedCustodyEvidence(evidenceId);
    setCustodyLogs([]);
    setTransferMessage("");
    setTransferError("");

    if (evidenceId) {
      fetchCustodyLogs(evidenceId);
    }
  };


  const handleTransferChange = (e) => {
    const { name, value } = e.target;

    setTransferForm((previous) => ({
      ...previous,
      [name]: value,
    }));
  };


  const handleTransfer = async (e) => {
    e.preventDefault();

    setTransferMessage("");
    setTransferError("");

    if (!selectedCustodyEvidence) {
      setTransferError("Please select evidence first.");
      return;
    }

    if (!transferForm.to_user) {
      setTransferError("Please select a recipient.");
      return;
    }

    const token = localStorage.getItem("token");

    if (!token) {
      setTransferError("You are not logged in.");
      return;
    }

    setTransferLoading(true);

    try {
      const response = await fetch(
        "http://localhost:3000/api/custody",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            evidence_id: Number(selectedCustodyEvidence),
            to_user: Number(transferForm.to_user),
            action: transferForm.action,
            remarks: transferForm.remarks,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || "Evidence transfer failed"
        );
      }

      setTransferMessage(
        "Evidence transferred successfully."
      );

      setTransferForm({
        to_user: "7",
        action: "TRANSFERRED",
        remarks: "",
      });

      await fetchCustodyLogs(selectedCustodyEvidence);

    } catch (error) {
      console.error("Transfer error:", error);

      setTransferError(error.message);

    } finally {
      setTransferLoading(false);
    }
  };
  // =========================
// FETCH AUDIT LOGS
// =========================

const fetchAuditLogs = async () => {
  const token = localStorage.getItem("token");

  if (!token) {
    return;
  }

  setAuditLoading(true);

  try {
    const response = await fetch(
      "http://localhost:3000/api/audit-logs",
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(
        data.message || "Failed to fetch audit logs"
      );
    }

    setAuditLogs(data.data || []);

  } catch (error) {
    console.error("Audit logs fetch error:", error);
    setAuditLogs([]);

  } finally {
    setAuditLoading(false);
  }
};


  // =========================
  // LOGIN
  // =========================
  // =========================
  // LOGIN
  // =========================

  const handleLogin = async (e) => {
    e.preventDefault();

    setMessage("");
    setLoading(true);

    try {
      const response = await fetch(
        "http://localhost:3000/api/login",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            employee_id: employeeId,
            password: password,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.message || "Login failed"
        );
      }

      localStorage.setItem(
        "token",
        data.data.token
      );

      localStorage.setItem(
        "user",
        JSON.stringify(data.data.user)
      );

      setUser(data.data.user);
      setLoggedIn(true);
      if (data.data.user.role_id === 4) {
        setCurrentPage("forensic");
      } else {
        setCurrentPage("dashboard");
      }

    } catch (error) {
      setMessage(error.message);

    } finally {
      setLoading(false);
    }
  };

  // =========================
  // LOGOUT
  // =========================

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");

    setUser(null);
    setLoggedIn(false);
    setEvidence([]);
    setVerificationResults({});
    setCurrentPage("dashboard");
  };

  // ============================================================
  // DASHBOARD PAGE
  // ============================================================

  const renderDashboard = () => {
    const verifiedCount = Object.values(
      verificationResults
    ).filter(
      (result) =>
        result.integrity_status === "VALID"
    ).length;

    const tamperedCount = Object.values(
      verificationResults
    ).filter(
      (result) =>
        result.integrity_status === "TAMPERED"
    ).length;

    return (
      <div className="dem-page-container">
        {/* Page Header */}
        <PageHeader
          title="Security Operations Dashboard"
          subtitle={`Welcome back, ${user?.full_name || "Investigator"}. Cryptographic custody and tamper telemetry are active.`}
          user={user}
        />

        {/* KPI STATISTICS GRID */}
        <div className="dem-kpi-grid">
          <div className="dem-kpi-card">
            <div className="dem-kpi-top">
              <span className="dem-kpi-label">Total Evidence</span>
              <span className="dem-kpi-icon">📦</span>
            </div>
            <div className="dem-kpi-val">{evidence.length}</div>
            <div className="dem-kpi-desc">Registered cryptographic files</div>
          </div>

          <div className="dem-kpi-card">
            <div className="dem-kpi-top">
              <span className="dem-kpi-label">Active Cases</span>
              <span className="dem-kpi-icon">📁</span>
            </div>
            <div className="dem-kpi-val">{cases.length}</div>
            <div className="dem-kpi-desc">Open investigation portfolios</div>
          </div>

          <div className="dem-kpi-card">
            <div className="dem-kpi-top">
              <span className="dem-kpi-label">Verified Assets</span>
              <span className="dem-kpi-icon" style={{ background: "rgba(16, 185, 129, 0.12)", borderColor: "rgba(16, 185, 129, 0.3)" }}>✓</span>
            </div>
            <div className="dem-kpi-val" style={{ color: "#34D399" }}>{verifiedCount}</div>
            <div className="dem-kpi-desc">Hash-verified without mutation</div>
          </div>

          <div className={`dem-kpi-card ${tamperedCount > 0 ? "dem-kpi-alert" : ""}`}>
            <div className="dem-kpi-top">
              <span className="dem-kpi-label">Tamper Alerts</span>
              <span className="dem-kpi-icon">⚠</span>
            </div>
            <div className="dem-kpi-val">{tamperedCount}</div>
            <div className="dem-kpi-desc">
              {tamperedCount > 0 ? "Potential integrity breach detected" : "Zero tampering discrepancies"}
            </div>
          </div>
        </div>

        {/* RECENT EVIDENCE SECTION */}
        <div>
          <div className="dem-section-header">
            <div>
              <h2 className="dem-section-title">Recent Digital Ingestion</h2>
              <p className="dem-section-subtitle">
                Latest digital assets committed into cryptographic custody
              </p>
            </div>

            <Button
              variant="primary"
              icon="+"
              onClick={() => setCurrentPage("upload")}
            >
              Upload Evidence
            </Button>
          </div>

          {evidenceLoading && (
            <Card>
              <div style={{ textAlign: "center", padding: "32px", color: "var(--text-secondary)" }}>
                <span className="dem-btn-spinner" style={{ display: "inline-block", marginBottom: "12px", width: "24px", height: "24px", borderColor: "rgba(139, 92, 246, 0.3)", borderTopColor: "var(--accent)" }} />
                <div>Loading recent evidence assets...</div>
              </div>
            </Card>
          )}

          {!evidenceLoading && evidence.length === 0 && (
            <EmptyState
              icon="📭"
              title="No Evidence Ingested Yet"
              message="Get started by submitting digital evidence files into an open case."
            />
          )}

          {!evidenceLoading && evidence.length > 0 && (
            <Card style={{ padding: "0", overflow: "hidden" }}>
              <div className="dem-table-container" style={{ border: "none" }}>
                <table className="dem-table">
                  <thead>
                    <tr>
                      <th>Evidence Number</th>
                      <th>Evidence Name</th>
                      <th>Type</th>
                      <th>Uploaded By</th>
                      <th>Date Ingested</th>
                      <th style={{ textAlign: "right" }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidence.slice(0, 5).map((item) => (
                      <tr key={item.evidence_id}>
                        <td>
                          <span className="dem-evidence-id-badge">
                            {item.evidence_number}
                          </span>
                        </td>
                        <td style={{ fontWeight: 600 }}>
                          {item.evidence_name}
                        </td>
                        <td>
                          <Badge
                            variant={
                              (item.evidence_type || "").toLowerCase().includes("doc")
                                ? "doc"
                                : (item.evidence_type || "").toLowerCase().includes("img") || (item.evidence_type || "").toLowerCase().includes("image")
                                ? "image"
                                : (item.evidence_type || "").toLowerCase().includes("vid")
                                ? "video"
                                : (item.evidence_type || "").toLowerCase().includes("aud")
                                ? "audio"
                                : "default"
                            }
                          >
                            {item.evidence_type || "File"}
                          </Badge>
                        </td>
                        <td style={{ color: "var(--text-secondary)" }}>
                          User {item.uploaded_by}
                        </td>
                        <td style={{ color: "var(--text-muted)", fontSize: "13px" }}>
                          {item.uploaded_at ? new Date(item.uploaded_at).toLocaleDateString() : "N/A"}
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setSelectedCaseId(item.case_id);
                              setCurrentPage("evidence");
                            }}
                          >
                            Inspect Vault ➔
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>

        {/* CRYPTOGRAPHIC SECURITY OVERVIEW */}
        <div>
          <div className="dem-section-header">
            <div>
              <h2 className="dem-section-title">Cryptographic Defense Framework</h2>
              <p className="dem-section-subtitle">
                Built-in mathematical integrity guarantees and access controls
              </p>
            </div>
          </div>

          <div className="dem-security-grid">
            <div className="dem-security-card">
              <span className="dem-security-icon-box">🔐</span>
              <div className="dem-security-info-box">
                <h4 className="dem-security-info-title">Envelope Encryption</h4>
                <p className="dem-security-info-desc">
                  Authenticated AES-256-GCM encryption with Galois/Counter Mode authentication tags.
                </p>
              </div>
            </div>

            <div className="dem-security-card">
              <span className="dem-security-icon-box">🛡️</span>
              <div className="dem-security-info-box">
                <h4 className="dem-security-info-title">SHA-256 Signatures</h4>
                <p className="dem-security-info-desc">
                  Strict cryptographic digest validation for zero-trust mathematical non-repudiation.
                </p>
              </div>
            </div>

            <div className="dem-security-card">
              <span className="dem-security-icon-box">🔗</span>
              <div className="dem-security-info-box">
                <h4 className="dem-security-info-title">Chain of Custody</h4>
                <p className="dem-security-info-desc">
                  Append-only immutable transfer events recording every custodial handover.
                </p>
              </div>
            </div>

            <div className="dem-security-card">
              <span className="dem-security-icon-box">📋</span>
              <div className="dem-security-info-box">
                <h4 className="dem-security-info-title">Immutable Audit Trail</h4>
                <p className="dem-security-info-desc">
                  Granular forensic logging for administrative actions, access events, and inspections.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // ============================================================
  // EVIDENCE PAGE
  // ============================================================

  const renderEvidencePage = () => {
    const selectedCase = cases.find(
      (c) => String(c.case_id) === String(selectedCaseId)
    );

    const caseEvidence = evidence.filter(
      (item) =>
        String(item.case_id) === String(selectedCaseId)
    );

    return (
      <div className="dem-page-container">
        {/* Page Header */}
        <PageHeader
          title="Evidence Vault"
          subtitle="Select an investigation case to view, verify, and decrypt cryptographic digital evidence."
          user={user}
        />

        {/* Case Selector Card */}
        <Card>
          <FormField
            label="SELECT INVESTIGATION CASE"
            id="evidence-case-select"
          >
            <select
              id="evidence-case-select"
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              disabled={casesLoading}
              className="dem-select"
            >
              <option value="">-- Choose an investigation case --</option>
              {cases.map((item) => (
                <option key={item.case_id} value={item.case_id}>
                  {item.case_number} — {item.case_title}
                </option>
              ))}
            </select>
          </FormField>
        </Card>

        {/* Selected Case Summary Card */}
        {selectedCase && (
          <div className="dem-case-summary-card">
            <div className="dem-case-summary-left">
              <span className="dem-case-summary-kicker">Active Case File</span>
              <h2 className="dem-case-summary-id">{selectedCase.case_number}</h2>
              <p className="dem-case-summary-title">{selectedCase.case_title}</p>
            </div>
            <div className="dem-case-summary-right">
              <Badge variant="count" size="lg">
                {caseEvidence.length} Evidence Record{caseEvidence.length !== 1 ? "s" : ""}
              </Badge>
            </div>
          </div>
        )}

        {/* Evidence Section Header */}
        <div className="dem-section-header">
          <div>
            <h2 className="dem-section-title">Evidence Records</h2>
            <p className="dem-section-subtitle">
              {caseEvidence.length} digital asset{caseEvidence.length !== 1 ? "s" : ""} registered in ledger
            </p>
          </div>

          <Button
            variant="outline"
            icon="↻"
            onClick={fetchEvidence}
            disabled={evidenceLoading}
          >
            {evidenceLoading ? "Refreshing..." : "Refresh"}
          </Button>
        </div>

        {/* Vault Status & Decryption Notification */}
        {vaultNotice && (
          <div className={`dem-vault-notice dem-vault-notice-${vaultNotice.type}`}>
            <div className="dem-vault-notice-content">
              <span className="dem-vault-notice-icon">
                {vaultNotice.type === "success" ? "✓" : vaultNotice.type === "error" ? "⚠" : "ℹ"}
              </span>
              <span className="dem-vault-notice-text">{vaultNotice.message}</span>
            </div>
            <button
              type="button"
              className="dem-vault-notice-close"
              onClick={() => setVaultNotice(null)}
              aria-label="Dismiss notice"
            >
              ✕
            </button>
          </div>
        )}

        {/* Evidence Loading State */}
        {evidenceLoading && (
          <Card>
            <div style={{ textAlign: "center", padding: "32px", color: "var(--text-secondary)" }}>
              <span className="dem-btn-spinner" style={{ display: "inline-block", marginBottom: "12px", width: "24px", height: "24px", borderColor: "rgba(139, 92, 246, 0.3)", borderTopColor: "var(--accent)" }} />
              <div>Loading cryptographic evidence records...</div>
            </div>
          </Card>
        )}

        {/* Empty States */}
        {!evidenceLoading && !selectedCaseId && (
          <EmptyState
            icon="📁"
            title="No Case Selected"
            message="Please select an investigation case from the dropdown above to view associated digital evidence."
          />
        )}

        {!evidenceLoading && selectedCaseId && caseEvidence.length === 0 && (
          <EmptyState
            icon="📭"
            title="No Evidence Records Found"
            message="No digital evidence has been uploaded for this case file yet."
          />
        )}

        {/* Evidence Cards Grid */}
        {!evidenceLoading && selectedCaseId && caseEvidence.length > 0 && (
          <div className="dem-evidence-grid">
            {caseEvidence.map((item) => (
              <EvidenceCard
                key={item.evidence_id}
                item={item}
                verification={verificationResults[item.evidence_id]}
                isVerifying={verifyingId === item.evidence_id}
                isDecrypting={decryptingId === item.evidence_id}
                onVerify={handleVerify}
                onDecrypt={handleDecrypt}
                onLegacyDownload={handleLegacyDownload}
                user={user}
              />
            ))}
          </div>
        )}
      </div>
    );
  };

  // ============================================================
  // UPLOAD EVIDENCE PAGE
  // ============================================================

  const renderUploadPage = () => {
    return (
      <div className="dem-page-container">
        {/* Page Header */}
        <PageHeader
          title="Upload Evidence"
          subtitle="Add and cryptographically seal new digital evidence into the immutable ledger."
          user={user}
        />

        {/* Form Card */}
        <Card>
          <div className="dem-card-header">
            <div>
              <h2 className="dem-section-title">Evidence Intake & Registration</h2>
              <p className="dem-section-subtitle">
                Provide file assets and case metadata. Cryptographic hashes are computed automatically upon intake.
              </p>
            </div>
          </div>

          <form
            onSubmit={handleUpload}
            style={{ display: "flex", flexDirection: "column", gap: "20px" }}
          >
            {/* 2-Column Field Grid */}
            <div className="dem-form-grid-2">
              <FormField
                label="Select Case"
                id="case_id"
                required
              >
                <select
                  id="case_id"
                  name="case_id"
                  value={uploadForm.case_id}
                  onChange={handleUploadChange}
                  required
                  className="dem-select"
                >
                  <option value="">
                    {casesLoading ? "Loading cases..." : "-- Select an active case --"}
                  </option>
                  {cases.map((item) => (
                    <option key={item.case_id} value={item.case_id}>
                      {item.case_number} — {item.case_title}
                    </option>
                  ))}
                </select>
              </FormField>

              <FormField
                label="Evidence Name"
                id="evidence_name"
                required
              >
                <input
                  id="evidence_name"
                  name="evidence_name"
                  type="text"
                  placeholder="e.g. CCTV Surveillance Footage Reel 04"
                  value={uploadForm.evidence_name}
                  onChange={handleUploadChange}
                  required
                  className="dem-input"
                />
              </FormField>

              <FormField
                label="Evidence Type"
                id="evidence_type"
                required
              >
                <select
                  id="evidence_type"
                  name="evidence_type"
                  value={uploadForm.evidence_type}
                  onChange={handleUploadChange}
                  required
                  className="dem-select"
                >
                  <option value="">-- Select evidence type --</option>
                  <option value="Image">Image</option>
                  <option value="Video">Video</option>
                  <option value="Audio">Audio</option>
                  <option value="Document">Document</option>
                  <option value="Other">Other / Binary</option>
                </select>
              </FormField>

              <FormField
                label="Evidence File"
                id="evidenceFile"
                required
              >
                <input
                  id="evidenceFile"
                  type="file"
                  onChange={handleFileChange}
                  required
                  className="dem-input"
                  style={{ paddingTop: "8px" }}
                />
                {selectedFile && (
                  <div className="dem-file-selected-badge">
                    <span>📄 {selectedFile.name}</span>
                    <span style={{ color: "var(--text-muted)" }}>
                      ({(selectedFile.size / 1024).toFixed(1)} KB)
                    </span>
                  </div>
                )}
              </FormField>
            </div>

            {/* Description (Full Width) */}
            <FormField
              label="Description & Context"
              id="description"
            >
              <textarea
                id="description"
                name="description"
                placeholder="Provide comprehensive forensic acquisition details, device serials, and chain of custody context..."
                value={uploadForm.description}
                onChange={handleUploadChange}
                rows="4"
                className="dem-textarea"
              />
            </FormField>

            {/* Security Callout */}
            <div className="dem-security-callout">
              <span className="dem-security-callout-icon">🔐</span>
              <div className="dem-security-callout-content">
                <h4 className="dem-security-callout-title">Cryptographic Integrity Seal</h4>
                <p className="dem-security-callout-desc">
                  This file will be automatically hashed using <strong>SHA-256</strong> to guarantee non-repudiation and encrypted using <strong>AES-256-GCM</strong> envelope encryption prior to persistent storage.
                </p>
              </div>
            </div>

            {/* Messages */}
            {uploadMessage && (
              <div className="dem-alert-banner dem-alert-success">
                <span>✓</span>
                <span>{uploadMessage}</span>
              </div>
            )}

            {uploadError && (
              <div className="dem-alert-banner dem-alert-error">
                <span>✕</span>
                <span>{uploadError}</span>
              </div>
            )}

            {/* Actions Footer */}
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px", marginTop: "8px", paddingTop: "16px", borderTop: "1px solid var(--border-subtle)" }}>
              <Button
                variant="secondary"
                onClick={() => {
                  setCurrentPage("evidence");
                  setUploadMessage("");
                  setUploadError("");
                }}
              >
                Cancel
              </Button>

              <Button
                type="submit"
                variant="primary"
                icon="🔐"
                loading={uploadLoading}
              >
                {uploadLoading ? "Uploading & Encrypting..." : "Upload Evidence"}
              </Button>
            </div>
          </form>
        </Card>
      </div>
    );
  };
     // ============================================================
  // CHAIN OF CUSTODY PAGE
  // ============================================================

  const renderCustodyPage = () => {
    const selectedEvidence = evidence.find(
      (item) =>
        String(item.evidence_id) ===
        String(selectedCustodyEvidence)
    );

    return (
      <div className="dem-page-container">
        {/* Page Header */}
        <PageHeader
          title="Chain of Custody"
          subtitle="Audit chronological custody transfers, custodian authentications, and evidentiary movement records."
          user={user}
        />

        {/* SELECT EVIDENCE CARD */}
        <Card>
          <FormField
            label="SELECT DIGITAL EVIDENCE ASSET"
            id="custodyEvidence"
          >
            <select
              id="custodyEvidence"
              value={selectedCustodyEvidence}
              onChange={handleCustodyEvidenceChange}
              disabled={evidenceLoading}
              className="dem-select"
            >
              <option value="">
                {evidenceLoading
                  ? "Loading evidence..."
                  : evidence.length === 0
                  ? "No evidence available"
                  : "-- Choose an evidence asset to inspect custody chain --"}
              </option>
              {evidence.map((item) => (
                <option key={item.evidence_id} value={item.evidence_id}>
                  {item.evidence_number} — {item.evidence_name}
                </option>
              ))}
            </select>
          </FormField>
        </Card>

        {/* SELECTED EVIDENCE SUMMARY */}
        {selectedEvidence && (
          <div className="dem-case-summary-card">
            <div className="dem-case-summary-left">
              <span className="dem-case-summary-kicker">Target Evidentiary Asset</span>
              <h2 className="dem-case-summary-id">{selectedEvidence.evidence_number}</h2>
              <p className="dem-case-summary-title">{selectedEvidence.evidence_name}</p>
            </div>
            <div className="dem-case-summary-right">
              <Badge variant="accent" size="lg">
                Case ID #{selectedEvidence.case_id}
              </Badge>
            </div>
          </div>
        )}

        {/* CUSTODY TIMELINE SECTION */}
        <div>
          <div className="dem-section-header">
            <div>
              <h2 className="dem-section-title">Custody Transfer Ledger</h2>
              <p className="dem-section-subtitle">
                {custodyLogs.length} immutable handover event{custodyLogs.length !== 1 ? "s" : ""} on record
              </p>
            </div>
          </div>

          {custodyLoading && (
            <Card>
              <div style={{ textAlign: "center", padding: "32px", color: "var(--text-secondary)" }}>
                <span className="dem-btn-spinner" style={{ display: "inline-block", marginBottom: "12px", width: "24px", height: "24px", borderColor: "rgba(139, 92, 246, 0.3)", borderTopColor: "var(--accent)" }} />
                <div>Loading custody timeline history...</div>
              </div>
            </Card>
          )}

          {!custodyLoading && !selectedCustodyEvidence && (
            <EmptyState
              icon="🔗"
              title="No Evidence Selected"
              message="Select a digital evidence asset from the dropdown above to view its verifiable custody trail."
            />
          )}

          {!custodyLoading && selectedCustodyEvidence && custodyLogs.length === 0 && (
            <EmptyState
              icon="📭"
              title="No Transfer Records Found"
              message="This evidence asset has not undergone any custodial transfers since registration."
            />
          )}

          {!custodyLoading && custodyLogs.length > 0 && (
            <div className="dem-timeline">
              {custodyLogs.map((log, index) => (
                <div className="dem-timeline-item" key={log.custody_id}>
                  <div className="dem-timeline-badge">{index + 1}</div>

                  <div className="dem-timeline-content">
                    <div className="dem-timeline-top">
                      <div className="dem-timeline-transfer">
                        <strong>{log.from_user_name || `User ${log.from_user}`}</strong>
                        <span className="dem-timeline-arrow">➔</span>
                        <strong>{log.to_user_name || `User ${log.to_user}`}</strong>
                      </div>

                      <Badge
                        variant={
                          log.action === "RECEIVED"
                            ? "valid"
                            : log.action === "TRANSFERRED"
                            ? "accent"
                            : "default"
                        }
                      >
                        {log.action}
                      </Badge>
                    </div>

                    <div className="dem-timeline-date">
                      Logged: {new Date(log.created_at).toLocaleString()}
                    </div>

                    {log.remarks && (
                      <div className="dem-timeline-remarks">
                        {log.remarks}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* TRANSFER EVIDENCE FORM CARD */}
        <Card>
          <div className="dem-card-header">
            <div>
              <h2 className="dem-section-title">Record Custodial Handover</h2>
              <p className="dem-section-subtitle">
                Authorize and document transfer of evidence responsibility to another credentialed party.
              </p>
            </div>
          </div>

          <form
            onSubmit={handleTransfer}
            style={{ display: "flex", flexDirection: "column", gap: "20px" }}
          >
            <div className="dem-form-grid-2">
              <FormField label="Target Evidence Asset">
                <input
                  type="text"
                  value={
                    selectedEvidence
                      ? `${selectedEvidence.evidence_number} — ${selectedEvidence.evidence_name}`
                      : "Please select an evidence asset above first"
                  }
                  readOnly
                  disabled
                  className="dem-input"
                />
              </FormField>

              <FormField label="Transfer To (Recipient)" id="to_user" required>
                <select
                  id="to_user"
                  name="to_user"
                  value={transferForm.to_user}
                  onChange={handleTransferChange}
                  required
                  className="dem-select"
                >
                  <option value="7">Forensic Officer — POL2026003</option>
                  <option value="6">System Administrator — POL2026002</option>
                </select>
              </FormField>

              <FormField label="Action Taken" id="action" required>
                <select
                  id="action"
                  name="action"
                  value={transferForm.action}
                  onChange={handleTransferChange}
                  required
                  className="dem-select"
                >
                  <option value="TRANSFERRED">TRANSFERRED</option>
                  <option value="RECEIVED">RECEIVED</option>
                </select>
              </FormField>
            </div>

            <FormField label="Custodial Transfer Remarks & Handover Notes" id="remarks">
              <textarea
                id="remarks"
                name="remarks"
                rows="3"
                placeholder="Detail reason for transfer, chain condition, transport container seal numbers..."
                value={transferForm.remarks}
                onChange={handleTransferChange}
                className="dem-textarea"
              />
            </FormField>

            {transferMessage && (
              <div className="dem-alert-banner dem-alert-success">
                <span>✓</span>
                <span>{transferMessage}</span>
              </div>
            )}

            {transferError && (
              <div className="dem-alert-banner dem-alert-error">
                <span>✕</span>
                <span>{transferError}</span>
              </div>
            )}

            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px", paddingTop: "14px", borderTop: "1px solid var(--border-subtle)" }}>
              <Button
                variant="secondary"
                onClick={() => {
                  setSelectedCustodyEvidence("");
                  setCustodyLogs([]);
                  setTransferMessage("");
                  setTransferError("");
                }}
              >
                Clear
              </Button>

              <Button
                type="submit"
                variant="primary"
                icon="🔗"
                disabled={transferLoading || !selectedCustodyEvidence}
                loading={transferLoading}
              >
                {transferLoading ? "Logging Transfer..." : "Record Custodial Transfer"}
              </Button>
            </div>
          </form>
        </Card>
      </div>
    );
  };
  // ============================================================
// AUDIT LOGS PAGE
// ============================================================

const renderAuditPage = () => {
  return (
    <div className="dem-page-container">
      {/* Page Header */}
      <PageHeader
        title="System Audit Logs"
        subtitle="Chronological, tamper-evident audit record tracking all system authentications and evidence operations."
        user={user}
      />

      {/* AUDIT LOGS SECTION */}
      <div>
        <div className="dem-section-header">
          <div>
            <h2 className="dem-section-title">System Activity Trail</h2>
            <p className="dem-section-subtitle">
              {auditLogs.length} immutable event record{auditLogs.length !== 1 ? "s" : ""} recorded in security journal
            </p>
          </div>

          <Button
            variant="outline"
            icon="↻"
            onClick={fetchAuditLogs}
            disabled={auditLoading}
          >
            {auditLoading ? "Refreshing..." : "Refresh"}
          </Button>
        </div>

        {auditLoading && (
          <Card>
            <div style={{ textAlign: "center", padding: "32px", color: "var(--text-secondary)" }}>
              <span className="dem-btn-spinner" style={{ display: "inline-block", marginBottom: "12px", width: "24px", height: "24px", borderColor: "rgba(139, 92, 246, 0.3)", borderTopColor: "var(--accent)" }} />
              <div>Loading cryptographic security journal...</div>
            </div>
          </Card>
        )}

        {!auditLoading && auditLogs.length === 0 && (
          <EmptyState
            icon="📋"
            title="No Audit Records Found"
            message="No system activities or evidence actions have been logged yet."
          />
        )}

        {!auditLoading && auditLogs.length > 0 && (
          <Card style={{ padding: "0", overflow: "hidden" }}>
            <div className="dem-table-container" style={{ border: "none" }}>
              <table className="dem-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>User / Operator</th>
                    <th>Evidence Reference</th>
                    <th>Operation Details</th>
                    <th style={{ textAlign: "right" }}>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log) => {
                    const actionStr = (log.action || "").toUpperCase();
                    const badgeVariant =
                      actionStr.includes("VERIF") || actionStr.includes("VALID")
                        ? "valid"
                        : actionStr.includes("TAMPER") || actionStr.includes("ERROR") || actionStr.includes("FAIL")
                        ? "tampered"
                        : actionStr.includes("TRANS")
                        ? "warning"
                        : actionStr.includes("UPLOAD") || actionStr.includes("CREATE")
                        ? "accent"
                        : actionStr.includes("AUTH") || actionStr.includes("LOGIN")
                        ? "info"
                        : "default";

                    return (
                      <tr key={log.audit_id}>
                        <td>
                          <Badge variant={badgeVariant}>
                            {log.action}
                          </Badge>
                        </td>
                        <td style={{ fontWeight: 600 }}>
                          {log.user_name || `User ${log.user_id}`}
                        </td>
                        <td>
                          {log.evidence_number ? (
                            <span className="dem-evidence-id-badge">
                              {log.evidence_number}
                            </span>
                          ) : (
                            <span style={{ color: "var(--text-dim)" }}>—</span>
                          )}
                        </td>
                        <td style={{ color: "var(--text-secondary)", maxWidth: "340px", wordBreak: "break-word" }}>
                          {log.details || "—"}
                        </td>
                        <td style={{ textAlign: "right", color: "var(--text-muted)", fontSize: "13px", fontFamily: "var(--font-mono)" }}>
                          {new Date(log.created_at).toLocaleString()}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
};
// ============================================================
// CASES PAGE
// ============================================================

const renderCasesPage = () => {
  return (
    <div className="dem-page-container">
      {/* Page Header */}
      <PageHeader
        title="Investigation Cases"
        subtitle="Manage official case investigations, track assigned officers, and inspect evidence registries."
        user={user}
      />

      {/* CREATE CASE CARD */}
      <Card>
        <div className="dem-card-header">
          <div>
            <h2 className="dem-section-title">Open New Investigation Case</h2>
            <p className="dem-section-subtitle">
              Register a unique case portfolio before attaching cryptographic digital evidence.
            </p>
          </div>
        </div>

        <form
          onSubmit={handleCreateCase}
          style={{ display: "flex", flexDirection: "column", gap: "20px" }}
        >
          <div className="dem-form-grid-2">
            <FormField
              label="Case Title"
              id="case_title"
              required
            >
              <input
                id="case_title"
                name="case_title"
                type="text"
                placeholder="e.g. Operation Nightfall Cyber Extortion"
                value={caseForm.case_title}
                onChange={handleCaseChange}
                required
                className="dem-input"
              />
            </FormField>

            <FormField
              label="Investigating Officer (User ID)"
              id="investigating_officer"
              required
            >
              <input
                id="investigating_officer"
                name="investigating_officer"
                type="number"
                placeholder="e.g. 2"
                value={caseForm.investigating_officer}
                onChange={handleCaseChange}
                required
                className="dem-input"
              />
            </FormField>
          </div>

          <FormField
            label="Case Synopsis & Description"
            id="case_description"
            required
          >
            <textarea
              id="case_description"
              name="case_description"
              placeholder="Outline the incident details, relevant statutory penal codes, and scope of investigation..."
              value={caseForm.case_description}
              onChange={handleCaseChange}
              required
              rows="4"
              className="dem-textarea"
            />
          </FormField>

          {caseMessage && (
            <div className="dem-alert-banner dem-alert-success">
              <span>✓</span>
              <span>{caseMessage}</span>
            </div>
          )}

          {caseError && (
            <div className="dem-alert-banner dem-alert-error">
              <span>✕</span>
              <span>{caseError}</span>
            </div>
          )}

          <div style={{ display: "flex", justifyContent: "flex-end", paddingTop: "14px", borderTop: "1px solid var(--border-subtle)" }}>
            <Button
              type="submit"
              variant="primary"
              icon="📁"
              loading={caseCreateLoading}
            >
              {caseCreateLoading ? "Creating Investigation..." : "Create Investigation Case"}
            </Button>
          </div>
        </form>
      </Card>

      {/* EXISTING CASES SECTION */}
      <div>
        <div className="dem-section-header">
          <div>
            <h2 className="dem-section-title">Active Case Registries</h2>
            <p className="dem-section-subtitle">
              {cases.length} investigation record{cases.length !== 1 ? "s" : ""} on file
            </p>
          </div>

          <Button
            variant="outline"
            icon="↻"
            onClick={fetchCases}
            disabled={casesLoading}
          >
            {casesLoading ? "Refreshing..." : "Refresh"}
          </Button>
        </div>

        {casesLoading && (
          <Card>
            <div style={{ textAlign: "center", padding: "32px", color: "var(--text-secondary)" }}>
              <span className="dem-btn-spinner" style={{ display: "inline-block", marginBottom: "12px", width: "24px", height: "24px", borderColor: "rgba(139, 92, 246, 0.3)", borderTopColor: "var(--accent)" }} />
              <div>Loading investigation cases...</div>
            </div>
          </Card>
        )}

        {!casesLoading && cases.length === 0 && (
          <EmptyState
            icon="📁"
            title="No Investigation Cases Found"
            message="No cases have been opened in the system yet. Use the form above to initialize the first case."
          />
        )}

        {!casesLoading && cases.length > 0 && (
          <Card style={{ padding: "0", overflow: "hidden" }}>
            <div className="dem-table-container" style={{ border: "none" }}>
              <table className="dem-table">
                <thead>
                  <tr>
                    <th>Case Number</th>
                    <th>Case Title</th>
                    <th>Lead Officer</th>
                    <th>Status</th>
                    <th>Registered At</th>
                    <th style={{ textAlign: "right" }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.map((item) => (
                    <tr key={item.case_id}>
                      <td>
                        <span className="dem-evidence-id-badge">
                          {item.case_number}
                        </span>
                      </td>
                      <td style={{ fontWeight: 600 }}>
                        {item.case_title}
                      </td>
                      <td style={{ color: "var(--text-secondary)" }}>
                        User {item.investigating_officer}
                      </td>
                      <td>
                        <Badge
                          variant={
                            item.status === "ACTIVE" || item.status === "OPEN"
                              ? "valid"
                              : item.status === "CLOSED"
                              ? "default"
                              : "accent"
                          }
                        >
                          {item.status || "ACTIVE"}
                        </Badge>
                      </td>
                      <td style={{ color: "var(--text-muted)", fontSize: "13px" }}>
                        {new Date(item.created_at).toLocaleString()}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSelectedCaseId(item.case_id);
                            setCurrentPage("evidence");
                          }}
                        >
                          View Vault ➔
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
};

  // ============================================================
  // LOGGED-IN APPLICATION
  // ============================================================

  if (loggedIn) {
    return (
      <div className="dashboard">

        {/* SIDEBAR */}

        <aside className="sidebar">

          <div className="brand">

            <div className="logo-circle">
              DE
            </div>

            <div>
              <h2>Digital Evidence</h2>

              <span>
                Management System
              </span>
            </div>

          </div>

          <nav>
            <div className="dem-sidebar-heading">Main</div>
            {user?.role_id === 4 ? (
              <SidebarItem
                icon={<ForensicIcon />}
                label="Forensic Suite"
                active={currentPage === "forensic" || currentPage === "reports"}
                onClick={() => setCurrentPage("forensic")}
              />
            ) : (
              <SidebarItem
                icon={<DashboardIcon />}
                label="Dashboard"
                active={currentPage === "dashboard"}
                onClick={() => setCurrentPage("dashboard")}
              />
            )}

            <SidebarItem
              icon={<VaultIcon />}
              label="Evidence Vault"
              active={currentPage === "evidence"}
              onClick={() => setCurrentPage("evidence")}
            />

            {user?.role_id !== 4 && (
              <SidebarItem
                icon={<UploadIcon />}
                label="Upload Evidence"
                active={currentPage === "upload"}
                onClick={() => setCurrentPage("upload")}
              />
            )}

            <SidebarItem
              icon={<CasesIcon />}
              label="Cases"
              active={currentPage === "cases"}
              onClick={() => setCurrentPage("cases")}
            />

            <div className="dem-sidebar-heading">Compliance</div>

            <SidebarItem
              icon={<CustodyIcon />}
              label="Chain of Custody"
              active={currentPage === "custody"}
              onClick={() => setCurrentPage("custody")}
            />

            <SidebarItem
              icon={<AuditIcon />}
              label="Audit Logs"
              active={currentPage === "audit"}
              onClick={() => setCurrentPage("audit")}
            />

            {user?.role_id === 1 && (
              <>
                <SidebarItem
                  icon={<ReportsIcon />}
                  label="Forensic Reports"
                  active={currentPage === "reports" || currentPage === "forensic"}
                  onClick={() => setCurrentPage("reports")}
                />
                <SidebarItem
                  icon={<AlertsIcon />}
                  label="Tamper Alerts"
                  active={currentPage === "alerts"}
                  onClick={() => setCurrentPage("alerts")}
                />
              </>
            )}

            {(user?.role_id === 2 || user?.role_id === 3) && (
              <SidebarItem
                icon={<ReportsIcon />}
                label="Forensic Reports"
                active={currentPage === "reports" || currentPage === "forensic"}
                onClick={() => setCurrentPage("reports")}
              />
            )}
          </nav>

          <div className="dem-sidebar-logout-container">
            <button
              type="button"
              className="dem-sidebar-logout-btn"
              onClick={handleLogout}
            >
              <LogoutIcon />
              <span>Logout</span>
            </button>
          </div>

        </aside>

        {/* MAIN CONTENT */}

        <main className="dashboard-content">

          {currentPage === "dashboard" &&
          renderDashboard()}

          {currentPage === "evidence" &&
          renderEvidencePage()}

          {currentPage === "upload" &&
          renderUploadPage()}

          {currentPage === "cases" &&
          renderCasesPage()}

         {currentPage === "custody" &&
        renderCustodyPage()}

        {currentPage === "audit" &&
         renderAuditPage()}

        {currentPage === "alerts" && (
          <AlertCenter user={user} onRefresh={() => { fetchEvidence(); fetchCases(); }} />
        )}

        {(currentPage === "reports" || currentPage === "forensic") && (
          <ForensicSuite user={user} evidence={evidence} cases={cases} onRefresh={() => { fetchEvidence(); fetchCases(); }} />
        )}


        </main>

      </div>
    );
  }

  // ============================================================
  // LOGIN PAGE
  // ============================================================

  return (
    <div className="login-page">

      <div className="login-card">

        <div className="logo-circle">
          DE
        </div>

        <h1>
          Digital Evidence
        </h1>

        <p className="subtitle">
          Evidence Management System
        </p>

        <form onSubmit={handleLogin}>

          <label>
            Employee ID / Username / Email
          </label>

          <input
            type="text"
            placeholder="Enter Employee ID, Username, or Email"
            value={employeeId}
            onChange={(e) =>
              setEmployeeId(e.target.value)
            }
            required
          />

          <label>
            Password
          </label>

          <input
            type="password"
            placeholder="Enter password"
            value={password}
            onChange={(e) =>
              setPassword(e.target.value)
            }
            required
          />

          <button
            type="submit"
            className="login-submit-btn"
            disabled={loading}
          >
            {loading
              ? "Signing in..."
              : "Sign In"}
          </button>

        </form>

        {message && (
          <p className="message">
            {message}
          </p>
        )}

        {/* QUICK DEMO LOGIN ACCOUNTS */}
        <div className="demo-accounts-box">
          <div className="demo-title">Quick Demo Login Accounts</div>
          <div className="demo-roles-list">
            <div className="demo-role-card">
              <span className="demo-role-icon">🛡️</span>
              <span className="demo-role-name">System Administrator</span>
            </div>

            <div className="demo-role-card">
              <span className="demo-role-icon">🔬</span>
              <span className="demo-role-name">Forensic Analyst</span>
            </div>

            <div className="demo-role-card">
              <span className="demo-role-icon">👮</span>
              <span className="demo-role-name">Police Officer</span>
            </div>

            <div className="demo-role-card">
              <span className="demo-role-icon">📁</span>
              <span className="demo-role-name">Case Manager</span>
            </div>
          </div>
        </div>

        <p className="security-text">
          🔒 Secure evidence management system
        </p>
      </div>

    </div>
  );
}

export default App;