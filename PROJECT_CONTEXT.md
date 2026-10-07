# DIG_EVI — Digital Evidence Management & Chain of Custody System
## Project Context & Technical Architecture Snapshot

> **Notice for Developers & AI Agents**:  
> Read this document first at the beginning of every session before modifying or extending this codebase. Ground all updates in code truth. Update this document's status table, checkboxes, and changelog whenever features, fixes, or redesigns are implemented.

---

## 1. Project Overview

**DIG_EVI** is an enterprise-grade Digital Evidence Management System (DEMS) engineered for law enforcement agencies, cybercrime investigators, and digital forensic laboratories. The system guarantees legal admissibility, evidentiary integrity, and complete non-repudiation across the entire lifecycle of digital evidence—from field seizure and ingestion to laboratory analysis and courtroom presentation.

### Primary Purpose
- **Forensic Integrity**: Enforce cryptographic SHA-256 verification and AES-256-GCM envelope encryption so files cannot be altered, forged, or accessed by unauthorized actors.
- **Chain of Custody (CoC)**: Maintain a tamper-evident, append-only custodial transfer trail documenting every transfer of possession, purpose, and timestamp.
- **Continuous Tamper Detection**: Proactively monitor file stores with an autonomous background integrity daemon that triggers instant security alerts and email notifications upon hash mismatch.
- **Courtroom Admissibility**: Generate deterministic forensic reports and case dossiers in standard PDF format without relying on nondeterministic generative AI.

### User Roles & Access Hierarchy
Role definitions are stored in the `roles` table and enforced via backend middleware (`roleMiddleware.js`) and service guards:
1. **System Administrator (`role_id: 1`)**: Full administrative control; user management, evidence upload, hash verification, file decryption, case management, alert resolution, and forensic PDF download. View-only access on Forensic Laboratory & Reports.
2. **Police Officer (`role_id: 2`)**: Field officer responsible for initial evidence intake, case registration, and basic custody transfers. View and download access on Forensic Laboratory & Reports.
3. **Case Manager (`role_id: 3`)**: Lead investigator supervising assigned cases, inspecting evidence inventories, initiating transfers, and downloading case dossiers. View-only access on Forensic Laboratory & Reports.
4. **Forensic Analyst (`role_id: 4`)**: Laboratory specialist (displayed in UI as Forensic Officer) authorized to decrypt encrypted evidence, conduct digital device hardware autopsies, draft and compile technical examination reports, and dispatch forensic findings. Exclusively authorized to author or dispatch reports.

---

## 2. Tech Stack and Architecture

### Technical Stack
- **Frontend**: React 19.2.8, Vite 8.2.1, Plain CSS with modular Design Tokens (`theme.css`, `layout.css`). Zero heavy third-party UI libraries (Tailwind/Bootstrap) to ensure lightweight, zero-dependency rendering.
- **Backend**: Node.js (v18+), Express 5.2.1 (REST API), CommonJS modules.
- **Database**: PostgreSQL with `pg` (v8.22.0) native connection pool.
- **Authentication**: Stateless JSON Web Tokens (`jsonwebtoken` v9.0.3) stored in client `localStorage`, passwords hashed with `bcrypt` (v6.0.0, salt rounds: 10).
- **Cryptography & Security**:
  - Hashing: Node.js native `crypto.createHash('sha256')`.
  - Storage Encryption: AES-256-GCM envelope encryption with per-file 256-bit symmetric keys wrapped by a master key (`MASTER_ENCRYPTION_KEY`).
  - Field-Level Database Encryption: Row-bound AES-256-GCM column encryption using HKDF subkey derivation (`DATA_ENCRYPTION_KEY`), storing payload as `enc:v1:<iv>:<tag>:<ciphertext>`.
  - Blind Index Search: HMAC-SHA256 deterministic hashes (`BLIND_INDEX_KEY`) for exact-match lookups on encrypted columns (`employee_id_bidx`, `email_bidx`).
  - Audit Log Hash Chain: Cryptographic SHA-256 blockchain-style chaining (`prev_hash`, `entry_hash`, `hash_version`), with dual-version verification across migration checkpoints.
  - Integrity Auditing: Automated periodic 60s cron (`node-cron` alternative via native timer loop) and on-demand verification.
- **Document Generation**: PDFKit (v0.20.2) for deterministic, vector-based PDF evidence dossiers and forensic reports.
- **Notification Services**: Nodemailer (v10.0.13) for SMTP-based critical intrusion alerts with non-blocking graceful fallback.
- **File Ingestion**: Multer (v2.2.0) handling multipart stream uploads.

### System Architecture Flow
```
[ Client Browser (React + Vite) ]
          │
          │ HTTPS / REST (JWT Bearer Auth)
          ▼
[ Express 5.2 Application Gateway ]
    ├── Auth & Role-Based Access Control (RBAC) Middleware
    ├── Multer File Streaming & In-Memory Pre-Processing
    └── Cryptographic Engine (crypto)
          │
          ├──> 1. Compute SHA-256 Digest of Raw Ingested File
          ├──> 2. Generate Random 32-byte AES Key & 12-byte IV
          ├──> 3. Encrypt File using AES-256-GCM -> Save to Disk (uploads/encrypted/)
          ├──> 4. Wrap File AES Key with MASTER_ENCRYPTION_KEY
          └──> 5. Securely Unlink/Purge Temporary Plaintext File Immediately
          │
          ├──> Database Persistence (PostgreSQL Pool)
          │      ├── Store Metadata, File Hash, Wrapped Key, Auth Tag, IV
          │      ├── Insert Immutable Chain of Custody Entry
          │      └── Insert Immutable Forensic Audit Record
          │
          └──> Background Daemon (integrityScheduler.js)
                 ├── Re-verifies All Disk Files against Stored Hashes Every 60s
                 ├── Active Anomaly -> Writes to `tamper_alerts` Table
                 └── Dispatches Critical Email Alert via Nodemailer (SMTP)
```

### Folder Structure
```
dig_evi/
├── .agent/                             # Agent & assistant rules
│   └── rules/
│       └── project_context.md          # Workspace persistence rule for context sync
├── backend/                            # Node.js + Express API backend
│   ├── src/
│   │   ├── config/
│   │   │   └── db.js                   # PostgreSQL connection pool with pg.Pool
│   │   ├── controllers/
│   │   │   ├── alertController.js      # Vault scan trigger, stats, and alert resolution
│   │   │   ├── auditController.js      # System-wide audit log queries
│   │   │   ├── caseController.js       # Case creation and listing with evidence aggregates
│   │   │   ├── custodyController.js    # Custody log recording and retrieval by evidence ID
│   │   │   ├── evidenceController.js   # Ingestion, hash verification, and decryption streaming
│   │   │   ├── reportController.js     # Forensic reports, autopsy records, dossiers, PDFKit download
│   │   │   └── userController.js       # User login, registration (Admin only), and user listing
│   │   ├── cron/
│   │   │   └── integrityScheduler.js   # Autonomous 60s background integrity scanner loop
│   │   ├── middleware/
│   │   │   ├── authMiddleware.js       # JWT validation and req.user payload injection
│   │   │   ├── roleMiddleware.js       # Role authorization guards for routes
│   │   │   └── uploadMiddleware.js     # Multer multipart upload handler with storage routing
│   │   ├── models/
│   │   │   ├── alertModel.js           # SQL queries for tamper alerts and metrics
│   │   │   ├── auditModel.js           # SQL queries for inserting and fetching audit events
│   │   │   ├── caseModel.js            # SQL queries for case records and relations
│   │   │   ├── evidenceModel.js        # SQL queries for evidence inventory and crypto metadata
│   │   │   ├── reportModel.js          # SQL queries for forensic reports and autopsies
│   │   │   └── userModel.js            # SQL queries for authentication and user accounts
│   │   ├── routes/
│   │   │   ├── alertRoutes.js          # /api/alerts endpoints
│   │   │   ├── auditRoutes.js          # /api/audit-logs endpoints
│   │   │   ├── caseRoutes.js           # /api/cases endpoints
│   │   │   ├── custodyRoutes.js        # /api/custody endpoints
│   │   │   ├── evidenceRoutes.js       # /api/evidence endpoints
│   │   │   ├── reportRoutes.js         # /api/reports and /api/cases/:id/dossier endpoints
│   │   │   └── userRoutes.js           # /api/users, /api/login, /api/profile endpoints
│   │   ├── services/
│   │   │   ├── alertService.js         # Vault-wide integrity scan logic and anomaly detection
│   │   │   ├── auditService.js         # Unified audit event logger service
│   │   │   ├── caseService.js          # Case business validation and numbering logic
│   │   │   ├── custodyService.js       # Custody verification and ledger logging
│   │   │   ├── emailService.js         # Nodemailer SMTP dispatcher with fallback resilience
│   │   │   ├── evidenceService.js      # Envelope encryption pipeline, verification, and streaming
│   │   │   └── forensicPdfService.js   # Deterministic PDF builder using PDFKit
│   │   ├── utils/
│   │   │   └── encryption.js           # AES-256-GCM encryption, decryption, and key wrapping
│   │   ├── app.js                      # Express application setup, CORS, and route registrations
│   │   └── server.js                   # Server entrypoint and background cron initializer
│   ├── uploads/
│   │   └── encrypted/                  # Physical storage location for AES-encrypted evidence (.enc)
│   ├── .env.example                    # Environment variable template for backend
│   └── package.json                    # Backend dependencies and execution scripts
├── database/
│   ├── schema.sql                      # Complete PostgreSQL schema (9 tables, indexes, constraints)
│   └── seed_demo_data.sql              # Initial roles and demo credentials
├── docs/                               # Project architecture and design specifications
├── frontend/                           # React 19 + Vite frontend application
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/                 # Reusable Design System Components
│   │   │   │   ├── Badge.jsx           # Semantic colored status/type tags
│   │   │   │   ├── Button.jsx          # Primary, secondary, and outline action buttons
│   │   │   │   ├── Card.jsx            # Dark theme container card with standardized borders
│   │   │   │   ├── EmptyState.jsx      # Empty inventory/search fallback displays
│   │   │   │   ├── FormField.jsx       # Standard vertical label-over-input wrapper
│   │   │   │   ├── MetaItem.jsx        # Standard vertical label-over-value display
│   │   │   │   ├── PageHeader.jsx      # Top header with title, subtitle, and user chip
│   │   │   │   └── index.js            # Barrel export for common design components
│   │   │   ├── AlertCenter.jsx         # Continuous tamper monitor dashboard and anomaly resolver
│   │   │   └── ForensicSuite.jsx       # Report generator, autopsy lab, and PDF download suite
│   │   ├── styles/
│   │   │   ├── theme.css               # Core CSS variables (colors, spacing, radii, font sizes)
│   │   │   └── layout.css              # Grid system, page layouts, cards, and form layouts
│   │   ├── App.css                     # Global component overrides and responsive styling
│   │   ├── App.jsx                     # View switcher and top-level authentication state wrapper
│   │   ├── AppRoot.jsx                 # Main application view container and sidebar navigation
│   │   ├── index.css                   # Global reset, typography, and Inter font loading
│   │   └── main.jsx                    # React 19 application mount point
│   ├── index.html                      # Single page application HTML entrypoint
│   ├── package.json                    # Frontend dependencies (React 19, Vite, Oxlint)
│   └── vite.config.js                  # Vite configuration and dev server proxy settings
├── .gitignore                          # Git ignore definitions (ignores secrets, uploads, node_modules)
├── PROJECT_CONTEXT.md                  # Complete codebase snapshot & developer handoff guide
└── README.md                           # General setup documentation and quickstart instructions
```

---

## 3. How to Run

### Prerequisites
- Node.js (v18.0.0 or higher)
- PostgreSQL (v14 or higher) running locally or remotely
- Git

### 1. Install Dependencies
```bash
# Backend dependencies
cd backend
npm install

# Frontend dependencies
cd ../frontend
npm install
```

### 2. Environment Variables Configuration
Create a `.env` file in the `backend/` directory based on `backend/.env.example`:
```ini
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=digital_evidence_db
DB_USER=postgres
DB_PASSWORD=your_db_password
JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRES_IN=7d
MASTER_ENCRYPTION_KEY=64_character_hex_string_32_bytes_here
DATA_ENCRYPTION_KEY=64_character_hex_string_32_bytes_here
BLIND_INDEX_KEY=64_character_hex_string_32_bytes_here

# Optional: SMTP Email Alerts
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SYSTEM_ADMIN_EMAIL=admin@police.gov
SMTP_FROM="Digital Evidence Vault" <no-reply@police.gov>
```

> **Generating 32-Byte Cryptographic Hex Keys**:  
> Run: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

### 3. Database Initialization
Run the initialization scripts in PostgreSQL:
```bash
psql -U postgres -d digital_evidence_db -f database/schema.sql
psql -U postgres -d digital_evidence_db -f database/seed_demo_data.sql
```

### 4. Running Development Servers
```bash
# Terminal 1 - Backend (starts on port 3000)
cd backend
npm run dev     # or node src/server.js

# Terminal 2 - Frontend (starts on port 5173)
cd frontend
npm run dev
```

### Default Port Allocations
- **Frontend App**: `http://localhost:5173`
- **Backend API**: `http://localhost:3000`
- **PostgreSQL Database**: `5432`

---

## 4. Implemented Features & Codebase Verification

### Implementation Status Table

| Module / Feature | Status | Key Files | Implementation Details & Code Truth |
| :--- | :---: | :--- | :--- |
| **Authentication & RBAC** | **Done** | `backend/src/routes/userRoutes.js`<br>`backend/src/controllers/userController.js`<br>`backend/src/middleware/authMiddleware.js`<br>`backend/src/middleware/roleMiddleware.js` | JWT login, profile endpoint, role-based route gating (Roles 1-4). System Admin only can create users. |
| **Case Management** | **Done** | `backend/src/routes/caseRoutes.js`<br>`backend/src/controllers/caseController.js`<br>`backend/src/services/caseService.js`<br>`frontend/src/AppRoot.jsx` | Unique case number generation, investigating officer assignment, status tracking, aggregate evidence counts. |
| **Evidence Ingestion** | **Done** | `backend/src/routes/evidenceRoutes.js`<br>`backend/src/controllers/evidenceController.js`<br>`backend/src/services/evidenceService.js`<br>`backend/src/utils/encryption.js` | Multer streaming, SHA-256 calculation, AES-256-GCM envelope encryption, master key wrapping, instant raw file purge. |
| **Evidence Vault** | **Done** | `backend/src/routes/evidenceRoutes.js`<br>`frontend/src/AppRoot.jsx`<br>`frontend/src/components/common/` | Filter by case, card layout with 2-column metadata, immediate hash verification and decryption triggers. |
| **Verify Integrity** | **Done** | `backend/src/routes/evidenceRoutes.js`<br>`backend/src/services/evidenceService.js`<br>`backend/src/models/auditModel.js` | On-demand decryption to buffer, recalculation of SHA-256, comparison against stored digest, audit log recording. |
| **Decrypt Evidence** | **Done** | `backend/src/routes/evidenceRoutes.js`<br>`backend/src/services/evidenceService.js`<br>`backend/src/controllers/evidenceController.js`<br>`backend/src/utils/encryption.js`<br>`backend/src/utils/mimeHelper.js` | Restricted to Roles 1 (Admin) & 4 (Analyst). Unwraps per-file key, decrypts stream, verifies GCM auth tag and post-decryption SHA-256 match, strips Multer timestamp prefix, maps MIME type by extension, exposes Content-Disposition via CORS, and streams original bytes back without plaintext remaining on server. |
| **Legacy Evidence Download** | **Done** | `backend/src/routes/evidenceRoutes.js`<br>`backend/src/services/evidenceService.js`<br>`backend/src/controllers/evidenceController.js`<br>`backend/src/utils/mimeHelper.js`<br>`frontend/src/AppRoot.jsx`<br>`frontend/src/components/ForensicSuite.jsx` | Authenticated download for legacy unencrypted exhibits. Restricted to Roles 1 (Admin) & 4 (Analyst). Verifies physical disk presence, recomputes SHA-256 before serving (422 on mismatch), strips timestamp prefix, streams MIME payload with Content-Disposition, and writes `LEGACY_FILE_DOWNLOAD` audit log. Catalog seed exhibits (1–3) return 404 without disk search. |
| **Chain of Custody** | **Done** | `backend/src/routes/custodyRoutes.js`<br>`backend/src/controllers/custodyController.js`<br>`backend/src/services/custodyService.js`<br>`frontend/src/AppRoot.jsx` | Append-only custody logs, evidence transfers from user to user with mandatory action & remarks, historical timeline view. |
| **Forensic Audit Logs** | **Done** | `backend/src/routes/auditRoutes.js`<br>`backend/src/controllers/auditController.js`<br>`backend/src/services/auditService.js`<br>`frontend/src/AppRoot.jsx` | Logs every action (`LOGIN`, `UPLOAD`, `VERIFY`, `DECRYPT`, `TRANSFER`). Searchable, filterable by action, card layout. Cryptographically chained (`prev_hash`, `entry_hash`, `hash_version`). |
| **Field-Level DB Encryption** | **Done** | `backend/src/utils/fieldEncryption.js`<br>`backend/src/utils/migrateFieldEncryption.js`<br>`backend/src/models/*` | AES-256-GCM column encryption using HKDF subkeys (`DATA_ENCRYPTION_KEY`) across 8 tables. Deterministic HMAC-SHA256 blind indexing (`BLIND_INDEX_KEY`) for exact-match lookups. Zero plaintext leaked to DB-only actors. |
| **Autonomous Integrity Scanner** | **Done** | `backend/src/cron/integrityScheduler.js`<br>`backend/src/services/alertService.js`<br>`backend/src/models/alertModel.js` | Native timer daemon running every 60s. Scans all physical encrypted files, flags missing files or hash corruptions, creates active alerts. Recognizes catalog-only seed exhibits (`EV-2026-001` to `003`) via `is_legacy_seed: true` database flag as `LEGACY_SEED` to prevent spurious alerts without relying on description text matching. |
| **Tamper Alert Center** | **Done** | `backend/src/routes/alertRoutes.js`<br>`backend/src/controllers/alertController.js`<br>`frontend/src/components/AlertCenter.jsx` | Dashboard showing active hash mismatches, manual trigger button for scans, alert resolution modal with audit notes, unconfigured email warnings banner, and test email trigger. |
| **Email Intrusion Alerts** | **Done** | `backend/src/services/emailService.js`<br>`backend/src/services/alertService.js`<br>`backend/src/utils/demoTamperAlert.js` | Nodemailer SMTP alerts sent to Admin upon critical tampering detection. When SMTP is unconfigured and `DEMO_MAIL` is not set, suppresses delivery, logs clear error, and writes `SYSTEM_WARNING` audit log. Falls back to Ethereal sandbox with preview URLs only when `DEMO_MAIL=true`. |
| **Administrative Test Email** | **Done** | `backend/src/routes/alertRoutes.js`<br>`backend/src/controllers/alertController.js`<br>`backend/src/services/emailService.js`<br>`frontend/src/components/AlertCenter.jsx` | Protected `POST /api/alerts/test-email` endpoint and Alert Center UI button allowing System Administrators to safely verify SMTP connectivity without exposing credentials. |
| **Forensic Reports & Autopsies** | **Done** | `backend/src/routes/reportRoutes.js`<br>`backend/src/controllers/reportController.js`<br>`backend/src/services/reportService.js`<br>`backend/src/middleware/roleMiddleware.js`<br>`frontend/src/utils/permissionHelper.js`<br>`frontend/src/components/ForensicSuite.jsx` | Technical examination reports, device hardware autopsy triage, recipient dispatch with priority levels. Full authoring and dispatch restricted strictly to Forensic Officer (`role_id: 4`). System Administrator (`1`), Police Officer (`2`), and Case Manager (`3`) have view-only and PDF download permissions. Denied attempts return HTTP 403 and are logged to `audit_logs` as `ACCESS_DENIED`. |
| **Deterministic PDF Dossier** | **Done** | `backend/src/routes/reportRoutes.js`<br>`backend/src/services/forensicPdfService.js`<br>`frontend/src/components/ForensicSuite.jsx` | Generates official PDF reports containing case metadata, evidence digests, custody trails, and audit records via PDFKit. Accessible to Roles 1, 2, 3, and 4. |
| **UI Design System Redesign** | **Done** | `frontend/src/styles/theme.css`<br>`frontend/src/styles/layout.css`<br>`frontend/src/components/common/` | All 7 primary pages redesigned to dark theme card layouts with standard vertical labels and purple accents. |
| **Alert Center UI Unification** | **Partial** | `frontend/src/components/AlertCenter.jsx` | Fully functional, but still relies on table layouts rather than the new `Card`, `Badge`, and `MetaItem` components. |
| **Automated Unit & E2E Testing** | **Partial** | `backend/package.json`<br>`frontend/package.json`<br>`backend/src/utils/verifyReportRoles.js`<br>`backend/src/utils/verifyEvidenceRoles.js` | Verification suites for RBAC (reports & evidence) and monitor hardening active; no automated CI runner configured (Jest/Mocha/Vitest). |
| **Live SMTP Production Testing** | **Verified (Demo)** | `backend/src/services/emailService.js`<br>`backend/src/utils/demoTamperAlert.js` | Verified end-to-end via Ethereal sandbox with live browser preview URLs; production delivery requires populated SMTP_PASS in `.env`. |

### Evidence Decryption & Legacy Download Permission Matrix

| Operation / Capability | Route / Surface | Admin (`1`) | Police (`2`) | Case Mgr (`3`) | Forensic Analyst (`4`) | Security & UI Behavior |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **List Evidence Items** | `GET /api/evidence` | Allowed (200) | Allowed (200) | Allowed (200) | Allowed (200) | All authenticated roles can browse evidence catalog. |
| **Verify Integrity Hash** | `GET /api/evidence/:id/verify` | Allowed (200) | Allowed (200) | Allowed (200) | Allowed (200) | All authenticated roles can trigger on-demand hash verification. |
| **Decrypt Encrypted Evidence** | `GET /api/evidence/:id/decrypt` | Allowed (200) | Denied (403) | Denied (403) | Allowed (200) | Button disabled for Roles 2 & 3 with informative tooltip. GCM authenticated + SHA-256 pre-stream verified. |
| **Download Legacy File** | `GET /api/evidence/:id/legacy-download` | Allowed (200) | Denied (403) | Denied (403) | Allowed (200) | Button visible only for Roles 1 & 4 on unencrypted files with disk payload. SHA-256 verified; 422 on mismatch. |
| **Download Legacy Seed Record** | `GET /api/evidence/:id/legacy-download` | Not Found (404) | Denied (403) | Denied (403) | Not Found (404) | Seed records 1–3 return 404 (`LEGACY_SEED_NO_FILE`); UI button disabled with "No encrypted data" tooltip. |
| **Autopsy Evidence Inspection** | UI Autopsy Quick Inspection | Hidden | Hidden | Hidden | Full Action | In Digital Autopsy Suite, displays selected evidence SHA-256 with Decrypt & Download / Legacy Download button. |

### Forensic Laboratory & Reports Permission Matrix

| Operation / Capability | Route / Surface | Admin (`1`) | Police (`2`) | Case Mgr (`3`) | Forensic Officer (`4`) | Security & UI Behavior |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **View Forensic Reports** | `GET /api/reports/forensic` | Allowed (200) | Allowed (200) | Allowed (200) | Allowed (200) | Full report list visible in Transmit & Dispatch tab. |
| **View Digital Autopsies** | `GET /api/reports/autopsy` | Allowed (200) | Allowed (200) | Allowed (200) | Allowed (200) | Saved autopsy records list visible in Autopsy Suite tab. |
| **Inspect Autopsy Details** | UI Modal (Autopsy Suite) | Allowed | Allowed | Allowed | Allowed | "🔍 View Details" inspection modal renders full hardware triage summary. |
| **View Case Dossier** | `GET /api/cases/:caseId/dossier` | Allowed (200) | Allowed (200) | Allowed (200) | Allowed (200) | Comprehensive evidence and custody timeline. |
| **Download Forensic PDF** | `GET /api/reports/forensic/:caseId/download` | Allowed (200) | Allowed (200) | Allowed (200) | Allowed (200) | Generates and streams deterministic PDF dossier. |
| **Generate Forensic Report** | `POST /api/reports/forensic` | Denied (403) | Denied (403) | Denied (403) | Allowed (201) | Tab hidden in UI; direct URL renders lock notice; service logs `ACCESS_DENIED`. |
| **Dispatch Forensic Report** | `POST /api/reports/forensic/:id/dispatch` | Denied (403) | Denied (403) | Denied (403) | Allowed (200) | "🚀 Dispatch" button hidden in UI; backend middleware + service reject with 403. |
| **Draft Autopsy Record** | `POST /api/reports/autopsy` | Denied (403) | Denied (403) | Denied (403) | Allowed (201) | Intake form completely hidden in UI; service logs `ACCESS_DENIED`. |
| **Dispatch Autopsy Record** | `POST /api/reports/autopsy/:id/dispatch` | Denied (403) | Denied (403) | Denied (403) | Allowed (200) | Dispatch action hidden in UI; backend rejects with 403. |
| **Forensic Workspace** | UI Workspace View | View Only | View Only | View Only | Full Authoring | Draft Report and Autopsy action buttons hidden for Roles 1–3. |
| **View-Only Mode Indicator** | UI Header Badge | Visible | Visible | Visible | Hidden | Displays prominent cyan "View-Only Mode" badge for Roles 1–3. |

---

### REST API Endpoints Specification

| Method | Endpoint | Purpose | Role Authorization |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/login` | Authenticate user & return JWT token | Public |
| `GET` | `/api/profile` | Retrieve authenticated user's profile | All Authenticated |
| `POST` | `/api/users` | Register a new user | System Administrator (Role 1) |
| `GET` | `/api/users` | List all active users (for transfers/dispatch) | All Authenticated |
| `POST` | `/api/cases` | Register a new investigation case | All Authenticated |
| `GET` | `/api/cases` | Retrieve all cases with evidence counts | All Authenticated |
| `GET` | `/api/cases/:caseId/dossier` | Retrieve complete case dossier JSON | All Authenticated |
| `POST` | `/api/evidence` | Ingest and encrypt new digital evidence | Admin (1), Police (2), Case Manager (3) |
| `GET` | `/api/evidence` | List all evidence items | All Authenticated |
| `GET` | `/api/evidence/:evidenceId/verify` | Recalculate & verify SHA-256 hash | All Authenticated |
| `GET` | `/api/evidence/:evidenceId/decrypt` | Decrypt and download encrypted evidence file | Admin (1), Forensic Analyst (4) |
| `GET` | `/api/evidence/:evidenceId/legacy-download` | Download and verify unencrypted legacy evidence | Admin (1), Forensic Analyst (4) |
| `POST` | `/api/custody` | Record a custody transfer | All Authenticated |
| `GET` | `/api/custody/:evidenceId` | Fetch custody history for an evidence item | All Authenticated |
| `GET` | `/api/audit-logs` | Fetch system-wide forensic audit logs | All Authenticated |
| `GET` | `/api/alerts` | List tamper alerts (with status filter) | All Authenticated |
| `GET` | `/api/alerts/stats` | Retrieve tamper detection metrics and email status | All Authenticated |
| `POST` | `/api/alerts/run-check` | Manually trigger full vault integrity scan | All Authenticated |
| `PUT` | `/api/alerts/:id/resolve` | Mark tamper alert resolved with audit notes | All Authenticated |
| `POST` | `/api/alerts/test-email` | Dispatch safe administrative SMTP test email | System Administrator (Role 1) |
| `GET` | `/api/reports/forensic` | List all forensic examination reports | All Authenticated (Roles 1–4) |
| `POST` | `/api/reports/forensic` | Create a new forensic examination report | Forensic Officer Only (Role 4) |
| `POST` | `/api/reports/forensic/:id/dispatch` | Dispatch forensic report to personnel/agency | Forensic Officer Only (Role 4) |
| `GET` | `/api/reports/forensic/:caseId/download` | Download official deterministic PDF dossier | All Authenticated (Roles 1–4) |
| `GET` | `/api/reports/autopsy` | List digital hardware autopsy records | All Authenticated (Roles 1–4) |
| `POST` | `/api/reports/autopsy` | Record hardware triage and bit-stream extraction | Forensic Officer Only (Role 4) |
| `POST` | `/api/reports/autopsy/:id/dispatch` | Dispatch autopsy report to investigator | Forensic Officer Only (Role 4) |

---

### Database Schema & Entities

The PostgreSQL database (`database/schema.sql`) consists of 9 normalized tables:

1. **`roles`**:
   - Fields: `role_id` (PK), `role_name` (UNIQUE: Administrator, Police Officer, Case Manager, Forensic Analyst).
2. **`users`**:
   - Fields: `user_id` (PK), `employee_id` (UNIQUE), `role_id` (FK -> `roles`), `password_hash`, `full_name`, `email` (UNIQUE), `phone_number`, `is_active`, `created_at`.
3. **`cases`**:
   - Fields: `case_id` (PK), `case_number` (UNIQUE), `case_title`, `case_description`, `investigating_officer` (FK -> `users`), `created_by` (FK -> `users`), `status`, `created_at`.
4. **`evidence`**:
   - Fields: `evidence_id` (PK), `evidence_number` (UNIQUE), `case_id` (FK -> `cases`), `evidence_name`, `evidence_type`, `description`, `file_name`, `file_path`, `file_hash` (64-char SHA-256), `encrypted_aes_key`, `encryption_iv`, `encryption_auth_tag`, `uploaded_by` (FK -> `users`), `uploaded_at`, `is_legacy_seed` (BOOLEAN DEFAULT FALSE, marks catalog-only seed records without physical disk payloads).
5. **`custody_logs`**:
   - Fields: `custody_id` (PK), `evidence_id` (FK -> `evidence`), `from_user` (FK -> `users`), `to_user` (FK -> `users`), `action`, `remarks`, `created_at`.
6. **`audit_logs`**:
   - Fields: `audit_id` (PK), `user_id` (FK -> `users`), `evidence_id` (FK -> `evidence`), `action`, `details`, `created_at`, `prev_hash` (VARCHAR(64)), `entry_hash` (VARCHAR(64)).
   - Cryptographic Hash Chain: SHA-256 hash chain linking each row to previous row's `entry_hash`, serialized via PostgreSQL advisory transaction lock (`pg_advisory_xact_lock`). Verified automatically by background integrity monitor; breaks raise `AUDIT_CHAIN_BROKEN` critical alerts.
   - Indexes: `idx_audit_logs_entry_hash`, `idx_audit_logs_prev_hash`.
7. **`tamper_alerts`**:
   - Fields: `alert_id` (PK), `evidence_id` (FK -> `evidence`, NULLABLE for system-wide alerts), `case_id` (FK -> `cases`), `alert_type`, `severity` (DEFAULT 'CRITICAL'), `stored_hash` (NULLABLE), `detected_hash`, `file_path`, `message`, `status` ('ACTIVE', 'RESOLVED'), `detected_at`, `resolved_by` (FK -> `users`), `resolved_at`, `resolution_notes`, `email_status` ('PENDING', 'SENT', 'FAILED'), `email_attempts` (INT DEFAULT 0), `email_last_error` (TEXT), `email_sent_at` (TIMESTAMP WITH TIME ZONE).
   - Constraints & Indexes: Partial unique index `idx_active_tamper_alerts_unique ON tamper_alerts (evidence_id, alert_type) WHERE status = 'ACTIVE'`.
   - Alert Types: `HASH_MISMATCH`, `FILE_MISSING`, `CORRUPTED_CIPHERTEXT`, `KEY_UNWRAP_FAILED`, `SCAN_ERROR`, `AUDIT_CHAIN_BROKEN`, `UNREGISTERED_FILE`, `EVIDENCE_RECORD_DELETED`, `MANIFEST_HASH_MISMATCH`, `MANIFEST_TAMPERED`.
8. **`forensic_reports`**:
   - Fields: `report_id` (PK), `report_number` (UNIQUE), `case_id` (FK -> `cases`), `evidence_id` (FK -> `evidence`), `analyst_id` (FK -> `users`), `report_title`, `report_type`, `tools_used`, `hash_verified`, `findings`, `artifacts_recovered`, `conclusion`, `status`, `recipient_id` (FK -> `users`), `recipient_name`, `recipient_agency`, `transmission_priority`, `dispatch_notes`, `sent_at`, `created_at`.
9. **`autopsy_records`**:
   - Fields: `autopsy_id` (PK), `autopsy_number` (UNIQUE), `case_id` (FK -> `cases`), `evidence_id` (FK -> `evidence`), `examiner_id` (FK -> `users`), `subject_name`, `device_type`, `hardware_condition`, `extraction_method`, `autopsy_findings`, `triage_summary`, `status`, `dispatched_to`, `recipient_id` (FK -> `users`), `dispatch_notes`, `dispatched_at`, `created_at`.

---

## 5. Security and Forensic Integrity

### Cryptographic Workflow
1. **Hashing (SHA-256)**:
   - When evidence is uploaded, the raw binary buffer is read and a 256-bit hash digest is generated using Node's `crypto.createHash('sha256')`.
   - The hex digest is stored in `evidence.file_hash`.
2. **Envelope Encryption (AES-256-GCM)**:
   - For every uploaded file, an ephemeral 256-bit symmetric key (`crypto.randomBytes(32)`) and a 96-bit initialization vector (`crypto.randomBytes(12)`) are generated.
   - The file payload is encrypted with AES-256-GCM, producing ciphertext and a 16-byte authentication tag (`cipher.getAuthTag()`).
   - The ephemeral AES key is wrapped (encrypted) with the server's `MASTER_ENCRYPTION_KEY`.
   - The original plaintext file on disk is immediately destroyed (`fs.unlinkSync`).
   - The ciphertext file is saved to `uploads/encrypted/{file_name}.enc`.
3. **Decryption on Demand**:
   - Authorized roles (Admin and Forensic Analyst) initiate decryption.
   - The wrapped key is decrypted using `MASTER_ENCRYPTION_KEY`.
   - The AES-256-GCM decipher stream verifies the authentication tag. If the ciphertext or tag has been tampered with, decryption fails immediately.
4. **Autonomous Tamper Detection & Hardened Integrity Monitor**:
   - `integrityScheduler.js` executes periodically, configured by `INTEGRITY_SCAN_MINUTES` (defaults to 60s).
   - In-memory `isScanRunning` mutex guard guarantees that scheduled scans and manual triggers (`/api/alerts/run-check`) never run concurrently.
   - Uses memory-efficient streaming SHA-256 computation and streaming AES-256-GCM decryption/verification via `crypto.createDecipheriv` (zero full-file buffering in memory).
   - Distinct error categorization:
     - `CORRUPTED_CIPHERTEXT`: Raised when AES-GCM authentication tag check fails on `.enc` payload tampering.
     - `KEY_UNWRAP_FAILED`: Raised on master key decipherment failures (logged as a single `SYSTEM_WARNING` audit event; does NOT create misleading individual tamper alerts).
     - `SCAN_ERROR`: Raised with duplicate suppression on unexpected scan exceptions.
   - Deduplication & Race Protection: Postgres partial unique index `(evidence_id, alert_type) WHERE status = 'ACTIVE'` catches race conditions at database level with graceful duplicate suppression (`already_exists: true`).
   - Email Dispatch & Retry Mechanism:
     - Creates 1 direct email notification if exactly 1 alert is newly created, or a unified HTML digest email if > 1 alerts are newly created in a scan.
     - Dynamic values are strictly HTML-escaped to prevent injection.
     - Tracks `email_status` (`PENDING`, `SENT`, `FAILED`), `email_attempts` (max 5), `email_sent_at`, and `email_last_error`.
     - Scans automatically retry unsent/failed alert emails up to 5 attempts, logging immutable `EMAIL_ALERT_SENT` and `EMAIL_ALERT_FAILED` entries to `audit_logs`.
     - Alert Center displays an active warning banner whenever unsent alert notifications exist, along with status badges (`SENT`, `PENDING`, `FAILED`) on each alert row.
   - Clear `SYSTEM` actor attribution: Automated scan and retry audit events record `user_id = null`, rendered cleanly as `SYSTEM` in audit logs.
5. **Non-Repudiation Audit Trail**:
   - Every read, write, decrypt, verify, and transfer action writes an immutable record to `audit_logs` containing user ID, evidence reference, timestamp, and metadata.

### Security Gaps & Known Vulnerabilities
- **Single Master Key Risk**: Currently, `MASTER_ENCRYPTION_KEY` is loaded from an environment variable. If the host environment is compromised, the master key could be extracted. (Recommended: Integrate AWS KMS, GCP KMS, or HashiCorp Vault).
- **Physical Storage Host**: Encrypted files are stored on the local file system under `backend/uploads/encrypted/`. In a multi-instance production environment, this requires migration to distributed secure object storage (e.g. Amazon S3 with SSE-KMS or Google Cloud Storage with bucket locks).
- **JWT Storage**: Frontend stores JWT tokens in `localStorage`. While standard for SPAs, it is susceptible to XSS. (Recommended: Transition to HTTP-only, SameSite Secure cookies).

---

## 6. UI and Design System State

### Design Standards (`frontend/src/styles/theme.css`, `layout.css`)
- **Theme**: Pure Dark Theme.
- **Palette**:
  - Background: `#0F1117`
  - Cards & Containers: `#1A1D27`
  - Subtle Borders: `1px solid rgba(255, 255, 255, 0.08)`
  - Purple Primary Accent: `#7C3AED` / Hover: `#6D28D9`
  - Critical / Tamper Red: `#EF4444` / Text: `#FCA5A5`
  - Success Green: `#10B981` / Light: `#6EE7B7`
  - Warning Amber: `#F59E0B`
  - Muted Text / Labels: `#8B90A0`
  - Main Text: `#FFFFFF`
- **Typography**: Inter, -apple-system, sans-serif.
  - Page Titles: `28px / 600 weight`
  - Section Titles: `18px / 600 weight`
  - Field & Metadata Labels: `12px uppercase, letter-spacing: 0.05em, color: #8B90A0` (rendered strictly above values)
  - Values / Body: `15px, line-height: 1.5`
- **Layout Scale**: 8px grid (Padding: 32px page, 24px cards, 24px between sections, 16px between form inputs).
- **Interactive Elements**: Inputs, selects, and buttons have a standardized height of `44px`, `12px` border radius, and a purple focus ring (`box-shadow: 0 0 0 3px rgba(124, 58, 237, 0.35)`).

### Page Redesign Status (All 7 Primary Pages Completed)
1. **Evidence Vault (`vault`)**: Fully redesigned. Features a case selector, case summary banner with evidence count badge, refresh action, and an evidence card grid with 2-column metadata and "Verify Integrity" / "Decrypt Evidence" buttons.
2. **Upload Evidence (`upload`)**: Fully redesigned. 2-column form card with case selector, evidence name, type, description, and file upload drop zone.
3. **Cases (`cases`)**: Fully redesigned. Create case modal form and card grid displaying case number, title, description, assigned officer, created date, and total evidence count badge.
4. **Forensic Dashboard (`dashboard`)**: Fully redesigned. 4-column KPI metric cards, active investigation cases section, recent evidence inventory cards, and quick navigation shortcuts.
5. **Chain of Custody (`custody`)**: Fully redesigned. Case and evidence selector, custody transfer form card (recipient selection, action type, remarks), and historical custodial log cards with timestamped transfer badges.
6. **Audit Logs (`audit`)**: Fully redesigned. Filter controls by action type, total log count badge, refresh action, and audit entry cards displaying action badge, user, evidence reference, and timestamp.
7. **Forensic Reports (`reports`)**: Fully redesigned. Tabbed interface for Workspace, Generate Report, Dispatch Reports, and Autopsy Suite, plus official deterministic PDF case report generation card.

---

## 7. Remaining Work (To-Do)

### Priority 1: Must Have (Critical Path for Production Deployment)
- [ ] **Automated Test Suite**: Configure Jest / Supertest for backend integration testing and Vitest for frontend components.
  - *Affected Files*: `backend/package.json`, `backend/tests/`, `frontend/package.json`.
  - *Dependencies*: None.
- [ ] **HTTP-only Cookie Auth**: Replace client `localStorage` JWT storage with secure HTTP-only cookies to eliminate XSS token theft vectors.
  - *Affected Files*: `backend/src/controllers/userController.js`, `backend/src/middleware/authMiddleware.js`, `frontend/src/App.jsx`.
  - *Dependencies*: Backend `cookie-parser` installation.
- [ ] **Multi-Part / Chunked Large File Streaming**: Current Multer setup buffers files up to memory limit; implement stream-to-disk encryption for multi-gigabyte forensic disk images (.E01 / .dd).
  - *Affected Files*: `backend/src/middleware/uploadMiddleware.js`, `backend/src/services/evidenceService.js`, `backend/src/utils/encryption.js`.
  - *Dependencies*: Node.js `stream.pipeline` refactor.

### Priority 2: Should Have (Enhancements & Operational Hardening)
- [ ] **Alert Center UI Unification**: Restyle `AlertCenter.jsx` using `PageHeader`, `Card`, `Badge`, `FormField`, and `MetaItem` to achieve 100% design system consistency.
  - *Affected Files*: `frontend/src/components/AlertCenter.jsx`.
  - *Dependencies*: None.
- [ ] **Real-time WebSockets / SSE**: Replace 12-second polling in `AlertCenter.jsx` with Server-Sent Events (SSE) or Socket.io for immediate push notifications of tamper alerts.
  - *Affected Files*: `backend/src/app.js`, `backend/src/services/alertService.js`, `frontend/src/components/AlertCenter.jsx`.
  - *Dependencies*: None (SSE uses native HTTP).
- [ ] **Role Management UI**: Build an administrative interface for the System Administrator to invite, deactivate, and manage user accounts and role assignments.
  - *Affected Files*: `frontend/src/AppRoot.jsx`, `frontend/src/components/UserManagement.jsx` (new).
  - *Dependencies*: Existing `/api/users` endpoint.

### Priority 3: Nice to Have (Future Enhancements)
- [ ] **Hardware Security Module (HSM) / Cloud KMS Key Management**: Support AWS KMS, Google Cloud KMS, or HashiCorp Vault for wrapping `MASTER_ENCRYPTION_KEY`.
  - *Affected Files*: `backend/src/utils/encryption.js`, `backend/.env.example`.
  - *Dependencies*: Cloud SDKs (`@aws-sdk/client-kms` or `@google-cloud/kms`).
- [ ] **Cloud Storage Driver (S3/GCS)**: Create an abstraction layer for storing encrypted evidence blobs in AWS S3 with Object Lock (WORM - Write Once, Read Many).
  - *Affected Files*: `backend/src/services/evidenceService.js`.
  - *Dependencies*: AWS S3 client.
- [ ] **Exportable Audit Evidence Packages**: Zip archive export containing the decrypted evidence, signed forensic report PDF, and full custody log in CSV/JSON format.
  - *Affected Files*: `backend/src/services/forensicPdfService.js`, `backend/src/routes/reportRoutes.js`.
  - *Dependencies*: `archiver` library.

---

## 8. Known Issues and Architectural Decisions

### Known Issues & Technical Debt
1. **Frontend Monolithic `AppRoot.jsx`**: `AppRoot.jsx` contains views for Vault, Upload, Cases, Dashboard, Custody, and Audit in a single file (~1,200 lines). While cleanly structured, breaking individual views into dedicated page components under `frontend/src/pages/` will improve maintainability.
2. **In-Memory File Encryption**: The current encryption utility reads the uploaded file buffer into memory. While efficient for documents and photos (< 100MB), massive disk images (> 4GB) could exhaust Node.js heap memory unless processed as chunked streams.
3. **Polling vs WebSockets**: Alert Center and Vault use manual refresh and interval polling. Adding SSE would reduce backend query volume.

### Architectural Decisions & Rationale
- **Deterministic PDF Generation (PDFKit)**: *Decision*: Generate forensic reports natively with PDFKit rather than invoking external generative AI APIs (Gemini/OpenAI).  
  *Rationale*: Forensic court reports must be 100% deterministic, verifiable, reproducible, and immune to AI hallucinations or external data leakage.
- **Zero Heavy UI Dependencies**: *Decision*: Standardize on plain CSS variables and custom components rather than installing Tailwind CSS or component libraries (MUI/AntD).  
  *Rationale*: Eliminates build-time bloat, prevents framework lock-in, and guarantees pixel-perfect compliance with the custom dark theme specification.
- **Envelope Encryption with AES-256-GCM**: *Decision*: Encrypt each file with an ephemeral key wrapped by a master key rather than using a single static key.  
  *Rationale*: If a single file key is compromised, the remaining vault remains uncompromised; enables instant key rotation without re-encrypting all storage.
- **Immediate Unencrypted File Destruction**: *Decision*: Delete the unencrypted temporary upload synchronously before returning the API response.  
  *Rationale*: Prevents plaintext forensic evidence from lingering in temporary operating system caches.

---

## 9. Changelog

- **2026-10-08**:
  - **Field-Level Database Encryption & Blind Indexing Live Migration**:
    - Architected and implemented field-level AES-256-GCM database encryption across 8 sensitive tables (`users`, `cases`, `evidence`, `custody_logs`, `audit_logs`, `tamper_alerts`, `forensic_reports`, `autopsy_records`), preventing database-only administrators or compromised SQL dumps from reading sensitive PII, case titles, evidence descriptions, or forensic reports.
    - Implemented HKDF per-table-and-column key derivation (`DATA_ENCRYPTION_KEY` + table name salt + column name info) generating isolated 256-bit subkeys. Stored ciphertext formatted as `enc:v1:<iv_b64>:<tag_b64>:<ciphertext_b64>`.
    - Added HMAC-SHA256 blind indexing (`BLIND_INDEX_KEY`) on `employee_id_bidx` and `email_bidx` to allow fast, indexed exact-match queries without exposing plaintext values.
    - Engineered dual-version audit log hash chain migration (`hash_version: 1` plaintext rule for legacy rows, `hash_version: 2` ciphertext rule for new rows) linked by a signed `MIGRATION_CHECKPOINT` record (`audit_id #305`), ensuring end-to-end chain verification across both eras without rewriting historical records.
    - Executed live migration on production database (`digital_evidence_db`) with automated pre-flight `pg_dump` backup. Verified 554 sensitive values with 100% round-trip match (0 mismatches) and verified audit log chain across all 290 records.
    - Preserved fallback `old_*` columns in database awaiting manual administrative drop confirmation.
    - Verified all 4 RBAC user roles, logins, evidence listing, decryption on EV-2026-011, forensic reports, autopsy authorization, audit logs, alerts, signed manifests, and tamper detection with 100% pass rate.
- **2026-10-07**:
  - **Alert Center Tamper Banner Removal**:
    - Added a single configurable toggle `const SHOW_TAMPER_BANNER = false;` at the top of [`frontend/src/components/AlertCenter.jsx`](file:///c:/Users/vrind/project_mini_mca/dig_evi/frontend/src/components/AlertCenter.jsx) to hide the large red "CRITICAL FILE TAMPERING DETECTED ... Re-Scan Vault" banner without leaving any empty layout gap or container element across desktop (1440px), tablet (1024px), and mobile (390px) viewports.
    - Preserved all filter chips ("All Alerts", "Active Anomalies", "Critical", "Resolved"), statistics cards, and the "▶ Run Integrity Scan Now" scan trigger.
    - Zero backend, audit logging, alert resolution, or email notification behavior changed.
  - **Audit Log Cryptographic Hash Chain**:
    - Added `prev_hash VARCHAR(64)` and `entry_hash VARCHAR(64)` columns and indexes to `audit_logs` (`database/migrations/20261007_audit_logs_hash_chain.sql`, `database/schema.sql`).
    - Backfilled entire history across all existing rows with SHA-256 chain without altering existing payload data (`backend/src/utils/migrateAuditHashChain.js`).
    - Implemented sequential hash chain computation (`computeAuditEntryHash`) in `backend/src/services/auditService.js` with PostgreSQL transaction advisory locking (`pg_advisory_xact_lock`) to serialize concurrent insertions and maintain strict sequential integrity.
    - Implemented `verifyAuditLogChain` verifier validating every entry's hash link; integrated into the integrity scheduler to raise `CRITICAL` `AUDIT_CHAIN_BROKEN` alerts upon detecting altered or deleted records.
  - **Daily Signed Integrity Manifest**:
    - Implemented `backend/src/services/manifestService.js` generating canonical JSON integrity manifests of all evidence records (`evidence_id`, `evidence_number`, `file_hash`) and the latest audit chain hash.
    - Signs manifests with HMAC-SHA256 using key configured via `MANIFEST_SIGNING_KEY`.
    - Persists signed manifests in secure directory outside the repository root configured via `MANIFEST_DIR` (default: `~/.digital_evidence_vault/manifests`).
    - Automatically sends daily signed manifest digest emails to administrators via `sendSignedManifestEmail` in `backend/src/services/emailService.js`.
    - Cross-references database evidence against latest manifest during every vault scan, raising `MANIFEST_HASH_MISMATCH`, `MANIFEST_TAMPERED`, and `EVIDENCE_RECORD_DELETED` alerts.
  - **Unregistered Files & Deleted Evidence Detection**:
    - Added `scanUnregisteredFiles` in `backend/src/services/alertService.js` identifying orphaned files in `uploads/` lacking database records, raising `UNREGISTERED_FILE` alerts.
    - Updated `tamper_alerts` schema (`database/migrations/20261007_tamper_alerts_nullable_fields.sql`) allowing `NULL` `evidence_id` and `stored_hash` for system-level alerts while maintaining duplicate suppression via unique `file_path`.
  - **Two-Tier Autonomous Integrity Scanning**:
    - Added tier configuration via environment variables: `INTEGRITY_SCAN_MINUTES` (lightweight scan detecting size/mtime modifications) and `INTEGRITY_FULL_SCAN_MINUTES` (full streaming SHA-256 rehash and GCM authentication).
  - **Append-Only Audit Log Migration Prepared**:
    - Prepared declarative migration `database/migrations/20261007_audit_logs_append_only.sql` providing an immutable `BEFORE UPDATE OR DELETE` PostgreSQL trigger and permission revocation commands, pending administrator approval.
  - **Security Test Verification Suite**:
    - Created `backend/src/utils/testHardeningSecurity.js` verifying hash chain breaks (`AUDIT_CHAIN_BROKEN`), deleted evidence rows vs manifest (`EVIDENCE_RECORD_DELETED`), stray physical files (`UNREGISTERED_FILE`), and duplicate suppression on consecutive scans. All scenarios verified end-to-end with 100% pass rate.
- **2026-10-06**:
  - **Evidence Decryption & Legacy Download RBAC Enforcement & Forensic Analyst Workflow Restoration**:
    - Separated `canDecryptEvidence` (Roles 1 & 4) from `canAuthorReports` (Role 4 only) in `frontend/src/utils/permissionHelper.js`, ensuring role permissions are decoupled.
    - Updated `frontend/src/AppRoot.jsx` lifecycle hooks to unconditionally invoke `fetchCases()` on authentication and route transitions, eliminating blank case selection dropdowns for Forensic Analyst on login.
    - Restored `EvidenceCard.jsx` state management and role controls:
      - Disabled decrypt action with `"No encrypted data for this record"` tooltip for legacy seed records (`is_legacy_seed: true` or missing encryption keys).
      - Disabled decrypt action with `"Decryption restricted to System Administrator and Forensic Analyst"` tooltip for Police Officers (Role 2) and Case Managers (Role 3).
      - Rendered distinct "Download (Legacy)" action for unencrypted files with physical disk payloads for Roles 1 & 4.
      - Restored `isDecrypting` loading indicator preventing concurrent double-clicks.
    - Implemented secure authenticated legacy evidence download endpoint (`GET /api/evidence/:evidenceId/legacy-download`) in backend (`routes/evidenceRoutes.js`, `controllers/evidenceController.js`, `services/evidenceService.js`):
      - Strictly gated via `authorizeRoles(1, 4)`.
      - Recomputes full SHA-256 binary digest from storage and aborts with HTTP 422 `TAMPER_DETECTED` and audit log if file does not match database `file_hash`.
      - Returns clean HTTP 404 `LEGACY_SEED_NO_FILE` for catalog-only seed records (1–3).
      - Rejects envelope-encrypted files with HTTP 400 directing callers to the decryption endpoint.
      - Dynamically resolves MIME types, strips Multer timestamp prefixes, exposes `Content-Disposition`, and logs immutable `LEGACY_FILE_DOWNLOAD` audit entries.
    - Added "Evidence Quick Inspection" card in Digital Autopsy Suite (`frontend/src/components/ForensicSuite.jsx`):
      - Displays selected evidence asset type, registered file, and SHA-256 digest with inline "Decrypt and Download" or "Download (Legacy)" triggers for Role 4.
    - Built and executed comprehensive RBAC verification script (`backend/src/utils/verifyEvidenceRoles.js`) testing Roles 1–4:
      - Confirmed 200 and identical SHA-256 matches for Roles 1 & 4 on decrypt and legacy download.
      - Confirmed 403 on decrypt and legacy download for Roles 2 & 3.
      - Confirmed 404 on legacy seed download for Roles 1 & 4, and 403 for Roles 2 & 3.
      - Confirmed `DECRYPTED` and `LEGACY_FILE_DOWNLOAD` audit records.
  - **Forensic Report & Digital Autopsy RBAC Restriction**:
    - Restricted report and digital autopsy authoring/dispatch write operations exclusively to Forensic Officer (`role_id: 4`, DB role name `Forensic Analyst`), covering both `POL2026003` and `FOR2026001`.
    - Hardened backend routes (`backend/src/routes/reportRoutes.js`) with `authorizeRoles(4)` on `POST /api/reports/forensic`, `POST /api/reports/forensic/:id/dispatch`, `POST /api/reports/autopsy`, and `POST /api/reports/autopsy/:id/dispatch`.
    - Added defense-in-depth service guards (`backend/src/services/reportService.js`) rejecting unauthorized calls with 403 `{ error: "FORBIDDEN", message: "Your role has view-only access to reports." }` and logging immutable `ACCESS_DENIED` entries to `audit_logs`.
    - Opened deterministic PDF report download (`GET /api/reports/forensic/:caseId/download`) to all authenticated roles (Roles 1, 2, 3, 4).
    - Preserved report immutability: zero edit or delete endpoints exist or were added.
    - Added frontend role check utility (`frontend/src/utils/permissionHelper.js` with `canAuthorReports`).
    - Updated `frontend/src/components/ForensicSuite.jsx`:
      - Displays cyan "View-Only Mode" badge for Roles 1, 2, 3.
      - Hides "Generate Forensic Report" tab for view-only roles (direct URL visits render locked notice with redirect to Transmit & Dispatch; form is never mounted).
      - Hides "Draft Report" and "Autopsy" action buttons from the Forensic Workspace table for view-only roles.
      - Retains PDF download card and per-report download buttons in Transmit & Dispatch, but hides dispatch action controls for view-only roles.
      - Hides Digital Autopsy intake form for view-only roles, displaying saved autopsy table with a full-detail inspection modal ("🔍 View Details").
      - Replaced all legacy `alert()` dialogs with inline status banners.
    - Verified entire matrix across all 4 roles via automated verification test (`backend/src/utils/verifyReportRoles.js`), confirming 403 on writes for Roles 1–3, 201/200 for Role 4, 200 on views and PDF downloads for all roles, and verified corresponding `ACCESS_DENIED` audit log entries.
  - **Integrity Monitor Hardening & Email Dispatch Telemetry**:
    - Applied schema migration `database/migrations/20261006_harden_tamper_alerts.sql` and updated `database/schema.sql` adding `email_status`, `email_attempts`, `email_last_error`, `email_sent_at` and partial unique index `idx_active_tamper_alerts_unique` on `tamper_alerts (evidence_id, alert_type) WHERE status = 'ACTIVE'`.
    - Updated `backend/src/models/alertModel.js` with error code `23505` (`unique_violation`) deduplication handling, email telemetry update method (`updateAlertEmailDispatch`), and `getUnsentActiveAlerts(5)` retrieval.
    - Replaced `fs.readFileSync` in `backend/src/services/alertService.js` with memory-safe streaming hashing (`streamComputeFileSha256`) and streaming AES-GCM verification (`streamDecryptAndHash`).
    - Separated master key unwrapping failures (`KEY_UNWRAP_FAILED`: single system warning, 0 per-record alerts) from ciphertext corruption (`CORRUPTED_CIPHERTEXT`).
    - Implemented batch alert digest emailing (`sendTamperAlertDigestEmail`) for multi-incident scans and HTML-escaped all dynamic values in email templates (`backend/src/services/emailService.js`).
    - Added `isScanRunning` mutex guard in `alertService.js` and `integrityScheduler.js` preventing overlapping scheduled and manual scans.
    - Implemented automatic retry loop in `alertService.js` for failed/pending alert emails up to 5 attempts, with per-attempt audit logging (`EMAIL_ALERT_SENT`, `EMAIL_ALERT_FAILED`).
    - Added unsent email warning banner and email dispatch status badges (`SENT`, `PENDING`, `FAILED`) to `AlertCenter.jsx`.
    - Formatted automated audit events with clear `SYSTEM` actor name in `auditModel.js` and `auditService.js`.
    - Built automated verification suite (`scratch/test_monitor_hardening.js`) verifying all 3 requirements: 1) single alert and single email across 3 scans, 2) forced SMTP failure retrying and recovering to `SENT`, 3) concurrent scans blocked by mutex guard creating exactly 1 alert.
- **2026-10-05**:
  - **`is_legacy_seed` Schema Migration & Description Exemption Removal**: Added `is_legacy_seed BOOLEAN DEFAULT FALSE` column to `evidence` table (`database/migrations/20261005_add_is_legacy_seed.sql`, `database/schema.sql`). Flagged verified seed exhibits (`evidence_id <= 3` with `encrypted_aes_key = 'temporary_key'`) with `is_legacy_seed = TRUE`. Restored original exhibit descriptions for records 1–3 (`"Camera footage from the bank entrance."`). Completely eliminated description string parsing from `backend/src/services/alertService.js`, strictly checking the boolean database flag. Verified via automated test script that regular exhibits with `"[LEGACY SEED"` in their description and missing disk files properly raise `CRITICAL` `FILE_MISSING` alerts.
  - **Vault Integrity Audit (20 Scanned Records, 2 Compromised)**: Audited all 20 records in the database. Discovered the history behind the 20 records (3 catalog seeds, 3 legacy images, 5 development uploads from August/September, 1 test data exhibit, and 8 records created in pairs during repeated verification tests of the forensic upload and report generator). Identified the 2 compromised records (`EV-2026-004` and `EV-2026-005`) as legacy unencrypted records from August 7 that were seeded with placeholder `temporary_hash` values, resulting in `HASH_MISMATCH` against their disk file hash `9690cbefa96b7263...` (records preserved without automatic resolution).
  - **Tamper Alert Hardening & Safe Admin Test Email**: Restricted Ethereal email fallback strictly to `DEMO_MAIL=true` environments (`backend/src/services/emailService.js`), logging a `SYSTEM_WARNING` audit event and displaying an unconfigured warning banner in `AlertCenter.jsx` when SMTP credentials are not present. Added an administrative `POST /api/alerts/test-email` endpoint and test email trigger in Alert Center allowing administrators to safely verify SMTP connectivity without exposing passwords or keys. Guarded `backend/src/utils/demoTamperAlert.js` to refuse execution in production (`NODE_ENV=production`) and restricted it strictly to test exhibit `EV-2026-012`.
  - **Decrypted Evidence Download & CORS Fix**: Exposed `Content-Disposition` and `X-Evidence-Legacy` in CORS middleware (`backend/src/app.js`), enabling frontend to parse the server's clean filename header. Dynamically mapped MIME types by extension (`backend/src/utils/mimeHelper.js`) with octet-stream fallback. Stripped Multer timestamp prefix (`^\d+-`) while preserving original filename and extension. Added cryptographic pre-stream SHA-256 verification and GCM auth tag check: on mismatch or tampering, returns HTTP 422 `TAMPER_DETECTED`, serves 0 bytes, and writes tamper alert to `audit_logs`. Disabled Decrypt button on legacy unencrypted records (`EV-2026-001` to `006`) with tooltip `"No encrypted data for this record"`, while preserving hash verification. Replaced all browser `alert()` popups with inline toast/notification banners, loading state, and double-click prevention. Labeled synthetic record EV-2026-012 as `[TEST DATA] Automated Verification Sample`.
  - **Evidence Vault Decryption & Integrity Fix (Bug 1)**: Resolved Node.js Buffer TypeError (`ERR_INVALID_ARG_TYPE: Received undefined`) on legacy unencrypted evidence records (`EV-2026-001` through `EV-2026-006`) by adding strict parameter validation in `backend/src/utils/encryption.js` (`decryptAESKey`, `decryptFile`) and `backend/src/services/evidenceService.js`. Legacy records uploaded prior to envelope encryption are now gracefully detected (`is_encrypted: false`); physical legacy files are served via clean unencrypted downloads (`legacy-unencrypted-*`), while missing seed files return clean 404 JSON errors (`LEGACY_FILE_NOT_FOUND`). Recorded all access and failure attempts in `audit_logs` without leaking sensitive keys, IVs, or auth tags. Replaced all browser `alert()` popups with inline dismissible notification banners and loading/disabled states on decrypt buttons.
  - **Evidence Card Layout & CSS Conflict Elimination (Bug 2)**: Diagnosed and eliminated conflicting legacy CSS classes in `frontend/src/App.css` (`.evidence-card`, `.evidence-info-grid` 2-column layout, `.evidence-card-footer`, `.btn-action`), ensuring modern design tokens in `theme.css` and `layout.css` govern rendering. Updated grid template columns to `repeat(auto-fill, minmax(min(100%, 340px), 1fr))` with `gap: 24px`, enforced `max-width: 100%` and text overflow protection on footer buttons, preserved single-column `MetaItem` stack with monospace break-all wrapping on filenames, and ensured uniform 18px SVG icons with prominent purple accent active indicators across all sidebar items.
  - **Upload Destination Path Resolution**: Fixed relative `"uploads/"` path in `backend/src/middleware/uploadMiddleware.js` and `backend/src/controllers/evidenceController.js` using `path.resolve(__dirname, "../../uploads")`, ensuring seamless uploads and encryption regardless of the command working directory.
  - Fixed Evidence Vault card overflow and restructured components: resolved button horizontal overflow via `flex-wrap: wrap` and flexible widths (`flex: 1 1 140px`), switched metadata to a single-column stack with `min-width: 0` and `overflow-wrap: anywhere; word-break: break-all;` to wrap long filenames without clipping, enforced `min-width: 0` across card children, clamped titles to 2 lines and descriptions to 3 lines, equalized card heights with aligned bottom footers via `margin-top: auto`, and standardized the sidebar with uniform 18px SVG icons, 44px items, left accent bars, and Main/Compliance section groupings.
  - Resolved `SASL: SCRAM-SERVER-FIRST-MESSAGE: client password must be a string` authentication error by adding robust absolute path resolution for `dotenv.config()` in `backend/src/server.js` and `backend/src/config/db.js`, ensuring `.env` variables are always reliably loaded into `process.env` regardless of command execution working directory.
  - Updated frontend System Administrator Quick Demo login button in `frontend/src/AppRoot.jsx` to accurately display and dispatch `POL2026002 / Admin@123`.
  - Created `PROJECT_CONTEXT.md` capturing complete codebase architecture, API specifications, DB schema, security mechanisms, and remaining tasks.
  - Established workspace rule `.agent/rules/project_context.md` for continuous context synchronization.
  - Completed comprehensive UI redesign across all 7 primary pages (`Evidence Vault`, `Upload Evidence`, `Cases`, `Dashboard`, `Chain of Custody`, `Audit Logs`, `Forensic Reports`) adopting the unified dark theme card design system (`theme.css`, `layout.css`).
  - Added reusable design system component suite (`Badge`, `Button`, `Card`, `EmptyState`, `FormField`, `MetaItem`, `PageHeader`) in `frontend/src/components/common/`.
- **2026-10-03**:
  - Implemented deterministic forensic report PDF generation with `PDFKit` (`backend/src/services/forensicPdfService.js`).
  - Implemented automated 60-second background integrity verification daemon (`backend/src/cron/integrityScheduler.js`).
  - Configured Nodemailer SMTP critical intrusion alert service (`backend/src/services/emailService.js`).
  - Added Digital Device Autopsy and Hardware Triage module (`forensic_reports`, `autopsy_records`).
- **2026-10-02**:
  - Built core database schema (`database/schema.sql`) with 9 tables, relational foreign keys, and integrity indexes.
  - Developed AES-256-GCM envelope encryption utility with SHA-256 digest calculations (`backend/src/utils/encryption.js`).
  - Configured JWT authentication, bcrypt hashing, and role-based access control.

---

## 10. Instructions for Future AI Sessions

1. **Read This File First**: At the start of every session or task, read `PROJECT_CONTEXT.md` to establish current system state, schema contracts, and design tokens.
2. **Preserve Forensic & Business Logic**: Never modify cryptographic algorithms (SHA-256, AES-256-GCM), audit logging pipelines, or authorization middleware without explicit user consent.
3. **Adhere to the Design System**:
   - Use the shared CSS tokens in `frontend/src/styles/theme.css`.
   - Never import external UI component libraries (Tailwind, Material UI, Bootstrap).
   - Use reusable components from `frontend/src/components/common/` (`PageHeader`, `Card`, `Badge`, `Button`, `FormField`, `MetaItem`, `EmptyState`).
   - Standardize all labels to render strictly *above* inputs/values (`12px uppercase #8B90A0`).
4. **Git Commit & Push Workflow**:
   - Make atomic, verified changes.
   - Commit with clear, conventional messages (e.g. `feat: ...`, `fix: ...`, `style: ...`, `docs: ...`).
   - Always push commits to `origin main`.
5. **Keep This Context Document Synchronized**:
   - After completing any feature, bug fix, or UI redesign, update the **Status Table**, the **Remaining Work Checkboxes**, and the **Changelog** in `PROJECT_CONTEXT.md` as part of the same commit.
