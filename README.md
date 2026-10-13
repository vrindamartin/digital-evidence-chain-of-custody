# DIG_EVI — Digital Evidence Chain of Custody & Management System

DIG_EVI is a secure, role-based Digital Evidence Management System (DEMS) built for law enforcement and digital forensics workflows. It provides AES-256-GCM client-side/server-side envelope encryption, SHA-256 cryptographic integrity verification, chain-of-custody transfer tracking, comprehensive tamper detection with automated email notifications, and deterministic system-generated forensic lab reports.

---

## Key Capabilities

- **Cryptographic Security**: Envelope encryption with AES-256-GCM for all evidence artifacts; SHA-256 checksums verified continuously.
- **Automated Integrity Monitoring**: Background sentinel scan executes every 60 seconds to detect missing files, corrupted ciphertexts, or hash mismatches.
- **Immediate Administrative Alerts**: In-app Alert Center and instant email notifications sent to the System Administrator upon tamper detection.
- **Unbroken Chain of Custody**: Immutable chronological ledger of every evidence handover, check-in, and transfer.
- **Deterministic Forensic Reports**: Automated, court-ready PDF report generation using PDFKit based entirely on verified database records.

---

## Prerequisites

- **Node.js** (v18.x or later)
- **PostgreSQL** (v14 or later)
- **npm** (included with Node.js)

---

## Setup & Installation

### 1. Database Initialization

Ensure PostgreSQL is running, then execute the schema and seed scripts:

```bash
# Create database
psql -U postgres -c "CREATE DATABASE digital_evidence_db;"

# Apply schema & demo data
psql -U postgres -d digital_evidence_db -f database/schema.sql
psql -U postgres -d digital_evidence_db -f database/seed_demo_data.sql
```

Alternatively, from the `backend/` directory:
```bash
node src/config/initTables.js
```

### 2. Backend Configuration

Navigate to `backend/` and copy the environment template:

```bash
cp .env.example .env
```

Configure `backend/.env` with your settings:

```env
PORT=3000
DB_HOST=localhost
DB_PORT=5432
DB_NAME=digital_evidence_db
DB_USER=postgres
DB_PASSWORD=your_postgres_password
JWT_SECRET=your_secure_jwt_secret
MASTER_ENCRYPTION_KEY=64_character_hex_master_encryption_key

# =============================================================================
# SMTP Email Notification Configuration (Tamper Alerts)
# =============================================================================
# For Gmail:
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USER=your_email@gmail.com
# SMTP_PASS=your_gmail_app_password
#
# For Ethereal (Dev/Testing):
# SMTP_HOST=smtp.ethereal.email
# SMTP_PORT=587
#
# Optional: Override the recipient email address
# (If omitted, DIG_EVI uses the active System Administrator email in PostgreSQL)
SYSTEM_ADMIN_EMAIL=admin@police.gov.in
```

Install backend dependencies:
```bash
npm install
```

### 3. Frontend Installation

Navigate to `frontend/`:
```bash
npm install
```

---

## Running the Application

### Start Backend Server
From the `backend/` folder:
```bash
npm start
# Or for development with auto-reload:
npm run dev
```
*Backend runs on `http://localhost:3000`.*

### Start Frontend Client
From the `frontend/` folder:
```bash
npm run dev
```
*Frontend runs on `http://localhost:5173`.*

---

## Default Demonstration Accounts

All demonstration accounts use the password: **`Admin@123`**

| Employee ID | Role | Name | Purpose |
| :--- | :--- | :--- | :--- |
| `POL2026002` | System Administrator (1) | System Administrator | Tamper alerts, sentinel logs, user management |
| `POL2026001` | Police Officer (2) | Officer John Davis | Evidence upload, case management, custody handovers |
| `CAS2026001` | Case Manager (3) | Robert Miller | Case review, evidence audits, case assignments |
| `FOR2026001` | Forensic Analyst (4) | Dr. Sarah Jenkins | Forensic suite, device autopsies, official PDF download |

---

## Automated Tamper Alerts & Email Notifications

### How It Works

1. **Continuous 60-Second Background Scan**:
   `integrityScheduler.js` triggers `alertService.scanAllEvidenceIntegrity()` every 60 seconds.
2. **Integrity Validation**:
   The engine reads each encrypted exhibit, verifies AES-256-GCM authentication tags, re-computes the plain SHA-256 checksum, and compares against the stored master digest.
3. **Failure Classification**:
   - `FILE_MISSING`: Stored physical file is missing from disk storage.
   - `CORRUPTED_CIPHERTEXT`: Encrypted payload corrupted or authentication tag mismatch.
   - `HASH_MISMATCH`: File altered; calculated hash does not match original stored hash.
4. **Alert & Audit Generation**:
   - A `CRITICAL` alert is created in `tamper_alerts` (status `ACTIVE`).
   - A `TAMPER_DETECTED` immutable entry is recorded in `audit_logs`.
5. **Email Dispatch**:
   - `emailService.sendTamperAlertEmail()` dispatches an email to `SYSTEM_ADMIN_EMAIL` (or the active System Admin from the database).
   - **Duplicate Prevention**: If the tamper alert is already active, no duplicate alert is created and no repeat emails are sent during subsequent scans.
   - **Non-blocking / Resilient**: Email failures are non-fatal; they do not crash the scheduler or roll back database records.

---

## Safe Testing of Email Notifications

You can test email notifications safely without modifying real evidence or creating false database alerts:

### Method 1: Automated Verification Script (Non-Destructive)

Run the included standalone email verification utility:

```bash
cd backend
node src/utils/testEmailNotification.js
```

**What it does:**
- If SMTP credentials are configured in `.env`, it verifies the SMTP handshake and sends a test alert email to your inbox.
- If SMTP credentials are NOT yet set, it automatically provisions an ephemeral **Ethereal Email** test mailbox, dispatches a sample tamper alert, and prints an **instant web preview URL** so you can view the formatted email in your browser!

### Method 2: Controlled End-to-End Incident Verification

1. Log in as **Officer John Davis** (`POL2026001`).
2. Upload a dummy test file (e.g. `test-file.txt`) to a test case.
3. Observe that the evidence is encrypted and verified as `INTACT`.
4. To test tampering in a sandbox environment:
   - Temporarily rename or edit the file in `backend/uploads/` or `backend/uploads/encrypted/`.
   - Wait up to 60 seconds for the scheduled integrity sweep (or click **Verify Integrity**).
   - The system detects the anomaly, logs a `TAMPER_DETECTED` audit event, displays an incident card in the **Alert Center**, and sends a tamper alert email.
5. Log in as **System Administrator** (`POL2026002`), navigate to **⚠️ Tamper Alerts**, review the incident, and click **Resolve Alert** with resolution remarks.

---

## Live Presentation Tamper Detection & Reset Demo Sequence

For project presentations and demonstrations, use the dedicated safe tamper trigger and reset utilities:

### Safety Guarantees
- **Strict Exhibit Restriction**: Restricted solely to designated test exhibit **`EV-2026-012`** (`evidence_id: 14`).
- **Production Guard**: Both scripts immediately abort if `NODE_ENV === 'production'`.
- **Zero Real Data Corruption**: Backs up intact ciphertext to `scratch/backups/` and verifies 100% bit-for-bit restoration.

### Step-by-Step Presentation Flow

1. **Step 1: Trigger Tamper (Induce single-byte ciphertext corruption)**
   ```bash
   node backend/src/utils/demoTamperAlert.js --tamper-only
   ```
   - Corrupts byte 0 of `EV-2026-012`'s `.enc` file.
   - Triggers cryptographic verification, detecting `CORRUPTED_CIPHERTEXT` (AES-GCM authentication failure).
   - Generates an immutable `TAMPER_DETECTED` audit log and dispatches security alert email via Ethereal sandbox.
   - Leaves exhibit in tampered state and outputs an Ethereal web preview URL.

2. **Step 2: Present Live Alert & Notification**
   - Navigate to the **Alert Center** in your browser: `http://localhost:5173/alerts`.
   - Point out the active **CRITICAL** incident card for `EV-2026-012`.
   - Open the Ethereal web preview URL in your browser to display the tamper email notification.

3. **Step 3: Reset Exhibit to Intact State**
   ```bash
   node backend/src/utils/resetDemoTamper.js
   ```
   - Restores the original `.enc` file bit-for-bit from `scratch/backups/`.
   - Marks the active demo alert as `RESOLVED` in PostgreSQL under System Administrator credentials.
   - Runs post-reset cryptographic scan confirming status **`INTACT`** with zero new alerts.

4. **Step 4: Verify Clean State**
   - Refresh `http://localhost:5173/alerts` to show the incident moved to **Resolved** and the system clean.

