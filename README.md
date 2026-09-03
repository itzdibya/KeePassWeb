# 🛡️ KeePass Web Team Edition

A self-hosted, secure web-based password manager inspired by KeePass2, featuring hierarchical group trees, rich entry metadata, **Salted Password Hashing**, **MFA Authenticator (2FA)**, **Native `.kdbx` Database Import**, **Daily Local Database Backups**, and **Granular Team Co-Access Permissions**.

---

## 🌟 Key Features

### 1. 🔐 Security & Salt Hashing
- **32-Byte Per-User Salt**: Every account is protected with a unique cryptographically random 32-byte salt.
- **PBKDF2-HMAC-SHA512**: 100,000 iterations for password verification with constant-time comparison.
- **AES-256-GCM Vault Encryption**: Sensitive credentials (passwords, MFA secrets, custom attributes, notes) stored with 12-byte random IVs and 16-byte authentication tags.

### 2. 📱 MFA Authenticator (2FA)
- **Login 2FA**: Requires 6-digit TOTP token verification on login (compatible with Google Authenticator, Microsoft Authenticator, Authy, 1Password).
- **Emergency Recovery Codes**: Single-use backup codes for account recovery.
- **Vault Item MFA**: Real-time 6-digit MFA code generation with circular SVG countdown timer.

### 3. 👥 Granular Team Co-Access Control
- **Private Vault**: Items accessible strictly by the owner/creator.
- **Selected Team Members**: Choose exact team members and assign permission levels (`Viewer`, `Editor`, `Co-Owner`).
- **Team-Wide Shared**: Accessible to all workspace members.
- **Role Switcher**: 1-click switcher in header between `Admin`, `Alice (DevOps Lead)`, `Bob (Frontend Dev)`, and `Charlie (Security Analyst)` to test and verify multi-user permission isolation live.

### 4. 📁 Native `.kdbx` and XML/CSV Import & Export
- **KeePass 2.x `.kdbx` File Import**: Drag-and-drop `.kdbx` database import with master password decryption.
- **KeePass XML & CSV Import**: Import XML or standard CSV spreadsheets.
- **Export Formats**: KeePass 2.x XML and CSV exports for offline backups.

### 5. 💾 Daily Automated Local Database Backups
- **Local Daily Snapshots**: Automatically takes consistent database snapshots in `./backups/` directory (e.g., `vault_backup_YYYY-MM-DD_HHMMSS.json`).
- **Rotation Retention**: Automatically retains the last 7 daily backups and 4 weekly snapshots.
- **Integrity Validation**: Computes and verifies SHA-256 checksums per snapshot.
- **Snapshot Now & Restore**: 1-click snapshot creation and restore directly in the UI.

---

## 🚀 Quick Start

### 1. Start the Server
```bash
cd /home/sysadmin/pdf-suite/keepass2
node server.js
```
The server will start on **Port 3080**:
👉 Open in browser: `http://10.200.74.214:3080` (or `http://localhost:3080`)

### 2. Default Demo Accounts
All seeded accounts use password format `<Name>123!@#`:
- **Admin (System Administrator)**: Username `admin` | Password `Pass123!@#`
- **Alice (DevOps Lead)**: Username `alice` | Password `Alice123!@#`
- **Bob (Frontend Developer)**: Username `bob` | Password `Bob123!@#`
- **Charlie (Security Analyst)**: Username `charlie` | Password `Charlie123!@#`

---

## 🧪 Running Automated Tests
```bash
node test/test-crypto.js
```
Verifies AES-256-GCM encryption, 32-byte salt hashing, RFC 6238 MFA token calculation, .kdbx parsing, backup rotation, and multi-user co-access isolation.
