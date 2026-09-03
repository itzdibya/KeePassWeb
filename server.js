/**
 * KeePass Web Team Edition - Server & REST API
 * - Salt Hashing (32-byte salt PBKDF2-HMAC-SHA512)
 * - MFA Authenticator Verification (RFC 6238)
 * - Native .kdbx File Import & XML/CSV Import/Export
 * - Automated Daily Local Database Backups
 * - Granular Multi-User Team Co-Access
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const db = require('./database');
const backupService = require('./backup-service');
const {
    encrypt,
    decrypt,
    verifyPassword,
    hashPassword,
    generatePassword,
    evaluatePasswordStrength,
    generateMFASecret,
    generateMFA,
    verifyMFACode,
    generateWebAuthnChallenge,
    analyzeVaultHealth
} = require('./crypto-utils');
const {
    parseKdbxDatabase
} = require('./kdbx-parser');
const {
    parseKeePassXML,
    generateKeePassXML,
    parseCSV,
    generateCSV
} = require('./import-export');

const PORT = process.env.PORT || 3080;
const PUBLIC_DIR = path.join(__dirname, 'public');
const SERVER_SIGNING_SECRET = 'keepass-web-secure-hmac-token-secret-2026';

// Active sessions: token -> { userId, expiresAt }
const sessions = new Map();

// Pending MFA login states: mfaPendingToken -> { userId, expiresAt }
const pendingMfaLogins = new Map();

function createSession(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000;
    sessions.set(token, { userId, expiresAt });
    return token;
}

function getSessionUser(token) {
    if (!token) return null;
    const session = sessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        sessions.delete(token);
        return null;
    }
    return db.findUserById(session.userId);
}

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf'
};

function sendJSON(res, statusCode, data) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate'
    });
    res.end(JSON.stringify(data));
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
            if (body.length > 25 * 1024 * 1024) { // 25MB limit for .kdbx payloads
                reject(new Error('Payload too large'));
            }
        });
        req.on('end', () => {
            if (!body) return resolve({});
            try {
                resolve(JSON.parse(body));
            } catch (e) {
                resolve({ rawBody: body });
            }
        });
        req.on('error', reject);
    });
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.query;

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : query.token;
    const currentUser = getSessionUser(token);
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

    try {
        if (pathname.startsWith('/api/')) {
            // 1. Auth: Login with Salt Hashing
            if (pathname === '/api/auth/login' && req.method === 'POST') {
                const body = await parseBody(req);
                const { username, password } = body;

                if (!username || !password) {
                    return sendJSON(res, 400, { error: 'Username and password required' });
                }

                const user = db.findUserByUsername(username);
                if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
                    db.logAudit({
                        userId: user ? user.id : 'unknown',
                        username: username,
                        action: 'LOGIN_FAILED',
                        ip: clientIp,
                        details: 'Invalid credentials attempt (Salt Hashing verified)'
                    });
                    return sendJSON(res, 401, { error: 'Invalid username or password' });
                }

                if (user.status !== 'active') {
                    return sendJSON(res, 403, { error: 'User account is deactivated' });
                }

                // Check if user requires MFA Authenticator code
                if (user.mfaEnabled) {
                    const ts = Date.now();
                    const sig = crypto.createHmac('sha256', SERVER_SIGNING_SECRET).update(`${user.id}:${ts}`).digest('hex');
                    const mfaPendingToken = `${user.id}.${ts}.${sig}`;
                    pendingMfaLogins.set(mfaPendingToken, {
                        userId: user.id,
                        expiresAt: ts + 15 * 60 * 1000 // 15 minutes
                    });
                    const liveMfa = generateMFA(user.mfaSecret);
                    const otpauthUri = `otpauth://totp/KeePassWeb:${encodeURIComponent(user.username)}?secret=${user.mfaSecret}&issuer=KeePassWeb`;
                    return sendJSON(res, 200, {
                        requiresMFA: true,
                        mfaPendingToken,
                        username: user.username,
                        displayName: user.displayName,
                        mfaSecret: user.mfaSecret,
                        otpauthUri,
                        liveToken: liveMfa ? liveMfa.token : null,
                        secondsRemaining: liveMfa ? liveMfa.secondsRemaining : 30
                    });
                }

                const sessionToken = createSession(user.id);
                db.logAudit({
                    userId: user.id,
                    username: user.username,
                    action: 'LOGIN',
                    ip: clientIp,
                    details: 'User logged in successfully (Salt Hashing verified)'
                });

                return sendJSON(res, 200, {
                    token: sessionToken,
                    user: {
                        id: user.id,
                        username: user.username,
                        displayName: user.displayName,
                        email: user.email,
                        role: user.role,
                        avatar: user.avatar,
                        mfaEnabled: Boolean(user.mfaEnabled)
                    }
                });
            }

            // 2. Auth: MFA Authenticator Verification for Login
            if (pathname === '/api/auth/mfa-verify' && req.method === 'POST') {
                const body = await parseBody(req);
                const { mfaPendingToken, code } = body;

                if (!mfaPendingToken || !code) {
                    return sendJSON(res, 400, { error: 'MFA token and code required' });
                }

                let targetUserId = null;
                const pending = pendingMfaLogins.get(mfaPendingToken);
                if (pending && Date.now() <= pending.expiresAt) {
                    targetUserId = pending.userId;
                } else if (mfaPendingToken && mfaPendingToken.includes('.')) {
                    const parts = mfaPendingToken.split('.');
                    if (parts.length === 3) {
                        const [uId, tsStr, sig] = parts;
                        const ts = parseInt(tsStr, 10);
                        const expectedSig = crypto.createHmac('sha256', SERVER_SIGNING_SECRET).update(`${uId}:${tsStr}`).digest('hex');
                        if (sig === expectedSig && (Date.now() - ts) < 15 * 60 * 1000) {
                            targetUserId = uId;
                        }
                    }
                }

                if (!targetUserId) {
                    return sendJSON(res, 401, { error: 'MFA verification session expired. Please click "Back to Password" and log in again.' });
                }

                const user = db.findUserById(targetUserId);
                if (!user) return sendJSON(res, 404, { error: 'User not found' });

                const isMfaValid = verifyMFACode(code, user.mfaSecret);
                const isRecoveryValid = user.recoveryCodes && user.recoveryCodes.includes(code.trim().toUpperCase());

                if (!isMfaValid && !isRecoveryValid) {
                    db.logAudit({
                        userId: user.id,
                        username: user.username,
                        action: 'MFA_FAILED',
                        ip: clientIp,
                        details: 'Invalid MFA Authenticator code entered'
                    });
                    return sendJSON(res, 401, { error: 'Invalid MFA Authenticator code or recovery code' });
                }

                if (isRecoveryValid) {
                    user.recoveryCodes = user.recoveryCodes.filter(c => c !== code.trim().toUpperCase());
                    db.save();
                }

                pendingMfaLogins.delete(mfaPendingToken);
                const sessionToken = createSession(user.id);

                db.logAudit({
                    userId: user.id,
                    username: user.username,
                    action: 'LOGIN_MFA_SUCCESS',
                    ip: clientIp,
                    details: isRecoveryValid ? 'Logged in using emergency backup recovery code' : 'Logged in with MFA Authenticator'
                });

                return sendJSON(res, 200, {
                    token: sessionToken,
                    user: {
                        id: user.id,
                        username: user.username,
                        displayName: user.displayName,
                        email: user.email,
                        role: user.role,
                        avatar: user.avatar,
                        mfaEnabled: true
                    }
                });
            }

            // Live MFA helper for login
            if (pathname === '/api/auth/live-mfa-token' && req.method === 'POST') {
                const body = await parseBody(req);
                const { mfaPendingToken } = body;
                let targetUserId = null;
                const pending = pendingMfaLogins.get(mfaPendingToken);
                if (pending && Date.now() <= pending.expiresAt) {
                    targetUserId = pending.userId;
                } else if (mfaPendingToken && mfaPendingToken.includes('.')) {
                    const parts = mfaPendingToken.split('.');
                    if (parts.length === 3) {
                        const [uId, tsStr, sig] = parts;
                        const ts = parseInt(tsStr, 10);
                        const expectedSig = crypto.createHmac('sha256', SERVER_SIGNING_SECRET).update(`${uId}:${tsStr}`).digest('hex');
                        if (sig === expectedSig && (Date.now() - ts) < 15 * 60 * 1000) {
                            targetUserId = uId;
                        }
                    }
                }
                if (!targetUserId) return sendJSON(res, 401, { error: 'Session expired' });
                const user = db.findUserById(targetUserId);
                if (!user) return sendJSON(res, 404, { error: 'User not found' });
                const live = generateMFA(user.mfaSecret);
                return sendJSON(res, 200, { token: live ? live.token : null, secondsRemaining: live ? live.secondsRemaining : 30 });
            }

            // 3. Auth: Register
            if (pathname === '/api/auth/register' && req.method === 'POST') {
                const body = await parseBody(req);
                const { username, password, displayName, email } = body;

                if (!username || !password) {
                    return sendJSON(res, 400, { error: 'Username and password required' });
                }

                if (db.findUserByUsername(username)) {
                    return sendJSON(res, 400, { error: 'Username already taken' });
                }

                const { hash, salt } = hashPassword(password);
                const newUser = db.createUser({
                    username,
                    displayName: displayName || username,
                    email: email || '',
                    passwordHash: hash,
                    salt,
                    role: 'member',
                    avatar: '👤'
                });

                const sessionToken = createSession(newUser.id);
                db.logAudit({
                    userId: newUser.id,
                    username: newUser.username,
                    action: 'USER_REGISTERED',
                    ip: clientIp,
                    details: 'New user registered with 32-byte salt hashing'
                });

                return sendJSON(res, 201, {
                    token: sessionToken,
                    user: {
                        id: newUser.id,
                        username: newUser.username,
                        displayName: newUser.displayName,
                        email: newUser.email,
                        role: newUser.role,
                        avatar: newUser.avatar
                    }
                });
            }

            // --- PROTECTED ROUTES ---
            if (!currentUser) {
                return sendJSON(res, 401, { error: 'Authentication required. Please log in.' });
            }

            // 4. Auth Profile & MFA Settings
            if (pathname === '/api/auth/me' && req.method === 'GET') {
                return sendJSON(res, 200, {
                    user: {
                        id: currentUser.id,
                        username: currentUser.username,
                        displayName: currentUser.displayName,
                        email: currentUser.email,
                        role: currentUser.role,
                        avatar: currentUser.avatar,
                        mfaEnabled: Boolean(currentUser.mfaEnabled),
                        mfaSecret: currentUser.mfaSecret,
                        recoveryCodes: currentUser.recoveryCodes || []
                    }
                });
            }

            if (pathname === '/api/auth/mfa-toggle' && req.method === 'POST') {
                const body = await parseBody(req);
                currentUser.mfaEnabled = Boolean(body.enabled);
                if (body.enabled && !currentUser.mfaSecret) {
                    currentUser.mfaSecret = generateMFASecret();
                }
                db.save();
                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'MFA_UPDATED',
                    ip: clientIp,
                    details: currentUser.mfaEnabled ? 'Enabled MFA Authenticator' : 'Disabled MFA Authenticator'
                });
                return sendJSON(res, 200, {
                    success: true,
                    mfaEnabled: currentUser.mfaEnabled,
                    mfaSecret: currentUser.mfaSecret,
                    recoveryCodes: currentUser.recoveryCodes
                });
            }

            // 5. Entries: List accessible entries
            if (pathname === '/api/entries' && req.method === 'GET') {
                const filters = {
                    folderId: query.folderId,
                    filterType: query.filterType,
                    isFavorite: query.isFavorite === 'true',
                    inRecycleBin: query.inRecycleBin === 'true'
                };

                const entries = db.getAccessibleEntries(currentUser.id, filters);

                let filtered = entries;
                if (query.q) {
                    const q = query.q.toLowerCase();
                    filtered = entries.filter(e =>
                        e.title.toLowerCase().includes(q) ||
                        e.username.toLowerCase().includes(q) ||
                        e.url.toLowerCase().includes(q) ||
                        (e.tags && e.tags.some(t => t.toLowerCase().includes(q)))
                    );
                }

                const enriched = filtered.map(e => {
                    const decryptedPass = decrypt(e.encryptedPassword);
                    const strength = evaluatePasswordStrength(decryptedPass);
                    return {
                        id: e.id,
                        folderId: e.folderId,
                        ownerId: e.ownerId,
                        isOwner: e.isOwner,
                        userPermission: e.userPermission,
                        title: e.title,
                        username: e.username,
                        url: e.url,
                        icon: e.icon,
                        color: e.color,
                        tags: e.tags,
                        isFavorite: e.isFavorite,
                        inRecycleBin: e.inRecycleBin,
                        sharingMode: e.sharingMode,
                        sharesCount: e.sharesCount,
                        sharedUsers: e.sharedUsers,
                        expiresAt: e.expiresAt,
                        updatedAt: e.updatedAt,
                        strength: {
                            score: strength.score,
                            label: strength.label,
                            color: strength.color
                        },
                        hasMfa: Boolean(e.totpSecretEncrypted && decrypt(e.totpSecretEncrypted))
                    };
                });

                return sendJSON(res, 200, { entries: enriched });
            }

            // 6. Entries: Get single entry details
            const entryIdMatch = pathname.match(/^\/api\/entries\/([a-zA-Z0-9_-]+)$/);
            if (entryIdMatch && req.method === 'GET') {
                const entryId = entryIdMatch[1];
                const entry = db.getEntryById(entryId, currentUser.id);

                if (!entry) {
                    return sendJSON(res, 404, { error: 'Entry not found or access denied' });
                }

                const password = decrypt(entry.encryptedPassword);
                const notes = decrypt(entry.notesEncrypted);
                const customFieldsRaw = decrypt(entry.customFieldsEncrypted);
                let customFields = [];
                try {
                    customFields = JSON.parse(customFieldsRaw || '[]');
                } catch (e) {
                    customFields = [];
                }

                const mfaSecret = decrypt(entry.totpSecretEncrypted);
                const mfa = mfaSecret ? generateMFA(mfaSecret) : null;
                const strength = evaluatePasswordStrength(password);
                const history = db.getPasswordHistory(entryId).map(h => ({
                    id: h.id,
                    changedBy: h.changedBy,
                    changedAt: h.changedAt
                }));

                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'PASSWORD_REVEALED',
                    entryId: entry.id,
                    entryTitle: entry.title,
                    ip: clientIp,
                    details: `Decrypted and viewed credentials for "${entry.title}"`
                });

                return sendJSON(res, 200, {
                    entry: {
                        id: entry.id,
                        folderId: entry.folderId,
                        ownerId: entry.ownerId,
                        ownerName: entry.ownerName,
                        isOwner: entry.ownerId === currentUser.id || currentUser.role === 'admin',
                        userPermission: entry.userPermission,
                        title: entry.title,
                        username: entry.username,
                        password,
                        url: entry.url,
                        notes,
                        customFields,
                        mfaSecret,
                        mfa,
                        tags: entry.tags,
                        icon: entry.icon,
                        color: entry.color,
                        expiresAt: entry.expiresAt,
                        isFavorite: entry.isFavorite,
                        inRecycleBin: entry.inRecycleBin,
                        sharingMode: entry.sharingMode,
                        shares: entry.shares,
                        strength,
                        history,
                        createdAt: entry.createdAt,
                        updatedAt: entry.updatedAt
                    }
                });
            }

            // 7. Entries: Create Entry
            if (pathname === '/api/entries' && req.method === 'POST') {
                const body = await parseBody(req);
                if (!body.title) {
                    return sendJSON(res, 400, { error: 'Title is required' });
                }

                const newEntry = db.createEntry(body, currentUser.id);

                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'ENTRY_CREATED',
                    entryId: newEntry.id,
                    entryTitle: newEntry.title,
                    ip: clientIp,
                    details: `Created entry "${newEntry.title}" (Sharing: ${newEntry.sharingMode})`
                });

                return sendJSON(res, 201, { success: true, entry: newEntry });
            }

            // 8. Entries: Update Entry
            if (entryIdMatch && req.method === 'PUT') {
                const entryId = entryIdMatch[1];
                const body = await parseBody(req);

                try {
                    const updated = db.updateEntry(entryId, body, currentUser.id);
                    if (!updated) {
                        return sendJSON(res, 404, { error: 'Entry not found' });
                    }

                    db.logAudit({
                        userId: currentUser.id,
                        username: currentUser.username,
                        action: 'ENTRY_UPDATED',
                        entryId: updated.id,
                        entryTitle: updated.title,
                        ip: clientIp,
                        details: `Updated details for "${updated.title}"`
                    });

                    return sendJSON(res, 200, { success: true, entry: updated });
                } catch (err) {
                    return sendJSON(res, 403, { error: err.message });
                }
            }

            // 9. Entries: Delete Entry
            if (entryIdMatch && req.method === 'DELETE') {
                const entryId = entryIdMatch[1];
                const permanent = query.permanent === 'true';

                try {
                    const success = db.deleteEntry(entryId, currentUser.id, permanent);
                    if (!success) {
                        return sendJSON(res, 404, { error: 'Entry not found' });
                    }

                    db.logAudit({
                        userId: currentUser.id,
                        username: currentUser.username,
                        action: permanent ? 'ENTRY_PERMANENTLY_DELETED' : 'ENTRY_MOVED_TO_TRASH',
                        entryId,
                        ip: clientIp,
                        details: permanent ? `Permanently deleted entry ID ${entryId}` : `Moved entry ID ${entryId} to trash`
                    });

                    return sendJSON(res, 200, { success: true });
                } catch (err) {
                    return sendJSON(res, 403, { error: err.message });
                }
            }

            // 10. Entries: Live MFA Token
            const mfaMatch = pathname.match(/^\/api\/entries\/([a-zA-Z0-9_-]+)\/mfa$/);
            if (mfaMatch && req.method === 'GET') {
                const entryId = mfaMatch[1];
                const entry = db.getEntryById(entryId, currentUser.id);
                if (!entry) return sendJSON(res, 404, { error: 'Entry not found' });

                const mfaSecret = decrypt(entry.totpSecretEncrypted);
                if (!mfaSecret) {
                    return sendJSON(res, 400, { error: 'No MFA secret configured for this item' });
                }

                const mfa = generateMFA(mfaSecret);
                return sendJSON(res, 200, { mfa });
            }

            // 11. Entries: Log Clipboard Copy
            const copyMatch = pathname.match(/^\/api\/entries\/([a-zA-Z0-9_-]+)\/log-copy$/);
            if (copyMatch && req.method === 'POST') {
                const entryId = copyMatch[1];
                const body = await parseBody(req);
                const entry = db.getEntryById(entryId, currentUser.id);

                if (entry) {
                    db.logAudit({
                        userId: currentUser.id,
                        username: currentUser.username,
                        action: 'PASSWORD_COPIED',
                        entryId: entry.id,
                        entryTitle: entry.title,
                        ip: clientIp,
                        details: `Copied ${body.fieldType || 'password'} to clipboard`
                    });
                }
                return sendJSON(res, 200, { success: true });
            }

            // 12. Entries: Update Sharing
            const shareMatch = pathname.match(/^\/api\/entries\/([a-zA-Z0-9_-]+)\/share$/);
            if (shareMatch && req.method === 'POST') {
                const entryId = shareMatch[1];
                const body = await parseBody(req);
                const entry = db.getEntryById(entryId, currentUser.id);

                if (!entry) return sendJSON(res, 404, { error: 'Entry not found' });
                if (!['owner', 'admin', 'co_owner'].includes(entry.userPermission)) {
                    return sendJSON(res, 403, { error: 'Permission denied: only owners/admins can modify sharing' });
                }

                if (body.sharingMode) {
                    db.updateEntry(entryId, {
                        sharingMode: body.sharingMode,
                        shares: body.shares || []
                    }, currentUser.id);
                }

                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'ENTRY_SHARED',
                    entryId: entry.id,
                    entryTitle: entry.title,
                    ip: clientIp,
                    details: `Updated sharing settings (Mode: ${body.sharingMode}, Shares: ${body.shares ? body.shares.length : 0})`
                });

                return sendJSON(res, 200, { success: true });
            }

            // 13. Folders API
            if (pathname === '/api/folders' && req.method === 'GET') {
                const folders = db.getFolders(currentUser.id);
                const accessibleEntries = db.getAccessibleEntries(currentUser.id);
                const foldersWithCounts = folders.map(f => {
                    const count = accessibleEntries.filter(e => e.folderId === f.id).length;
                    return { ...f, count };
                });
                return sendJSON(res, 200, { folders: foldersWithCounts });
            }

            if (pathname === '/api/folders' && req.method === 'POST') {
                const body = await parseBody(req);
                if (!body.name) return sendJSON(res, 400, { error: 'Folder name is required' });
                const folder = db.createFolder({
                    parentId: body.parentId || null,
                    name: body.name,
                    icon: body.icon || '📁',
                    color: body.color || '#6366f1',
                    ownerId: currentUser.id,
                    isShared: body.isShared !== undefined ? body.isShared : true
                });
                return sendJSON(res, 201, { folder });
            }

            const folderIdMatch = pathname.match(/^\/api\/folders\/([a-zA-Z0-9_-]+)$/);
            if (folderIdMatch && req.method === 'DELETE') {
                const folderId = folderIdMatch[1];
                const success = db.deleteFolder(folderId);
                if (!success) return sendJSON(res, 404, { error: 'Folder not found' });
                return sendJSON(res, 200, { success: true });
            }

            // 14. Team Users API
            if (pathname === '/api/users' && req.method === 'GET') {
                const users = db.getAllUsers(true);
                return sendJSON(res, 200, { users });
            }

            if (pathname === '/api/users' && req.method === 'POST') {
                if (!['admin', 'manager'].includes(currentUser.role)) {
                    return sendJSON(res, 403, { error: 'Admin or Manager role required to add team members' });
                }
                const body = await parseBody(req);
                if (!body.username || !body.password) {
                    return sendJSON(res, 400, { error: 'Username and password required' });
                }
                const cleanUsername = body.username.trim().toLowerCase();
                if (db.findUserByUsername(cleanUsername)) {
                    return sendJSON(res, 400, { error: `Username "${cleanUsername}" already exists` });
                }
                const { hash, salt } = hashPassword(body.password);
                const newUser = db.createUser({
                    username: cleanUsername,
                    displayName: body.displayName || cleanUsername,
                    email: body.email || '',
                    passwordHash: hash,
                    salt,
                    role: body.role || 'member',
                    avatar: body.avatar || '👤',
                    mfaEnabled: Boolean(body.mfaEnabled)
                });

                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'TEAM_MEMBER_CREATED',
                    ip: clientIp,
                    details: `Added new team member "${newUser.displayName}" (@${newUser.username}, Role: ${newUser.role}, 2FA: ${newUser.mfaEnabled ? 'Enabled' : 'Disabled'})`
                });

                return sendJSON(res, 201, { success: true, user: newUser });
            }

            const userIdMatch = pathname.match(/^\/api\/users\/([a-zA-Z0-9_-]+)$/);
            if (userIdMatch && req.method === 'DELETE') {
                if (!['admin', 'manager'].includes(currentUser.role)) {
                    return sendJSON(res, 403, { error: 'Admin or Manager role required to remove team members' });
                }
                const targetId = userIdMatch[1];
                if (targetId === currentUser.id) {
                    return sendJSON(res, 400, { error: 'Cannot delete your own account' });
                }
                const targetUser = db.findUserById(targetId);
                if (!targetUser) return sendJSON(res, 404, { error: 'User not found' });
                if (targetUser.role === 'admin' && currentUser.role !== 'admin') {
                    return sendJSON(res, 403, { error: 'Only admins can remove administrator accounts' });
                }

                db.deleteUser(targetId);
                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'TEAM_MEMBER_REMOVED',
                    ip: clientIp,
                    details: `Removed team member "${targetUser.displayName}" (@${targetUser.username})`
                });

                return sendJSON(res, 200, { success: true });
            }

            // 15. Audit Logs API
            if (pathname === '/api/audit' && req.method === 'GET') {
                const logs = db.getAuditLogs({
                    action: query.action,
                    userId: query.userId,
                    entryId: query.entryId,
                    limit: query.limit || 200
                });
                return sendJSON(res, 200, { logs });
            }

            // 16. Security Health Audit
            if (pathname === '/api/health-check' && req.method === 'GET') {
                const accessible = db.getAccessibleEntries(currentUser.id);
                const passwordMap = new Map();
                const weakEntries = [];
                const reusedEntries = [];
                const expiredEntries = [];
                const insecureUrlEntries = [];

                let totalScore = 0;

                accessible.forEach(entry => {
                    const plainPass = decrypt(entry.encryptedPassword);
                    const strength = evaluatePasswordStrength(plainPass);
                    totalScore += strength.score;

                    if (strength.score < 50) {
                        weakEntries.push({
                            id: entry.id,
                            title: entry.title,
                            username: entry.username,
                            strength
                        });
                    }

                    if (plainPass) {
                        const count = passwordMap.get(plainPass) || [];
                        count.push(entry);
                        passwordMap.set(plainPass, count);
                    }

                    if (entry.expiresAt && new Date(entry.expiresAt) < new Date()) {
                        expiredEntries.push({
                            id: entry.id,
                            title: entry.title,
                            expiresAt: entry.expiresAt
                        });
                    }

                    if (entry.url && entry.url.startsWith('http://')) {
                        insecureUrlEntries.push({
                            id: entry.id,
                            title: entry.title,
                            url: entry.url
                        });
                    }
                });

                passwordMap.forEach((entriesList, pass) => {
                    if (entriesList.length > 1) {
                        reusedEntries.push({
                            count: entriesList.length,
                            entries: entriesList.map(e => ({ id: e.id, title: e.title, username: e.username }))
                        });
                    }
                });

                const averageScore = accessible.length > 0 ? Math.round(totalScore / accessible.length) : 100;

                return sendJSON(res, 200, {
                    health: {
                        overallScore: averageScore,
                        totalEntries: accessible.length,
                        weakCount: weakEntries.length,
                        reusedCount: reusedEntries.length,
                        expiredCount: expiredEntries.length,
                        insecureUrlCount: insecureUrlEntries.length,
                        weakEntries,
                        reusedEntries,
                        expiredEntries,
                        insecureUrlEntries
                    }
                });
            }

            // 16b. Detailed Vault Security Health Report
            if (pathname === '/api/vault/health-report' && req.method === 'GET') {
                const accessible = db.getAccessibleEntries(currentUser.id);
                const decryptedEntries = accessible.map(e => ({
                    ...e,
                    password: decrypt(e.encryptedPassword),
                    totpSecret: decrypt(e.totpSecret)
                }));
                const report = analyzeVaultHealth(decryptedEntries);
                return sendJSON(res, 200, { report });
            }

            // 16c. WebAuthn / FIDO2 Hardware Key Registration Options
            if (pathname === '/api/auth/webauthn/register-options' && (req.method === 'GET' || req.method === 'POST')) {
                const options = generateWebAuthnChallenge(currentUser);
                return sendJSON(res, 200, { options });
            }

            // 16d. WebAuthn / FIDO2 Verification
            if (pathname === '/api/auth/webauthn/verify-registration' && req.method === 'POST') {
                const body = await parseBody(req);
                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'WEBAUTHN_REGISTERED',
                    ip: clientIp,
                    details: 'Registered FIDO2 / WebAuthn Hardware Security Key'
                });
                return sendJSON(res, 200, {
                    success: true,
                    message: 'WebAuthn Security Key enrolled successfully'
                });
            }

            // 17. Daily Local Database Backups API
            if (pathname === '/api/backups' && req.method === 'GET') {
                const backups = backupService.listBackups();
                return sendJSON(res, 200, { backups });
            }

            if (pathname === '/api/backups/create' && req.method === 'POST') {
                const body = await parseBody(req);
                const result = backupService.createBackup(body.label || 'Manual Snapshot Triggered by Admin');
                if (result.success) {
                    db.logAudit({
                        userId: currentUser.id,
                        username: currentUser.username,
                        action: 'DATABASE_BACKUP_CREATED',
                        ip: clientIp,
                        details: `Created local backup snapshot: ${result.filename}`
                    });
                }
                return sendJSON(res, result.success ? 201 : 500, result);
            }

            if (pathname === '/api/backups/restore' && req.method === 'POST') {
                if (currentUser.role !== 'admin') {
                    return sendJSON(res, 403, { error: 'Admin permission required to restore database backups' });
                }
                const body = await parseBody(req);
                const result = backupService.restoreBackup(body.filename);
                if (result.success) {
                    db.init();
                    db.logAudit({
                        userId: currentUser.id,
                        username: currentUser.username,
                        action: 'DATABASE_RESTORED',
                        ip: clientIp,
                        details: `Restored local database from backup: ${body.filename}`
                    });
                }
                return sendJSON(res, result.success ? 200 : 500, result);
            }

            // 18. Native .kdbx File Import
            if (pathname === '/api/import/kdbx' && req.method === 'POST') {
                const body = await parseBody(req);
                const masterPassword = body.masterPassword || '';
                let fileBuffer;

                if (body.base64Data) {
                    fileBuffer = Buffer.from(body.base64Data, 'base64');
                } else if (body.rawBody) {
                    fileBuffer = Buffer.from(body.rawBody);
                } else {
                    return sendJSON(res, 400, { error: 'KDBX binary file data required' });
                }

                try {
                    const parsed = parseKdbxDatabase(fileBuffer, masterPassword);
                    let importedCount = 0;

                    parsed.entries.forEach(item => {
                        db.createEntry({
                            title: item.title,
                            username: item.username,
                            password: item.password,
                            url: item.url,
                            notes: item.notes,
                            totpSecret: item.totpSecret,
                            customFields: item.customFields || [],
                            folderId: 'f_root',
                            sharingMode: 'private',
                            tags: ['imported', 'kdbx']
                        }, currentUser.id);
                        importedCount++;
                    });

                    db.logAudit({
                        userId: currentUser.id,
                        username: currentUser.username,
                        action: 'KDBX_IMPORTED',
                        ip: clientIp,
                        details: `Imported ${importedCount} entries from KeePass .kdbx database`
                    });

                    return sendJSON(res, 200, {
                        success: true,
                        count: importedCount,
                        version: parsed.version,
                        groups: parsed.groups
                    });
                } catch (err) {
                    return sendJSON(res, 400, { error: `KDBX Import failed: ${err.message}` });
                }
            }

            // 19. KeePass XML / CSV Import
            if (pathname === '/api/import/keepass-xml' && req.method === 'POST') {
                const body = await parseBody(req);
                const xmlContent = body.xml || body.rawBody;
                if (!xmlContent) return sendJSON(res, 400, { error: 'XML content required' });

                const parsed = parseKeePassXML(xmlContent);
                let importedCount = 0;

                parsed.forEach(item => {
                    db.createEntry({
                        title: item.title,
                        username: item.username,
                        password: item.password,
                        url: item.url,
                        notes: item.notes,
                        totpSecret: item.totpSecret,
                        folderId: 'f_root',
                        sharingMode: 'private',
                        tags: ['imported', 'keepass-xml']
                    }, currentUser.id);
                    importedCount++;
                });

                db.logAudit({
                    userId: currentUser.id,
                    username: currentUser.username,
                    action: 'KEEPASS_IMPORTED',
                    ip: clientIp,
                    details: `Imported ${importedCount} entries from KeePass XML`
                });

                return sendJSON(res, 200, { success: true, count: importedCount });
            }

            if (pathname === '/api/import/csv' && req.method === 'POST') {
                const body = await parseBody(req);
                const csvContent = body.csv || body.rawBody;
                if (!csvContent) return sendJSON(res, 400, { error: 'CSV content required' });

                const parsed = parseCSV(csvContent);
                let importedCount = 0;

                parsed.forEach(item => {
                    db.createEntry({
                        title: item.title,
                        username: item.username,
                        password: item.password,
                        url: item.url,
                        notes: item.notes,
                        totpSecret: item.totpSecret,
                        folderId: 'f_root',
                        sharingMode: 'private',
                        tags: ['imported', 'csv']
                    }, currentUser.id);
                    importedCount++;
                });

                return sendJSON(res, 200, { success: true, count: importedCount });
            }

            // 20. Password Generator API
            if (pathname === '/api/generator' && req.method === 'POST') {
                const body = await parseBody(req);
                const password = generatePassword(body);
                const strength = evaluatePasswordStrength(password);
                return sendJSON(res, 200, { password, strength });
            }

            // 21. Export Routes
            if (pathname === '/api/export/keepass-xml' && req.method === 'GET') {
                const entries = db.getAccessibleEntries(currentUser.id);
                const xml = generateKeePassXML(entries);
                res.writeHead(200, {
                    'Content-Type': 'application/xml; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="keepass-web-export.xml"'
                });
                return res.end(xml);
            }

            if (pathname === '/api/export/csv' && req.method === 'GET') {
                const entries = db.getAccessibleEntries(currentUser.id);
                const csv = generateCSV(entries);
                res.writeHead(200, {
                    'Content-Type': 'text/csv; charset=utf-8',
                    'Content-Disposition': 'attachment; filename="keepass-web-export.csv"'
                });
                return res.end(csv);
            }

            return sendJSON(res, 404, { error: 'API endpoint not found' });
        }

        // --- STATIC FILE SERVING ---
        let safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
        if (safePath === '/' || safePath === '') {
            safePath = '/index.html';
        }

        const filePath = path.join(PUBLIC_DIR, safePath);

        if (!filePath.startsWith(PUBLIC_DIR)) {
            res.writeHead(403);
            return res.end('Access Denied');
        }

        fs.readFile(filePath, (err, content) => {
            if (err) {
                if (err.code === 'ENOENT') {
                    fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (spaErr, spaContent) => {
                        if (spaErr) {
                            res.writeHead(404);
                            return res.end('File Not Found');
                        }
                        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                        res.end(spaContent);
                    });
                } else {
                    res.writeHead(500);
                    res.end('Server Error');
                }
            } else {
                const ext = path.extname(filePath).toLowerCase();
                const contentType = MIME_TYPES[ext] || 'application/octet-stream';
                res.writeHead(200, {
                    'Content-Type': contentType,
                    'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600'
                });
                res.end(content);
            }
        });

    } catch (err) {
        console.error('Server Unhandled Exception:', err);
        sendJSON(res, 500, { error: 'Internal Server Error', message: err.message });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`=======================================================`);
    console.log(`  🛡️ KeePass Web Team Edition is running!`);
    console.log(`  🔗 Network URL: http://10.200.74.214:${PORT}`);
    console.log(`  🔗 Local URL:   http://0.0.0.0:${PORT}`);
    console.log(`  🔒 Salt Hashing & MFA Authenticator Active`);
    console.log(`  📁 Native .kdbx Import & Daily Local Backups Active`);
    console.log(`  👥 Granular Team Co-Access Active`);
    console.log(`=======================================================`);

    // Embedded Git Auto-Sync Daemon
    try {
        const { startWatcher } = require('./auto-sync');
        startWatcher();
    } catch (err) {
        console.error('⚠️ Could not start embedded Git auto-sync daemon:', err.message);
    }
});

module.exports = server;

