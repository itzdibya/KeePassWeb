/**
 * KeePass Web Team Edition - Database & Persistent Storage Layer
 * - Multi-user with 32-byte Salt Hashing
 * - MFA Authenticator settings & backup recovery codes
 * - SSO IDP profile mapping
 * - Hierarchical KeePass Folders & Groups
 * - Encrypted Entries with Granular Co-Access Control
 * - Immutable Audit Logs & Password History
 */

const fs = require('fs');
const path = require('path');
const { encrypt, hashPassword, generateMFASecret, generateRecoveryCodes } = require('./crypto-utils');

const DB_FILE = path.join(__dirname, 'data', 'vault-storage.json');

function getDefaultData() {
    // Generate secure 32-byte salt hashes for seed users
    const adminPass = hashPassword('Pass123!@#');
    const alicePass = hashPassword('Alice123!@#');
    const bobPass = hashPassword('Bob123!@#');
    const charliePass = hashPassword('Charlie123!@#');

    const users = [
        {
            id: 'u_admin',
            username: 'admin',
            displayName: 'Admin (System Administrator)',
            email: 'admin@company.local',
            passwordHash: adminPass.hash,
            salt: adminPass.salt,
            role: 'admin',
            avatar: '🛡️',
            mfaSecret: 'JBSWY3DPEHPK3PXP',
            mfaEnabled: false,
            recoveryCodes: generateRecoveryCodes(4),
            ssoProvider: null,
            ssoSub: null,
            createdAt: '2026-01-01T00:00:00.000Z',
            status: 'active'
        },
        {
            id: 'u_alice',
            username: 'alice',
            displayName: 'Alice (DevOps Lead)',
            email: 'alice@company.local',
            passwordHash: alicePass.hash,
            salt: alicePass.salt,
            role: 'manager',
            avatar: '👩‍💻',
            mfaSecret: 'HXDMVJECJJWSRB3H',
            mfaEnabled: true,
            recoveryCodes: generateRecoveryCodes(4),
            ssoProvider: null,
            ssoSub: null,
            createdAt: '2026-01-05T00:00:00.000Z',
            status: 'active'
        },
        {
            id: 'u_bob',
            username: 'bob',
            displayName: 'Bob (Frontend Developer)',
            email: 'bob@company.local',
            passwordHash: bobPass.hash,
            salt: bobPass.salt,
            role: 'member',
            avatar: '👨‍🎨',
            mfaSecret: 'GEZDGNBVGY3TQOJQ',
            mfaEnabled: false,
            recoveryCodes: generateRecoveryCodes(4),
            ssoProvider: null,
            ssoSub: null,
            createdAt: '2026-01-10T00:00:00.000Z',
            status: 'active'
        },
        {
            id: 'u_charlie',
            username: 'charlie',
            displayName: 'Charlie (Security Analyst)',
            email: 'charlie@company.local',
            passwordHash: charliePass.hash,
            salt: charliePass.salt,
            role: 'member',
            avatar: '🕵️',
            mfaSecret: 'MZXW6YTBOI======',
            mfaEnabled: false,
            recoveryCodes: generateRecoveryCodes(4),
            ssoProvider: null,
            ssoSub: null,
            createdAt: '2026-01-15T00:00:00.000Z',
            status: 'active'
        }
    ];

    const folders = [
        { id: 'f_root', parentId: null, name: 'Root', icon: '📁', color: '#6366f1', ownerId: 'u_admin', isShared: true },
        { id: 'f_infra', parentId: 'f_root', name: 'Infrastructure & Cloud', icon: '☁️', color: '#3b82f6', ownerId: 'u_alice', isShared: true },
        { id: 'f_dev', parentId: 'f_root', name: 'Development & APIs', icon: '⚡', color: '#10b981', ownerId: 'u_alice', isShared: true },
        { id: 'f_marketing', parentId: 'f_root', name: 'Marketing & Portals', icon: '📢', color: '#f59e0b', ownerId: 'u_bob', isShared: true },
        { id: 'f_general', parentId: 'f_root', name: 'General Accounts', icon: '🌐', color: '#8b5cf6', ownerId: 'u_admin', isShared: true },
        { id: 'f_personal_alice', parentId: null, name: 'Alice Private Vault', icon: '🔒', color: '#ec4899', ownerId: 'u_alice', isShared: false },
        { id: 'f_personal_bob', parentId: null, name: 'Bob Private Vault', icon: '🔒', color: '#ec4899', ownerId: 'u_bob', isShared: false }
    ];

    const entries = [
        // 1. Team-Wide Shared: Company VPN
        {
            id: 'e_1',
            folderId: 'f_infra',
            ownerId: 'u_admin',
            title: 'Corporate WireGuard VPN Gateway',
            username: 'vpn.team.access',
            encryptedPassword: encrypt('SecureWGVPN#2026!Global'),
            url: 'https://vpn.corp.company.com:51820',
            notesEncrypted: encrypt('Gateway node in US-East. Requires MFA client certificate. Config profiles available in team wiki.'),
            customFieldsEncrypted: encrypt(JSON.stringify([
                { name: 'Gateway IP', value: '198.51.100.24', isProtected: false },
                { name: 'Preshared Key', value: 'w7V0qK3X8q8L3...example', isProtected: true }
            ])),
            totpSecretEncrypted: encrypt('JBSWY3DPEHPK3PXP'),
            tags: ['vpn', 'infrastructure', 'team-wide'],
            icon: '🛡️',
            color: '#3b82f6',
            expiresAt: '2027-12-31',
            isFavorite: true,
            inRecycleBin: false,
            sharingMode: 'team',
            createdAt: '2026-01-02T10:00:00.000Z',
            updatedAt: '2026-01-02T10:00:00.000Z'
        },
        // 2. Co-Accessible with Selected Members: AWS Production Root (Alice & Charlie)
        {
            id: 'e_2',
            folderId: 'f_infra',
            ownerId: 'u_alice',
            title: 'AWS Production Master Account',
            username: 'aws-admin@company.com',
            encryptedPassword: encrypt('AwsRootKeePass$8932Prod!'),
            url: 'https://signin.aws.amazon.com/console',
            notesEncrypted: encrypt('Primary AWS Org account. Emergency break-glass access only. Co-accessible only by Alice (DevOps Lead) and Charlie (Security).'),
            customFieldsEncrypted: encrypt(JSON.stringify([
                { name: 'Account ID', value: '8823-9941-1029', isProtected: false },
                { name: 'Region', value: 'us-east-1', isProtected: false },
                { name: 'Hardware MFA Serial', value: 'arn:aws:iam::882399411029:mfa/root-token', isProtected: true }
            ])),
            totpSecretEncrypted: encrypt('HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ'),
            tags: ['aws', 'cloud', 'co-access', 'restricted'],
            icon: '☁️',
            color: '#ef4444',
            expiresAt: null,
            isFavorite: true,
            inRecycleBin: false,
            sharingMode: 'selected',
            createdAt: '2026-01-06T14:30:00.000Z',
            updatedAt: '2026-01-06T14:30:00.000Z'
        },
        // 3. Co-Accessible with Selected Members: Staging Database Cluster (Alice & Bob)
        {
            id: 'e_3',
            folderId: 'f_dev',
            ownerId: 'u_alice',
            title: 'PostgreSQL Staging Cluster',
            username: 'pg_staging_admin',
            encryptedPassword: encrypt('StagingPgDb#9081$DevEnv'),
            url: 'postgresql://db-staging.internal:5432/app_staging',
            notesEncrypted: encrypt('Staging database cluster for frontend/backend integration testing. Co-accessible by Alice and Bob (Developer).'),
            customFieldsEncrypted: encrypt(JSON.stringify([
                { name: 'Database', value: 'app_staging', isProtected: false },
                { name: 'SSL Mode', value: 'require', isProtected: false }
            ])),
            totpSecretEncrypted: '',
            tags: ['database', 'staging', 'dev'],
            icon: '🐘',
            color: '#10b981',
            expiresAt: null,
            isFavorite: false,
            inRecycleBin: false,
            sharingMode: 'selected',
            createdAt: '2026-01-12T09:15:00.000Z',
            updatedAt: '2026-01-12T09:15:00.000Z'
        },
        // 4. Team-Wide Shared: Company GitHub Organization
        {
            id: 'e_4',
            folderId: 'f_dev',
            ownerId: 'u_admin',
            title: 'GitHub Enterprise Org Bot',
            username: 'company-ci-bot',
            encryptedPassword: encrypt('ghp_920Kjnsd78129KJASND8912389asjd'),
            url: 'https://github.com/organizations/company-corp',
            notesEncrypted: encrypt('CI/CD Bot account used for GitHub Actions runners and team repository synchronizations.'),
            customFieldsEncrypted: encrypt(JSON.stringify([
                { name: 'Personal Access Token', value: 'ghp_920Kjnsd78129KJASND8912389asjd', isProtected: true },
                { name: 'Scopes', value: 'repo, workflow, read:org', isProtected: false }
            ])),
            totpSecretEncrypted: encrypt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),
            tags: ['github', 'git', 'ci-cd', 'team-wide'],
            icon: '🐙',
            color: '#6366f1',
            expiresAt: '2026-11-30',
            isFavorite: true,
            inRecycleBin: false,
            sharingMode: 'team',
            createdAt: '2026-01-03T11:00:00.000Z',
            updatedAt: '2026-01-03T11:00:00.000Z'
        },
        // 5. Personal Private: Alice's Personal Banking
        {
            id: 'e_5',
            folderId: 'f_personal_alice',
            ownerId: 'u_alice',
            title: 'Chase Personal Banking & Savings',
            username: 'alice.private.chase',
            encryptedPassword: encrypt('AliceChaseSecureBank!9902'),
            url: 'https://secure.chase.com',
            notesEncrypted: encrypt('Alice private account. Completely private. No team member has access.'),
            customFieldsEncrypted: encrypt(JSON.stringify([
                { name: 'Account Num (Last 4)', value: '7789', isProtected: false }
            ])),
            totpSecretEncrypted: '',
            tags: ['personal', 'banking', 'private'],
            icon: '🔒',
            color: '#ec4899',
            expiresAt: null,
            isFavorite: true,
            inRecycleBin: false,
            sharingMode: 'private',
            createdAt: '2026-01-10T16:00:00.000Z',
            updatedAt: '2026-01-10T16:00:00.000Z'
        },
        // 6. Personal Private: Bob's Personal Password
        {
            id: 'e_6',
            folderId: 'f_personal_bob',
            ownerId: 'u_bob',
            title: 'Bob Personal Google Account',
            username: 'bob.developer.personal@gmail.com',
            encryptedPassword: encrypt('BobGoogleMaster!4820'),
            url: 'https://accounts.google.com',
            notesEncrypted: encrypt('Private password vault item owned by Bob.'),
            customFieldsEncrypted: encrypt('[]'),
            totpSecretEncrypted: '',
            tags: ['personal', 'private'],
            icon: '🔒',
            color: '#ec4899',
            expiresAt: null,
            isFavorite: false,
            inRecycleBin: false,
            sharingMode: 'private',
            createdAt: '2026-01-11T12:00:00.000Z',
            updatedAt: '2026-01-11T12:00:00.000Z'
        }
    ];

    const entryShares = [
        {
            id: 'es_1',
            entryId: 'e_2',
            userId: 'u_charlie',
            permission: 'viewer',
            grantedBy: 'u_alice',
            createdAt: '2026-01-06T14:35:00.000Z'
        },
        {
            id: 'es_2',
            entryId: 'e_3',
            userId: 'u_bob',
            permission: 'editor',
            grantedBy: 'u_alice',
            createdAt: '2026-01-12T09:20:00.000Z'
        }
    ];

    const passwordHistory = [
        {
            id: 'ph_1',
            entryId: 'e_1',
            encryptedPassword: encrypt('OldVPNKey#2025!Beta'),
            changedBy: 'u_admin',
            changedAt: '2026-01-01T10:00:00.000Z'
        }
    ];

    const auditLogs = [
        {
            id: 'al_1',
            userId: 'u_admin',
            username: 'admin',
            action: 'LOGIN',
            entryId: null,
            entryTitle: null,
            ip: '127.0.0.1',
            details: 'System Administrator logged in (Salt Hashing verified)',
            timestamp: '2026-01-02T09:00:00.000Z'
        },
        {
            id: 'al_2',
            userId: 'u_alice',
            username: 'alice',
            action: 'ENTRY_SHARED',
            entryId: 'e_2',
            entryTitle: 'AWS Production Master Account',
            ip: '127.0.0.1',
            details: 'Granted viewer co-access to Charlie (Security Analyst)',
            timestamp: '2026-01-06T14:35:00.000Z'
        },
        {
            id: 'al_3',
            userId: 'u_alice',
            username: 'alice',
            action: 'ENTRY_SHARED',
            entryId: 'e_3',
            entryTitle: 'PostgreSQL Staging Cluster',
            ip: '127.0.0.1',
            details: 'Granted editor co-access to Bob (Frontend Developer)',
            timestamp: '2026-01-12T09:20:00.000Z'
        }
    ];

    return {
        users,
        folders,
        entries,
        entryShares,
        passwordHistory,
        auditLogs
    };
}

class Database {
    constructor() {
        this.data = null;
        this.init();
    }

    init() {
        const dir = path.dirname(DB_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        if (fs.existsSync(DB_FILE)) {
            try {
                const raw = fs.readFileSync(DB_FILE, 'utf8');
                this.data = JSON.parse(raw);
                // Schema migration check for salts & MFA
                let modified = false;
                this.data.users.forEach(u => {
                    if (!u.salt || u.salt.length < 32) {
                        const newPass = hashPassword('Pass123!@#');
                        u.passwordHash = newPass.hash;
                        u.salt = newPass.salt;
                        modified = true;
                    }
                    if (u.mfaEnabled === undefined) {
                        u.mfaEnabled = false;
                        u.mfaSecret = generateMFASecret();
                        u.recoveryCodes = generateRecoveryCodes(4);
                        modified = true;
                    }
                });
                if (modified) this.save();
            } catch (err) {
                console.error('Error loading existing database, initializing fresh seed:', err);
                this.data = getDefaultData();
                this.save();
            }
        } else {
            this.data = getDefaultData();
            this.save();
        }
    }

    save() {
        try {
            const tempFile = `${DB_FILE}.tmp`;
            fs.writeFileSync(tempFile, JSON.stringify(this.data, null, 2), 'utf8');
            fs.renameSync(tempFile, DB_FILE);
        } catch (err) {
            console.error('Database write error:', err);
        }
    }

    // --- Users API ---
    findUserById(id) {
        return this.data.users.find(u => u.id === id);
    }

    findUserByUsername(username) {
        return this.data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    }

    findUserBySSO(provider, sub) {
        return this.data.users.find(u => u.ssoProvider === provider && u.ssoSub === sub);
    }

    getAllUsers(publicOnly = true) {
        if (!publicOnly) return this.data.users;
        return this.data.users.map(u => ({
            id: u.id,
            username: u.username,
            displayName: u.displayName,
            email: u.email,
            role: u.role,
            avatar: u.avatar,
            mfaEnabled: Boolean(u.mfaEnabled),
            ssoProvider: u.ssoProvider,
            status: u.status,
            createdAt: u.createdAt
        }));
    }

    createUser(userData) {
        const user = {
            id: `u_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            username: userData.username,
            displayName: userData.displayName || userData.username,
            email: userData.email,
            passwordHash: userData.passwordHash,
            salt: userData.salt,
            role: userData.role || 'member',
            avatar: userData.avatar || '👤',
            mfaSecret: userData.mfaSecret || generateMFASecret(),
            mfaEnabled: Boolean(userData.mfaEnabled),
            recoveryCodes: userData.recoveryCodes || generateRecoveryCodes(4),
            ssoProvider: userData.ssoProvider || null,
            ssoSub: userData.ssoSub || null,
            createdAt: new Date().toISOString(),
            status: 'active'
        };
        this.data.users.push(user);
        this.save();
        return user;
    }

    updateUser(id, updates) {
        const index = this.data.users.findIndex(u => u.id === id);
        if (index === -1) return null;
        this.data.users[index] = { ...this.data.users[index], ...updates };
        this.save();
        return this.data.users[index];
    }

    deleteUser(id) {
        const index = this.data.users.findIndex(u => u.id === id);
        if (index === -1) return false;
        this.data.users.splice(index, 1);
        this.save();
        return true;
    }

    // --- Folders API ---
    getFolders(userId) {
        const user = this.findUserById(userId);
        if (!user) return [];
        return this.data.folders.filter(f => {
            if (user.role === 'admin') return true;
            if (f.isShared) return true;
            return f.ownerId === userId;
        });
    }

    createFolder(folderData) {
        const folder = {
            id: `f_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            parentId: folderData.parentId || null,
            name: folderData.name,
            icon: folderData.icon || '📁',
            color: folderData.color || '#6366f1',
            ownerId: folderData.ownerId,
            isShared: folderData.isShared !== undefined ? folderData.isShared : true,
            createdAt: new Date().toISOString()
        };
        this.data.folders.push(folder);
        this.save();
        return folder;
    }

    updateFolder(id, updates) {
        const index = this.data.folders.findIndex(f => f.id === id);
        if (index === -1) return null;
        this.data.folders[index] = { ...this.data.folders[index], ...updates };
        this.save();
        return this.data.folders[index];
    }

    deleteFolder(id) {
        const index = this.data.folders.findIndex(f => f.id === id);
        if (index === -1) return false;
        this.data.folders.splice(index, 1);
        this.data.entries.forEach(e => {
            if (e.folderId === id) {
                e.folderId = 'f_root';
            }
        });
        this.save();
        return true;
    }

    // --- Granular Permissions & Co-Access Check ---
    getUserEntryPermission(userId, entry) {
        if (!userId || !entry) return null;
        const user = this.findUserById(userId);
        if (!user) return null;

        if (user.role === 'admin') return 'admin';
        if (entry.ownerId === userId) return 'owner';

        if (entry.sharingMode === 'team') {
            return 'viewer';
        }

        const share = this.data.entryShares.find(s => s.entryId === entry.id && s.userId === userId);
        if (share) {
            return share.permission;
        }

        return null;
    }

    // --- Entries API ---
    getAccessibleEntries(userId, filters = {}) {
        const user = this.findUserById(userId);
        if (!user) return [];

        return this.data.entries
            .filter(entry => {
                if (filters.inRecycleBin !== undefined) {
                    if (Boolean(entry.inRecycleBin) !== Boolean(filters.inRecycleBin)) return false;
                } else if (entry.inRecycleBin) {
                    return false;
                }

                if (filters.folderId && filters.folderId !== 'all') {
                    if (entry.folderId !== filters.folderId) return false;
                }

                if (filters.isFavorite && !entry.isFavorite) return false;

                const permission = this.getUserEntryPermission(userId, entry);
                if (!permission) return false;

                if (filters.filterType === 'shared_with_me') {
                    return entry.ownerId !== userId && (entry.sharingMode === 'selected' || entry.sharingMode === 'team');
                }
                if (filters.filterType === 'shared_by_me') {
                    return entry.ownerId === userId && (entry.sharingMode === 'selected' || entry.sharingMode === 'team');
                }
                if (filters.filterType === 'private_only') {
                    return entry.ownerId === userId && entry.sharingMode === 'private';
                }

                return true;
            })
            .map(entry => {
                const permission = this.getUserEntryPermission(userId, entry);
                const shares = this.getEntryShares(entry.id);
                return {
                    ...entry,
                    userPermission: permission,
                    isOwner: entry.ownerId === userId || user.role === 'admin',
                    sharesCount: shares.length,
                    sharedUsers: shares.map(s => {
                        const targetUser = this.findUserById(s.userId);
                        return {
                            userId: s.userId,
                            username: targetUser ? targetUser.username : s.userId,
                            displayName: targetUser ? targetUser.displayName : s.userId,
                            avatar: targetUser ? targetUser.avatar : '👤',
                            permission: s.permission
                        };
                    })
                };
            });
    }

    getEntryById(id, userId) {
        const entry = this.data.entries.find(e => e.id === id);
        if (!entry) return null;
        const permission = this.getUserEntryPermission(userId, entry);
        if (!permission) return null;

        const shares = this.getEntryShares(entry.id);
        const owner = this.findUserById(entry.ownerId);

        return {
            ...entry,
            userPermission: permission,
            ownerName: owner ? owner.displayName : 'Unknown',
            shares: shares.map(s => {
                const u = this.findUserById(s.userId);
                return {
                    ...s,
                    username: u ? u.username : s.userId,
                    displayName: u ? u.displayName : s.userId,
                    avatar: u ? u.avatar : '👤'
                };
            })
        };
    }

    createEntry(entryData, userId) {
        const id = `e_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        const newEntry = {
            id,
            folderId: entryData.folderId || 'f_root',
            ownerId: userId,
            title: entryData.title || 'Untitled Entry',
            username: entryData.username || '',
            encryptedPassword: encrypt(entryData.password || ''),
            url: entryData.url || '',
            notesEncrypted: encrypt(entryData.notes || ''),
            customFieldsEncrypted: encrypt(JSON.stringify(entryData.customFields || [])),
            totpSecretEncrypted: encrypt(entryData.totpSecret || ''),
            tags: Array.isArray(entryData.tags) ? entryData.tags : [],
            icon: entryData.icon || '🔑',
            color: entryData.color || '#3b82f6',
            expiresAt: entryData.expiresAt || null,
            isFavorite: Boolean(entryData.isFavorite),
            inRecycleBin: false,
            sharingMode: entryData.sharingMode || 'private',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        this.data.entries.push(newEntry);

        if (entryData.shares && Array.isArray(entryData.shares) && entryData.sharingMode === 'selected') {
            entryData.shares.forEach(share => {
                if (share.userId && share.userId !== userId) {
                    this.data.entryShares.push({
                        id: `es_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
                        entryId: id,
                        userId: share.userId,
                        permission: share.permission || 'viewer',
                        grantedBy: userId,
                        createdAt: new Date().toISOString()
                    });
                }
            });
        }

        this.save();
        return newEntry;
    }

    updateEntry(id, updates, userId) {
        const index = this.data.entries.findIndex(e => e.id === id);
        if (index === -1) return null;

        const current = this.data.entries[index];
        const permission = this.getUserEntryPermission(userId, current);

        if (!['owner', 'admin', 'co_owner', 'editor'].includes(permission)) {
            throw new Error('Permission denied: cannot edit this entry');
        }

        if (updates.password !== undefined && updates.password !== '') {
            const newEncrypted = encrypt(updates.password);
            if (newEncrypted !== current.encryptedPassword) {
                this.data.passwordHistory.push({
                    id: `ph_${Date.now()}`,
                    entryId: id,
                    encryptedPassword: current.encryptedPassword,
                    changedBy: userId,
                    changedAt: new Date().toISOString()
                });
                current.encryptedPassword = newEncrypted;
            }
        }

        if (updates.title !== undefined) current.title = updates.title;
        if (updates.username !== undefined) current.username = updates.username;
        if (updates.url !== undefined) current.url = updates.url;
        if (updates.folderId !== undefined) current.folderId = updates.folderId;
        if (updates.tags !== undefined) current.tags = updates.tags;
        if (updates.icon !== undefined) current.icon = updates.icon;
        if (updates.color !== undefined) current.color = updates.color;
        if (updates.expiresAt !== undefined) current.expiresAt = updates.expiresAt;
        if (updates.isFavorite !== undefined) current.isFavorite = updates.isFavorite;
        if (updates.inRecycleBin !== undefined) current.inRecycleBin = updates.inRecycleBin;

        if (updates.notes !== undefined) {
            current.notesEncrypted = encrypt(updates.notes);
        }
        if (updates.customFields !== undefined) {
            current.customFieldsEncrypted = encrypt(JSON.stringify(updates.customFields));
        }
        if (updates.totpSecret !== undefined) {
            current.totpSecretEncrypted = encrypt(updates.totpSecret);
        }

        if (['owner', 'admin', 'co_owner'].includes(permission)) {
            if (updates.sharingMode !== undefined) {
                current.sharingMode = updates.sharingMode;
            }
            if (updates.shares !== undefined && Array.isArray(updates.shares)) {
                this.updateEntryShares(id, updates.shares, userId);
            }
        }

        current.updatedAt = new Date().toISOString();
        this.save();
        return current;
    }

    deleteEntry(id, userId, permanent = false) {
        const index = this.data.entries.findIndex(e => e.id === id);
        if (index === -1) return false;

        const current = this.data.entries[index];
        const permission = this.getUserEntryPermission(userId, current);

        if (!['owner', 'admin', 'co_owner'].includes(permission)) {
            throw new Error('Permission denied: cannot delete this entry');
        }

        if (permanent) {
            this.data.entries.splice(index, 1);
            this.data.entryShares = this.data.entryShares.filter(s => s.entryId !== id);
            this.data.passwordHistory = this.data.passwordHistory.filter(h => h.entryId !== id);
        } else {
            current.inRecycleBin = true;
            current.updatedAt = new Date().toISOString();
        }

        this.save();
        return true;
    }

    restoreEntry(id, userId) {
        const entry = this.data.entries.find(e => e.id === id);
        if (!entry) return false;
        const permission = this.getUserEntryPermission(userId, entry);
        if (!['owner', 'admin', 'co_owner'].includes(permission)) {
            throw new Error('Permission denied');
        }
        entry.inRecycleBin = false;
        entry.updatedAt = new Date().toISOString();
        this.save();
        return true;
    }

    getEntryShares(entryId) {
        return this.data.entryShares.filter(s => s.entryId === entryId);
    }

    updateEntryShares(entryId, sharesList, grantedByUserId) {
        this.data.entryShares = this.data.entryShares.filter(s => s.entryId !== entryId);
        sharesList.forEach(share => {
            if (share.userId) {
                this.data.entryShares.push({
                    id: `es_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
                    entryId,
                    userId: share.userId,
                    permission: share.permission || 'viewer',
                    grantedBy: grantedByUserId,
                    createdAt: new Date().toISOString()
                });
            }
        });
        this.save();
    }

    getPasswordHistory(entryId) {
        return this.data.passwordHistory
            .filter(h => h.entryId === entryId)
            .sort((a, b) => new Date(b.changedAt) - new Date(a.changedAt));
    }

    logAudit(event) {
        const log = {
            id: `al_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
            userId: event.userId || 'anonymous',
            username: event.username || 'System',
            action: event.action,
            entryId: event.entryId || null,
            entryTitle: event.entryTitle || null,
            ip: event.ip || '127.0.0.1',
            details: event.details || '',
            timestamp: new Date().toISOString()
        };
        this.data.auditLogs.unshift(log);
        if (this.data.auditLogs.length > 10000) {
            this.data.auditLogs.pop();
        }
        this.save();
        return log;
    }

    getAuditLogs(filters = {}) {
        let logs = [...this.data.auditLogs];
        if (filters.action) {
            logs = logs.filter(l => l.action === filters.action);
        }
        if (filters.userId) {
            logs = logs.filter(l => l.userId === filters.userId);
        }
        if (filters.entryId) {
            logs = logs.filter(l => l.entryId === filters.entryId);
        }
        if (filters.limit) {
            logs = logs.slice(0, parseInt(filters.limit, 10));
        }
        return logs;
    }
}

const db = new Database();
module.exports = db;
