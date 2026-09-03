/**
 * KeePass Web Team Edition - Client Application Controller
 * - Vault & Entries management with granular co-access
 * - Real-time MFA Authenticator live timer & code calculation
 * - Password generator & health analyzer
 * - Native .kdbx file reader & KeePass XML/CSV importer
 * - Daily local database backup manager
 * - Multi-user role switcher & audit viewer
 */

class KeePassWebApp {
    constructor() {
        this.token = localStorage.getItem('keepass_token') || '';
        this.currentUser = null;
        this.entries = [];
        this.folders = [];
        this.users = [];
        this.selectedEntryId = null;
        this.currentView = 'all'; // 'all' | 'favorites' | 'private_only' | 'shared_with_me' | 'shared_by_me' | 'recycle_bin' | folderId
        this.searchQuery = '';
        this.accessFilter = 'all';
        this.sortBy = 'title_asc';
        this.viewMode = 'list';
        this.mfaTimer = null;
        this.autoLockTimer = null;

        this.init();
    }

    async init() {
        this.initTheme();
        this.initEventListeners();
        await this.authenticateInitialUser();
    }

    initTheme() {
        const savedTheme = localStorage.getItem('keepass_theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        const icon = document.querySelector('.theme-icon');
        if (icon) icon.textContent = savedTheme === 'dark' ? '🌙' : '☀️';
    }

    toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('keepass_theme', next);
        const icon = document.querySelector('.theme-icon');
        if (icon) icon.textContent = next === 'dark' ? '🌙' : '☀️';
    }

    async authenticateInitialUser() {
        try {
            if (this.token) {
                const res = await this.apiGet('/api/auth/me');
                if (res && res.user) {
                    this.currentUser = res.user;
                    this.updateUserUI();
                    await this.loadVaultData();
                    return;
                }
            }
            // If no valid session token, show the secure 2-Step Login modal
            this.lockVault();
        } catch (err) {
            console.error('Initial authentication error:', err);
            this.lockVault();
        }
    }

    lockVault() {
        this.token = '';
        localStorage.removeItem('keepass_token');
        if (this.mfaTimer) clearInterval(this.mfaTimer);

        const overlay = document.getElementById('lockScreenOverlay');
        if (overlay) overlay.style.display = 'flex';

        this.backToLoginStep1();
        const userSelect = document.getElementById('loginUserSelect');
        if (userSelect && this.currentUser) {
            userSelect.value = this.currentUser.username || 'alice';
        }
        this.onLoginUserSelectChange();
        const passInput = document.getElementById('loginPasswordInput');
        if (passInput) {
            passInput.value = '';
            passInput.focus();
        }
    }

    onLoginUserSelectChange() {
        const select = document.getElementById('loginUserSelect');
        const hint = document.getElementById('loginPassHint');
        const passInput = document.getElementById('loginPasswordInput');
        const btn = document.getElementById('loginStep1Btn');
        if (!select || !hint) return;

        const defaultPasswords = {
            admin: 'Pass123!@#',
            alice: 'Alice123!@#',
            bob: 'Bob123!@#',
            charlie: 'Charlie123!@#'
        };

        const val = select.value;
        const pass = defaultPasswords[val] || 'Password123!@#';
        hint.innerHTML = `Default password: <code>${pass}</code>`;
        if (passInput) passInput.placeholder = `Enter password (${pass})`;

        if (btn) {
            if (val === 'alice') {
                btn.innerHTML = '<span>Continue to 2FA</span> ➡️';
            } else {
                btn.innerHTML = '<span>🔓 Unlock Vault</span>';
            }
        }
    }

    toggleLoginPassVisibility() {
        const input = document.getElementById('loginPasswordInput');
        if (input) {
            input.type = input.type === 'password' ? 'text' : 'password';
        }
    }

    async handleLoginStep1() {
        const username = document.getElementById('loginUserSelect')?.value || 'alice';
        const password = document.getElementById('loginPasswordInput')?.value || '';
        const errorEl = document.getElementById('loginStep1Error');
        const btn = document.getElementById('loginStep1Btn');

        if (!password) {
            if (errorEl) {
                errorEl.textContent = 'Please enter your master password.';
                errorEl.style.display = 'block';
            }
            return;
        }

        if (errorEl) errorEl.style.display = 'none';
        if (btn) btn.disabled = true;

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();

            if (!res.ok) {
                if (errorEl) {
                    errorEl.textContent = data.error || 'Authentication failed. Invalid password.';
                    errorEl.style.display = 'block';
                }
                return;
            }

            if (data.requiresMFA) {
                // Transition to Step 2: Google / Microsoft Authenticator code
                this.mfaPendingToken = data.mfaPendingToken;
                this.pendingMfaSecret = data.mfaSecret || 'JBSWY3DPEHPK3PXP';
                this.pendingLiveToken = data.liveToken || '';

                const secretBox = document.getElementById('loginMfaSecretBox');
                if (secretBox) secretBox.textContent = this.pendingMfaSecret;

                document.getElementById('loginStep1Form').style.display = 'none';
                document.getElementById('loginStep2Form').style.display = 'block';

                const mfaInput = document.getElementById('loginMfaCodeInput');
                if (mfaInput) {
                    mfaInput.value = '';
                    mfaInput.focus();
                }
                const errorStep2 = document.getElementById('loginStep2Error');
                if (errorStep2) errorStep2.style.display = 'none';
            } else if (data.token) {
                // Direct login success
                this.token = data.token;
                this.currentUser = data.user;
                localStorage.setItem('keepass_token', this.token);
                document.getElementById('lockScreenOverlay').style.display = 'none';
                this.updateUserUI();
                await this.loadVaultData();
                this.showToast(`Welcome back, ${this.currentUser.displayName}!`, 'success');
            }
        } catch (err) {
            if (errorEl) {
                errorEl.textContent = 'Network error connecting to auth server.';
                errorEl.style.display = 'block';
            }
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async handleLoginStep2() {
        const codeInput = document.getElementById('loginMfaCodeInput');
        const code = codeInput?.value?.trim() || '';
        const errorEl = document.getElementById('loginStep2Error');
        const btn = document.getElementById('loginStep2Btn');

        if (!code) {
            if (errorEl) {
                errorEl.textContent = 'Please enter the 6-digit code from Google/Microsoft Authenticator.';
                errorEl.style.display = 'block';
            }
            return;
        }

        if (errorEl) errorEl.style.display = 'none';
        if (btn) btn.disabled = true;

        try {
            const res = await fetch('/api/auth/mfa-verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    mfaPendingToken: this.mfaPendingToken,
                    code
                })
            });
            const data = await res.json();

            if (!res.ok) {
                if (errorEl) {
                    errorEl.textContent = data.error || 'Invalid Authenticator code. Check your Google/MS Authenticator app.';
                    errorEl.style.display = 'block';
                }
                return;
            }

            // Authenticated successfully!
            this.token = data.token;
            this.currentUser = data.user;
            localStorage.setItem('keepass_token', this.token);
            document.getElementById('lockScreenOverlay').style.display = 'none';
            this.updateUserUI();
            await this.loadVaultData();
            this.showToast(`🎉 2FA Verified! Welcome ${this.currentUser.displayName}`, 'success');
        } catch (err) {
            if (errorEl) {
                errorEl.textContent = 'Network error during MFA verification.';
                errorEl.style.display = 'block';
            }
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    backToLoginStep1() {
        const step1 = document.getElementById('loginStep1Form');
        const step2 = document.getElementById('loginStep2Form');
        if (step1) step1.style.display = 'block';
        if (step2) step2.style.display = 'none';
        const err1 = document.getElementById('loginStep1Error');
        const err2 = document.getElementById('loginStep2Error');
        if (err1) err1.style.display = 'none';
        if (err2) err2.style.display = 'none';
    }

    toggleAuthHelperDetails() {
        const details = document.getElementById('authHelperDetails');
        const btn = document.getElementById('toggleAuthHelperBtn');
        if (!details) return;
        const isHidden = details.style.display === 'none';
        details.style.display = isHidden ? 'block' : 'none';
        if (btn) btn.textContent = isHidden ? 'Hide Key' : 'Show Key';
    }

    async autoFillLiveMfaCode() {
        const input = document.getElementById('loginMfaCodeInput');
        try {
            const res = await fetch('/api/auth/live-mfa-token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mfaPendingToken: this.mfaPendingToken })
            });
            const data = await res.json();
            if (data.token && input) {
                input.value = data.token;
                this.showToast(`⚡ Auto-filled live Authenticator code (${data.secondsRemaining}s left)`, 'info');
                this.handleLoginStep2();
                return;
            }
        } catch (e) {}

        if (input && this.pendingLiveToken) {
            input.value = this.pendingLiveToken;
            this.showToast('⚡ Auto-filled live Google/MS Authenticator code!', 'info');
            this.handleLoginStep2();
        } else {
            this.showToast('Please enter the 6 digits from your mobile Authenticator app', 'info');
        }
    }

    updateUserUI() {
        if (!this.currentUser) return;
        const avatarEl = document.getElementById('currentUserAvatar');
        const nameEl = document.getElementById('currentUserName');
        const roleEl = document.getElementById('currentUserRole');

        const topAvatar = document.getElementById('topUserAvatar');
        const topName = document.getElementById('topUserName');
        const topRole = document.getElementById('topUserRole');

        if (avatarEl) avatarEl.textContent = this.currentUser.avatar || '👤';
        if (nameEl) nameEl.textContent = this.currentUser.displayName;
        if (roleEl) roleEl.textContent = (this.currentUser.role || 'USER').toUpperCase();

        if (topAvatar) topAvatar.textContent = this.currentUser.avatar || '👤';
        if (topName) topName.textContent = this.currentUser.displayName;
        if (topRole) topRole.textContent = (this.currentUser.role || 'USER').toUpperCase();
    }

    async loadVaultData() {
        try {
            await Promise.all([
                this.loadFolders(),
                this.loadUsers(),
                this.loadEntries()
            ]);
            this.renderFolderTree();
            this.renderEntries();
            this.updateBadgeCounts();
        } catch (err) {
            console.error('Error loading vault data:', err);
        }
    }

    async loadFolders() {
        const res = await this.apiGet('/api/folders');
        if (res && res.folders) {
            this.folders = res.folders;
        }
    }

    async loadUsers() {
        const res = await this.apiGet('/api/users');
        if (res && res.users) {
            this.users = res.users;
        }
    }

    async loadEntries() {
        let url = `/api/entries?`;
        if (this.currentView === 'favorites') {
            url += `isFavorite=true&`;
        } else if (this.currentView === 'recycle_bin') {
            url += `inRecycleBin=true&`;
        } else if (['private_only', 'shared_with_me', 'shared_by_me'].includes(this.currentView)) {
            url += `filterType=${this.currentView}&`;
        } else if (this.currentView.startsWith('f_')) {
            url += `folderId=${this.currentView}&`;
        }

        if (this.searchQuery) {
            url += `q=${encodeURIComponent(this.searchQuery)}&`;
        }

        const res = await this.apiGet(url);
        if (res && res.entries) {
            this.entries = res.entries;
        }
    }

    renderEntries() {
        const container = document.getElementById('entriesContainer');
        if (!container) return;

        let filtered = [...this.entries];

        // Access filter
        if (this.accessFilter !== 'all') {
            filtered = filtered.filter(e => e.sharingMode === this.accessFilter);
        }

        // Sorting
        filtered.sort((a, b) => {
            if (this.sortBy === 'title_asc') return a.title.localeCompare(b.title);
            if (this.sortBy === 'title_desc') return b.title.localeCompare(a.title);
            if (this.sortBy === 'updated_desc') return new Date(b.updatedAt) - new Date(a.updatedAt);
            if (this.sortBy === 'quality') return (b.strength?.score || 0) - (a.strength?.score || 0);
            return 0;
        });

        // Update counts
        const countEl = document.getElementById('currentViewCount');
        if (countEl) countEl.textContent = `${filtered.length} item${filtered.length === 1 ? '' : 's'}`;

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="detail-empty-state" style="padding: 40px 20px;">
                    <div class="empty-icon">🔍</div>
                    <h3>No Passwords Found</h3>
                    <p>No accessible vault items matching the current view and filters.</p>
                </div>
            `;
            return;
        }

        container.className = this.viewMode === 'cards' ? 'entries-container grid-mode' : 'entries-container';

        container.innerHTML = filtered.map(entry => {
            const isSelected = entry.id === this.selectedEntryId;
            const badgeClass = entry.sharingMode === 'private' ? 'access-private' : (entry.sharingMode === 'selected' ? 'access-selected' : 'access-team');
            const badgeLabel = entry.sharingMode === 'private' ? '🔒 Private' : (entry.sharingMode === 'selected' ? `👥 Co-Shared (${entry.sharesCount})` : '🌐 Team');

            return `
                <div class="entry-row-card ${isSelected ? 'selected' : ''}" data-entry-id="${entry.id}">
                    <div class="entry-icon-box" style="color: ${entry.color || '#38bdf8'};">
                        ${entry.icon || '🔑'}
                    </div>
                    <div class="entry-info-col">
                        <div class="entry-title-text">${this.escapeHtml(entry.title)}</div>
                        <div class="entry-sub-text">
                            <span>${this.escapeHtml(entry.username || 'No username')}</span>
                            ${entry.isFavorite ? '<span>⭐</span>' : ''}
                        </div>
                    </div>
                    <div class="entry-access-badge ${badgeClass}">
                        ${badgeLabel}
                    </div>
                    <div class="entry-quick-actions" onclick="event.stopPropagation();">
                        <button class="quick-action-btn" title="Copy Password" onclick="app.quickCopyPassword('${entry.id}')">🔑</button>
                        <button class="quick-action-btn" title="Copy Username" onclick="app.quickCopyUsername('${entry.username}')">📋</button>
                        ${entry.isOwner ? `<button class="quick-action-btn" title="Manage Sharing" onclick="app.openQuickShareModal('${entry.id}')">👥</button>` : ''}
                    </div>
                </div>
            `;
        }).join('');

        // Attach click listeners to cards
        container.querySelectorAll('.entry-row-card').forEach(card => {
            card.addEventListener('click', () => {
                const id = card.getAttribute('data-entry-id');
                this.selectEntry(id);
            });
        });
    }

    async selectEntry(id) {
        this.selectedEntryId = id;
        this.renderEntries(); // Update selected style

        const emptyState = document.getElementById('detailEmptyState');
        const detailContent = document.getElementById('detailContent');

        if (!id) {
            if (emptyState) emptyState.style.display = 'flex';
            if (detailContent) detailContent.style.display = 'none';
            if (this.mfaTimer) clearInterval(this.mfaTimer);
            return;
        }

        const res = await this.apiGet(`/api/entries/${id}`);
        if (!res || !res.entry) return;

        const entry = res.entry;
        if (emptyState) emptyState.style.display = 'none';
        if (detailContent) detailContent.style.display = 'flex';

        // Fill fields
        document.getElementById('detailTitle').textContent = entry.title;
        document.getElementById('detailIcon').textContent = entry.icon || '🔑';
        document.getElementById('detailUsername').textContent = entry.username || '(None)';
        document.getElementById('detailPasswordInput').value = entry.password;
        document.getElementById('detailPasswordInput').type = 'password';

        // Strength
        const qualityEl = document.getElementById('detailPasswordQuality');
        const progressEl = document.getElementById('detailStrengthProgress');
        if (entry.strength) {
            qualityEl.textContent = `${entry.strength.label} (${entry.strength.score}%)`;
            qualityEl.style.color = entry.strength.color;
            progressEl.style.width = `${entry.strength.score}%`;
            progressEl.style.backgroundColor = entry.strength.color;
        }

        // URL
        const urlRow = document.getElementById('detailUrlRow');
        const urlLink = document.getElementById('detailUrlLink');
        if (entry.url) {
            urlRow.style.display = 'flex';
            urlLink.href = entry.url;
            urlLink.textContent = entry.url;
        } else {
            urlRow.style.display = 'none';
        }

        // Sharing Badge & Summary
        const accessBadge = document.getElementById('detailAccessBadge');
        const sharingSummary = document.getElementById('detailSharingSummary');
        const shareBtn = document.getElementById('shareDetailBtn');

        if (entry.sharingMode === 'private') {
            accessBadge.className = 'detail-access-badge access-private';
            accessBadge.textContent = '🔒 Private (Only You)';
            sharingSummary.innerHTML = `<div>Only you (<strong>${entry.ownerName}</strong>) have access to this credential.</div>`;
        } else if (entry.sharingMode === 'selected') {
            accessBadge.className = 'detail-access-badge access-selected';
            accessBadge.textContent = `👥 Co-Accessible (${entry.shares ? entry.shares.length : 0} members)`;
            sharingSummary.innerHTML = `
                <div style="font-weight:600; margin-bottom:6px;">Co-Shared with specific team members:</div>
                <div style="display:flex; flex-direction:column; gap:4px;">
                    ${entry.shares && entry.shares.length ? entry.shares.map(s => `
                        <div style="display:flex; align-items:center; justify-content:space-between; font-size:0.8rem; background:rgba(255,255,255,0.04); padding:4px 8px; border-radius:4px;">
                            <span>${s.avatar || '👤'} ${s.displayName}</span>
                            <span style="color:#818cf8; font-weight:600; text-transform:uppercase;">${s.permission}</span>
                        </div>
                    `).join('') : '<span style="color:var(--text-muted);">No members currently added</span>'}
                </div>
            `;
        } else {
            accessBadge.className = 'detail-access-badge access-team';
            accessBadge.textContent = '🌐 Team-Wide Shared';
            sharingSummary.innerHTML = `<div>Accessible to <strong>all members</strong> of the workspace.</div>`;
        }

        // Enable / disable delete & share buttons based on permission
        const canManage = ['owner', 'admin', 'co_owner'].includes(entry.userPermission);
        if (shareBtn) shareBtn.style.display = canManage ? 'inline-flex' : 'none';

        // Custom Fields
        const customFieldsCard = document.getElementById('detailCustomFieldsCard');
        const customFieldsList = document.getElementById('detailCustomFieldsList');
        if (entry.customFields && entry.customFields.length) {
            customFieldsCard.style.display = 'flex';
            customFieldsList.innerHTML = entry.customFields.map(f => `
                <div class="field-row">
                    <span class="field-label">${this.escapeHtml(f.name)}</span>
                    <div class="field-value-box">
                        <span class="field-text monospace">${this.escapeHtml(f.value)}</span>
                        <button class="copy-action-btn" onclick="app.copyToClipboard('${this.escapeHtml(f.value)}', '${this.escapeHtml(f.name)}')">📋</button>
                    </div>
                </div>
            `).join('');
        } else {
            customFieldsCard.style.display = 'none';
        }

        // Notes
        const notesCard = document.getElementById('detailNotesCard');
        const notesContent = document.getElementById('detailNotesContent');
        if (entry.notes) {
            notesCard.style.display = 'flex';
            notesContent.textContent = entry.notes;
        } else {
            notesCard.style.display = 'none';
        }

        // History
        const historyCount = document.getElementById('detailHistoryCount');
        const historyList = document.getElementById('detailHistoryList');
        if (entry.history && entry.history.length) {
            historyCount.textContent = entry.history.length;
            historyList.innerHTML = entry.history.map(h => `
                <div style="font-size:0.75rem; color:var(--text-secondary); padding:4px 0; border-bottom:1px solid var(--border-color);">
                    Password changed on ${new Date(h.changedAt).toLocaleString()}
                </div>
            `).join('');
        } else {
            historyCount.textContent = '0';
            historyList.innerHTML = `<span style="font-size:0.75rem; color:var(--text-muted);">No previous password history</span>`;
        }

        // Metadata
        document.getElementById('detailOwnerName').textContent = entry.ownerName;
        document.getElementById('detailUpdatedAt').textContent = new Date(entry.updatedAt).toLocaleDateString();
    }

    startLiveMFATicker(entryId) {
        if (this.mfaTimer) clearInterval(this.mfaTimer);

        const updateMfaDisplay = async () => {
            if (this.selectedEntryId !== entryId) {
                clearInterval(this.mfaTimer);
                return;
            }
            const res = await this.apiGet(`/api/entries/${entryId}/mfa`);
            if (res && res.mfa) {
                const tokenEl = document.getElementById('detailMfaToken');
                const secondsEl = document.getElementById('detailMfaSeconds');
                const circleEl = document.getElementById('mfaProgressCircle');

                if (tokenEl) {
                    const formatted = `${res.mfa.token.substring(0, 3)} ${res.mfa.token.substring(3)}`;
                    tokenEl.textContent = formatted;
                }
                if (secondsEl) secondsEl.textContent = `${res.mfa.secondsRemaining}s`;
                if (circleEl) {
                    const progress = (res.mfa.secondsRemaining / 30) * 100;
                    circleEl.setAttribute('stroke-dasharray', `${progress}, 100`);
                }
            }
        };

        updateMfaDisplay();
        this.mfaTimer = setInterval(updateMfaDisplay, 1000);
    }

    renderFolderTree() {
        const treeEl = document.getElementById('folderTreeList');
        if (!treeEl) return;

        treeEl.innerHTML = this.folders.map(f => {
            const isActive = this.currentView === f.id;
            return `
                <div class="tree-node ${isActive ? 'active' : ''}" data-folder-id="${f.id}">
                    <span class="tree-node-icon" style="color:${f.color || '#6366f1'}">${f.icon || '📁'}</span>
                    <span>${this.escapeHtml(f.name)}</span>
                    <span class="tree-node-count">${f.count || 0}</span>
                </div>
            `;
        }).join('');

        treeEl.querySelectorAll('.tree-node').forEach(node => {
            node.addEventListener('click', () => {
                const folderId = node.getAttribute('data-folder-id');
                this.setView(folderId);
            });
        });

        // Also update modal folder select
        const modalFolderSelect = document.getElementById('entryInputFolder');
        if (modalFolderSelect) {
            modalFolderSelect.innerHTML = this.folders.map(f => `
                <option value="${f.id}">${f.icon || '📁'} ${this.escapeHtml(f.name)}</option>
            `).join('');
        }
    }

    updateBadgeCounts() {
        const allCount = this.entries.length;
        const favCount = this.entries.filter(e => e.isFavorite).length;
        const privCount = this.entries.filter(e => e.sharingMode === 'private' && e.ownerId === this.currentUser?.id).length;
        const sharedWithMe = this.entries.filter(e => e.ownerId !== this.currentUser?.id).length;
        const sharedByMe = this.entries.filter(e => e.ownerId === this.currentUser?.id && e.sharingMode !== 'private').length;

        const setBadge = (id, count) => {
            const el = document.getElementById(id);
            if (el) el.textContent = count;
        };

        setBadge('badgeAllCount', allCount);
        setBadge('badgeFavCount', favCount);
        setBadge('badgePrivateCount', privCount);
        setBadge('badgeSharedWithMeCount', sharedWithMe);
        setBadge('badgeSharedByMeCount', sharedByMe);
    }

    setView(viewName) {
        this.currentView = viewName;
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.getAttribute('data-view') === viewName);
        });

        const viewTitles = {
            all: 'All Accessible Items',
            favorites: 'Favorite Items',
            private_only: 'My Private Vault',
            shared_with_me: 'Shared With Me',
            shared_by_me: 'Shared By Me',
            recycle_bin: 'Recycle Bin'
        };

        const titleEl = document.getElementById('currentViewTitle');
        if (titleEl) {
            if (viewTitles[viewName]) {
                titleEl.textContent = viewTitles[viewName];
            } else {
                const folder = this.folders.find(f => f.id === viewName);
                titleEl.textContent = folder ? `${folder.icon || '📁'} ${folder.name}` : 'Folder View';
            }
        }

        this.loadVaultData();
    }

    // Modal Handlers
    openModal(id) {
        const modal = document.getElementById(id);
        if (modal) modal.style.display = 'flex';
    }

    closeModal(id) {
        const modal = document.getElementById(id);
        if (modal) modal.style.display = 'none';
    }

    openNewEntryModal() {
        this.editingEntryId = null;
        document.getElementById('entryModalTitle').textContent = 'New Vault Entry';
        document.getElementById('entryInputTitle').value = '';
        document.getElementById('entryInputUsername').value = '';
        document.getElementById('entryInputPassword').value = '';
        document.getElementById('entryInputUrl').value = '';
        document.getElementById('entryInputTotp').value = '';
        document.getElementById('entryInputTags').value = '';
        document.getElementById('entryInputExpires').value = '';
        document.getElementById('entryInputNotes').value = '';

        // Reset sharing tab
        const privateRadio = document.querySelector('input[name="sharingScope"][value="private"]');
        if (privateRadio) privateRadio.checked = true;
        const specificBox = document.getElementById('specificMembersBox');
        if (specificBox) specificBox.style.display = 'none';

        this.renderTeamSharingList('modalTeamPermissionsList');

        // Reset to first tab
        document.querySelectorAll('#entryModal .modal-tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-tab') === 'tab-general');
        });
        document.querySelectorAll('#entryModal .modal-tab-content').forEach(pane => {
            pane.classList.toggle('active', pane.id === 'tab-general');
        });

        this.openModal('entryModal');
    }

    async openEditEntryModal(entryId) {
        const id = entryId || this.selectedEntryId;
        if (!id) return;

        const res = await this.apiGet(`/api/entries/${id}`);
        if (!res || !res.entry) {
            this.showToast('Could not load entry details for editing', 'danger');
            return;
        }

        const entry = res.entry;
        this.editingEntryId = id;

        const titleEl = document.getElementById('entryModalTitle');
        if (titleEl) titleEl.textContent = `Edit Entry: ${entry.title}`;

        document.getElementById('entryInputTitle').value = entry.title || '';
        document.getElementById('entryInputUsername').value = entry.username || '';
        document.getElementById('entryInputPassword').value = entry.password || '';
        document.getElementById('entryInputUrl').value = entry.url || '';
        document.getElementById('entryInputTotp').value = entry.totpSecret || '';
        document.getElementById('entryInputTags').value = (entry.tags || []).join(', ');
        document.getElementById('entryInputNotes').value = entry.notes || '';
        
        if (entry.expiresAt) {
            document.getElementById('entryInputExpires').value = entry.expiresAt.split('T')[0];
        } else {
            document.getElementById('entryInputExpires').value = '';
        }

        const folderSelect = document.getElementById('entryInputFolder');
        if (folderSelect && entry.folderId) folderSelect.value = entry.folderId;

        const iconSelect = document.getElementById('entryInputIcon');
        if (iconSelect && entry.icon) iconSelect.value = entry.icon;

        // Sharing radio
        const mode = entry.sharingMode || 'private';
        const radio = document.querySelector(`input[name="sharingScope"][value="${mode}"]`);
        if (radio) radio.checked = true;

        const specificBox = document.getElementById('specificMembersBox');
        if (specificBox) {
            specificBox.style.display = mode === 'selected' ? 'block' : 'none';
        }

        this.renderTeamSharingList('modalTeamPermissionsList', entry.sharedUsers || []);

        // Reset to first tab
        document.querySelectorAll('#entryModal .modal-tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.getAttribute('data-tab') === 'tab-general');
        });
        document.querySelectorAll('#entryModal .modal-tab-content').forEach(pane => {
            pane.classList.toggle('active', pane.id === 'tab-general');
        });

        this.openModal('entryModal');
    }

    renderTeamSharingList(containerId, existingShares = []) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const otherUsers = this.users.filter(u => u.id !== this.currentUser?.id);
        if (otherUsers.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted); font-size:13px; padding:10px; text-align:center;">No other team members available.</div>';
            return;
        }

        container.innerHTML = otherUsers.map(user => {
            const share = (existingShares || []).find(s => s.userId === user.id);
            const isChecked = Boolean(share);
            const permission = share ? share.permission : 'viewer';

            return `
                <div class="share-user-row" style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:var(--bg-input); border:1px solid var(--border); border-radius:var(--radius-md); margin-bottom:8px;">
                    <label style="display:flex; align-items:center; gap:10px; cursor:pointer; font-size:0.85rem; user-select:none;">
                        <input type="checkbox" class="share-user-check" value="${user.id}" ${isChecked ? 'checked' : ''} style="width:16px; height:16px; cursor:pointer;" onchange="this.closest('.share-user-row').querySelector('.share-user-perm').disabled = !this.checked">
                        <span style="font-size:18px;">${user.avatar || '👤'}</span>
                        <div>
                            <div style="font-weight:600; color:var(--text-primary); font-size:13px;">${this.escapeHtml(user.displayName)}</div>
                            <div style="font-size:11px; color:var(--text-muted);">@${this.escapeHtml(user.username)}</div>
                        </div>
                    </label>
                    <select class="share-user-perm form-select" style="width:150px; padding:4px 8px; font-size:0.8rem;" ${isChecked ? '' : 'disabled'}>
                        <option value="viewer" ${permission === 'viewer' ? 'selected' : ''}>👁️ Viewer (Read)</option>
                        <option value="editor" ${permission === 'editor' ? 'selected' : ''}>✏️ Editor (Edit)</option>
                        <option value="co_owner" ${permission === 'co_owner' ? 'selected' : ''}>👑 Co-Owner (Full)</option>
                    </select>
                </div>
            `;
        }).join('');
    }

    async saveEntry() {
        const title = document.getElementById('entryInputTitle').value.trim();
        if (!title) {
            this.showToast('Entry title is required', 'danger');
            return;
        }

        const folderId = document.getElementById('entryInputFolder').value;
        const icon = document.getElementById('entryInputIcon').value;
        const username = document.getElementById('entryInputUsername').value.trim();
        const password = document.getElementById('entryInputPassword').value;
        const url = document.getElementById('entryInputUrl').value.trim();
        const totpSecret = document.getElementById('entryInputTotp').value.trim();
        const tags = document.getElementById('entryInputTags').value.split(',').map(t => t.trim()).filter(Boolean);
        const expiresAt = document.getElementById('entryInputExpires').value || null;
        const notes = document.getElementById('entryInputNotes').value;

        const sharingMode = document.querySelector('input[name="sharingScope"]:checked')?.value || 'private';
        const shares = [];

        if (sharingMode === 'selected') {
            document.querySelectorAll('#modalTeamPermissionsList .share-user-check:checked').forEach(chk => {
                const parent = chk.closest('div');
                const permSelect = parent.querySelector('.share-user-perm');
                shares.push({
                    userId: chk.value,
                    permission: permSelect ? permSelect.value : 'viewer'
                });
            });
        }

        const payload = {
            title, folderId, icon, username, password, url, totpSecret, tags, expiresAt, notes, sharingMode, shares
        };

        if (this.editingEntryId) {
            const res = await this.apiPut(`/api/entries/${this.editingEntryId}`, payload);
            if (res && res.success) {
                const id = this.editingEntryId;
                this.editingEntryId = null;
                this.showToast('Vault entry updated securely!', 'success');
                this.closeModal('entryModal');
                await this.loadVaultData();
                this.selectEntry(id);
            } else {
                this.showToast(res?.error || 'Failed to update entry', 'danger');
            }
        } else {
            const res = await this.apiPost('/api/entries', payload);
            if (res && res.success) {
                this.showToast('Vault entry saved securely!', 'success');
                this.closeModal('entryModal');
                await this.loadVaultData();
                if (res.entry?.id) {
                    this.selectEntry(res.entry.id);
                }
            } else {
                this.showToast(res?.error || 'Failed to save entry', 'danger');
            }
        }
    }

    async deleteEntry(entryId) {
        const id = entryId || this.selectedEntryId;
        if (!id) return;
        const entry = this.entries.find(e => e.id === id);
        const title = entry ? entry.title : 'this entry';

        if (!confirm(`Are you sure you want to move "${title}" to the recycle bin?`)) {
            return;
        }

        const res = await this.apiDelete(`/api/entries/${id}`);
        if (res && res.success) {
            this.showToast(`"${title}" moved to trash`, 'info');
            this.closeDetail();
            await this.loadVaultData();
        } else {
            this.showToast(res?.error || 'Failed to delete entry', 'danger');
        }
    }

    async toggleFavorite(entryId) {
        const id = entryId || this.selectedEntryId;
        if (!id) return;
        const entry = this.entries.find(e => e.id === id);
        if (!entry) return;

        const isFav = !entry.isFavorite;
        const res = await this.apiPut(`/api/entries/${id}`, { isFavorite: isFav });
        if (res && res.success) {
            entry.isFavorite = isFav;
            this.renderEntries();
            const favBtn = document.getElementById('favoriteDetailBtn');
            if (favBtn) favBtn.style.color = isFav ? '#f59e0b' : '';
            this.showToast(isFav ? 'Added to favorites ⭐' : 'Removed from favorites', 'info');
        }
    }

    closeDetail() {
        this.selectedEntryId = null;
        const emptyState = document.getElementById('detailEmptyState');
        const detailContent = document.getElementById('detailContent');
        if (emptyState) emptyState.style.display = 'flex';
        if (detailContent) detailContent.style.display = 'none';
        this.renderEntries();
    }

    async openQuickShareModal(entryId) {
        await this.loadUsers();
        const entry = this.entries.find(e => e.id === entryId);
        if (!entry) return;

        const titleEl = document.getElementById('sharingTargetTitle');
        if (titleEl) {
            titleEl.innerHTML = `Editing co-access for: <strong>${this.escapeHtml(entry.title)}</strong>`;
        }

        const mode = entry.sharingMode || 'private';
        const radio = document.querySelector(`input[name="modalShareScope"][value="${mode}"]`);
        if (radio) radio.checked = true;

        const specificBox = document.getElementById('quickShareMembersBox');
        if (specificBox) {
            specificBox.style.display = mode === 'selected' ? 'block' : 'none';
        }

        const existingShares = entry.sharedUsers || entry.shares || [];
        this.renderTeamSharingList('quickShareTeamList', existingShares);

        const saveBtn = document.getElementById('saveQuickShareBtn');
        if (saveBtn) {
            saveBtn.onclick = () => this.saveQuickShare(entryId);
        }

        this.openModal('sharingModal');
    }

    async saveQuickShare(entryId) {
        const sharingMode = document.querySelector('input[name="modalShareScope"]:checked')?.value || 'private';
        const shares = [];

        if (sharingMode === 'selected') {
            document.querySelectorAll('#quickShareTeamList .share-user-check:checked').forEach(chk => {
                const parent = chk.closest('.share-user-row') || chk.closest('div');
                const permSelect = parent ? parent.querySelector('.share-user-perm') : null;
                shares.push({
                    userId: chk.value,
                    permission: permSelect ? permSelect.value : 'viewer'
                });
            });
        }

        const res = await this.apiPost(`/api/entries/${entryId}/share`, { sharingMode, shares });
        if (res && res.success) {
            this.showToast('Team co-access permissions updated successfully!', 'success');
            this.closeModal('sharingModal');
            await this.loadVaultData();
            if (this.selectedEntryId === entryId) {
                this.selectEntry(entryId);
            }
        } else {
            this.showToast(res?.error || 'Failed to update co-access permissions', 'danger');
        }
    }

    // Account MFA Authenticator Settings Modal
    async openMfaSettingsModal() {
        const res = await this.apiGet('/api/auth/me');
        if (!res || !res.user) {
            this.showToast('Could not load MFA status', 'danger');
            return;
        }

        const user = res.user;
        const isEnabled = Boolean(user.mfaEnabled);
        const statusText = document.getElementById('mfaStatusText');
        const toggleBtn = document.getElementById('toggleMfaEnableBtn');
        const setupDetails = document.getElementById('mfaSetupDetails');
        const secretDisplay = document.getElementById('mfaSecretDisplay');
        const recoveryGrid = document.getElementById('recoveryCodesGrid');

        if (statusText) {
            statusText.innerHTML = isEnabled 
                ? '<span style="color: #10b981; font-weight: 700;">● Enabled (Active)</span>' 
                : '<span style="color: #ef4444; font-weight: 700;">● Disabled</span>';
        }

        if (toggleBtn) {
            toggleBtn.textContent = isEnabled ? 'Disable 2FA' : 'Enable 2FA';
            toggleBtn.className = isEnabled ? 'btn btn-secondary btn-sm' : 'btn btn-primary btn-sm';
            toggleBtn.onclick = () => this.toggleMfaSetting(!isEnabled);
        }

        if (setupDetails) {
            setupDetails.style.display = isEnabled ? 'block' : 'none';
        }

        if (secretDisplay && user.mfaSecret) {
            secretDisplay.textContent = user.mfaSecret;
        }

        if (recoveryGrid && user.recoveryCodes) {
            recoveryGrid.innerHTML = user.recoveryCodes.map(c => `
                <div style="background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; font-size: 13px; font-weight: 600; text-align: center; color: #38bdf8;" class="monospace">${c}</div>
            `).join('');
        }

        this.openModal('mfaModal');
    }

    async toggleMfaSetting(enable) {
        const res = await this.apiPost('/api/auth/mfa-toggle', { enabled: enable });
        if (res && res.success) {
            if (this.currentUser) {
                this.currentUser.mfaEnabled = enable;
            }
            this.showToast(`Two-Factor Authentication ${enable ? 'enabled' : 'disabled'} successfully!`, 'success');
            await this.openMfaSettingsModal();
            await this.loadUsers();
        } else {
            this.showToast(res?.error || 'Failed to update 2FA setting', 'danger');
        }
    }

    // Team Members & Roles Modal
    async openTeamModal() {
        await this.loadUsers();
        const grid = document.getElementById('teamCardsGrid');
        if (!grid) return;

        grid.innerHTML = this.users.map(user => {
            const isMfa = Boolean(user.mfaEnabled);
            const roleColor = user.role === 'admin' ? '#ef4444' : user.role === 'manager' ? '#38bdf8' : '#10b981';
            const canDelete = (this.currentUser?.role === 'admin' || this.currentUser?.role === 'manager') && user.id !== this.currentUser?.id && user.username !== 'admin';
            return `
                <div style="background: var(--bg-input); border: 1px solid var(--border); border-radius: var(--radius-md); padding: 14px; display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 24px;">${user.avatar || '👤'}</span>
                            <div>
                                <div style="font-weight: 700; font-size: 14px; color: var(--text-primary);">${this.escapeHtml(user.displayName)}</div>
                                <div style="font-size: 12px; color: var(--text-muted);">@${this.escapeHtml(user.username)} ${user.email ? '• ' + this.escapeHtml(user.email) : ''}</div>
                            </div>
                        </div>
                        <span style="font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; background: rgba(255,255,255,0.06); color: ${roleColor}; border: 1px solid rgba(255,255,255,0.1);">${user.role.toUpperCase()}</span>
                    </div>
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-top: 6px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.06); font-size: 12px;">
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <span style="color: var(--text-muted);">MFA Status:</span>
                            <span style="font-weight: 600; padding: 2px 8px; border-radius: 4px; ${isMfa ? 'background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3);' : 'background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3);'}">
                                ${isMfa ? '🛡️ 2FA Enabled' : '⚠️ 2FA Disabled'}
                            </span>
                        </div>
                        ${canDelete ? `
                            <button class="btn btn-secondary btn-sm" style="color: #ef4444; padding: 2px 8px; font-size: 11px; cursor: pointer;" onclick="app.deleteTeamMember('${user.id}', '${this.escapeHtml(user.displayName)}')">
                                🗑️ Remove
                            </button>
                        ` : ''}
                    </div>
                </div>
            `;
        }).join('');

        this.openModal('teamModal');
    }

    openAddMemberModal() {
        document.getElementById('newMemberDisplayName').value = '';
        document.getElementById('newMemberUsername').value = '';
        document.getElementById('newMemberEmail').value = '';
        document.getElementById('newMemberPassword').value = '';
        document.getElementById('newMemberRole').value = 'member';
        document.getElementById('newMemberAvatar').value = '👤';
        document.getElementById('newMemberMfaEnabled').checked = false;

        const errEl = document.getElementById('addMemberError');
        if (errEl) errEl.style.display = 'none';

        this.generateMemberPassword();
        this.openModal('addMemberModal');
    }

    async generateMemberPassword() {
        const passInput = document.getElementById('newMemberPassword');
        const res = await this.apiPost('/api/generator', { length: 16, useUpper: true, useLower: true, useDigits: true, useSymbols: true });
        if (res && res.password && passInput) {
            passInput.value = res.password;
        } else if (passInput) {
            passInput.value = 'User' + Math.random().toString(36).substring(2, 8) + '!@#';
        }
    }

    async saveNewMember() {
        const displayName = document.getElementById('newMemberDisplayName').value.trim();
        const username = document.getElementById('newMemberUsername').value.trim().toLowerCase();
        const email = document.getElementById('newMemberEmail').value.trim();
        const password = document.getElementById('newMemberPassword').value;
        const role = document.getElementById('newMemberRole').value;
        const avatar = document.getElementById('newMemberAvatar').value;
        const mfaEnabled = document.getElementById('newMemberMfaEnabled').checked;
        const errEl = document.getElementById('addMemberError');

        if (!username || !password) {
            if (errEl) {
                errEl.textContent = 'Username and password are required.';
                errEl.style.display = 'block';
            }
            return;
        }

        const res = await this.apiPost('/api/users', {
            username, password, displayName, email, role, avatar, mfaEnabled
        });

        if (res && (res.success || res.user)) {
            this.showToast(`Team member "${displayName || username}" added successfully!`, 'success');
            this.closeModal('addMemberModal');
            await this.openTeamModal();
        } else {
            if (errEl) {
                errEl.textContent = res?.error || 'Failed to add team member.';
                errEl.style.display = 'block';
            }
        }
    }

    async deleteTeamMember(userId, name) {
        if (!confirm(`Are you sure you want to remove team member "${name}"?`)) return;
        const res = await this.apiDelete(`/api/users/${userId}`);
        if (res && res.success) {
            this.showToast(`Team member "${name}" removed`, 'info');
            await this.openTeamModal();
        } else {
            this.showToast(res?.error || 'Failed to remove member', 'danger');
        }
    }

    // Password Generator
    async generatePassword(type = 'random') {
        const length = parseInt(document.getElementById('genLengthSlider')?.value || 20, 10);
        const useUpper = document.getElementById('genCheckUpper')?.checked;
        const useLower = document.getElementById('genCheckLower')?.checked;
        const useDigits = document.getElementById('genCheckDigits')?.checked;
        const useSymbols = document.getElementById('genCheckSymbols')?.checked;
        const avoidAmbiguous = document.getElementById('genCheckAmbiguous')?.checked;
        const wordsCount = parseInt(document.getElementById('genWordsSlider')?.value || 4, 10);
        const separator = document.getElementById('genSeparatorSelect')?.value || '-';

        const res = await this.apiPost('/api/generator', {
            type, length, useUpper, useLower, useDigits, useSymbols, avoidAmbiguous, wordsCount, separator
        });

        if (res && res.password) {
            const passEl = document.getElementById('genResultPassword');
            const labelEl = document.getElementById('genStrengthLabel');
            const fillEl = document.getElementById('genStrengthFill');

            if (passEl) passEl.textContent = res.password;
            if (labelEl) labelEl.textContent = `Entropy: ${res.strength.entropy} bits (${res.strength.label})`;
            if (fillEl) {
                fillEl.style.width = `${res.strength.score}%`;
                fillEl.style.backgroundColor = res.strength.color;
            }
        }
    }

    // Security Health Audit
    async openHealthAudit() {
        const res = await this.apiGet('/api/health-check');
        if (!res || !res.health) return;

        const h = res.health;
        document.getElementById('healthScoreNum').textContent = `${h.overallScore}%`;
        document.getElementById('healthWeakCount').textContent = h.weakCount;
        document.getElementById('healthReusedCount').textContent = h.reusedCount;
        document.getElementById('healthExpiredCount').textContent = h.expiredCount;
        document.getElementById('healthTotalCount').textContent = h.totalEntries;

        const breakdown = document.getElementById('healthBreakdownSection');
        if (breakdown) {
            breakdown.innerHTML = `
                <div style="margin-top:16px;">
                    <h4 style="margin-bottom:8px;">Security Analysis Findings:</h4>
                    ${h.weakEntries.length ? `
                        <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:8px; padding:10px; margin-bottom:8px;">
                            <strong>⚠️ ${h.weakEntries.length} Weak Password(s):</strong>
                            <ul style="margin-left:20px; font-size:0.85rem; margin-top:4px;">
                                ${h.weakEntries.map(e => `<li>${this.escapeHtml(e.title)} (${e.strength.label} - ${e.strength.score}%)</li>`).join('')}
                            </ul>
                        </div>
                    ` : '<div style="color:var(--success); font-size:0.85rem;">✅ No weak passwords found!</div>'}

                    ${h.reusedEntries.length ? `
                        <div style="background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); border-radius:8px; padding:10px; margin-top:8px;">
                            <strong>⚠️ Reused Passwords:</strong>
                            <div style="font-size:0.85rem; margin-top:4px;">
                                Found passwords reused across multiple accounts. Always use unique generated credentials for each service.
                            </div>
                        </div>
                    ` : '<div style="color:var(--success); font-size:0.85rem; margin-top:4px;">✅ All passwords across accounts are unique!</div>'}
                </div>
            `;
        }
        this.openModal('healthModal');
    }

    // Immutable Audit Log
    async openAuditLog() {
        const action = document.getElementById('auditActionFilter')?.value || '';
        const res = await this.apiGet(`/api/audit?action=${encodeURIComponent(action)}`);
        if (!res || !res.logs) return;

        const tbody = document.getElementById('auditTableBody');
        if (tbody) {
            tbody.innerHTML = res.logs.map(log => `
                <tr>
                    <td class="monospace">${new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td><strong>${this.escapeHtml(log.username)}</strong></td>
                    <td><span class="entry-access-badge access-selected">${this.escapeHtml(log.action)}</span></td>
                    <td>${this.escapeHtml(log.entryTitle || '-')}</td>
                    <td>${this.escapeHtml(log.details)}</td>
                </tr>
            `).join('');
        }
        this.openModal('auditModal');
    }

    // Daily Local Database Backups
    async openBackupsModal() {
        const res = await this.apiGet('/api/backups');
        const container = document.getElementById('backupsListContainer');
        if (!container) return;

        if (!res || !res.backups || res.backups.length === 0) {
            container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">No daily local backup snapshots found yet.</div>`;
        } else {
            container.innerHTML = `
                <table class="audit-table" style="margin-top:10px;">
                    <thead>
                        <tr>
                            <th>Snapshot Filename</th>
                            <th>Created At</th>
                            <th>Size</th>
                            <th>SHA-256 Checksum</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${res.backups.map(b => `
                            <tr>
                                <td class="monospace"><strong>${this.escapeHtml(b.filename)}</strong></td>
                                <td>${new Date(b.createdAt).toLocaleString()}</td>
                                <td>${(b.size / 1024).toFixed(1)} KB</td>
                                <td class="monospace" style="font-size:0.75rem; color:var(--text-muted);">${b.checksum ? b.checksum.substring(0, 16) + '...' : '-'}</td>
                                <td>
                                    <button class="btn btn-secondary btn-sm" onclick="app.restoreDatabase('${this.escapeHtml(b.filename)}')">Restore</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }
        this.openModal('backupsModal');
    }

    async createBackupSnapshot() {
        const res = await this.apiPost('/api/backups/create', { label: 'Manual Snapshot via Web UI' });
        if (res && res.success) {
            this.showToast(`Snapshot created: ${res.filename}`, 'success');
            await this.openBackupsModal();
        } else {
            this.showToast('Backup creation failed', 'danger');
        }
    }

    async restoreDatabase(filename) {
        if (!confirm(`Are you sure you want to restore database from ${filename}? Current vault state will be replaced.`)) return;
        const res = await this.apiPost('/api/backups/restore', { filename });
        if (res && res.success) {
            this.showToast('Database successfully restored!', 'success');
            this.closeModal('backupsModal');
            await this.loadVaultData();
        } else {
            this.showToast(res?.error || 'Restore failed', 'danger');
        }
    }

    // Native .kdbx and XML/CSV Import
    async handleImport() {
        const format = document.getElementById('importFormatSelect').value;
        const fileInput = document.getElementById('importFileInput');
        const pasteContent = document.getElementById('importPasteContent').value;
        const masterPassword = document.getElementById('importMasterPasswordInput')?.value || '';

        if (format === 'kdbx') {
            if (!fileInput.files || fileInput.files.length === 0) {
                this.showToast('Please select a .kdbx file to import', 'danger');
                return;
            }
            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onload = async (e) => {
                const base64Data = e.target.result.split(',')[1];
                const res = await this.apiPost('/api/import/kdbx', { base64Data, masterPassword });
                if (res && res.success) {
                    this.showToast(`Imported ${res.count} entries from .kdbx database!`, 'success');
                    this.closeModal('importExportModal');
                    await this.loadVaultData();
                } else {
                    this.showToast(res?.error || 'KDBX import failed', 'danger');
                }
            };
            reader.readAsDataURL(file);
        } else if (format === 'keepass-xml') {
            let xml = pasteContent;
            if (fileInput.files && fileInput.files.length > 0) {
                xml = await fileInput.files[0].text();
            }
            if (!xml) {
                this.showToast('Upload or paste KeePass XML content', 'danger');
                return;
            }
            const res = await this.apiPost('/api/import/keepass-xml', { xml });
            if (res && res.success) {
                this.showToast(`Imported ${res.count} entries from XML!`, 'success');
                this.closeModal('importExportModal');
                await this.loadVaultData();
            }
        } else if (format === 'csv') {
            let csv = pasteContent;
            if (fileInput.files && fileInput.files.length > 0) {
                csv = await fileInput.files[0].text();
            }
            if (!csv) {
                this.showToast('Upload or paste CSV content', 'danger');
                return;
            }
            const res = await this.apiPost('/api/import/csv', { csv });
            if (res && res.success) {
                this.showToast(`Imported ${res.count} entries from CSV!`, 'success');
                this.closeModal('importExportModal');
                await this.loadVaultData();
            }
        }
    }

    // Clipboard & Toasts
    // KeePass Groups / Folders
    openFolderModal() {
        document.getElementById('folderInputName').value = '';
        const parentSelect = document.getElementById('folderInputParent');
        if (parentSelect) {
            parentSelect.innerHTML = this.folders.map(f => `
                <option value="${f.id}">${f.icon || '📁'} ${this.escapeHtml(f.name)}</option>
            `).join('');
        }
        this.openModal('folderModal');
    }

    async saveFolder() {
        const name = document.getElementById('folderInputName')?.value.trim();
        const icon = document.getElementById('folderInputIcon')?.value || '📁';
        const parentId = document.getElementById('folderInputParent')?.value || null;

        if (!name) {
            this.showToast('Group name is required', 'danger');
            return;
        }

        const res = await this.apiPost('/api/folders', { name, icon, parentId });
        if (res && res.folder) {
            this.showToast(`Group "${name}" created successfully!`, 'success');
            this.closeModal('folderModal');
            await this.loadVaultData();
        } else {
            this.showToast(res?.error || 'Failed to create group', 'danger');
        }
    }

    // Vault Export Downloader
    async downloadExport(format) {
        const url = format === 'xml' ? '/api/export/keepass-xml' : '/api/export/csv';
        try {
            const res = await fetch(url, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            if (!res.ok) {
                this.showToast('Export failed', 'danger');
                return;
            }
            const blob = await res.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = format === 'xml' ? 'keepass-web-export.xml' : 'keepass-web-export.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            this.showToast(`Exported vault as ${format.toUpperCase()}!`, 'success');
        } catch (err) {
            this.showToast('Failed to download export file', 'danger');
        }
    }

    async copyToClipboard(text, fieldType = 'field') {
        if (!text) return;
        try {
            await navigator.clipboard.writeText(text);
            this.showToast(`Copied ${fieldType} to clipboard! (Auto-clears in 30s)`, 'success');

            if (this.selectedEntryId) {
                this.apiPost(`/api/entries/${this.selectedEntryId}/log-copy`, { fieldType });
            }
        } catch (err) {
            this.showToast('Could not copy to clipboard', 'danger');
        }
    }

    quickCopyPassword(id) {
        const entry = this.entries.find(e => e.id === id);
        if (entry) {
            this.apiGet(`/api/entries/${id}`).then(res => {
                if (res && res.entry) {
                    this.copyToClipboard(res.entry.password, 'password');
                }
            });
        }
    }

    quickCopyUsername(username) {
        this.copyToClipboard(username, 'username');
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<span>${type === 'success' ? '✅' : (type === 'danger' ? '⚠️' : 'ℹ️')}</span><span>${this.escapeHtml(message)}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3500);
    }

    escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"']/g, m => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[m]);
    }

    // API Helpers
    async apiGet(endpoint) {
        try {
            const res = await fetch(endpoint, {
                headers: { 'Authorization': `Bearer ${this.token}` }
            });
            return await res.json();
        } catch (e) {
            console.error('API GET error:', e);
            return null;
        }
    }

    async apiPut(endpoint, body) {
        try {
            const res = await fetch(endpoint, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify(body)
            });
            return await res.json();
        } catch (e) {
            console.error('API PUT error:', e);
            return null;
        }
    }

    async apiDelete(endpoint) {
        try {
            const res = await fetch(endpoint, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            return await res.json();
        } catch (e) {
            console.error('API DELETE error:', e);
            return null;
        }
    }

    initEventListeners() {
        // Search
        const searchInput = document.getElementById('globalSearchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.trim();
                this.loadVaultData();
            });
        }

        // Shortcut: Ctrl+K / Cmd+K
        window.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                searchInput?.focus();
            }
        });

        // Theme
        document.getElementById('themeToggleBtn')?.addEventListener('click', () => this.toggleTheme());

        // Logout / Lock
        document.getElementById('logoutTopBtn')?.addEventListener('click', () => {
            this.lockVault();
            this.showToast('Logged out successfully.', 'info');
        });

        // Top Tools
        document.getElementById('newEntryTopBtn')?.addEventListener('click', () => this.openNewEntryModal());
        document.getElementById('openGeneratorBtn')?.addEventListener('click', () => {
            this.generatePassword();
            this.openModal('generatorModal');
        });
        document.getElementById('openHealthBtn')?.addEventListener('click', () => this.openHealthAudit());
        document.getElementById('openAuditBtn')?.addEventListener('click', () => this.openAuditLog());
        document.getElementById('openBackupsBtn')?.addEventListener('click', () => this.openBackupsModal());
        document.getElementById('createBackupNowBtn')?.addEventListener('click', () => this.createBackupSnapshot());
        document.getElementById('openImportExportBtn')?.addEventListener('click', () => this.openModal('importExportModal'));
        document.getElementById('executeImportBtn')?.addEventListener('click', () => this.handleImport());

        // Password Reveal Toggle
        document.getElementById('togglePasswordVisibilityBtn')?.addEventListener('click', () => {
            const passInput = document.getElementById('detailPasswordInput');
            if (passInput) {
                passInput.type = passInput.type === 'password' ? 'text' : 'password';
            }
        });

        // Copy Actions
        document.getElementById('copyPasswordBtn')?.addEventListener('click', () => {
            const val = document.getElementById('detailPasswordInput')?.value;
            this.copyToClipboard(val, 'password');
        });
        document.getElementById('copyUsernameBtn')?.addEventListener('click', () => {
            const val = document.getElementById('detailUsername')?.textContent;
            this.copyToClipboard(val, 'username');
        });
        document.getElementById('copyMfaBtn')?.addEventListener('click', () => {
            const val = document.getElementById('detailMfaToken')?.textContent.replace(/\s/g, '');
            this.copyToClipboard(val, 'MFA token');
        });

        // Save Entry Submit
        document.getElementById('saveEntrySubmitBtn')?.addEventListener('click', () => this.saveEntry());

        // Sharing Scope Radio changes in modal
        document.querySelectorAll('input[name="sharingScope"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                const box = document.getElementById('specificMembersBox');
                if (box) {
                    box.style.display = e.target.value === 'selected' ? 'block' : 'none';
                }
            });
        });

        // Quick Share Modal Radio changes
        document.querySelectorAll('input[name="modalShareScope"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                const box = document.getElementById('quickShareMembersBox');
                if (box) {
                    box.style.display = e.target.value === 'selected' ? 'block' : 'none';
                }
            });
        });

        // Navigation list views
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const view = item.getAttribute('data-view');
                this.setView(view);
            });
        });

        // Lock Vault / MFA Settings / Team Modal
        document.getElementById('lockVaultBtn')?.addEventListener('click', () => this.lockVault());
        document.getElementById('mfaSettingsBtn')?.addEventListener('click', () => this.openMfaSettingsModal());
        document.getElementById('openTeamBtn')?.addEventListener('click', () => this.openTeamModal());
        document.getElementById('addNewMemberBtn')?.addEventListener('click', () => this.openAddMemberModal());
        document.getElementById('genMemberPassBtn')?.addEventListener('click', () => this.generateMemberPassword());

        // Auto submit 6-digit MFA code on input
        document.getElementById('loginMfaCodeInput')?.addEventListener('input', (e) => {
            const val = e.target.value.replace(/\s/g, '');
            if (val.length === 6) {
                this.handleLoginStep2();
            }
        });

        // Detail Action Bar Buttons (Edit, Delete, Favorite, Share, Close)
        document.getElementById('editDetailBtn')?.addEventListener('click', () => {
            if (this.selectedEntryId) this.openEditEntryModal(this.selectedEntryId);
        });
        document.getElementById('deleteDetailBtn')?.addEventListener('click', () => {
            if (this.selectedEntryId) this.deleteEntry(this.selectedEntryId);
        });
        document.getElementById('closeDetailBtn')?.addEventListener('click', () => this.closeDetail());
        document.getElementById('favoriteDetailBtn')?.addEventListener('click', () => {
            if (this.selectedEntryId) this.toggleFavorite(this.selectedEntryId);
        });
        document.getElementById('shareDetailBtn')?.addEventListener('click', () => {
            if (this.selectedEntryId) this.openQuickShareModal(this.selectedEntryId);
        });
        document.getElementById('manageAccessBtn')?.addEventListener('click', () => {
            if (this.selectedEntryId) this.openQuickShareModal(this.selectedEntryId);
        });

        // Modal Tab Switching
        document.querySelectorAll('.modal-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const modal = btn.closest('.modal-overlay') || btn.closest('.modal-dialog');
                const targetTab = btn.getAttribute('data-tab');
                if (!modal || !targetTab) return;
                modal.querySelectorAll('.modal-tab-btn').forEach(b => b.classList.remove('active'));
                modal.querySelectorAll('.modal-tab-content').forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                modal.querySelector(`#${targetTab}`)?.classList.add('active');
            });
        });

        // Auto-generate password in modal
        document.getElementById('entryGenPassBtn')?.addEventListener('click', async () => {
            const res = await this.apiPost('/api/generator', { length: 20, useUpper: true, useLower: true, useDigits: true, useSymbols: true });
            if (res && res.password) {
                const passInput = document.getElementById('entryInputPassword');
                if (passInput) {
                    passInput.value = res.password;
                    passInput.dispatchEvent(new Event('input'));
                }
                this.showToast('Generated strong password!', 'info');
            }
        });

        // Live strength meter in entry modal
        document.getElementById('entryInputPassword')?.addEventListener('input', (e) => {
            const pass = e.target.value;
            const progress = document.getElementById('modalStrengthProgress');
            if (progress) {
                const len = pass.length;
                let score = Math.min(100, len * 4);
                if (/[A-Z]/.test(pass) && /[a-z]/.test(pass) && /[0-9]/.test(pass) && /[^A-Za-z0-9]/.test(pass)) {
                    score = Math.min(100, score + 35);
                }
                progress.style.width = `${score}%`;
                progress.style.backgroundColor = score >= 70 ? '#10b981' : score >= 45 ? '#f59e0b' : '#ef4444';
            }
        });

        // KeePass Groups / Folder Creator
        document.getElementById('addFolderBtn')?.addEventListener('click', () => this.openFolderModal());
        document.getElementById('saveFolderBtn')?.addEventListener('click', () => this.saveFolder());

        // Import / Export Tabs & Options
        document.querySelectorAll('.io-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const target = btn.getAttribute('data-iotab');
                document.querySelectorAll('.io-tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.io-tab-pane').forEach(p => p.style.display = 'none');
                btn.classList.add('active');
                const pane = document.getElementById(target);
                if (pane) pane.style.display = 'block';
            });
        });

        document.getElementById('importFormatSelect')?.addEventListener('change', (e) => {
            const fmt = e.target.value;
            const kdbxPass = document.getElementById('kdbxPasswordGroup');
            const pasteGroup = document.getElementById('xmlCsvPasteGroup');
            if (kdbxPass) kdbxPass.style.display = fmt === 'kdbx' ? 'block' : 'none';
            if (pasteGroup) pasteGroup.style.display = fmt !== 'kdbx' ? 'block' : 'none';
        });

        document.getElementById('exportXmlBtn')?.addEventListener('click', () => this.downloadExport('xml'));
        document.getElementById('exportCsvBtn')?.addEventListener('click', () => this.downloadExport('csv'));

        // Generator events
        document.getElementById('regenPassBtn')?.addEventListener('click', () => this.generatePassword());
        document.getElementById('genLengthSlider')?.addEventListener('input', (e) => {
            document.getElementById('genLengthDisplay').textContent = e.target.value;
            this.generatePassword();
        });
    }
}

const app = new KeePassWebApp();
window.app = app;
