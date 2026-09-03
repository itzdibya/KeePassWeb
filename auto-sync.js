#!/usr/bin/env node

/**
 * KeePass Web Team Edition - Automated Git Sync & CI Deployment Daemon
 * 
 * Continuously watches the workspace for file modifications.
 * Debounces rapid edits, validates tests, commits changes, and automatically pushes to GitHub.
 * 
 * Usage:
 *   node auto-sync.js --watch       (Daemon mode: watches for changes and pushes automatically)
 *   node auto-sync.js --once        (One-time sync: commits and pushes any pending changes immediately)
 *   node auto-sync.js --no-test     (Skip pre-push automated tests)
 *   node auto-sync.js --debounce=5000 (Set debounce window in milliseconds, default 5000ms)
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');

const WORKSPACE_DIR = __dirname;
const ARGS = process.argv.slice(2);

const IS_WATCH_MODE = ARGS.includes('--watch');
const IS_ONCE_MODE = ARGS.includes('--once') || (!IS_WATCH_MODE && ARGS.length === 0);
const SKIP_TEST = ARGS.includes('--no-test') || process.env.SKIP_TEST === '1';

const debounceArg = ARGS.find(a => a.startsWith('--debounce='));
const DEBOUNCE_MS = debounceArg ? parseInt(debounceArg.split('=')[1], 10) : 5000;

// Directories and file patterns to ignore during watch & sync
const IGNORED_PATHS = [
    '.git',
    'node_modules',
    'backups',
    '.DS_Store',
    'npm-debug.log',
    'auto-sync.log'
];

let syncTimer = null;
let isSyncing = false;
let pendingChangedFiles = new Set();

function log(msg, level = 'INFO') {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const prefix = level === 'ERROR' ? '❌ [ERROR]' : level === 'WARN' ? '⚠️ [WARN]' : level === 'SUCCESS' ? '✅ [SUCCESS]' : 'ℹ️ [SYNC]';
    console.log(`[${timestamp}] ${prefix} ${msg}`);
}

function runCommand(cmd, options = {}) {
    try {
        const result = execSync(cmd, {
            cwd: WORKSPACE_DIR,
            encoding: 'utf8',
            stdio: options.silent ? 'pipe' : 'inherit',
            ...options
        });
        return { success: true, stdout: result ? result.trim() : '' };
    } catch (err) {
        return {
            success: false,
            error: err.message,
            stdout: err.stdout ? err.stdout.toString() : '',
            stderr: err.stderr ? err.stderr.toString() : ''
        };
    }
}

function ensureGitIdentity() {
    const nameCheck = runCommand('git config user.name', { silent: true });
    if (!nameCheck.success || !nameCheck.stdout) {
        runCommand('git config user.name "KeePass Web AutoSync"');
    }
    const emailCheck = runCommand('git config user.email', { silent: true });
    if (!emailCheck.success || !emailCheck.stdout) {
        runCommand('git config user.email "autosync@keepassweb.local"');
    }
}

function getCurrentBranch() {
    const res = runCommand('git rev-parse --abbrev-ref HEAD', { silent: true });
    if (res.success && res.stdout) {
        return res.stdout;
    }
    return 'master';
}

function getRemoteName() {
    const res = runCommand('git remote', { silent: true });
    if (res.success && res.stdout) {
        const remotes = res.stdout.split('\n').filter(Boolean);
        if (remotes.includes('origin')) return 'origin';
        if (remotes.length > 0) return remotes[0];
    }
    return 'origin';
}

function hasUncommittedChanges() {
    const status = runCommand('git status --porcelain', { silent: true });
    if (!status.success) return false;
    const lines = status.stdout.split('\n').filter(l => l.trim().length > 0);
    return lines.length > 0;
}

function getChangedFilesList() {
    const status = runCommand('git status --porcelain', { silent: true });
    if (!status.success || !status.stdout) return [];
    return status.stdout.split('\n')
        .filter(l => l.trim().length > 0)
        .map(l => l.substring(3).trim());
}

async function performSync() {
    if (isSyncing) {
        log('Sync already in progress, queuing next check...', 'WARN');
        return;
    }

    isSyncing = true;
    try {
        ensureGitIdentity();

        if (!hasUncommittedChanges()) {
            if (IS_ONCE_MODE) {
                log('No uncommitted changes found. Workspace is up-to-date with Git.');
            }
            return;
        }

        const changedFiles = getChangedFilesList();
        log(`Detected ${changedFiles.length} modified file(s):\n   - ${changedFiles.slice(0, 5).join('\n   - ')}${changedFiles.length > 5 ? `\n   - ... and ${changedFiles.length - 5} more` : ''}`);

        // Run Verification Tests before committing/pushing
        if (!SKIP_TEST) {
            log('Running verification test suite before deployment...');
            const testResult = runCommand('npm test', { silent: false });
            if (!testResult.success) {
                log('Tests failed! Aborting auto-sync to protect GitHub repository integrity.', 'ERROR');
                log('Please fix the failing tests before syncing.', 'ERROR');
                return;
            }
            log('All verification tests passed!', 'SUCCESS');
        } else {
            log('Skipping tests (--no-test active).', 'WARN');
        }

        // Stage all modifications
        log('Staging changes (git add -A)...');
        const addRes = runCommand('git add -A', { silent: true });
        if (!addRes.success) {
            log(`git add failed: ${addRes.stderr || addRes.error}`, 'ERROR');
            return;
        }

        // Commit changes
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const summary = changedFiles.length <= 3 
            ? changedFiles.join(', ') 
            : `${changedFiles.length} files (${changedFiles.slice(0, 2).join(', ')}...)`;
        const commitMsg = `Auto-deploy: update ${summary} [${timestamp}]`;

        log(`Committing: "${commitMsg}"...`);
        const commitRes = runCommand(`git commit -m "${commitMsg.replace(/"/g, '\\"')}"`, { silent: false });
        if (!commitRes.success) {
            log(`git commit failed: ${commitRes.stderr || commitRes.error}`, 'ERROR');
            return;
        }

        // Push to GitHub
        const branch = getCurrentBranch();
        const remote = getRemoteName();
        log(`Pushing commit to GitHub remote (${remote}/${branch})...`);

        const pushRes = runCommand(`git push ${remote} ${branch}`, { silent: false });
        if (!pushRes.success) {
            log(`git push failed: ${pushRes.stderr || pushRes.error}`, 'ERROR');
            log('Tip: Check network connectivity or ensure Git credentials/SSH keys are configured for GitHub.', 'WARN');
            return;
        }

        const latestCommit = runCommand('git rev-parse --short HEAD', { silent: true });
        const hash = latestCommit.success ? latestCommit.stdout : 'latest';
        log(`Successfully deployed ${hash} to GitHub (${remote}/${branch})!`, 'SUCCESS');

        pendingChangedFiles.clear();
    } catch (err) {
        log(`Unexpected auto-sync failure: ${err.message}`, 'ERROR');
    } finally {
        isSyncing = false;
    }
}

function shouldIgnore(filePath) {
    if (!filePath) return true;
    const normalized = filePath.replace(/\\/g, '/');
    return IGNORED_PATHS.some(ignored => {
        return normalized === ignored || normalized.startsWith(ignored + '/') || normalized.includes('/' + ignored + '/');
    }) || normalized.endsWith('.tmp') || normalized.endsWith('.log');
}

function scheduleSync(filePath) {
    if (shouldIgnore(filePath)) return;

    pendingChangedFiles.add(filePath);
    log(`File changed: ${filePath}. Syncing in ${DEBOUNCE_MS / 1000}s...`);

    if (syncTimer) {
        clearTimeout(syncTimer);
    }

    syncTimer = setTimeout(async () => {
        syncTimer = null;
        await performSync();
    }, DEBOUNCE_MS);
}

function startWatcher() {
    log(`=======================================================`);
    log(`  🚀 KeePass Web Auto-Sync CI/CD Daemon Active`);
    log(`  📁 Watching workspace: ${WORKSPACE_DIR}`);
    log(`  ⏱️  Debounce window:    ${DEBOUNCE_MS}ms`);
    log(`  🌿 Target branch:      ${getCurrentBranch()} -> ${getRemoteName()}`);
    log(`  🧪 Test verification:  ${SKIP_TEST ? 'Disabled' : 'Enabled (npm test)'}`);
    log(`=======================================================`);

    // Perform initial check on startup
    performSync();

    // Watch files recursively
    try {
        fs.watch(WORKSPACE_DIR, { recursive: true }, (eventType, filename) => {
            if (filename) {
                scheduleSync(filename);
            }
        });
    } catch (err) {
        log(`Recursive fs.watch error: ${err.message}. Falling back to polling watcher.`, 'WARN');
        // Fallback: Check every 10 seconds
        setInterval(() => {
            if (hasUncommittedChanges()) {
                performSync();
            }
        }, 10000);
    }
}

module.exports = {
    startWatcher,
    performSync
};

if (require.main === module) {
    if (IS_WATCH_MODE) {
        startWatcher();
    } else {
        performSync().then(() => {
            process.exit(0);
        });
    }
}

