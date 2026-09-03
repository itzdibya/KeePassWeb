/**
 * KeePass Web Team Edition - Cryptographic, Salt Hashing & MFA Utilities
 * - AES-256-GCM authenticated vault encryption
 * - Per-user 32-byte salt hashing with PBKDF2-HMAC-SHA512
 * - RFC 6238 / RFC 4226 MFA Authenticator Engine
 * - Password generator & entropy evaluator
 */

const crypto = require('crypto');

const APP_SECRET_SALT = 'keepass-web-team-vault-v2-secure-salt-2026';
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV
const KEY_LENGTH = 32; // 256 bits
const PBKDF2_VAULT_ITERATIONS = 100000;
const PBKDF2_AUTH_ITERATIONS = 100000;

/**
 * Derive vault master encryption key
 */
function getMasterKey(customSalt = APP_SECRET_SALT) {
    return crypto.pbkdf2Sync(
        process.env.VAULT_MASTER_SECRET || 'keepass-web-team-default-vault-master-key-change-in-prod',
        customSalt,
        PBKDF2_VAULT_ITERATIONS,
        KEY_LENGTH,
        'sha512'
    );
}

/**
 * Encrypt plaintext string using AES-256-GCM
 * Format: iv_hex:authTag_hex:ciphertext_hex
 */
function encrypt(text, key = getMasterKey()) {
    if (text === null || text === undefined || text === '') return '';
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        let encrypted = cipher.update(String(text), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();
        return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (err) {
        console.error('Encryption error:', err);
        throw new Error('Encryption failed');
    }
}

/**
 * Decrypt ciphertext string using AES-256-GCM
 */
function decrypt(encryptedText, key = getMasterKey()) {
    if (!encryptedText || typeof encryptedText !== 'string' || !encryptedText.includes(':')) {
        return encryptedText || '';
    }
    try {
        const parts = encryptedText.split(':');
        if (parts.length !== 3) return encryptedText;

        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const ciphertext = parts[2];

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error('Decryption error:', err.message);
        return '[Encrypted Secret]';
    }
}

/**
 * Salted Password Hashing using unique 32-byte cryptographically random salt and PBKDF2-HMAC-SHA512
 */
function hashPassword(password, salt = crypto.randomBytes(32).toString('hex')) {
    const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_AUTH_ITERATIONS, 64, 'sha512').toString('hex');
    return { hash, salt };
}

/**
 * Verify password against stored hash and unique salt with constant-time comparison
 */
function verifyPassword(password, storedHash, salt) {
    if (!password || !storedHash || !salt) return false;
    const computedHash = crypto.pbkdf2Sync(password, salt, PBKDF2_AUTH_ITERATIONS, 64, 'sha512').toString('hex');
    try {
        return crypto.timingSafeEqual(Buffer.from(computedHash, 'utf8'), Buffer.from(storedHash, 'utf8'));
    } catch (e) {
        return false;
    }
}

/**
 * Generate Base32 Secret for MFA Authenticator
 */
function generateMFASecret(length = 20) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bytes = crypto.randomBytes(length);
    let secret = '';
    for (let i = 0; i < length; i++) {
        secret += alphabet[bytes[i] % alphabet.length];
    }
    return secret;
}

/**
 * Generate 8 single-use emergency backup recovery codes
 */
function generateRecoveryCodes(count = 8) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const hex = crypto.randomBytes(4).toString('hex').toUpperCase();
        codes.push(`${hex.substring(0, 4)}-${hex.substring(4, 8)}`);
    }
    return codes;
}

/**
 * Base32 Decode (RFC 4648)
 */
function base32Decode(base32Str) {
    if (!base32Str) return Buffer.alloc(0);
    const cleaned = base32Str.toUpperCase().replace(/[\s=-]/g, '');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (let i = 0; i < cleaned.length; i++) {
        const val = alphabet.indexOf(cleaned[i]);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

/**
 * Generate Live 6-digit MFA Code (RFC 6238)
 */
function generateMFA(secret, timeStep = 30, digits = 6) {
    try {
        if (!secret) return null;
        const key = base32Decode(secret);
        if (key.length === 0) return null;

        const epoch = Math.floor(Date.now() / 1000);
        const counter = Math.floor(epoch / timeStep);
        const secondsRemaining = timeStep - (epoch % timeStep);

        const counterBuffer = Buffer.alloc(8);
        counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

        const hmac = crypto.createHmac('sha1', key);
        hmac.update(counterBuffer);
        const digest = hmac.digest();

        const offset = digest[digest.length - 1] & 0xf;
        const codeInt = (
            ((digest[offset] & 0x7f) << 24) |
            ((digest[offset + 1] & 0xff) << 16) |
            ((digest[offset + 2] & 0xff) << 8) |
            (digest[offset + 3] & 0xff)
        ) % Math.pow(10, digits);

        const token = codeInt.toString().padStart(digits, '0');
        return {
            token,
            secondsRemaining,
            timeStep,
            progress: Math.round((secondsRemaining / timeStep) * 100)
        };
    } catch (err) {
        console.error('MFA calculation error:', err.message);
        return null;
    }
}

/**
 * Verify MFA Code with +/- 1 time step window for clock skew tolerance
 */
function verifyMFACode(token, secret, timeStep = 30) {
    if (!token || !secret) return false;
    const cleanToken = token.trim().replace(/\s/g, '');
    const key = base32Decode(secret);
    if (key.length === 0) return false;

    const epoch = Math.floor(Date.now() / 1000);
    const currentCounter = Math.floor(epoch / timeStep);

    // Check windows: current, -2, -1, +1, +2 steps (absorbs clock drift between mobile devices and server)
    for (let window = -2; window <= 2; window++) {
        const counter = currentCounter + window;
        const counterBuffer = Buffer.alloc(8);
        counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

        const hmac = crypto.createHmac('sha1', key);
        hmac.update(counterBuffer);
        const digest = hmac.digest();

        const offset = digest[digest.length - 1] & 0xf;
        const codeInt = (
            ((digest[offset] & 0x7f) << 24) |
            ((digest[offset + 1] & 0xff) << 16) |
            ((digest[offset + 2] & 0xff) << 8) |
            (digest[offset + 3] & 0xff)
        ) % 1000000;

        const expectedToken = codeInt.toString().padStart(6, '0');
        if (expectedToken === cleanToken) {
            return true;
        }
    }
    return false;
}

/**
 * Generate secure random password or memorable passphrase
 */
function generatePassword(options = {}) {
    const {
        length = 16,
        useUpper = true,
        useLower = true,
        useDigits = true,
        useSymbols = true,
        avoidAmbiguous = true,
        type = 'random', // 'random' | 'passphrase' | 'pin'
        wordsCount = 4,
        separator = '-'
    } = options;

    if (type === 'pin') {
        const digits = '0123456789';
        let pin = '';
        const bytes = crypto.randomBytes(length);
        for (let i = 0; i < length; i++) {
            pin += digits[bytes[i] % digits.length];
        }
        return pin;
    }

    if (type === 'passphrase') {
        const wordlist = [
            'albatross', 'avocado', 'beacon', 'breeze', 'cascade', 'canyon', 'crimson',
            'crystal', 'dolphin', 'dragon', 'eclipse', 'emerald', 'falcon', 'galaxy',
            'glacier', 'horizon', 'island', 'jupiter', 'lagoon', 'lantern', 'meteor',
            'monarch', 'nebula', 'oasis', 'orchid', 'phoenix', 'pioneer', 'prism',
            'quantum', 'radiant', 'safari', 'shadow', 'solstice', 'summit', 'thunder',
            'titan', 'tundra', 'universe', 'valiant', 'vortex', 'whisper', 'zenith',
            'anchor', 'blizzard', 'celestial', 'dynamo', 'enigma', 'frontier', 'haven'
        ];
        const selectedWords = [];
        const randomBytes = crypto.randomBytes(wordsCount * 2);
        for (let i = 0; i < wordsCount; i++) {
            const index = randomBytes.readUInt16BE(i * 2) % wordlist.length;
            let word = wordlist[index];
            if (useUpper && i === 0) {
                word = word.charAt(0).toUpperCase() + word.slice(1);
            }
            selectedWords.push(word);
        }
        if (useDigits) {
            const digit = crypto.randomBytes(1)[0] % 100;
            selectedWords.push(digit.toString());
        }
        return selectedWords.join(separator);
    }

    let upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let lower = 'abcdefghijklmnopqrstuvwxyz';
    let digits = '0123456789';
    let symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (avoidAmbiguous) {
        upper = upper.replace(/[IO]/g, '');
        lower = lower.replace(/[lo]/g, '');
        digits = digits.replace(/[01]/g, '');
        symbols = symbols.replace(/[|`'"]/g, '');
    }

    let charPool = '';
    const guaranteed = [];

    if (useUpper && upper.length) {
        charPool += upper;
        guaranteed.push(upper[crypto.randomBytes(1)[0] % upper.length]);
    }
    if (useLower && lower.length) {
        charPool += lower;
        guaranteed.push(lower[crypto.randomBytes(1)[0] % lower.length]);
    }
    if (useDigits && digits.length) {
        charPool += digits;
        guaranteed.push(digits[crypto.randomBytes(1)[0] % digits.length]);
    }
    if (useSymbols && symbols.length) {
        charPool += symbols;
        guaranteed.push(symbols[crypto.randomBytes(1)[0] % symbols.length]);
    }

    if (!charPool) charPool = lower + digits;

    const passChars = [...guaranteed];
    const remainingCount = Math.max(0, length - passChars.length);
    const randomBytes = crypto.randomBytes(remainingCount);

    for (let i = 0; i < remainingCount; i++) {
        passChars.push(charPool[randomBytes[i] % charPool.length]);
    }

    for (let i = passChars.length - 1; i > 0; i--) {
        const j = crypto.randomBytes(1)[0] % (i + 1);
        [passChars[i], passChars[j]] = [passChars[j], passChars[i]];
    }

    return passChars.join('');
}

/**
 * Calculate Password Entropy and Strength Score (0 to 100)
 */
function evaluatePasswordStrength(password) {
    if (!password) return { score: 0, label: 'Empty', entropy: 0, suggestions: ['Enter a password'] };

    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

    if (poolSize === 0) poolSize = 1;
    const entropy = Math.round(password.length * Math.log2(poolSize));

    let score = 0;
    const suggestions = [];

    if (password.length < 8) {
        suggestions.push('Make password at least 8 characters long (14+ recommended)');
    } else if (password.length >= 16) {
        score += 35;
    } else if (password.length >= 12) {
        score += 25;
    } else {
        score += 15;
    }

    let varietyCount = 0;
    if (/[a-z]/.test(password)) varietyCount++;
    if (/[A-Z]/.test(password)) varietyCount++;
    if (/[0-9]/.test(password)) varietyCount++;
    if (/[^a-zA-Z0-9]/.test(password)) varietyCount++;

    score += varietyCount * 15;

    if (/^[0-9]+$/.test(password) || /^[a-zA-Z]+$/.test(password)) {
        score -= 15;
        suggestions.push('Mix uppercase, lowercase, numbers, and symbols');
    }
    if (/(.)\1{2,}/.test(password)) {
        score -= 10;
        suggestions.push('Avoid repeated characters (e.g. "aaa")');
    }
    if (/12345|abcdef|qwerty|password|admin/i.test(password)) {
        score -= 25;
        suggestions.push('Avoid common words and keyboard sequences');
    }

    score = Math.max(5, Math.min(100, score));

    let label = 'Very Weak';
    let color = '#ef4444';
    if (score >= 80) {
        label = 'Very Strong';
        color = '#10b981';
    } else if (score >= 65) {
        label = 'Strong';
        color = '#22c55e';
    } else if (score >= 45) {
        label = 'Moderate';
        color = '#f59e0b';
    } else if (score >= 25) {
        label = 'Weak';
        color = '#f97316';
    }

    return { score, label, color, entropy, suggestions };
}

/**
 * Generate WebAuthn Challenge & Registration Options
 */
function generateWebAuthnChallenge(user) {
    const challenge = crypto.randomBytes(32).toString('base64url');
    const userIdBase64 = Buffer.from(user ? user.id : 'anonymous').toString('base64url');
    return {
        challenge,
        rp: {
            name: 'KeePass Web Team Edition',
            id: 'localhost'
        },
        user: {
            id: userIdBase64,
            name: user ? user.username : 'user',
            displayName: user ? user.displayName : 'Team Member'
        },
        pubKeyCredParams: [
            { alg: -7, type: 'public-key' },  // ES256
            { alg: -257, type: 'public-key' } // RS256
        ],
        authenticatorSelection: {
            authenticatorAttachment: 'cross-platform',
            userVerification: 'preferred',
            requireResidentKey: false
        },
        timeout: 60000,
        attestation: 'none'
    };
}

/**
 * Analyze overall Vault Security Health across accessible entries
 */
function analyzeVaultHealth(entries = []) {
    let strongCount = 0;
    let moderateCount = 0;
    let weakCount = 0;
    let missingMfaCount = 0;
    let withMfaCount = 0;

    const passwordMap = new Map(); // password -> [entrySummary]
    const itemReports = [];

    for (const entry of entries) {
        const password = entry.password || '';
        const strength = evaluatePasswordStrength(password);
        const hasMfa = !!(entry.totpSecret || entry.mfaSecret);

        if (hasMfa) withMfaCount++;
        else missingMfaCount++;

        if (strength.score >= 65) strongCount++;
        else if (strength.score >= 45) moderateCount++;
        else weakCount++;

        if (password) {
            const list = passwordMap.get(password) || [];
            list.push({ id: entry.id, title: entry.title, username: entry.username });
            passwordMap.set(password, list);
        }

        itemReports.push({
            id: entry.id,
            title: entry.title,
            username: entry.username,
            score: strength.score,
            label: strength.label,
            entropy: strength.entropy,
            hasMfa,
            isWeak: strength.score < 50,
            isShort: password.length < 10,
            suggestions: strength.suggestions
        });
    }

    // Find reused passwords
    const reusedGroups = [];
    let reusedCount = 0;
    for (const [pass, items] of passwordMap.entries()) {
        if (items.length > 1) {
            reusedCount += items.length;
            reusedGroups.push({
                count: items.length,
                entries: items
            });
        }
    }

    const total = entries.length;
    let overallScore = 100;
    if (total > 0) {
        const avgStrength = itemReports.reduce((acc, i) => acc + i.score, 0) / total;
        const reusedPenalty = Math.min(30, (reusedCount / total) * 35);
        const weakPenalty = Math.min(25, (weakCount / total) * 30);
        overallScore = Math.max(0, Math.min(100, Math.round(avgStrength * 0.7 - reusedPenalty - weakPenalty + (withMfaCount / total) * 30)));
    }

    let grade = 'A+';
    if (overallScore < 50) grade = 'F';
    else if (overallScore < 65) grade = 'C';
    else if (overallScore < 80) grade = 'B';
    else if (overallScore < 95) grade = 'A';

    return {
        totalEntries: total,
        overallScore,
        grade,
        strongCount,
        moderateCount,
        weakCount,
        reusedCount,
        missingMfaCount,
        withMfaCount,
        reusedGroups,
        itemReports
    };
}

module.exports = {
    encrypt,
    decrypt,
    hashPassword,
    verifyPassword,
    generatePassword,
    evaluatePasswordStrength,
    generateMFASecret,
    generateRecoveryCodes,
    generateMFA,
    verifyMFACode,
    base32Decode,
    generateWebAuthnChallenge,
    analyzeVaultHealth
};

