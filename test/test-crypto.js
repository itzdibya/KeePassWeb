/**
 * KeePass Web Team Edition - Automated Cryptography, Salt Hashing, MFA & Permission Test Suite
 */

const assert = require('assert');
const {
    encrypt,
    decrypt,
    hashPassword,
    verifyPassword,
    generatePassword,
    evaluatePasswordStrength,
    generateMFA,
    verifyMFACode,
    generateMFASecret,
    generateWebAuthnChallenge,
    analyzeVaultHealth
} = require('../crypto-utils');
const db = require('../database');
const backupService = require('../backup-service');
const {
    parseKdbxDatabase,
    isKdbxFile
} = require('../kdbx-parser');
const {
    parseKeePassXML,
    generateKeePassXML,
    parseCSV,
    generateCSV
} = require('../import-export');

console.log('================================================================');
console.log('  🧪 Running KeePass Web Team Edition Verification Tests');
console.log('================================================================\n');

// 1. Test Salt Hashing (32-byte Cryptographically Random Salt + PBKDF2-HMAC-SHA512)
{
    const password = 'SuperSecretVaultMasterPass#2026!';
    const { hash, salt } = hashPassword(password);

    assert(salt && salt.length >= 64, 'Salt must be at least 32 bytes (64 hex characters)');
    assert(hash && hash.length === 128, 'PBKDF2-SHA512 hash must be 64 bytes (128 hex characters)');

    // Verify correct password matches
    assert.strictEqual(verifyPassword(password, hash, salt), true, 'Valid password must verify against salt and hash');

    // Verify incorrect password fails
    assert.strictEqual(verifyPassword('WrongPassword123!', hash, salt), false, 'Incorrect password must fail verification');

    // Verify unique salts produce distinct hashes for identical passwords
    const secondHash = hashPassword(password);
    assert.notStrictEqual(salt, secondHash.salt, 'Consecutive password hashes must use unique random salts');
    assert.notStrictEqual(hash, secondHash.hash, 'Hashes of identical passwords with different salts must differ');

    console.log('✅ Test 1 Passed: Salt Hashing (32-byte Random Salt + PBKDF2-HMAC-SHA512)');
}

// 2. Test AES-256-GCM Vault Encryption & Decryption
{
    const secret = 'EnterpriseRootKey$9982!WithUnicode🚀&SpecialChars';
    const encrypted = encrypt(secret);

    assert(encrypted !== secret, 'Ciphertext must not equal plaintext');
    const parts = encrypted.split(':');
    assert.strictEqual(parts.length, 3, 'Ciphertext format must be iv:authTag:ciphertext');
    assert.strictEqual(parts[0].length, 24, 'IV must be 12 bytes (24 hex characters)');
    assert.strictEqual(parts[1].length, 32, 'Auth tag must be 16 bytes (32 hex characters)');

    const decrypted = decrypt(encrypted);
    assert.strictEqual(decrypted, secret, 'Decrypted string must match original secret');

    console.log('✅ Test 2 Passed: AES-256-GCM Vault Authenticated Encryption & Decryption');
}

// 3. Test MFA Authenticator Engine (RFC 6238 / RFC 4226)
{
    const secret = 'JBSWY3DPEHPK3PXP';
    const mfa = generateMFA(secret);

    assert(mfa !== null, 'MFA generation must succeed');
    assert(/^\d{6}$/.test(mfa.token), 'MFA token must be a 6-digit numeric string');
    assert(mfa.secondsRemaining >= 1 && mfa.secondsRemaining <= 30, 'Seconds remaining must be between 1 and 30');

    // Verify current token
    const isValid = verifyMFACode(mfa.token, secret);
    assert.strictEqual(isValid, true, 'Current MFA token must verify successfully');

    // Verify invalid token fails
    const isInvalid = verifyMFACode('000000', secret);
    assert.strictEqual(isInvalid, false, 'Invalid token must fail verification');

    console.log(`✅ Test 3 Passed: MFA Authenticator Engine (Token: ${mfa.token}, ${mfa.secondsRemaining}s left)`);
}

// 4. Test Native .kdbx File & XML/CSV Parsers
{
    // Test XML parser
    const sampleXml = `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>DevOps Cluster</Name>
      <Entry>
        <String><Key>Title</Key><Value>Kubernetes Master</Value></String>
        <String><Key>UserName</Key><Value>kubeadmin</Value></String>
        <String><Key>Password</Key><Value>KubeSecretPass#2026</Value></String>
        <String><Key>URL</Key><Value>https://k8s.internal:6443</Value></String>
        <String><Key>Notes</Key><Value>Main cluster root node</Value></String>
        <String><Key>TimeOtp-Secret-Base32</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>`;

    const parsed = parseKdbxDatabase(Buffer.from(sampleXml, 'utf8'));
    assert.strictEqual(parsed.entries.length, 1, 'KDBX/XML parser must extract 1 entry');
    assert.strictEqual(parsed.entries[0].title, 'Kubernetes Master');
    assert.strictEqual(parsed.entries[0].username, 'kubeadmin');
    assert.strictEqual(parsed.entries[0].password, 'KubeSecretPass#2026');

    // Test CSV parser
    const sampleCsv = `"Group","Title","Username","Password","URL","Notes","TOTP"\n"General","Slack","alice","SlackSecret!123","https://slack.com","Chat","JBSWY3DPEHPK3PXP"`;
    const parsedCsv = parseCSV(sampleCsv);
    assert.strictEqual(parsedCsv.length, 1, 'CSV parser must extract 1 entry');
    assert.strictEqual(parsedCsv[0].title, 'Slack');

    console.log('✅ Test 4 Passed: Native .kdbx Database and XML/CSV Parser Engine');
}

// 5. Test Daily Local Database Backup Service
{
    const backupResult = backupService.createBackup('Automated Verification Test Snapshot');
    assert.strictEqual(backupResult.success, true, 'Backup snapshot creation must succeed');
    assert(backupResult.filename && backupResult.filename.startsWith('vault_backup_'), 'Backup filename must have timestamp prefix');
    assert(backupResult.checksum && backupResult.checksum.length === 64, 'SHA-256 checksum must be 64 hex characters');

    const backupsList = backupService.listBackups();
    assert(backupsList.length > 0, 'Backups list must contain at least 1 backup');

    console.log(`✅ Test 5 Passed: Daily Local Database Backup Service (Snapshot: ${backupResult.filename})`);
}

// 6. Test Multi-User Isolation & Granular Co-Access Control
{
    const aliceId = 'u_alice';
    const bobId = 'u_bob';
    const charlieId = 'u_charlie';

    const aliceEntries = db.getAccessibleEntries(aliceId);
    const bobEntries = db.getAccessibleEntries(bobId);
    const charlieEntries = db.getAccessibleEntries(charlieId);

    // Alice can see her private banking item (e_5)
    assert(aliceEntries.some(e => e.id === 'e_5'), 'Alice must be able to access her private vault item');

    // Bob CANNOT see Alice's private banking item (e_5)
    assert.strictEqual(bobEntries.some(e => e.id === 'e_5'), false, 'Bob MUST NOT have access to Alice\'s private vault item');

    // Bob CAN see the co-shared Staging DB item (e_3)
    assert(bobEntries.some(e => e.id === 'e_3'), 'Bob MUST have access to co-shared Staging DB entry');

    // Charlie CAN see co-shared AWS Master item (e_2)
    assert(charlieEntries.some(e => e.id === 'e_2'), 'Charlie MUST have access to co-shared AWS Master entry');

    // Bob CANNOT see AWS Master item (e_2) because it was only co-shared with Charlie
    assert.strictEqual(bobEntries.some(e => e.id === 'e_2'), false, 'Bob MUST NOT see AWS Master entry restricted to Alice & Charlie');

    // All members can see Team-Wide Corporate VPN (e_1)
    assert(aliceEntries.some(e => e.id === 'e_1'), 'Alice can see team VPN');
    assert(bobEntries.some(e => e.id === 'e_1'), 'Bob can see team VPN');
    assert(charlieEntries.some(e => e.id === 'e_1'), 'Charlie can see team VPN');

    console.log('✅ Test 6 Passed: Multi-User Isolation & Granular Team Co-Access Control');
}

// 7. Test Vault Security Health Analyzer & Password Entropy Engine
{
    const testEntries = [
        { id: '1', title: 'Strong Account', username: 'user1', password: 'K9#vL!8xPqZ2$wT9', totpSecret: 'JBSWY3DPEHPK3PXP' },
        { id: '2', title: 'Weak Account 1', username: 'user2', password: '12345password', totpSecret: null },
        { id: '3', title: 'Weak Account 2 (Reused)', username: 'user3', password: '12345password', totpSecret: null },
        { id: '4', title: 'Moderate Account', username: 'user4', password: 'StandardPass#99', totpSecret: null }
    ];

    const health = analyzeVaultHealth(testEntries);

    assert.strictEqual(health.totalEntries, 4, 'Health analysis must process 4 entries');
    assert.strictEqual(health.strongCount, 2, 'Should identify 2 strong passwords');
    assert.strictEqual(health.weakCount, 2, 'Should identify 2 weak passwords');
    assert.strictEqual(health.reusedCount, 2, 'Should detect 2 entries with reused passwords');
    assert.strictEqual(health.reusedGroups.length, 1, 'Should identify 1 group of reused passwords');
    assert.strictEqual(health.withMfaCount, 1, 'Should count 1 entry with MFA configured');
    assert.strictEqual(health.missingMfaCount, 3, 'Should count 3 entries missing MFA');
    assert(health.overallScore >= 0 && health.overallScore <= 100, 'Score must be between 0 and 100');
    assert(['A+', 'A', 'B', 'C', 'F'].includes(health.grade), 'Grade must be a valid tier');

    console.log(`✅ Test 7 Passed: Vault Security Health Analyzer (Score: ${health.overallScore}%, Grade: ${health.grade}, Reused: ${health.reusedCount})`);
}

// 8. Test WebAuthn / FIDO2 Challenge & Attestation Generation
{
    const mockUser = { id: 'u_alice', username: 'alice', displayName: 'Alice (DevOps Lead)' };
    const options = generateWebAuthnChallenge(mockUser);

    assert(options.challenge && options.challenge.length >= 32, 'WebAuthn challenge must be random and non-empty');
    assert.strictEqual(options.rp.name, 'KeePass Web Team Edition', 'RP name must match app');
    assert.strictEqual(options.user.name, 'alice', 'User name in challenge must match user');
    assert(Array.isArray(options.pubKeyCredParams) && options.pubKeyCredParams.length > 0, 'Must provide public key credential parameters');

    console.log(`✅ Test 8 Passed: WebAuthn / FIDO2 Hardware Key Challenge Engine (Challenge: ${options.challenge.substring(0, 16)}...)`);
}

console.log('\n================================================================');
console.log('  🎉 ALL 8 COMPREHENSIVE VERIFICATION TESTS PASSED SUCCESSFULLY!');
console.log('================================================================\n');

