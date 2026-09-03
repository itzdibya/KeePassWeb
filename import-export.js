/**
 * KeePass Web Team Edition - KeePass 2.x XML, CSV & JSON Import/Export Engine
 */

const { decrypt, encrypt } = require('./crypto-utils');

/**
 * Basic XML parser for KeePass 2.x XML format
 */
function parseKeePassXML(xmlContent) {
    const entries = [];
    const groups = [];

    // Extract Root and Groups
    const groupRegex = /<Group>([\s\S]*?)<\/Group>/g;
    let groupMatch;

    while ((groupMatch = groupRegex.exec(xmlContent)) !== null) {
        const groupBody = groupMatch[1];
        const nameMatch = /<Name>([\s\S]*?)<\/Name>/.exec(groupBody);
        const groupName = nameMatch ? unescapeXml(nameMatch[1].trim()) : 'Imported Group';

        // Extract Entries in this group
        const entryRegex = /<Entry>([\s\S]*?)<\/Entry>/g;
        let entryMatch;

        while ((entryMatch = entryRegex.exec(groupBody)) !== null) {
            const entryBody = entryMatch[1];
            const fields = {};

            const stringRegex = /<String>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<Value(?: Protected="True")?>([\s\S]*?)<\/Value>[\s\S]*?<\/String>/g;
            let strMatch;

            while ((strMatch = stringRegex.exec(entryBody)) !== null) {
                const key = unescapeXml(strMatch[1].trim());
                const val = unescapeXml(strMatch[2].trim());
                fields[key] = val;
            }

            if (fields.Title || fields.UserName || fields.Password) {
                entries.push({
                    title: fields.Title || 'Imported Entry',
                    username: fields.UserName || '',
                    password: fields.Password || '',
                    url: fields.URL || '',
                    notes: fields.Notes || '',
                    totpSecret: fields.TOTP || fields['TimeOtp-Secret-Base32'] || fields.otp || '',
                    groupName
                });
            }
        }
    }

    // Fallback if flat entries XML
    if (entries.length === 0) {
        const entryRegex = /<Entry>([\s\S]*?)<\/Entry>/g;
        let entryMatch;
        while ((entryMatch = entryRegex.exec(xmlContent)) !== null) {
            const entryBody = entryMatch[1];
            const fields = {};
            const stringRegex = /<String>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<Value(?: Protected="True")?>([\s\S]*?)<\/Value>[\s\S]*?<\/String>/g;
            let strMatch;
            while ((strMatch = stringRegex.exec(entryBody)) !== null) {
                fields[unescapeXml(strMatch[1].trim())] = unescapeXml(strMatch[2].trim());
            }
            if (fields.Title || fields.UserName || fields.Password) {
                entries.push({
                    title: fields.Title || 'Imported Entry',
                    username: fields.UserName || '',
                    password: fields.Password || '',
                    url: fields.URL || '',
                    notes: fields.Notes || '',
                    totpSecret: fields.TOTP || fields['TimeOtp-Secret-Base32'] || '',
                    groupName: 'Imported'
                });
            }
        }
    }

    return entries;
}

/**
 * Generate KeePass 2.x XML string
 */
function generateKeePassXML(entriesList, groupsList = []) {
    let xml = `<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n`;
    xml += `<KeePassFile>\n`;
    xml += `  <Meta>\n`;
    xml += `    <Generator>KeePass Web Team Edition</Generator>\n`;
    xml += `    <DatabaseName>KeePass Web Export</DatabaseName>\n`;
    xml += `    <DatabaseDescription>Exported from KeePass Web Team Edition</DatabaseDescription>\n`;
    xml += `  </Meta>\n`;
    xml += `  <Root>\n`;
    xml += `    <Group>\n`;
    xml += `      <Name>KeePass Web Vault</Name>\n`;

    entriesList.forEach(entry => {
        const password = decrypt(entry.encryptedPassword);
        const notes = decrypt(entry.notesEncrypted);
        const totp = decrypt(entry.totpSecretEncrypted);

        xml += `      <Entry>\n`;
        xml += `        <String><Key>Title</Key><Value>${escapeXml(entry.title)}</Value></String>\n`;
        xml += `        <String><Key>UserName</Key><Value>${escapeXml(entry.username)}</Value></String>\n`;
        xml += `        <String><Key>Password</Key><Value Protected="True">${escapeXml(password)}</Value></String>\n`;
        xml += `        <String><Key>URL</Key><Value>${escapeXml(entry.url)}</Value></String>\n`;
        xml += `        <String><Key>Notes</Key><Value>${escapeXml(notes)}</Value></String>\n`;
        if (totp) {
            xml += `        <String><Key>TimeOtp-Secret-Base32</Key><Value Protected="True">${escapeXml(totp)}</Value></String>\n`;
        }
        xml += `      </Entry>\n`;
    });

    xml += `    </Group>\n`;
    xml += `  </Root>\n`;
    xml += `</KeePassFile>\n`;
    return xml;
}

/**
 * Parse CSV format (KeePass / standard password manager CSV)
 */
function parseCSV(csvContent) {
    const lines = csvContent.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];

    const headers = parseCSVLine(lines[0]).map(h => h.trim().toLowerCase());
    const entries = [];

    const titleIdx = headers.findIndex(h => h.includes('title') || h.includes('name') || h.includes('account'));
    const userIdx = headers.findIndex(h => h.includes('user') || h.includes('login') || h.includes('email'));
    const passIdx = headers.findIndex(h => h.includes('pass'));
    const urlIdx = headers.findIndex(h => h.includes('url') || h.includes('link') || h.includes('web'));
    const notesIdx = headers.findIndex(h => h.includes('note') || h.includes('comment'));
    const groupIdx = headers.findIndex(h => h.includes('group') || h.includes('folder') || h.includes('category'));
    const totpIdx = headers.findIndex(h => h.includes('totp') || h.includes('otp') || h.includes('2fa'));

    for (let i = 1; i < lines.length; i++) {
        const row = parseCSVLine(lines[i]);
        if (row.length === 0) continue;

        entries.push({
            title: titleIdx !== -1 && row[titleIdx] ? row[titleIdx] : `Entry ${i}`,
            username: userIdx !== -1 && row[userIdx] ? row[userIdx] : '',
            password: passIdx !== -1 && row[passIdx] ? row[passIdx] : '',
            url: urlIdx !== -1 && row[urlIdx] ? row[urlIdx] : '',
            notes: notesIdx !== -1 && row[notesIdx] ? row[notesIdx] : '',
            groupName: groupIdx !== -1 && row[groupIdx] ? row[groupIdx] : 'Imported',
            totpSecret: totpIdx !== -1 && row[totpIdx] ? row[totpIdx] : ''
        });
    }

    return entries;
}

/**
 * Generate CSV format
 */
function generateCSV(entriesList) {
    const headers = ['"Group"', '"Title"', '"Username"', '"Password"', '"URL"', '"Notes"', '"TOTP"', '"SharingMode"'];
    const rows = [headers.join(',')];

    entriesList.forEach(entry => {
        const password = decrypt(entry.encryptedPassword);
        const notes = decrypt(entry.notesEncrypted);
        const totp = decrypt(entry.totpSecretEncrypted);

        const row = [
            `"${escapeCsv(entry.folderName || 'General')}"`,
            `"${escapeCsv(entry.title)}"`,
            `"${escapeCsv(entry.username)}"`,
            `"${escapeCsv(password)}"`,
            `"${escapeCsv(entry.url)}"`,
            `"${escapeCsv(notes)}"`,
            `"${escapeCsv(totp)}"`,
            `"${escapeCsv(entry.sharingMode)}"`
        ];
        rows.push(row.join(','));
    });

    return rows.join('\n');
}

function parseCSVLine(text) {
    const p = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
        const c = text[i];
        if (c === '"') {
            if (inQuotes && text[i + 1] === '"') {
                cur += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (c === ',' && !inQuotes) {
            p.push(cur);
            cur = '';
        } else {
            cur += c;
        }
    }
    p.push(cur);
    return p;
}

function escapeXml(unsafe) {
    if (!unsafe) return '';
    return unsafe.replace(/[<>&'"]/g, c => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

function unescapeXml(safe) {
    if (!safe) return '';
    return safe
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .replace(/&apos;/g, '\'')
        .replace(/&quot;/g, '"');
}

function escapeCsv(text) {
    if (!text) return '';
    return text.replace(/"/g, '""');
}

module.exports = {
    parseKeePassXML,
    generateKeePassXML,
    parseCSV,
    generateCSV
};
