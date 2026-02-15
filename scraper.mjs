/**
 * Lune — Nuance Scraper
 * Extracts TOTP secrets from Spotify's web-player JS bundles.
 * Output: nuance.json → [{ s: "BASE32...", v: N }, ...]
 */

import puppeteer from 'puppeteer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const nuance_FILE = path.join(__dirname, 'nuance.json');
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const SPOTIFY_URL = 'https://open.spotify.com';
const RUN_ONCE = process.argv.includes('--once');

// ─── Styled Logger ──────────────────────────────────────────────────────────────

const R = '\x1b[1m\x1b[31m';   // bold red
const W = '\x1b[37m';          // white
const G = '\x1b[90m';          // gray
const GR = '\x1b[32m';         // green
const X = '\x1b[0m';           // reset

const log = (tag, msg) => {
    const time = new Date().toLocaleTimeString([], { hour12: false });
    process.stdout.write(`${R}[ ${tag.padEnd(6)} ]${X} ${G}${time}${X} ${R}→${X} ${W}${msg}${X}\n`);
};

const logSuccess = (tag, msg) => {
    const time = new Date().toLocaleTimeString([], { hour12: false });
    process.stdout.write(`${R}[ ${tag.padEnd(6)} ]${X} ${G}${time}${X} ${R}→${X} ${GR}${msg}${X}\n`);
};

const logError = (tag, msg) => {
    const time = new Date().toLocaleTimeString([], { hour12: false });
    process.stdout.write(`${R}[ ${tag.padEnd(6)} ]${X} ${G}${time}${X} ${R}→ ${msg}${X}\n`);
};

// ─── Core Scraper ───────────────────────────────────────────────────────────────

async function scrapenuance() {
    log('SCRAPE', 'Starting nuance extraction...');

    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
            ],
        });

        const page = await browser.newPage();

        await page.setUserAgent(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        );

        page.on('console', msg => {
            const text = msg.text();
            if (text.startsWith('LUNE:')) {
                log('LUNE', text.replace('LUNE:', '').trim());
            } else {
                // Optional: log other browser messages if needed
                // log('DEBUG', text);
            }
        });

        log('FETCH', `Navigating to ${SPOTIFY_URL}`);
        await page.goto(SPOTIFY_URL, { waitUntil: 'domcontentloaded', timeout: 30000 });
        logSuccess('FETCH', 'DOMContentLoaded — proceeding with scan...');
        await new Promise(resolve => setTimeout(resolve, 2000));

        const result = await page.evaluate(async () => {
            const emit = (msg) => console.log(`LUNE: ${msg}`);

            try {
                const allScriptUrls = Array.from(document.scripts)
                    .map(s => s.src)
                    .filter(s => s && s.includes('spotifycdn.com') && s.endsWith('.js'));

                emit(`Detected ${allScriptUrls.length} Spotify CDN scripts.`);

                let targetContent = null;
                let targetUrl = null;

                for (let i = 0; i < allScriptUrls.length; i++) {
                    const url = allScriptUrls[i];
                    const filename = url.split('/').pop();

                    emit(`Scanning [${i + 1}/${allScriptUrls.length}] ${filename}...`);

                    try {
                        const resp = await fetch(url);
                        const text = await resp.text();

                        if (text.includes('charCodeAt(0)^') && text.includes('secret:')) {
                            targetContent = text;
                            targetUrl = url;
                            emit(`[ MATCH ] Found secret bundle: ${filename} (${(text.length / 1024).toFixed(0)} KB)`);
                            break;
                        }
                    } catch (e) {
                        emit(`[ FAIL ] Could not fetch ${filename}`);
                    }
                }

                if (!targetContent) {
                    return { error: 'No script containing secrets was found' };
                }

                emit('Analyzing logic structure for cryptographic keys...');
                const xorIdx = targetContent.indexOf('charCodeAt(0)^');
                const searchStart = Math.max(0, xorIdx - 3000);
                const searchEnd = Math.min(targetContent.length, xorIdx + 1500);
                const context = targetContent.substring(searchStart, searchEnd);

                const paramsMatch = context.match(/let\s+(\w)=(\d+),(\w)=(\d+),(\w)=\[\];.*?charCodeAt\(0\)\^/s);
                let xorMod = 33;
                let xorOffset = 9;
                if (paramsMatch) {
                    xorMod = parseInt(paramsMatch[2]);
                    xorOffset = parseInt(paramsMatch[4]);
                    emit(`Keys Extracted: { mod: ${xorMod}, offset: ${xorOffset} }`);
                } else {
                    emit(`Using fallback keys: { mod: 33, offset: 9 }`);
                }

                const pairs = [];
                let searchPos = 0;

                emit('Searching for secrets in extracted logic pool...');
                while (true) {
                    const secretStart = context.indexOf('secret:', searchPos);
                    if (secretStart === -1) break;

                    emit(`  [ PROCESS ] Extracting nuance at position ${secretStart}...`);

                    const quotePos = secretStart + 'secret:'.length;
                    const quoteChar = context[quotePos];

                    if (quoteChar !== "'" && quoteChar !== '"') {
                        searchPos = secretStart + 1;
                        continue;
                    }

                    let secretEnd = quotePos + 1;
                    let secretValue = '';
                    while (secretEnd < context.length) {
                        if (context[secretEnd] === '\\') {
                            secretValue += context[secretEnd + 1];
                            secretEnd += 2;
                        } else if (context[secretEnd] === quoteChar) {
                            break;
                        } else {
                            secretValue += context[secretEnd];
                            secretEnd++;
                        }
                    }

                    const afterSecret = context.substring(secretEnd, secretEnd + 100);
                    const versionMatch = afterSecret.match(/version:(\d+)/);

                    if (versionMatch) {
                        const v = parseInt(versionMatch[1]);
                        pairs.push({
                            secret: secretValue,
                            version: v
                        });
                        emit(`  → Nuance Found: Version ${v}`);
                    }

                    searchPos = secretEnd + 1;
                }

                if (pairs.length === 0) {
                    return { error: 'No secret/version pairs found' };
                }

                emit(`Finalizing decoding for ${pairs.length} nuance...`);
                const decoded = [];

                for (const pair of pairs) {
                    try {
                        const xorValues = pair.secret
                            .split('')
                            .map((char, idx) => char.charCodeAt(0) ^ (idx % xorMod) + xorOffset);

                        const joinedStr = xorValues.join('');
                        const encoder = new TextEncoder();
                        const utf8Bytes = encoder.encode(joinedStr);
                        const hexStr = Array.from(utf8Bytes)
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');

                        const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
                        const hexBytes = [];
                        for (let i = 0; i < hexStr.length; i += 2) {
                            hexBytes.push(parseInt(hexStr.substring(i, i + 2), 16));
                        }

                        let bits = 0;
                        let value = 0;
                        let base32 = '';
                        for (const byte of hexBytes) {
                            value = (value << 8) | byte;
                            bits += 8;
                            while (bits >= 5) {
                                base32 += BASE32[(value >>> (bits - 5)) & 31];
                                bits -= 5;
                            }
                        }
                        if (bits > 0) {
                            base32 += BASE32[(value << (5 - bits)) & 31];
                        }

                        decoded.push({ s: base32, v: pair.version });
                        emit(`v${pair.version} nuance decoded successfully.`);
                    } catch (e) {
                        emit(`Error decoding v${pair.version}`);
                    }
                }

                return { nuance: decoded, sourceUrl: targetUrl };

            } catch (e) {
                return { error: e.message };
            }
        });

        if (result.error) {
            throw new Error(result.error);
        }

        const nuance = result.nuance;

        if (!nuance || nuance.length === 0) {
            throw new Error('No nuance could be extracted');
        }

        logSuccess('LUNE', `Extracted ${nuance.length} nuance(s)`);

        // Merge: same version → overwrite, new version → append below
        const existing = loadExistingnuance();
        const map = new Map();
        for (const n of existing) map.set(n.v, n);

        let overwritten = 0;
        let added = 0;

        for (const n of nuance) {
            if (map.has(n.v)) {
                const old = map.get(n.v);
                if (old.s !== n.s) {
                    map.set(n.v, n);
                    overwritten++;
                    log('MERGE', `v${n.v} overwritten (secret changed)`);
                }
            } else {
                map.set(n.v, n);
                added++;
                logSuccess('MERGE', `v${n.v} added (new version)`);
            }
        }

        // Sort ascending by version — new versions appear below previous
        const merged = Array.from(map.values()).sort((a, b) => a.v - b.v);

        if (overwritten > 0 || added > 0) {
            fs.writeFileSync(nuance_FILE, JSON.stringify(merged, null, 2), 'utf8');
            logSuccess('SAVE', `nuance.json updated — ${merged.length} total (${overwritten} overwritten, ${added} new)`);
        } else {
            log('SAVE', 'No changes — nuance.json is current');
        }

        return { success: true, nuance: merged, hasChanges: overwritten > 0 || added > 0 };

    } catch (error) {
        logError('ERROR', error.message);
        return { success: false, error: error.message };
    } finally {
        if (browser) {
            await browser.close();
        }
    }
}

// ─── File I/O ───────────────────────────────────────────────────────────────────

function loadExistingnuance() {
    try {
        if (fs.existsSync(nuance_FILE)) {
            const data = JSON.parse(fs.readFileSync(nuance_FILE, 'utf8'));
            if (Array.isArray(data)) return data;
        }
    } catch (err) {
        logError('WARN', `Could not read nuance.json: ${err.message}`);
    }
    return [];
}

// ─── Entry ──────────────────────────────────────────────────────────────────────

async function main() {
    console.clear();
    process.stdout.write(`${R}
    ╦  ╦ ╦╔╗╔╔═╗
    ║  ║ ║║║║║╣
    ╩═╝╚═╝╝╚╝╚═╝${X}
    ${G}→ Nuance Scraper v1.0${X}
\n`);

    const mode = RUN_ONCE ? 'single' : `continuous (${CHECK_INTERVAL_MS / 1000 / 60 / 60}h)`;
    log('SYSTEM', `Mode: ${mode}`);
    log('SYSTEM', `Output: nuance.json`);
    process.stdout.write('\n');

    if (RUN_ONCE) {
        const result = await scrapenuance();
        process.exit(result.success ? 0 : 1);
    }

    while (true) {
        await scrapenuance();

        const nextRun = new Date(Date.now() + CHECK_INTERVAL_MS);
        const nextTime = nextRun.toLocaleTimeString([], { hour12: false });
        const nextDate = nextRun.toLocaleDateString();
        process.stdout.write('\n');
        log('WAIT', `Next scrape at ${nextTime} on ${nextDate}`);
        process.stdout.write('\n');

        await new Promise(resolve => setTimeout(resolve, CHECK_INTERVAL_MS));
    }
}

main().catch(err => {
    logError('FATAL', err.message);
    process.exit(1);
});
