#!/usr/bin/env node
/*
 * Validates manifest.json against Manifest V3 / Chrome Web Store rules and bundles only the
 * runtime extension files into phishguard-extension.zip. No dependencies.
 *
 *   node scripts/package.js           validate + write phishguard-extension.zip
 *   node scripts/package.js --check   validate only
 *
 * The file list is derived from manifest.json and popup.html, so tests/, node_modules/,
 * screenshots, docs and git files can never end up in the zip.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.resolve(__dirname, '..');
const OUTPUT = path.join(ROOT, 'phishguard-extension.zip');
const ALLOWED_PERMISSIONS = new Set(['storage']);
const ALLOWED_HOSTS = new Set(['https://mail.google.com/*']);
const REQUIRED_ICON_SIZES = [16, 48, 128];

const problems = [];
const passed = [];
const check = (ok, message) => (ok ? passed : problems).push(message);

function readPngSize(file) {
  const buf = fs.readFileSync(file);
  const signature = '89504e470d0a1a0a';
  if (buf.length < 24 || buf.subarray(0, 8).toString('hex') !== signature) return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

function collectFiles(manifest) {
  const files = new Set(['manifest.json']);
  const add = (p) => p && files.add(p.replace(/^\.?\//, ''));
  add(manifest.background && manifest.background.service_worker);
  for (const cs of manifest.content_scripts || []) [...(cs.js || []), ...(cs.css || [])].forEach(add);
  Object.values(manifest.icons || {}).forEach(add);
  if (manifest.action) {
    add(manifest.action.default_popup);
    Object.values(manifest.action.default_icon || {}).forEach(add);
  }
  for (const war of manifest.web_accessible_resources || []) (war.resources || []).forEach(add);

  for (const page of [...files].filter((f) => f.endsWith('.html'))) {
    const html = fs.readFileSync(path.join(ROOT, page), 'utf8');
    for (const m of html.matchAll(/\b(?:src|href)="([^"]+)"/g)) {
      if (!/^[a-z]+:/i.test(m[1]) && !m[1].startsWith('#')) add(path.posix.join(path.posix.dirname(page), m[1]));
    }
  }
  return [...files].sort();
}

function validate(manifest, files) {
  check(manifest.manifest_version === 3, 'manifest_version is 3');

  const version = String(manifest.version || '');
  const parts = version.split('.');
  check(
    /^\d+(\.\d+){0,3}$/.test(version) && parts.every((p) => Number(p) <= 65535 && !(p.length > 1 && p.startsWith('0'))),
    `version "${version}" is 1-4 dot-separated integers (0-65535, no leading zeros)`,
  );

  check(typeof manifest.name === 'string' && manifest.name.length > 0 && manifest.name.length <= 75,
    `name is ${String(manifest.name || '').length} characters (limit 75)`);
  const description = String(manifest.description || '');
  check(description.length > 0 && description.length <= 132, `description is ${description.length} characters (limit 132)`);

  const permissions = manifest.permissions || [];
  check(permissions.every((p) => ALLOWED_PERMISSIONS.has(p)), `permissions are minimal: ${JSON.stringify(permissions)}`);
  const hosts = manifest.host_permissions || [];
  check(hosts.every((h) => ALLOWED_HOSTS.has(h)), `host_permissions limited to Gmail: ${JSON.stringify(hosts)}`);
  check(!manifest.background || (manifest.background.service_worker && !manifest.background.scripts && !manifest.background.persistent),
    'background uses a non-persistent service worker');

  const csp = (manifest.content_security_policy && manifest.content_security_policy.extension_pages) || '';
  check(!/unsafe-eval|unsafe-inline|https?:/.test(csp), `extension CSP allows no eval, inline or remote scripts: "${csp}"`);

  for (const size of REQUIRED_ICON_SIZES) {
    const rel = manifest.icons && manifest.icons[size];
    const file = rel && path.join(ROOT, rel);
    const dims = file && fs.existsSync(file) ? readPngSize(file) : null;
    check(Boolean(dims && dims.width === size && dims.height === size), `icon ${size}x${size} is a PNG of the right size (${rel || 'missing'})`);
  }

  const missing = files.filter((f) => !fs.existsSync(path.join(ROOT, f)));
  check(!missing.length, missing.length ? `referenced files missing: ${missing.join(', ')}` : 'every referenced file exists');

  const codeFiles = files.filter((f) => f.endsWith('.js') || f.endsWith('.html'));
  const offenders = codeFiles.filter((f) => {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    return /\beval\s*\(|new\s+Function\s*\(|<script[^>]+src="https?:|importScripts\s*\(\s*['"]https?:/.test(src);
  });
  check(!offenders.length, offenders.length ? `remote/dynamic code found in: ${offenders.join(', ')}` : 'no eval, new Function or remote scripts in packaged code');
}

// ---------- minimal ZIP writer (deflate, no dependencies) ----------

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

function buildZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data, mtime } of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const compressed = zlib.deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const { time, day } = dosDateTime(mtime);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(day, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(day, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);

    offset += local.length + nameBuf.length + compressed.length;
  }
  const centralSize = centrals.reduce((n, b) => n + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

function main() {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const files = collectFiles(manifest);
  validate(manifest, files);

  console.log('\nManifest V3 / store checks');
  passed.forEach((m) => console.log(`  PASS  ${m}`));
  problems.forEach((m) => console.log(`  FAIL  ${m}`));
  if (problems.length) {
    console.log(`\n${problems.length} check(s) failed; no zip written.`);
    process.exitCode = 1;
    return;
  }
  if (process.argv.includes('--check')) return;

  const entries = files.map((name) => {
    const full = path.join(ROOT, name);
    return { name, data: fs.readFileSync(full), mtime: fs.statSync(full).mtime };
  });
  fs.writeFileSync(OUTPUT, buildZip(entries));

  console.log(`\nPackaged ${entries.length} runtime files into ${path.basename(OUTPUT)} (${(fs.statSync(OUTPUT).size / 1024).toFixed(1)} KB):`);
  files.forEach((f) => console.log(`  ${f}`));
}

main();
