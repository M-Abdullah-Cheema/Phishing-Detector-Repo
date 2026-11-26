#!/usr/bin/env node
/*
 * End-to-end smoke test: loads the unpacked extension into Chromium and checks the real
 * MV3 service worker, content scripts, banner, toolbar badge, popup and storage cleanup.
 *
 *   cd tests/e2e && npm install && npx playwright install chromium && npm test
 *   HEADED=1 npm test      (watch it run)
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { PAGES, THREAD_HASH, MESSAGES, expandedMessage } = require('./gmail-fixtures.js');

const REPO_DIR = path.resolve(__dirname, '..', '..');
// PHISHGUARD_EXTENSION_DIR lets the same checks run against an unpacked phishguard-extension.zip.
const EXTENSION_DIR = path.resolve(process.env.PHISHGUARD_EXTENSION_DIR || REPO_DIR);
const SCREENSHOT_DIR = path.join(__dirname, 'screenshots');
const TEST_HOST = 'https://phishguard-tests.local';
const gmailUrl = (name) => `https://mail.google.com/mail/u/0/?pg=${name}${THREAD_HASH}`;

const BANNER_COLORS = {
  phishing: 'rgb(253, 236, 234)',
  suspicious: 'rgb(255, 244, 229)',
  safe: 'rgb(237, 247, 237)',
  trusted: 'rgb(232, 241, 251)',
};
const BADGE = {
  phishing: { text: '!', color: [198, 40, 40, 255] },
  suspicious: { text: '?', color: [230, 81, 0, 255] },
  safe: { text: 'OK', color: [46, 125, 50, 255] },
  trusted: { text: 'OK', color: [21, 101, 192, 255] },
};
const PILL = { phishing: 'Likely phishing', suspicious: 'Suspicious email', safe: 'Low risk', trusted: 'Trusted sender' };

// ---------- tiny async test runner ----------

const results = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function check(name, fn) {
  try {
    await fn();
    results.push({ name, passed: true });
    console.log(`  PASS  ${name}`);
  } catch (err) {
    results.push({ name, passed: false, error: err.message });
    console.log(`  FAIL  ${name}\n        ${String(err.message).split('\n').join('\n        ')}`);
  }
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

function expectEqual(actual, expected, label) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Error(`${label}: expected ${e}, got ${a}`);
}

async function waitFor(fn, label, timeout = 8000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try {
      last = await fn();
      if (last) return last;
    } catch (err) {
      last = err.message;
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${label} (last value: ${JSON.stringify(last)})`);
}

// ---------- extension helpers ----------

let context;
let extensionId;
const pageErrors = [];
const consoleWarnings = [];

async function worker() {
  const existing = context.serviceWorkers().find((w) => w.url().startsWith(`chrome-extension://${extensionId}/`));
  if (existing) return existing;
  return context.waitForEvent('serviceworker', { timeout: 10000 });
}

// Evaluating in a stopped worker can hang instead of failing, so every call is time-boxed.
async function inWorker(fn, arg, timeout = 4000) {
  const w = await worker();
  let timer;
  try {
    return await Promise.race([
      w.evaluate(fn, arg),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('service worker did not respond')), timeout); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const storage = () => inWorker(() => chrome.storage.local.get(null));

// Uses the same "Stop" button as chrome://serviceworker-internals, simulating Chrome idling the worker.
async function stopWorker() {
  const internals = await context.newPage();
  await internals.goto('chrome://serviceworker-internals/');
  const registration = internals.locator('.serviceworker-registration', { hasText: `chrome-extension://${extensionId}/` });
  const status = registration.locator('.serviceworker-running-status .value').first();
  await waitFor(async () => (await status.textContent()) === 'RUNNING', 'worker RUNNING before stop');
  await registration.locator('cr-button[data-command="stop"]').click();
  await waitFor(async () => (await status.textContent()) === 'STOPPED', 'worker STOPPED');
  await internals.close();
}

async function tabIdFor(page) {
  const url = page.url();
  return waitFor(
    () => inWorker(async (u) => {
      const tabs = await chrome.tabs.query({});
      const tab = tabs.find((t) => t.url === u);
      return tab ? tab.id : null;
    }, url),
    `tab id for ${url}`,
  );
}

const badge = (tabId) => inWorker(async (id) => ({
  text: await chrome.action.getBadgeText({ tabId: id }),
  color: await chrome.action.getBadgeBackgroundColor({ tabId: id }),
  title: await chrome.action.getTitle({ tabId: id }),
}), tabId);

async function expectBadge(tabId, verdict) {
  const expected = BADGE[verdict];
  const actual = await waitFor(async () => {
    const b = await badge(tabId);
    return b.text === expected.text && JSON.stringify(b.color) === JSON.stringify(expected.color) ? b : null;
  }, `badge "${expected.text}" for ${verdict}`).catch(async (err) => {
    throw new Error(`${err.message}; actual badge ${JSON.stringify(await badge(tabId))}`);
  });
  return actual;
}

async function openGmail(name) {
  const page = await context.newPage();
  page.on('pageerror', (err) => pageErrors.push(`${name}: ${err.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'warning' || msg.type() === 'error') consoleWarnings.push({ page: name, type: msg.type(), text: msg.text() });
  });
  await page.goto(gmailUrl(name));
  return page;
}

function bannerInfo(page) {
  return page.$$eval('[data-phishguard-banner]', (nodes) => nodes.map((n) => {
    const findings = n.querySelector('.pg-findings');
    const next = n.nextElementSibling;
    return {
      key: n.getAttribute('data-phishguard-banner'),
      verdict: ([...n.classList].find((c) => c.startsWith('pg-banner--')) || '').replace('pg-banner--', ''),
      background: getComputedStyle(n).backgroundColor,
      role: n.getAttribute('role'),
      title: (n.querySelector('.pg-banner__title') || {}).textContent,
      subtitle: (n.querySelector('.pg-banner__subtitle') || {}).textContent,
      findingsPresent: Boolean(findings),
      findingsVisible: Boolean(findings && !findings.hidden && findings.getClientRects().length),
      findingTitles: [...n.querySelectorAll('.pg-finding__title')].map((t) => t.textContent),
      buttons: [...n.querySelectorAll('button')].map((b) => b.textContent),
      directlyAboveBody: Boolean(next && next.classList.contains('a3s')),
      parentIsBodyWrapper: Boolean(n.parentElement && n.parentElement.classList.contains('ii')),
      messageId: (n.closest('[data-message-id]') || { getAttribute: () => null }).getAttribute('data-message-id'),
    };
  }));
}

async function waitForBanners(page, count, label) {
  return waitFor(async () => {
    const banners = await bannerInfo(page);
    return banners.length === count ? banners : null;
  }, `${count} banner(s) on ${label}`);
}

async function openPopup(tabId) {
  const popup = await context.newPage();
  popup.on('pageerror', (err) => pageErrors.push(`popup: ${err.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html${tabId ? `?tabId=${tabId}` : ''}`);
  await popup.waitForFunction(() => document.getElementById('current').childElementCount > 0);
  return popup;
}

function popupInfo(popup) {
  return popup.evaluate(() => ({
    empty: (document.querySelector('#current .pg-empty') || {}).textContent || null,
    cards: [...document.querySelectorAll('.pg-card')].map((c) => ({
      pill: c.querySelector('.pg-pill').textContent,
      score: c.querySelector('.pg-card__score').textContent,
      meterWidth: c.querySelector('.pg-meter__fill').style.width,
      subject: c.querySelector('.pg-card__subject').textContent,
      sender: c.querySelector('.pg-card__sender').textContent,
      findings: [...c.querySelectorAll('.pg-finding__title')].map((t) => t.textContent),
      button: (c.querySelector('.pg-card__actions button') || {}).textContent,
    })),
    trusted: [...document.querySelectorAll('#trusted .pg-trusted__email')].map((n) => n.textContent),
    trustedEmpty: Boolean(document.querySelector('#trusted .pg-empty')),
    version: document.getElementById('version').textContent,
  }));
}

async function expectPopupMatchesStorage(popup, tabId) {
  const { tabResults } = await storage();
  const stored = tabResults[tabId].messages;
  const info = await popupInfo(popup);
  expectEqual(info.cards.length, stored.length, 'popup card count');
  stored.forEach((r, i) => {
    const card = info.cards[i];
    expectEqual(card.pill, PILL[r.verdict], `card ${i} verdict label`);
    expectEqual(card.score, `${r.score}/100`, `card ${i} score`);
    expectEqual(card.meterWidth, `${r.score}%`, `card ${i} meter width`);
    expectEqual(card.subject, r.subject, `card ${i} subject`);
    expect(card.sender.includes(r.sender.email), `card ${i} sender should include ${r.sender.email}`);
    expectEqual(card.findings, r.findings.map((f) => `${f.title} (+${f.weight})`), `card ${i} reasons`);
  });
  return info;
}

async function screenshot(page, name, selector) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  const file = path.join(SCREENSHOT_DIR, `${name}.png`);
  if (selector) await page.locator(selector).first().screenshot({ path: file });
  else await page.screenshot({ path: file, fullPage: true });
}

// ---------- test run ----------

async function main() {
  context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: process.env.HEADED !== '1',
    viewport: { width: 1000, height: 900 },
    args: [`--disable-extensions-except=${EXTENSION_DIR}`, `--load-extension=${EXTENSION_DIR}`],
  });

  await context.route('https://mail.google.com/**', (route) => {
    const url = new URL(route.request().url());
    const page = PAGES[url.searchParams.get('pg')];
    if (route.request().resourceType() === 'document' && page) {
      return route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: page() });
    }
    return route.fulfill({ status: 204, body: '' });
  });
  await context.route(`${TEST_HOST}/**`, (route) => {
    const rel = decodeURIComponent(new URL(route.request().url()).pathname).replace(/^\/+/, '');
    const file = path.resolve(REPO_DIR, rel);
    if (!file.startsWith(REPO_DIR) || !fs.existsSync(file)) return route.fulfill({ status: 404, body: '' });
    const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png' };
    return route.fulfill({ status: 200, contentType: types[path.extname(file)] || 'text/plain', body: fs.readFileSync(file) });
  });

  console.log('\nSetup');
  await check('extension loads and its MV3 service worker starts', async () => {
    const sw = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker', { timeout: 15000 }));
    extensionId = new URL(sw.url()).host;
    expect(sw.url().endsWith('/background.js'), `unexpected worker ${sw.url()}`);
    const manifest = await sw.evaluate(() => chrome.runtime.getManifest());
    expectEqual(manifest.manifest_version, 3, 'manifest_version');
    expectEqual(manifest.name, 'PhishGuard Mail Analyzer', 'name');
  });
  if (!extensionId) throw new Error('Extension did not load; aborting.');

  await check('onInstalled initialises chrome.storage.local defaults', async () => {
    const data = await waitFor(async () => {
      const d = await storage();
      return Array.isArray(d.trustedSenders) && d.tabResults ? d : null;
    }, 'storage defaults');
    expectEqual(data.trustedSenders, [], 'trustedSenders');
    expectEqual(data.tabResults, {}, 'tabResults');
  });

  console.log('\nUnit tests inside real Chromium');
  await check('tests/test-runner.html passes in Chromium', async () => {
    const page = await context.newPage();
    await page.goto(`${TEST_HOST}/tests/test-runner.html`);
    const summary = await page.textContent('#summary');
    const failures = await page.$$eval('.fail-item', (n) => n.map((x) => x.textContent));
    await page.close();
    expect(failures.length === 0, `${summary}\n${failures.join('\n')}`);
    console.log(`        (${summary})`);
  });

  console.log('\nSingle-message view');
  const pages = {};
  const tabs = {};

  await check('benign email: green banner directly above the body, no reasons, badge OK', async () => {
    pages.benign = await openGmail('benign');
    tabs.benign = await tabIdFor(pages.benign);
    const [b] = await waitForBanners(pages.benign, 1, 'benign');
    expectEqual(b.verdict, 'safe', 'verdict');
    expectEqual(b.background, BANNER_COLORS.safe, 'background');
    expect(b.directlyAboveBody && b.parentIsBodyWrapper, 'banner should be inserted right before div.a3s inside div.ii');
    expectEqual(b.findingsPresent, false, 'no reasons for a clean email');
    expectEqual(b.role, 'status', 'role');
    const badgeState = await expectBadge(tabs.benign, 'safe');
    expect(badgeState.title.includes('Low risk'), `badge title: ${badgeState.title}`);
  });

  await check('suspicious email: orange banner, reasons collapsed until "Why?" is clicked, badge ?', async () => {
    pages.suspicious = await openGmail('suspicious');
    tabs.suspicious = await tabIdFor(pages.suspicious);
    const [b] = await waitForBanners(pages.suspicious, 1, 'suspicious');
    expectEqual(b.verdict, 'suspicious', 'verdict');
    expectEqual(b.background, BANNER_COLORS.suspicious, 'background');
    expectEqual(b.findingsVisible, false, 'reasons start collapsed');
    expect(b.findingTitles.some((t) => t.startsWith('Sender claims to be Amazon')), `reasons: ${b.findingTitles}`);

    const toggle = pages.suspicious.locator('.pg-banner__actions button').first();
    expectEqual(await toggle.textContent(), 'Why?', 'toggle label');
    await toggle.click();
    expectEqual((await bannerInfo(pages.suspicious))[0].findingsVisible, true, 'reasons visible after click');
    expectEqual(await toggle.getAttribute('aria-expanded'), 'true', 'aria-expanded');
    expectEqual(await toggle.textContent(), 'Hide reasons', 'toggle label after click');
    await toggle.click();
    expectEqual((await bannerInfo(pages.suspicious))[0].findingsVisible, false, 'reasons hidden again');
    expectEqual(await toggle.getAttribute('aria-expanded'), 'false', 'aria-expanded after second click');
    await expectBadge(tabs.suspicious, 'suspicious');
  });

  await check('phishing email (disguised link + .pdf.exe attachment): red alert banner, reasons visible, badge !', async () => {
    pages.phishing = await openGmail('phishing');
    tabs.phishing = await tabIdFor(pages.phishing);
    const [b] = await waitForBanners(pages.phishing, 1, 'phishing');
    expectEqual(b.verdict, 'phishing', 'verdict');
    expectEqual(b.background, BANNER_COLORS.phishing, 'background');
    expectEqual(b.role, 'alert', 'role');
    expectEqual(b.findingsVisible, true, 'reasons expanded by default');
    expect(b.directlyAboveBody, 'banner above body');
    for (const prefix of ['Link text hides a different destination', 'Attachment can run code', 'Sender domain imitates PayPal']) {
      expect(b.findingTitles.some((t) => t.startsWith(prefix)), `missing reason "${prefix}" in ${JSON.stringify(b.findingTitles)}`);
    }
    const badgeState = await expectBadge(tabs.phishing, 'phishing');
    expect(/Likely phishing \(risk \d+\/100\)/.test(badgeState.title), `badge title: ${badgeState.title}`);
    await screenshot(pages.phishing, 'phishing-banner', '[data-phishguard-banner]');
  });

  await check('banner is injected once and stays stable while Gmail keeps mutating the page', async () => {
    const reportsBefore = (await storage()).tabResults[tabs.phishing].updatedAt;
    await pages.phishing.evaluate(async () => {
      for (let i = 0; i < 10; i++) {
        document.body.appendChild(document.createElement('div')).textContent = `noise ${i}`;
        await new Promise((r) => setTimeout(r, 100));
      }
    });
    await sleep(2000);
    expectEqual((await bannerInfo(pages.phishing)).length, 1, 'banner count');
    expectEqual((await storage()).tabResults[tabs.phishing].updatedAt, reportsBefore, 'no redundant re-reports to the worker');
  });

  console.log('\nThread view');
  await check('thread: collapsed message skipped, one banner per expanded message, badge shows worst verdict', async () => {
    pages.thread = await openGmail('thread');
    tabs.thread = await tabIdFor(pages.thread);
    const banners = await waitForBanners(pages.thread, 2, 'thread');
    expectEqual(banners.map((b) => b.verdict), ['safe', 'phishing'], 'verdicts in thread order');
    expectEqual(banners.map((b) => b.messageId), [`#msg-f:${MESSAGES.THREAD_BENIGN.id}`, `#msg-f:${MESSAGES.THREAD_PHISHING.id}`], 'banner placement');
    expect(banners.every((b) => b.directlyAboveBody), 'each banner sits above its own body');
    expect(banners[1].findingTitles.some((t) => t.startsWith('Links point to a raw IP address')), 'IP link reason');
    await expectBadge(tabs.thread, 'phishing');
    const stored = (await storage()).tabResults[tabs.thread].messages;
    expectEqual(stored.map((m) => m.sender.email), [MESSAGES.THREAD_BENIGN.email, MESSAGES.THREAD_PHISHING.email], 'stored messages');
    expect(stored.every((m) => m.subject === 'Re: Project files'), 'subject extracted from h2.hP');
    expect(!JSON.stringify(stored).includes('meeting'), 'email body text must not be stored');
    await screenshot(pages.thread, 'thread-view');
  });

  console.log('\nGmail DOM robustness');
  await check('lazy-loaded body: no banner while empty, banner once Gmail fills the body', async () => {
    pages.lazy = await openGmail('lazy');
    await sleep(1500);
    expectEqual((await bannerInfo(pages.lazy)).length, 0, 'no banner for an empty body');
    await pages.lazy.evaluate((html) => {
      document.querySelector('div.a3s').innerHTML = html;
    }, MESSAGES.PHISHING.bodyHtml);
    const [b] = await waitForBanners(pages.lazy, 1, 'lazy');
    expectEqual(b.verdict, 'phishing', 'verdict after body loads');
    await pages.lazy.close();
  });

  await check('renamed Gmail classes: fallback selectors still extract the email and log a clear warning', async () => {
    pages.renamed = await openGmail('renamed');
    const [b] = await waitForBanners(pages.renamed, 1, 'renamed');
    expect(['phishing', 'suspicious'].includes(b.verdict), `verdict ${b.verdict}`);
    const tabId = await tabIdFor(pages.renamed);
    const [stored] = (await storage()).tabResults[tabId].messages;
    expectEqual(stored.sender.email, MESSAGES.RENAMED.email, 'sender from h3 (not the recipient)');
    expectEqual(stored.subject, 'Verify now', 'subject from page title');
    const warnings = consoleWarnings.filter((w) => w.page === 'renamed' && w.text.includes('[PhishGuard] Gmail markup differs'));
    for (const selector of ['div.adn', 'div.a3s', 'span.gD', 'page title']) {
      expect(warnings.some((w) => w.text.includes(selector)), `expected a warning mentioning ${selector}; got ${JSON.stringify(warnings.map((w) => w.text))}`);
    }
    await pages.renamed.close();
  });

  await check('current Gmail markup produces no PhishGuard warnings', async () => {
    const unexpected = consoleWarnings.filter((w) => w.page !== 'renamed' && w.text.includes('[PhishGuard]'));
    expectEqual(unexpected, [], 'warnings');
  });

  console.log('\nPopup');
  await check('popup (for the thread tab) shows each message with verdict, score, reasons, matching storage', async () => {
    const popup = await openPopup(tabs.thread);
    const info = await expectPopupMatchesStorage(popup, tabs.thread);
    expectEqual(info.cards.map((c) => c.pill), ['Low risk', 'Likely phishing'], 'verdict labels');
    expectEqual(info.trustedEmpty, true, 'trusted list empty state');
    expect(/^v\d+\.\d+\.\d+$/.test(info.version), `version label ${info.version}`);
    await screenshot(popup, 'popup-thread');
    await popup.close();
  });

  await check('popup opened as a plain tab (no tabId) falls back to the latest scanned Gmail tab', async () => {
    const popup = await openPopup(null);
    const info = await popupInfo(popup);
    expect(info.cards.length >= 1, `expected cards, got empty state: ${info.empty}`);
    await popup.close();
  });

  await check('popup for a non-Gmail tab shows the "Open Gmail" empty state', async () => {
    // Without the "tabs" permission the extension cannot read non-Gmail URLs, so find the new tab by id.
    const tabIds = () => inWorker(async () => (await chrome.tabs.query({})).map((t) => t.id));
    const before = await tabIds();
    const other = await context.newPage();
    await other.goto(`${TEST_HOST}/README.md`);
    const otherId = await waitFor(async () => (await tabIds()).find((id) => !before.includes(id)), 'new tab id');
    const popup = await openPopup(otherId);
    const info = await popupInfo(popup);
    expect(info.cards.length === 0 && /Open Gmail/.test(info.empty), JSON.stringify(info));
    await popup.close();
    await other.close();
  });

  console.log('\nTrusted senders');
  await check('"Trust sender" on a phishing email asks for confirmation; cancelling changes nothing', async () => {
    pages.phishing.once('dialog', (d) => d.dismiss());
    await pages.phishing.locator('.pg-banner button', { hasText: 'Trust sender' }).click();
    await sleep(1000);
    expectEqual((await storage()).trustedSenders, [], 'trustedSenders after cancel');
    expectEqual((await bannerInfo(pages.phishing))[0].verdict, 'phishing', 'still phishing');
  });

  await check('confirming "Trust sender" stores the address, turns the banner blue and the badge to OK', async () => {
    let dialogText = '';
    pages.phishing.once('dialog', (d) => {
      dialogText = d.message();
      d.accept();
    });
    await pages.phishing.locator('.pg-banner button', { hasText: 'Trust sender' }).click();
    const b = await waitFor(async () => {
      const [x] = await bannerInfo(pages.phishing);
      return x && x.verdict === 'trusted' ? x : null;
    }, 'trusted banner');
    expect(dialogText.includes(MESSAGES.PHISHING.email), `dialog text: ${dialogText}`);
    expectEqual(b.background, BANNER_COLORS.trusted, 'background');
    expect(b.buttons.includes('Stop trusting sender'), `buttons: ${b.buttons}`);
    expectEqual((await storage()).trustedSenders, [MESSAGES.PHISHING.email], 'trustedSenders');
    await expectBadge(tabs.phishing, 'trusted');
    await screenshot(pages.phishing, 'trusted-banner', '[data-phishguard-banner]');
  });

  await check('popup lists the trusted sender, and "Remove" there restores the red warning in Gmail', async () => {
    const popup = await openPopup(tabs.phishing);
    let info = await expectPopupMatchesStorage(popup, tabs.phishing);
    expectEqual(info.cards[0].pill, 'Trusted sender', 'card verdict');
    expectEqual(info.trusted, [MESSAGES.PHISHING.email], 'trusted list');
    await screenshot(popup, 'popup-trusted');

    await popup.locator('#trusted button', { hasText: 'Remove' }).click();
    await waitFor(async () => (await popupInfo(popup)).trustedEmpty, 'trusted list empty in popup');
    await waitFor(async () => (await bannerInfo(pages.phishing))[0]?.verdict === 'phishing', 'banner back to phishing');
    await expectBadge(tabs.phishing, 'phishing');
    info = await waitFor(async () => {
      const i = await popupInfo(popup);
      return i.cards[0] && i.cards[0].pill === 'Likely phishing' ? i : null;
    }, 'popup card back to phishing');
    expectEqual((await storage()).trustedSenders, [], 'trustedSenders');
    await popup.close();
  });

  await check('the service worker rejects invalid addresses and scan results that do not come from Gmail', async () => {
    const other = await context.newPage();
    await other.goto(`chrome-extension://${extensionId}/popup.html`);
    const bad = await other.evaluate(() => chrome.runtime.sendMessage({ type: 'PG_TRUST_SENDER', email: 'not an email' }));
    expectEqual(bad.ok, false, 'invalid address rejected');
    const spoof = await other.evaluate(() => chrome.runtime.sendMessage({ type: 'PG_VIEW_RESULTS', results: [] }));
    expectEqual(spoof.ok, false, 'results from a non-Gmail sender rejected');
    await other.close();
  });

  console.log('\nGmail single-page navigation');
  await check('switching to another email in the same tab replaces the banner and updates the badge', async () => {
    await pages.suspicious.evaluate((html) => {
      document.querySelector('[role="list"]').innerHTML = html;
      document.querySelector('h2.hP').textContent = '[org/repo] Add phishing heuristics (PR #42)';
    }, expandedMessage({ ...MESSAGES.BENIGN, id: 1781000000000040 }));
    const [b] = await waitForBanners(pages.suspicious, 1, 'navigated tab');
    expectEqual(b.verdict, 'safe', 'new banner verdict');
    await expectBadge(tabs.suspicious, 'safe');
  });

  await check('going back to the inbox clears the badge and the tab\'s stored results', async () => {
    await pages.suspicious.evaluate(() => {
      document.querySelector('[role="list"]').innerHTML = '<div class="zA">inbox rows…</div>';
      window.location.hash = '#inbox';
    });
    await waitFor(async () => !(await storage()).tabResults[tabs.suspicious], 'tab entry removed');
    expectEqual((await badge(tabs.suspicious)).text, '', 'badge text');
  });

  console.log('\nService worker lifecycle');
  await check('after the service worker is stopped, results survive in storage and it wakes up for new scans', async () => {
    const before = await storage();
    // A global set now must be gone after the restart, proving a fresh worker instance.
    await inWorker(() => { self.__phishguardTestMarker = 'old-instance'; });

    await stopWorker();

    const popup = await openPopup(tabs.thread);
    expectEqual((await popupInfo(popup)).cards.length, before.tabResults[tabs.thread].messages.length, 'popup renders from storage while worker is stopped');
    await popup.close();

    // A new email in the benign tab sends a message, which must restart the worker.
    await pages.benign.evaluate((html) => {
      document.querySelector('[role="list"]').innerHTML = html;
    }, expandedMessage({ ...MESSAGES.PHISHING, id: 1781000000000050 }));
    await waitForBanners(pages.benign, 1, 'benign tab after restart');
    const marker = await waitFor(() => inWorker(() => self.__phishguardTestMarker || 'fresh-instance'), 'restarted worker');
    expectEqual(marker, 'fresh-instance', 'worker globals after restart');
    await expectBadge(tabs.benign, 'phishing');
    const after = await storage();
    expect(after.tabResults[tabs.thread], 'other tabs\' results were not lost when the worker restarted');
    expectEqual(after.tabResults[tabs.benign].messages[0].verdict, 'phishing', 'new result stored by restarted worker');
  });

  console.log('\nStorage cleanup');
  await check('closing a tab removes its entry from chrome.storage.local', async () => {
    await pages.thread.close();
    await waitFor(async () => !(await storage()).tabResults[tabs.thread], 'thread entry removed');
    expect((await storage()).tabResults[tabs.phishing], 'entries of open tabs are kept');
  });

  await check('closing a tab while the service worker is stopped still cleans up (tabs.onRemoved wakes it)', async () => {
    expect((await storage()).tabResults[tabs.benign], 'precondition: benign tab has an entry');
    await stopWorker();
    await pages.benign.close();
    await waitFor(async () => !(await storage()).tabResults[tabs.benign], 'benign entry removed');
    expect((await storage()).tabResults[tabs.phishing], 'entries of open tabs are kept');
  });

  await check('no uncaught errors in Gmail pages or the popup', async () => {
    expectEqual(pageErrors, [], 'page errors');
    const errors = consoleWarnings.filter((w) => w.type === 'error');
    expectEqual(errors, [], 'console errors');
  });

  await context.close();

  const failed = results.filter((r) => !r.passed);
  console.log(`\n${results.length - failed.length}/${results.length} smoke checks passed`);
  console.log(`Screenshots: ${SCREENSHOT_DIR}`);
  process.exitCode = failed.length ? 1 : 0;
}

main().catch(async (err) => {
  console.error(err);
  if (context) await context.close().catch(() => {});
  process.exitCode = 1;
});
