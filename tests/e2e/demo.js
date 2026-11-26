#!/usr/bin/env node
/*
 * Offline demo: opens a visible Chromium window with the real extension loaded and the
 * Gmail-like test emails in tabs (served locally through request interception, so no
 * internet connection or Gmail login is needed). Close the browser window to exit.
 *
 *   cd tests/e2e && npm run demo
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const { PAGES, THREAD_HASH } = require('./gmail-fixtures.js');

const REPO_DIR = path.resolve(__dirname, '..', '..');
const EXTENSION_DIR = path.resolve(process.env.PHISHGUARD_EXTENSION_DIR || REPO_DIR);
const TEST_HOST = 'https://phishguard-tests.local';
const DEMO_TABS = [
  { name: 'benign', label: 'Benign (green, OK)' },
  { name: 'suspicious', label: 'Suspicious (orange, ?)' },
  { name: 'phishing', label: 'Phishing (red, !)' },
  { name: 'thread', label: 'Thread with mixed verdicts' },
];

async function main() {
  const context = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    headless: false,
    viewport: null,
    args: [`--disable-extensions-except=${EXTENSION_DIR}`, `--load-extension=${EXTENSION_DIR}`, '--start-maximized'],
  });

  await context.route('https://mail.google.com/**', (route) => {
    const page = PAGES[new URL(route.request().url()).searchParams.get('pg')];
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

  const worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  const extensionId = new URL(worker.url()).host;

  const [blank] = context.pages();
  const opened = [];
  for (const tab of DEMO_TABS) {
    const page = opened.length === 0 && blank ? blank : await context.newPage();
    await page.goto(`https://mail.google.com/mail/u/0/?pg=${tab.name}${THREAD_HASH}`);
    opened.push({ ...tab, page });
  }
  const tests = await context.newPage();
  await tests.goto(`${TEST_HOST}/tests/test-runner.html`);
  await opened[0].page.bringToFront();

  const tabIds = await worker.evaluate(async () => (await chrome.tabs.query({ url: 'https://mail.google.com/*' })).map((t) => ({ id: t.id, url: t.url })));
  console.log('\nPhishGuard offline demo is running. Tabs:');
  for (const tab of opened) {
    const match = tabIds.find((t) => t.url === tab.page.url());
    console.log(`  ${tab.label.padEnd(28)} popup: chrome-extension://${extensionId}/popup.html${match ? `?tabId=${match.id}` : ''}`);
  }
  console.log('  Unit tests                   (last tab)');
  console.log('\nTip: pin PhishGuard from the puzzle-piece menu to show the badge and open the popup.');
  console.log('Close the browser window to end the demo.\n');

  await new Promise((resolve) => context.on('close', resolve));
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
