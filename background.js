/*
 * PhishGuard service worker (Manifest V3, non-persistent).
 *
 * Chrome can terminate this worker whenever it is idle, so it holds no state of its own:
 * every handler reads from and writes to chrome.storage.local.
 *
 * Storage layout:
 *   tabResults:     { [tabId]: { updatedAt, messages: [result, ...] } }   results for the email(s) open in each tab
 *   trustedSenders: [ "alice@example.com", ... ]                           exact addresses the user trusts
 */
'use strict';

const GMAIL_ORIGIN = 'https://mail.google.com/';
const POPUP_URL = chrome.runtime.getURL('popup.html');
const VERDICTS = ['trusted', 'safe', 'suspicious', 'phishing'];
const SEVERITIES = ['low', 'medium', 'high'];
const MAX_TRUSTED_SENDERS = 500;
const EMAIL_PATTERN = /^[^\s@]{1,64}@[^\s@]{1,255}$/;

const BADGES = {
  phishing: { text: '!', color: '#c62828', label: 'Likely phishing' },
  suspicious: { text: '?', color: '#e65100', label: 'Suspicious' },
  safe: { text: 'OK', color: '#2e7d32', label: 'Low risk' },
  trusted: { text: 'OK', color: '#1565c0', label: 'Trusted sender' },
};

// Serializes read-modify-write cycles on storage so concurrent messages cannot overwrite each other.
// Losing this chain when the worker sleeps is harmless: by then no write is in flight.
let storageQueue = Promise.resolve();
function withStorageLock(task) {
  const run = storageQueue.then(task, task);
  storageQueue = run.catch(() => {});
  return run;
}

function clampString(value, max) {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

function sanitizeFinding(f) {
  if (!f || typeof f !== 'object') return null;
  return {
    id: clampString(f.id, 64),
    severity: SEVERITIES.includes(f.severity) ? f.severity : 'low',
    weight: Math.max(0, Math.min(100, Number(f.weight) || 0)),
    title: clampString(f.title, 200),
    explanation: clampString(f.explanation, 600),
    evidence: Array.isArray(f.evidence) ? f.evidence.slice(0, 10).map((e) => clampString(e, 300)) : [],
  };
}

// Content scripts run next to an untrusted page, so their messages are validated before storage.
function sanitizeResult(r) {
  if (!r || typeof r !== 'object' || !VERDICTS.includes(r.verdict)) return null;
  const sender = r.sender && typeof r.sender === 'object' ? r.sender : {};
  return {
    key: clampString(r.key, 200),
    provider: clampString(r.provider, 32),
    subject: clampString(r.subject, 300),
    sender: { name: clampString(sender.name, 200), email: clampString(sender.email, 320) },
    verdict: r.verdict,
    score: Math.max(0, Math.min(100, Number(r.score) || 0)),
    findings: Array.isArray(r.findings) ? r.findings.slice(0, 30).map(sanitizeFinding).filter(Boolean) : [],
    analyzedAt: Number(r.analyzedAt) || Date.now(),
  };
}

function normalizeEmailAddress(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!EMAIL_PATTERN.test(email)) throw new Error('Invalid email address');
  return email;
}

function worstVerdict(messages) {
  return messages.reduce((worst, m) => (VERDICTS.indexOf(m.verdict) > VERDICTS.indexOf(worst) ? m.verdict : worst), 'trusted');
}

async function updateBadge(tabId, messages) {
  try {
    if (!messages.length) {
      await chrome.action.setBadgeText({ tabId, text: '' });
      await chrome.action.setTitle({ tabId, title: 'PhishGuard Mail Analyzer' });
      return;
    }
    const verdict = worstVerdict(messages);
    const badge = BADGES[verdict];
    const top = messages.find((m) => m.verdict === verdict);
    await chrome.action.setBadgeText({ tabId, text: badge.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
    await chrome.action.setTitle({ tabId, title: `PhishGuard: ${badge.label} (risk ${top.score}/100)` });
  } catch {
    // The tab was closed before the badge could be updated.
  }
}

function setTabResults(tabId, messages) {
  return withStorageLock(async () => {
    const { tabResults = {} } = await chrome.storage.local.get('tabResults');
    if (messages && messages.length) {
      tabResults[tabId] = { updatedAt: Date.now(), messages };
    } else {
      delete tabResults[tabId];
    }
    await chrome.storage.local.set({ tabResults });
  });
}

function updateTrustedSenders(email, add) {
  return withStorageLock(async () => {
    const { trustedSenders = [] } = await chrome.storage.local.get('trustedSenders');
    const next = trustedSenders.filter((s) => s !== email);
    if (add) {
      if (next.length >= MAX_TRUSTED_SENDERS) throw new Error('Trusted sender list is full');
      next.push(email);
    }
    await chrome.storage.local.set({ trustedSenders: next });
    return next;
  });
}

function isGmailTab(sender) {
  return Boolean(sender.tab && sender.frameId === 0 && typeof sender.url === 'string' && sender.url.startsWith(GMAIL_ORIGIN));
}

function isPopup(sender) {
  // popup.html may be opened as a tab (with ?tabId=...), so compare without query/fragment.
  return typeof sender.url === 'string' && sender.url.split(/[?#]/)[0] === POPUP_URL;
}

async function handleMessage(message, sender) {
  switch (message.type) {
    case 'PG_VIEW_RESULTS': {
      if (!isGmailTab(sender)) throw new Error('Results are only accepted from Gmail tabs');
      const results = Array.isArray(message.results) ? message.results.slice(0, 20).map(sanitizeResult).filter(Boolean) : [];
      await setTabResults(sender.tab.id, results);
      await updateBadge(sender.tab.id, results);
      return {};
    }
    case 'PG_TRUST_SENDER':
    case 'PG_UNTRUST_SENDER': {
      if (!isGmailTab(sender) && !isPopup(sender)) throw new Error('Unauthorized sender');
      const trustedSenders = await updateTrustedSenders(normalizeEmailAddress(message.email), message.type === 'PG_TRUST_SENDER');
      return { trustedSenders };
    }
    default:
      throw new Error(`Unknown message type: ${message.type}`);
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message || typeof message.type !== 'string') return false;
  handleMessage(message, sender).then(
    (data) => sendResponse({ ok: true, ...data }),
    (err) => sendResponse({ ok: false, error: String((err && err.message) || err) }),
  );
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  withStorageLock(async () => {
    const { trustedSenders, tabResults } = await chrome.storage.local.get(['trustedSenders', 'tabResults']);
    const defaults = {};
    if (!Array.isArray(trustedSenders)) defaults.trustedSenders = [];
    if (!tabResults || typeof tabResults !== 'object') defaults.tabResults = {};
    if (Object.keys(defaults).length) await chrome.storage.local.set(defaults);
  });
});

// Tab ids are not reused across browser sessions, so results from the previous session are stale.
chrome.runtime.onStartup.addListener(() => {
  withStorageLock(() => chrome.storage.local.set({ tabResults: {} }));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  setTabResults(tabId, null);
});
