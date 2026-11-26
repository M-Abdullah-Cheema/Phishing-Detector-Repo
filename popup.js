'use strict';

const { VERDICT_META, el, renderFindings, summaryLine } = globalThis.PhishGuardUI;
const GMAIL_ORIGIN = 'https://mail.google.com/';

let activeTab = null;

function emptyState(text) {
  return el('p', 'pg-empty', text);
}

async function sendMessage(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response || !response.ok) throw new Error((response && response.error) || 'No response from PhishGuard');
  return response;
}

function renderResultCard(result) {
  const meta = VERDICT_META[result.verdict] || VERDICT_META.suspicious;
  const card = el('article', `pg-card pg-card--${result.verdict}`);

  const header = el('header', 'pg-card__header');
  header.appendChild(el('span', `pg-pill pg-pill--${result.verdict}`, meta.label));
  header.appendChild(el('span', 'pg-card__score', `${result.score}/100`));
  card.appendChild(header);

  const meter = el('div', 'pg-meter');
  meter.setAttribute('role', 'meter');
  meter.setAttribute('aria-valuemin', '0');
  meter.setAttribute('aria-valuemax', '100');
  meter.setAttribute('aria-valuenow', String(result.score));
  meter.setAttribute('aria-label', 'Risk score');
  const fill = el('div', 'pg-meter__fill');
  fill.style.width = `${result.score}%`;
  meter.appendChild(fill);
  card.appendChild(meter);

  card.appendChild(el('p', 'pg-card__subject', result.subject || '(no subject)'));
  const senderText = result.sender.name ? `${result.sender.name} <${result.sender.email}>` : result.sender.email;
  card.appendChild(el('p', 'pg-card__sender', senderText));
  card.appendChild(el('p', 'pg-card__summary', `${summaryLine(result)}. ${meta.advice}`));

  if (result.findings.length) {
    card.appendChild(renderFindings(result.findings));
  }

  if (result.sender.email) {
    const trusted = result.verdict === 'trusted';
    const button = el('button', 'pg-btn', trusted ? 'Stop trusting sender' : 'Trust sender');
    button.type = 'button';
    button.addEventListener('click', async () => {
      if (!trusted && result.verdict === 'phishing' &&
          !window.confirm(`This email looks like phishing. Trust ${result.sender.email} anyway?`)) {
        return;
      }
      button.disabled = true;
      try {
        await sendMessage({ type: trusted ? 'PG_UNTRUST_SENDER' : 'PG_TRUST_SENDER', email: result.sender.email });
      } catch (err) {
        button.disabled = false;
        button.textContent = `Failed: ${err.message}`;
      }
    });
    const actions = el('div', 'pg-card__actions');
    actions.appendChild(button);
    card.appendChild(actions);
  }
  return card;
}

function renderCurrent(tabEntry) {
  const container = document.getElementById('current');
  container.replaceChildren();

  if (!activeTab || typeof activeTab.url !== 'string' || !activeTab.url.startsWith(GMAIL_ORIGIN)) {
    container.appendChild(emptyState('Open Gmail (mail.google.com) in this tab. PhishGuard scans emails automatically when you open them.'));
    return;
  }
  if (!tabEntry || !tabEntry.messages || !tabEntry.messages.length) {
    container.appendChild(emptyState('No email is open. Open an email and PhishGuard will scan it automatically.'));
    return;
  }
  for (const result of tabEntry.messages) container.appendChild(renderResultCard(result));
}

function renderTrusted(trustedSenders) {
  const list = document.getElementById('trusted');
  list.replaceChildren();
  if (!trustedSenders.length) {
    list.appendChild(el('li', 'pg-empty', 'No trusted senders yet.'));
    return;
  }
  for (const email of [...trustedSenders].sort()) {
    const item = el('li', 'pg-trusted__item');
    item.appendChild(el('span', 'pg-trusted__email', email));
    const remove = el('button', 'pg-btn pg-btn--ghost', 'Remove');
    remove.type = 'button';
    remove.setAttribute('aria-label', `Remove ${email} from trusted senders`);
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try {
        await sendMessage({ type: 'PG_UNTRUST_SENDER', email });
      } catch {
        remove.disabled = false;
      }
    });
    item.appendChild(remove);
    list.appendChild(item);
  }
}

async function render() {
  const { tabResults = {}, trustedSenders = [] } = await chrome.storage.local.get(['tabResults', 'trustedSenders']);
  renderCurrent(activeTab ? tabResults[activeTab.id] : null);
  renderTrusted(trustedSenders);
}

async function getTabOrNull(tabId) {
  try {
    return await chrome.tabs.get(tabId);
  } catch {
    return null;
  }
}

// In the toolbar popup this is the active tab. When popup.html is opened as a regular tab
// (for debugging or automated tests), the active tab would be the popup itself, so use
// ?tabId=<id> if given, otherwise the most recently scanned Gmail tab.
async function resolveTargetTab() {
  const requested = Number(new URLSearchParams(window.location.search).get('tabId'));
  if (Number.isInteger(requested) && requested > 0) return getTabOrNull(requested);

  const self = await chrome.tabs.getCurrent();
  if (!self) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab || null;
  }

  const { tabResults = {} } = await chrome.storage.local.get('tabResults');
  const newestFirst = Object.entries(tabResults).sort((a, b) => b[1].updatedAt - a[1].updatedAt);
  for (const [id] of newestFirst) {
    const tab = await getTabOrNull(Number(id));
    if (tab) return tab;
  }
  return null;
}

async function init() {
  document.getElementById('version').textContent = `v${chrome.runtime.getManifest().version}`;
  activeTab = await resolveTargetTab();
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes.tabResults || changes.trustedSenders)) render();
  });
  await render();
}

init();
