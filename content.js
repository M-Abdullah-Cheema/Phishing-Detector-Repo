/*
 * Content script: finds opened emails via the matching provider adapter, analyzes them locally,
 * shows a warning banner above each one, and reports the results to the service worker.
 * Email content is never sent anywhere; only the analysis results are stored, in chrome.storage.local.
 */
(() => {
  'use strict';

  const Analyzer = globalThis.PhishGuardAnalyzer;
  const UI = globalThis.PhishGuardUI;
  const provider = (globalThis.PhishGuardProviders || []).find((p) => p.matches(window.location));
  if (!Analyzer || !UI || !provider) return;

  const BANNER_ATTR = 'data-phishguard-banner';
  const SCAN_DEBOUNCE_MS = 400;
  const SCAN_MAX_WAIT_MS = 1500;
  const MAX_CACHED_RESULTS = 200;

  const resultCache = new Map();
  let trustedSenders = [];
  let lastReportKey = null;
  let scanTimer = null;
  let pendingSince = 0;
  let observer = null;

  function extensionAlive() {
    return Boolean(chrome.runtime && chrome.runtime.id);
  }

  function shutdown() {
    if (observer) observer.disconnect();
    clearTimeout(scanTimer);
  }

  function sendMessage(message) {
    if (!extensionAlive()) {
      shutdown();
      return Promise.resolve(null);
    }
    return chrome.runtime.sendMessage(message).catch((err) => {
      console.warn('[PhishGuard] message failed:', err && err.message);
      return null;
    });
  }

  function scheduleScan(delay = SCAN_DEBOUNCE_MS) {
    const now = Date.now();
    if (!pendingSince) pendingSince = now;
    const wait = Math.max(0, Math.min(delay, pendingSince + SCAN_MAX_WAIT_MS - now));
    clearTimeout(scanTimer);
    scanTimer = setTimeout(runScan, wait);
  }

  function runScan() {
    pendingSince = 0;
    scanTimer = null;
    if (!extensionAlive()) {
      shutdown();
      return;
    }
    try {
      scan();
    } catch (err) {
      console.error('[PhishGuard] scan failed:', err);
    }
  }

  function analyze(message) {
    const cached = resultCache.get(message.key);
    if (cached) return cached;

    const email = message.extract();
    const analysis = Analyzer.analyzeEmail(email, { trustedSenders });
    const result = {
      key: message.key,
      provider: provider.id,
      subject: email.subject,
      sender: email.sender,
      verdict: analysis.verdict,
      score: analysis.score,
      findings: analysis.findings,
      analyzedAt: Date.now(),
    };

    resultCache.set(message.key, result);
    if (resultCache.size > MAX_CACHED_RESULTS) resultCache.delete(resultCache.keys().next().value);
    return result;
  }

  function scan() {
    const results = [];
    for (const message of provider.findOpenMessages(document, window.location)) {
      const result = analyze(message);
      results.push(result);

      const existing = message.container.querySelector(`[${BANNER_ATTR}]`);
      if (existing && existing.getAttribute(BANNER_ATTR) === message.key) continue;
      if (existing) existing.remove();
      message.bannerParent.insertBefore(buildBanner(result), message.bannerBefore);
    }
    report(results);
  }

  function report(results) {
    const reportKey = results.map((r) => `${r.key}:${r.verdict}:${r.score}`).join('|');
    if (reportKey === lastReportKey) return;
    lastReportKey = reportKey;
    sendMessage({ type: 'PG_VIEW_RESULTS', results });
  }

  function trustSender(result) {
    if (result.verdict === 'phishing') {
      const ok = window.confirm(
        `PhishGuard rated this email as likely phishing.\n\nTrust ${result.sender.email} anyway? Future warnings for this exact address will be suppressed.`,
      );
      if (!ok) return;
    }
    sendMessage({ type: 'PG_TRUST_SENDER', email: result.sender.email });
  }

  function buildBanner(result) {
    const { el } = UI;
    const meta = UI.VERDICT_META[result.verdict] || UI.VERDICT_META.suspicious;

    const banner = el('div', `pg-banner pg-banner--${result.verdict}`);
    banner.setAttribute(BANNER_ATTR, result.key);
    banner.setAttribute('role', result.verdict === 'phishing' ? 'alert' : 'status');

    const header = el('div', 'pg-banner__header');
    header.appendChild(el('span', 'pg-banner__icon', meta.icon));

    const headline = el('div', 'pg-banner__headline');
    headline.appendChild(el('strong', 'pg-banner__title', `PhishGuard: ${meta.label}`));
    headline.appendChild(el('span', 'pg-banner__subtitle', UI.summaryLine(result)));
    header.appendChild(headline);

    const actions = el('div', 'pg-banner__actions');
    header.appendChild(actions);
    banner.appendChild(header);

    let advice = meta.advice;
    if (result.verdict === 'trusted' && result.findings.length) {
      advice += ` ${result.findings.length} indicator(s) were still detected; expand the details to review them.`;
    }
    banner.appendChild(el('p', 'pg-banner__advice', advice));

    if (result.findings.length) {
      const details = UI.renderFindings(result.findings);
      details.hidden = result.verdict !== 'phishing';
      const toggle = el('button', 'pg-btn', details.hidden ? 'Why?' : 'Hide reasons');
      toggle.type = 'button';
      toggle.setAttribute('aria-expanded', String(!details.hidden));
      toggle.addEventListener('click', () => {
        details.hidden = !details.hidden;
        toggle.textContent = details.hidden ? 'Why?' : 'Hide reasons';
        toggle.setAttribute('aria-expanded', String(!details.hidden));
      });
      actions.appendChild(toggle);
      banner.appendChild(details);
    }

    if (result.sender.email) {
      const trusted = result.verdict === 'trusted';
      const trustBtn = el('button', 'pg-btn', trusted ? 'Stop trusting sender' : 'Trust sender');
      trustBtn.type = 'button';
      trustBtn.title = trusted
        ? `Remove ${result.sender.email} from your trusted senders`
        : `Suppress warnings for ${result.sender.email}`;
      trustBtn.addEventListener('click', () => {
        if (trusted) sendMessage({ type: 'PG_UNTRUST_SENDER', email: result.sender.email });
        else trustSender(result);
      });
      actions.appendChild(trustBtn);
    }

    const dismiss = el('button', 'pg-btn pg-btn--ghost', 'Dismiss');
    dismiss.type = 'button';
    dismiss.title = 'Hide this banner (the result stays available in the PhishGuard popup)';
    dismiss.addEventListener('click', () => {
      banner.hidden = true;
    });
    actions.appendChild(dismiss);

    banner.appendChild(el('p', 'pg-banner__footer', 'Analyzed locally on your device. No email content left your browser.'));
    return banner;
  }

  function rescanAll() {
    resultCache.clear();
    lastReportKey = null;
    document.querySelectorAll(`[${BANNER_ATTR}]`).forEach((node) => node.remove());
    scheduleScan(0);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes.trustedSenders) return;
    trustedSenders = changes.trustedSenders.newValue || [];
    rescanAll();
  });

  chrome.storage.local.get({ trustedSenders: [] }).then((stored) => {
    trustedSenders = Array.isArray(stored.trustedSenders) ? stored.trustedSenders : [];
    observer = new MutationObserver(() => scheduleScan());
    observer.observe(document.body, { childList: true, subtree: true });
    scheduleScan(0);
  });
})();
