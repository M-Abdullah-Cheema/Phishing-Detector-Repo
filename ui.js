/*
 * Shared rendering helpers for the in-page banner (content script) and the popup.
 * Everything is built with createElement/textContent: email-derived strings never reach innerHTML.
 */
(function (root) {
  'use strict';

  const VERDICT_META = {
    phishing: {
      label: 'Likely phishing',
      icon: '!',
      advice: 'Do not click links, open attachments, or reply with personal information. Verify the sender through an official website or phone number.',
    },
    suspicious: {
      label: 'Suspicious email',
      icon: '?',
      advice: 'Be careful with links and attachments in this email. Review the reasons below before acting on it.',
    },
    safe: {
      label: 'Low risk',
      icon: '\u2713',
      advice: 'PhishGuard did not find enough warning signs to flag this email. Stay alert anyway: no automated check is perfect.',
    },
    trusted: {
      label: 'Trusted sender',
      icon: '\u2605',
      advice: 'You marked this sender as trusted, so warnings are suppressed.',
    },
  };

  const SEVERITY_LABELS = { high: 'High', medium: 'Medium', low: 'Low' };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderFindings(findings) {
    const list = el('ul', 'pg-findings');
    for (const f of findings) {
      const item = el('li', `pg-finding pg-finding--${f.severity}`);
      item.appendChild(el('span', `pg-chip pg-chip--${f.severity}`, SEVERITY_LABELS[f.severity] || f.severity));

      const body = el('div', 'pg-finding__body');
      body.appendChild(el('div', 'pg-finding__title', `${f.title} (+${f.weight})`));
      body.appendChild(el('div', 'pg-finding__text', f.explanation));
      if (f.evidence && f.evidence.length) {
        const evidence = el('ul', 'pg-evidence');
        for (const e of f.evidence) evidence.appendChild(el('li', null, e));
        body.appendChild(evidence);
      }
      item.appendChild(body);
      list.appendChild(item);
    }
    return list;
  }

  function summaryLine(result) {
    const count = result.findings.length;
    const signs = count === 1 ? '1 warning sign' : `${count} warning signs`;
    return `Risk score ${result.score}/100 \u00b7 ${signs}`;
  }

  root.PhishGuardUI = { VERDICT_META, el, renderFindings, summaryLine };
})(globalThis);
