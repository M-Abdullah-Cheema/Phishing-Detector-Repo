/*
 * Gmail provider adapter.
 *
 * A provider knows how to find opened messages in one webmail UI and turn them into the
 * plain object the analyzer expects. Adding another webmail service means adding another
 * file like this one and listing it in manifest.json; content.js and analyzer.js stay unchanged.
 *
 * Gmail's class names are obfuscated and can change without notice, so every lookup has an
 * ordered list of selectors: the first is the current Gmail markup, the rest are fallbacks
 * built on attributes Gmail has kept stable for longer. Using a fallback logs a one-time warning.
 */
(function (root) {
  'use strict';

  const SELECTORS = {
    message: ['div.adn', 'div[data-message-id]', 'div[data-legacy-message-id]'],
    body: ['div.a3s', 'div.ii.gt', 'div.ii'],
    // Recipients also carry [email], so fallbacks stay inside the sender heading (h3).
    sender: ['span.gD[email]', 'h3 span[email]', 'h3 [email]'],
    subject: ['h2.hP', 'h2[data-thread-perm-id]', '[data-thread-perm-id]'],
    attachmentName: ['span.aV3'],
    attachmentDownload: ['[download_url]'],
  };
  const MAX_BODY_CHARS = 20000;
  const MAX_LINKS = 300;
  const OPEN_THREAD_HASH = /\/[A-Za-z]{2,}[A-Za-z0-9]{14,}$/;
  const EMPTY_THREAD_WARNING_MS = 5000;

  const warned = new Set();
  let emptyThread = { hash: null, since: 0 };

  function warnOnce(key, message) {
    if (warned.has(key)) return;
    warned.add(key);
    console.warn(`[PhishGuard] Gmail markup differs from what PhishGuard expects: ${message} ` +
      'Detection may be incomplete; update the selectors in providers/gmail.js.');
  }

  function usedFallback(kind, selector) {
    warnOnce(`fallback:${kind}:${selector}`, `primary ${kind} selector "${SELECTORS[kind][0]}" matched nothing, using fallback "${selector}".`);
  }

  function queryFirst(scope, kind) {
    const selectors = SELECTORS[kind];
    for (let i = 0; i < selectors.length; i++) {
      const node = scope.querySelector(selectors[i]);
      if (node) {
        if (i > 0) usedFallback(kind, selectors[i]);
        return node;
      }
    }
    return null;
  }

  function queryAll(scope, kind) {
    const selectors = SELECTORS[kind];
    for (let i = 0; i < selectors.length; i++) {
      const nodes = [...scope.querySelectorAll(selectors[i])];
      if (nodes.length) {
        if (i > 0) usedFallback(kind, selectors[i]);
        // Attribute fallbacks can match both a container and an element nested inside it.
        return nodes.filter((n) => !nodes.some((other) => other !== n && other.contains(n)));
      }
    }
    return [];
  }

  function queryEvery(scope, kind) {
    const nodes = new Set();
    for (const selector of SELECTORS[kind]) scope.querySelectorAll(selector).forEach((n) => nodes.add(n));
    return [...nodes];
  }

  function cleanText(node) {
    return node ? node.textContent.replace(/\s+/g, ' ').trim() : '';
  }

  function hash(text) {
    let h = 5381;
    for (let i = 0; i < text.length; i++) h = ((h << 5) + h + text.charCodeAt(i)) | 0;
    return (h >>> 0).toString(36);
  }

  function messageId(container) {
    const own = container.getAttribute('data-message-id') || container.getAttribute('data-legacy-message-id');
    if (own) return own;
    const inner = container.querySelector('[data-message-id], [data-legacy-message-id]');
    return inner ? inner.getAttribute('data-message-id') || inner.getAttribute('data-legacy-message-id') : null;
  }

  function subjectFromTitle(doc) {
    // Gmail titles look like "Subject - you@gmail.com - Gmail".
    const m = /^(.*) - [^\s]+@[^\s]+ - Gmail$/.exec(doc.title || '');
    return m ? m[1].trim() : '';
  }

  function extractSubject(doc) {
    const node = queryFirst(doc, 'subject');
    if (node) return cleanText(node);
    const fromTitle = subjectFromTitle(doc);
    if (fromTitle) warnOnce('fallback:subject:title', 'no subject heading found, using the page title instead.');
    return fromTitle;
  }

  function extractAttachments(container) {
    const names = new Set();
    queryEvery(container, 'attachmentName').forEach((node) => {
      const name = cleanText(node);
      if (name) names.add(name);
    });
    // download_url format: "mime/type:file name.ext:https://..."
    queryEvery(container, 'attachmentDownload').forEach((node) => {
      const parts = (node.getAttribute('download_url') || '').split(':');
      if (parts.length >= 3 && parts[1]) names.add(parts[1].trim());
    });
    return [...names].map((name) => ({ name }));
  }

  function extract(doc, container, body, senderEl) {
    const links = [];
    for (const a of body.querySelectorAll('a[href]')) {
      if (links.length >= MAX_LINKS) break;
      links.push({ text: cleanText(a), href: a.getAttribute('href') });
    }
    return {
      provider: 'gmail',
      subject: extractSubject(doc),
      sender: {
        name: (senderEl.getAttribute('name') || cleanText(senderEl)).trim(),
        email: (senderEl.getAttribute('email') || '').trim().toLowerCase(),
      },
      bodyText: (body.innerText || body.textContent || '').slice(0, MAX_BODY_CHARS),
      links,
      attachments: extractAttachments(container),
    };
  }

  // Warns when the URL says a conversation is open but nothing could be extracted for a while.
  function noteEmptyScan(location) {
    const hash = (location && location.hash) || '';
    if (!OPEN_THREAD_HASH.test(hash)) {
      emptyThread = { hash: null, since: 0 };
      return;
    }
    const now = Date.now();
    if (emptyThread.hash !== hash) {
      emptyThread = { hash, since: now };
      return;
    }
    if (now - emptyThread.since >= EMPTY_THREAD_WARNING_MS) {
      warnOnce('empty-thread', 'a conversation appears to be open, but no message body and sender could be found.');
    }
  }

  const gmailProvider = {
    id: 'gmail',

    matches(location) {
      return location.hostname === 'mail.google.com';
    },

    // Returns the expanded messages currently on screen. Collapsed messages in a thread have no body yet.
    findOpenMessages(doc, location) {
      const messages = [];
      for (const container of queryAll(doc, 'message')) {
        const body = queryFirst(container, 'body');
        const senderEl = queryFirst(container, 'sender');
        if (!body || !senderEl || !body.parentNode) continue;
        // Gmail fills the body lazily; scanning it empty would cache a misleading "low risk" result.
        if (!body.textContent.trim() && !body.querySelector('a[href]')) continue;

        const senderEmail = (senderEl.getAttribute('email') || '').toLowerCase();
        const id = messageId(container) || 'h' + hash(senderEmail + '|' + body.textContent.slice(0, 500));
        messages.push({
          key: 'gmail:' + id,
          container,
          bannerParent: body.parentNode,
          bannerBefore: body,
          extract: () => extract(doc, container, body, senderEl),
        });
      }
      if (!messages.length) noteEmptyScan(location);
      return messages;
    },

    resetDiagnostics() {
      warned.clear();
      emptyThread = { hash: null, since: 0 };
    },
  };

  const providers = root.PhishGuardProviders || (root.PhishGuardProviders = []);
  providers.push(gmailProvider);
})(globalThis);
