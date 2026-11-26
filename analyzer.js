/*
 * PhishGuard Mail Analyzer - detection engine.
 *
 * Pure functions only: no DOM access, no chrome.* APIs, no network requests.
 * The same file runs as a content script, in the browser test runner, and in Node.
 *
 * Input:  { subject, bodyText, sender: { name, email }, links: [{ text, href }], attachments: [{ name }] }
 * Output: { verdict, score, findings: [{ id, category, severity, weight, title, explanation, evidence }], trusted, analyzerVersion }
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PhishGuardAnalyzer = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const VERSION = '1.0.0';
  const THRESHOLDS = Object.freeze({ suspicious: 30, phishing: 60 });

  // `names` are matched against the sender display name, `keywords` against domain labels,
  // `domains` are registrable domains the brand is known to send mail / host pages from.
  const BRANDS = [
    { name: 'PayPal', names: ['paypal'], keywords: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal.co.uk'] },
    {
      name: 'Microsoft',
      names: ['microsoft', 'microsoft 365', 'office 365', 'outlook', 'onedrive', 'sharepoint'],
      keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint'],
      domains: ['microsoft.com', 'office.com', 'office365.com', 'microsoftonline.com', 'microsoft365.com', 'sharepoint.com', 'onedrive.com'],
    },
    { name: 'Apple', names: ['apple', 'icloud', 'itunes', 'app store'], keywords: ['apple', 'icloud', 'itunes'], domains: ['apple.com', 'itunes.com'] },
    { name: 'Amazon', names: ['amazon', 'amazon prime'], keywords: ['amazon'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.ca', 'amazonses.com'] },
    { name: 'Google', names: ['google', 'gmail'], keywords: ['google', 'gmail'], domains: ['google.com', 'youtube.com'] },
    { name: 'Netflix', names: ['netflix'], keywords: ['netflix'], domains: ['netflix.com'] },
    { name: 'Facebook', names: ['facebook', 'instagram'], keywords: ['facebook', 'instagram'], domains: ['facebook.com', 'facebookmail.com', 'instagram.com', 'meta.com'] },
    { name: 'LinkedIn', names: ['linkedin'], keywords: ['linkedin'], domains: ['linkedin.com'] },
    { name: 'DHL', names: ['dhl'], keywords: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
    { name: 'FedEx', names: ['fedex'], keywords: ['fedex'], domains: ['fedex.com'] },
    { name: 'UPS', names: ['ups'], keywords: ['ups'], domains: ['ups.com'] },
    { name: 'DocuSign', names: ['docusign'], keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'Dropbox', names: ['dropbox'], keywords: ['dropbox'], domains: ['dropbox.com', 'dropboxmail.com'] },
    { name: 'Bank of America', names: ['bank of america', 'bofa'], keywords: ['bankofamerica', 'bofa'], domains: ['bankofamerica.com', 'bofa.com'] },
    { name: 'Chase', names: ['chase', 'jpmorgan chase'], keywords: ['chase'], domains: ['chase.com', 'jpmorganchase.com'] },
    { name: 'Wells Fargo', names: ['wells fargo'], keywords: ['wellsfargo'], domains: ['wellsfargo.com'] },
    { name: 'IRS', names: ['irs', 'internal revenue service'], keywords: ['irs'], domains: ['irs.gov'] },
    { name: 'Coinbase', names: ['coinbase'], keywords: ['coinbase'], domains: ['coinbase.com'] },
  ];

  const FREE_MAIL_DOMAINS = new Set([
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com',
    'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com',
    'yandex.com', 'yandex.ru', 'zoho.com',
  ]);

  // Anyone can create a subdomain on these, so the registrable domain says nothing about the owner.
  const HOSTING_PLATFORMS = new Set([
    'amazonaws.com', 'cloudfront.net', 'firebaseapp.com', 'web.app', 'appspot.com', 'github.io', 'netlify.app',
    'vercel.app', 'pages.dev', 'workers.dev', 'herokuapp.com', 'glitch.me', 'blogspot.com', 'wixsite.com',
    'weebly.com', '000webhostapp.com', 'ngrok.io', 'ngrok-free.app', 'azurewebsites.net', 'windows.net',
  ]);

  const KNOWN_LEGIT_DOMAINS = new Set([...FREE_MAIL_DOMAINS, ...BRANDS.flatMap((b) => b.domains)]);

  const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'tiny.cc', 'rb.gy', 't.ly', 'bl.ink', 's.id', 'v.gd', 'lnkd.in', 'qrco.de',
  ]);

  const SUSPICIOUS_TLDS = new Set([
    'zip', 'mov', 'xyz', 'top', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'rest', 'cam', 'buzz',
    'icu', 'cyou', 'sbs', 'monster', 'quest',
  ]);

  // Without a scheme or "www.", link text is only treated as a domain if it ends in one of these,
  // so that file names like "invoice.pdf" are not mistaken for domains.
  const COMMON_TLDS = new Set([
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'io', 'co', 'ai', 'app', 'dev', 'info', 'biz', 'me', 'us', 'uk', 'ca',
    'au', 'de', 'fr', 'in', 'pk', 'ru', 'cn', 'jp', 'br', 'xyz', 'top', 'ly', 'to', 'tv', 'cc',
  ]);

  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'co.nz', 'co.in',
    'net.in', 'org.in', 'co.jp', 'ne.jp', 'com.br', 'com.pk', 'edu.pk', 'gov.pk', 'org.pk', 'net.pk', 'com.cn',
    'com.mx', 'co.za', 'com.sg', 'com.tr', 'com.sa', 'co.kr', 'com.hk', 'com.tw',
  ]);

  const SECURITY_WORDS = new Set([
    'secure', 'security', 'login', 'signin', 'verify', 'verification', 'account', 'accounts', 'support', 'update',
    'service', 'services', 'help', 'helpdesk', 'billing', 'bill', 'alert', 'alerts', 'online', 'auth', 'confirm',
    'id', 'team', 'center', 'safe', 'tracking', 'delivery', 'parcel', 'package', 'shipping', 'notice', 'refund',
    'payment', 'pay', 'wallet', 'recovery', 'reset', 'customer', 'care', 'portal', 'access', 'unlock', 'locked',
    'renew', 'invoice', 'tax', 'mail', 'web',
  ]);

  const URGENCY_PHRASES = [
    'urgent', 'immediately', 'within 24 hours', 'within 48 hours', 'act now', 'action required',
    'account will be suspended', 'account has been suspended', 'account will be closed', 'account has been locked',
    'account has been limited', 'unusual activity', 'suspicious activity', 'unauthorized access', 'final notice',
    'last warning', 'failure to', 'will be terminated', 'expires today', 'limited time', 'verify within',
  ];

  const CREDENTIAL_PHRASES = [
    'verify your account', 'verify your identity', 'confirm your account', 'confirm your identity',
    'confirm your password', 'enter your password', 'login credentials', 'log in to verify', 'sign in to verify',
    'update your payment', 'update your billing', 'payment information', 'billing information',
    'credit card number', 'card details', 'bank account details', 'social security number', 'one-time password',
    'otp', 'pin code', 'wire transfer', 'gift card',
  ];

  const GENERIC_GREETING = /\bdear (?:valued )?(?:customer|user|member|client|account holder|sir\/madam|sir or madam)\b/i;

  const ATTACHMENT_RULES = [
    {
      kind: 'executable',
      weight: 40,
      label: 'executable or script file',
      extensions: ['exe', 'scr', 'pif', 'bat', 'cmd', 'com', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta', 'ps1', 'jar', 'msi', 'msp', 'lnk', 'iso', 'img', 'vhd', 'reg', 'cpl', 'dll'],
    },
    { kind: 'macro', weight: 30, label: 'Office document with macros', extensions: ['docm', 'xlsm', 'pptm', 'dotm', 'xlam'] },
    { kind: 'html', weight: 25, label: 'web page file (can contain a fake login form)', extensions: ['html', 'htm', 'shtml', 'svg'] },
    { kind: 'archive', weight: 10, label: 'compressed archive (can hide other files)', extensions: ['zip', 'rar', '7z', 'gz', 'ace', 'cab'] },
  ];
  const DECOY_EXTENSIONS = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'txt']);

  const MAX_EVIDENCE = 5;

  function str(value) {
    return typeof value === 'string' ? value : value == null ? '' : String(value);
  }

  function escapeRegExp(text) {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function truncate(text, max = 120) {
    return text.length > max ? text.slice(0, max - 1) + '\u2026' : text;
  }

  function unique(items) {
    return [...new Set(items)];
  }

  function normalizeHost(host) {
    return str(host).trim().toLowerCase().replace(/\.$/, '');
  }

  function isIpAddress(host) {
    const h = normalizeHost(host);
    if (h.startsWith('[') && h.endsWith(']')) return true;
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    return !!m && m.slice(1).every((octet) => Number(octet) <= 255);
  }

  // Approximation of the Public Suffix List that covers the common multi-part suffixes.
  function getRegistrableDomain(host) {
    const h = normalizeHost(host);
    if (!h || isIpAddress(h)) return h;
    const parts = h.split('.');
    if (parts.length <= 2) return h;
    const lastTwo = parts.slice(-2).join('.');
    return MULTI_PART_SUFFIXES.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
  }

  function getTld(host) {
    const parts = normalizeHost(host).split('.');
    return parts[parts.length - 1] || '';
  }

  // Collapses characters that look alike so "paypa1" and "paypal" compare equal.
  function skeleton(text) {
    return str(text)
      .toLowerCase()
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w')
      .replace(/[1il|!]/g, 'l')
      .replace(/0/g, 'o')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/8/g, 'b');
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const curr = [i];
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = curr;
    }
    return prev[b.length];
  }

  function isInternationalized(host) {
    const h = normalizeHost(host);
    return /[^\x00-\x7f]/.test(h) || h.split('.').some((label) => label.startsWith('xn--'));
  }

  function brandOwnsDomain(brand, registrable) {
    return brand.domains.includes(registrable);
  }

  function matchBrandLabel(label) {
    const tokens = label.split('-').filter(Boolean);
    const joined = tokens.join('');

    for (const brand of BRANDS) {
      for (const keyword of brand.keywords) {
        if (label === keyword) return { brand, reason: 'unofficial-domain' };
        if (tokens.length > 1 && joined === keyword) return { brand, reason: 'combined' };
        if (tokens.includes(keyword) && tokens.some((t) => t !== keyword && SECURITY_WORDS.has(t))) {
          return { brand, reason: 'combined' };
        }

        for (const token of tokens) {
          if (token.startsWith(keyword) && SECURITY_WORDS.has(token.slice(keyword.length))) return { brand, reason: 'combined' };
          if (token.endsWith(keyword) && SECURITY_WORDS.has(token.slice(0, -keyword.length))) return { brand, reason: 'combined' };
          if (keyword.length < 4 || token === keyword) continue;

          const tokenSkeleton = skeleton(token);
          const keywordSkeleton = skeleton(keyword);
          if (tokenSkeleton === keywordSkeleton) return { brand, reason: 'homoglyph' };

          const distance = levenshtein(tokenSkeleton, keywordSkeleton);
          const closeEnough = (keyword.length >= 6 && distance === 1) || (keyword.length >= 9 && distance === 2);
          if (token.length >= 6 && closeEnough) return { brand, reason: 'typo' };
        }
      }
    }
    return null;
  }

  // Returns { brand, reason, host, registrable } when the host looks like it impersonates a known brand.
  function findImpersonation(rawHost) {
    const host = normalizeHost(rawHost);
    if (!host || isIpAddress(host)) return null;
    const registrable = getRegistrableDomain(host);
    const onHostingPlatform = HOSTING_PLATFORMS.has(registrable);
    if (KNOWN_LEGIT_DOMAINS.has(registrable) && !onHostingPlatform) return null;

    if (!onHostingPlatform) {
      const hit = matchBrandLabel(registrable.split('.')[0]);
      if (hit) return { ...hit, host, registrable };
    }

    const sub = host.length > registrable.length ? host.slice(0, -(registrable.length + 1)) : '';
    if (sub) {
      const subTokens = sub.split(/[.-]/);
      for (const brand of BRANDS) {
        const embedsDomain = brand.domains.some((d) => ('.' + sub + '.').includes('.' + d + '.'));
        const embedsKeyword = brand.keywords.some((k) => k.length >= 4 && subTokens.includes(k));
        if (embedsDomain || embedsKeyword) return { brand, reason: 'subdomain', host, registrable };
      }
    }
    return null;
  }

  function describeImpersonation(hit) {
    const { brand, host, registrable } = hit;
    switch (hit.reason) {
      case 'homoglyph':
        return `"${host}" imitates ${brand.name} by swapping in look-alike characters (for example "1" for "l" or "rn" for "m").`;
      case 'typo':
        return `"${host}" is only one or two letters away from ${brand.name}'s name, a common typosquatting trick.`;
      case 'combined':
        return `"${host}" combines the ${brand.name} name with other words, but it is not an official ${brand.name} domain.`;
      case 'subdomain':
        return `"${host}" puts ${brand.name}'s name in the subdomain to look official, but the domain actually belongs to "${registrable}".`;
      default:
        return `"${host}" uses the ${brand.name} name on a domain that is not one of ${brand.name}'s known official domains.`;
    }
  }

  const REASON_SHORT = {
    homoglyph: 'look-alike characters',
    typo: 'misspelling',
    combined: 'brand name plus extra words',
    subdomain: 'brand name in subdomain',
    'unofficial-domain': 'unofficial domain',
  };

  function parseLink(href) {
    if (!href) return null;
    let url;
    try {
      url = new URL(href);
    } catch {
      return null;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

    if ((url.hostname === 'www.google.com' || url.hostname === 'google.com') && url.pathname === '/url') {
      const target = url.searchParams.get('q') || url.searchParams.get('url');
      try {
        const inner = target ? new URL(target) : null;
        if (inner && (inner.protocol === 'http:' || inner.protocol === 'https:')) url = inner;
      } catch {
        /* keep the redirect URL itself */
      }
    }
    return url;
  }

  function domainFromLinkText(text) {
    const t = str(text).trim().replace(/[)\].,;:!?'"]+$/, '');
    if (!t || /\s/.test(t) || t.length > 2048) return null;
    const m = /^(https?:\/\/)?(www\.)?((?:[a-z0-9-]+\.)+([a-z]{2,63}))(?::\d+)?(?:[/?#].*)?$/i.exec(t);
    if (!m) return null;
    const looksLikeUrl = Boolean(m[1] || m[2]);
    if (!looksLikeUrl && !COMMON_TLDS.has(m[4].toLowerCase())) return null;
    return m[3].toLowerCase();
  }

  function sameOwner(hostA, hostB) {
    const a = getRegistrableDomain(hostA);
    const b = getRegistrableDomain(hostB);
    if (a === b) return true;
    return BRANDS.some((brand) => brandOwnsDomain(brand, a) && brandOwnsDomain(brand, b));
  }

  function senderDomain(address) {
    const at = address.lastIndexOf('@');
    return at === -1 ? '' : normalizeHost(address.slice(at + 1));
  }

  function finding(id, category, weight, title, explanation, evidence = []) {
    const cleanEvidence = unique(evidence.filter(Boolean));
    const shown = cleanEvidence.slice(0, MAX_EVIDENCE);
    if (cleanEvidence.length > MAX_EVIDENCE) shown.push(`\u2026and ${cleanEvidence.length - MAX_EVIDENCE} more`);
    return {
      id,
      category,
      weight,
      severity: weight >= 30 ? 'high' : weight >= 15 ? 'medium' : 'low',
      title,
      explanation,
      evidence: shown,
    };
  }

  function checkSender(email, findings) {
    const { name, email: address } = email.sender;
    const domain = senderDomain(address);
    const registrable = getRegistrableDomain(domain);

    const shownAddress = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.exec(name);
    if (shownAddress && address && shownAddress[0].toLowerCase() !== address) {
      findings.push(finding(
        'display-name-email-mismatch', 'sender', 35,
        'Display name shows a different email address',
        `The display name shows "${shownAddress[0]}", but the real sender address is "${address}". Attackers put a trusted address in the name field because many mail apps show only the name.`,
        [`Name: ${name}`, `Actual address: ${address}`],
      ));
    }

    if (name && domain) {
      const brand = BRANDS.find((b) => b.names.some((n) => new RegExp('\\b' + escapeRegExp(n) + '\\b', 'i').test(name)));
      if (brand && !brandOwnsDomain(brand, registrable)) {
        const freeMail = FREE_MAIL_DOMAINS.has(registrable);
        findings.push(finding(
          'brand-impersonation', 'sender', freeMail ? 40 : 30,
          `Sender claims to be ${brand.name} but uses another domain`,
          `The sender name "${name}" suggests ${brand.name}, but the email was sent from "${domain}", which ${brand.name} does not use.` +
            (freeMail ? ` "${registrable}" is a free webmail service that anyone can sign up for.` : ''),
          [`From: ${name} <${address}>`],
        ));
      }
    }

    const hit = domain ? findImpersonation(domain) : null;
    if (hit) {
      findings.push(finding(
        'sender-lookalike-domain', 'sender', 40,
        `Sender domain imitates ${hit.brand.name}`,
        describeImpersonation(hit),
        [`From: ${address}`],
      ));
    }
  }

  function checkLinks(email, findings) {
    const mismatches = [];
    const ipLinks = [];
    const shortened = [];
    const lookalikes = [];

    for (const link of email.links) {
      const url = parseLink(link.href);
      if (!url) continue;
      const host = normalizeHost(url.hostname);
      const registrable = getRegistrableDomain(host);

      const shownDomain = domainFromLinkText(link.text);
      if (shownDomain && !sameOwner(shownDomain, host)) {
        mismatches.push(`Shows "${truncate(link.text, 60)}" but opens "${host}"`);
      }
      if (isIpAddress(host)) ipLinks.push(truncate(url.href));
      if (URL_SHORTENERS.has(registrable)) shortened.push(truncate(url.href));

      const hit = findImpersonation(host);
      if (hit) lookalikes.push(`${host} (imitates ${hit.brand.name}: ${REASON_SHORT[hit.reason]})`);
    }

    if (mismatches.length) {
      findings.push(finding(
        'link-text-mismatch', 'links', 30,
        'Link text hides a different destination',
        'The visible text of a link shows one website, but clicking it opens a different one. This is a classic way to disguise a malicious link.',
        mismatches,
      ));
    }
    if (lookalikes.length) {
      findings.push(finding(
        'link-lookalike-domain', 'links', 30,
        'Links lead to domains imitating a known brand',
        'One or more links go to domains made to look like a trusted company. Attackers use these to host fake login pages.',
        lookalikes,
      ));
    }
    if (ipLinks.length) {
      findings.push(finding(
        'ip-address-link', 'links', 25,
        'Links point to a raw IP address',
        'Legitimate companies almost always link to named domains. Links to bare IP addresses are often used to avoid domain blocklists.',
        ipLinks,
      ));
    }
    if (shortened.length) {
      findings.push(finding(
        'url-shortener', 'links', 10,
        'Links use a URL shortener',
        'Shortened links hide the real destination until you click them.',
        shortened,
      ));
    }
  }

  function checkDomains(email, findings) {
    const hosts = [];
    const fromDomain = senderDomain(email.sender.email);
    if (fromDomain) hosts.push({ host: fromDomain, label: `sender ${fromDomain}` });
    for (const link of email.links) {
      const url = parseLink(link.href);
      if (url) hosts.push({ host: normalizeHost(url.hostname), label: `link ${normalizeHost(url.hostname)}` });
    }

    const internationalized = hosts.filter((h) => isInternationalized(h.host)).map((h) => h.label);
    if (internationalized.length) {
      findings.push(finding(
        'punycode-domain', 'links', 30,
        'Domain uses look-alike international characters',
        'A domain contains internationalized (punycode or non-Latin) characters, which can make a fake domain look identical to a real one, such as "\u0430pple.com" written with a Cyrillic "\u0430".',
        internationalized,
      ));
    }

    const riskyTld = hosts.filter((h) => !isIpAddress(h.host) && SUSPICIOUS_TLDS.has(getTld(h.host))).map((h) => h.label);
    if (riskyTld.length) {
      findings.push(finding(
        'suspicious-tld', 'links', 10,
        'Uses a domain ending often abused for phishing',
        'The sender or a link uses a top-level domain (such as .xyz, .top or .zip) that is cheap to register and frequently used in phishing campaigns.',
        riskyTld,
      ));
    }
  }

  function matchPhrases(text, phrases) {
    return phrases.filter((p) => new RegExp('\\b' + escapeRegExp(p) + '\\b', 'i').test(text));
  }

  function checkContent(email, findings) {
    const text = (email.subject + ' \n ' + email.bodyText).replace(/\s+/g, ' ').toLowerCase();

    const urgency = matchPhrases(text, URGENCY_PHRASES);
    if (urgency.length) {
      findings.push(finding(
        'urgency-language', 'content', Math.min(20, urgency.length * 5),
        'Pressures you to act quickly',
        'The email creates urgency or threatens consequences. Rushing you is a common social-engineering tactic to stop you from checking carefully.',
        urgency.map((p) => `"${p}"`),
      ));
    }

    const credential = matchPhrases(text, CREDENTIAL_PHRASES);
    if (credential.length) {
      findings.push(finding(
        'credential-request', 'content', Math.min(30, credential.length * 10),
        'Asks for passwords, payment or personal details',
        'The email asks you to provide or confirm sensitive information. Legitimate organizations rarely request this by email.',
        credential.map((p) => `"${p}"`),
      ));
    }

    const greeting = GENERIC_GREETING.exec(text);
    if (greeting) {
      findings.push(finding(
        'generic-greeting', 'content', 5,
        'Uses a generic greeting',
        'The email addresses you generically instead of by name, which suggests it was sent in bulk.',
        [`"${greeting[0]}"`],
      ));
    }
  }

  function classifyAttachment(fileName) {
    const parts = fileName.toLowerCase().split('.');
    if (parts.length < 2) return null;
    const ext = parts[parts.length - 1];
    const rule = ATTACHMENT_RULES.find((r) => r.extensions.includes(ext));
    if (!rule) return null;
    const previous = parts.length > 2 ? parts[parts.length - 2] : '';
    if (rule.kind === 'executable' && DECOY_EXTENSIONS.has(previous)) {
      return { weight: 45, text: `${fileName} (disguised as .${previous}, really .${ext})` };
    }
    return { weight: rule.weight, text: `${fileName} (${rule.label})` };
  }

  function checkAttachments(email, findings) {
    const risky = email.attachments.map(classifyAttachment).filter(Boolean);
    if (!risky.length) return;
    const worst = Math.max(...risky.map((r) => r.weight));
    findings.push(finding(
      'dangerous-attachment', 'attachments', Math.min(50, worst + (risky.length - 1) * 5),
      worst >= 40 ? 'Attachment can run code on your computer' : 'Attachment type is commonly abused',
      'Attachments of this type can run programs, contain macros, or open fake login pages. Do not open them unless you were expecting the file and have confirmed it with the sender.',
      risky.map((r) => r.text),
    ));
  }

  function normalizeInput(input) {
    const e = input || {};
    const sender = e.sender || {};
    return {
      subject: str(e.subject),
      bodyText: str(e.bodyText),
      sender: { name: str(sender.name).trim(), email: str(sender.email).trim().toLowerCase() },
      links: Array.isArray(e.links)
        ? e.links.filter(Boolean).map((l) => ({ text: str(l.text).trim(), href: str(l.href).trim() }))
        : [],
      attachments: Array.isArray(e.attachments)
        ? e.attachments.map((a) => str(typeof a === 'string' ? a : a && a.name).trim()).filter(Boolean)
        : [],
    };
  }

  function verdictForScore(score) {
    if (score >= THRESHOLDS.phishing) return 'phishing';
    if (score >= THRESHOLDS.suspicious) return 'suspicious';
    return 'safe';
  }

  function analyzeEmail(input, options = {}) {
    const email = normalizeInput(input);
    const findings = [];
    checkSender(email, findings);
    checkLinks(email, findings);
    checkDomains(email, findings);
    checkContent(email, findings);
    checkAttachments(email, findings);
    findings.sort((a, b) => b.weight - a.weight);

    const score = Math.min(100, findings.reduce((sum, f) => sum + f.weight, 0));
    const trustedSenders = new Set((options.trustedSenders || []).map((s) => str(s).trim().toLowerCase()));
    const trusted = Boolean(email.sender.email) && trustedSenders.has(email.sender.email);

    return {
      verdict: trusted ? 'trusted' : verdictForScore(score),
      score,
      findings,
      trusted,
      analyzerVersion: VERSION,
    };
  }

  return {
    VERSION,
    THRESHOLDS,
    analyzeEmail,
    helpers: {
      getRegistrableDomain,
      isIpAddress,
      skeleton,
      levenshtein,
      findImpersonation,
      domainFromLinkText,
      parseLink,
      classifyAttachment,
    },
  };
});
