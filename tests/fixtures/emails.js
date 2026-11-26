/*
 * Sample emails in the analyzer's input format.
 * `expect` is the required verdict; `mustInclude` / `mustExclude` list finding ids.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PhishGuardFixtures = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  return [
    {
      name: 'PayPal credential phish with homoglyph domain and disguised link',
      expect: 'phishing',
      mustInclude: ['brand-impersonation', 'sender-lookalike-domain', 'link-text-mismatch', 'link-lookalike-domain', 'urgency-language', 'credential-request', 'generic-greeting'],
      email: {
        subject: 'Urgent: Your account has been limited',
        sender: { name: 'PayPal Security', email: 'service@paypa1-security.com' },
        bodyText: 'Dear Customer, we detected unusual activity. Please verify your account within 24 hours or your account will be suspended.',
        links: [{ text: 'https://www.paypal.com/signin', href: 'http://paypa1-security.com/login' }],
        attachments: [],
      },
    },
    {
      name: 'Microsoft 365 password-expiry phish linking to an IP address',
      expect: 'phishing',
      mustInclude: ['brand-impersonation', 'ip-address-link', 'suspicious-tld', 'credential-request'],
      email: {
        subject: 'Action required: password expires today',
        sender: { name: 'Microsoft 365', email: 'no-reply@office-notify.xyz' },
        bodyText: 'Your mailbox password expires today. Confirm your password to keep access to your email.',
        links: [{ text: 'Keep my password', href: 'http://192.168.13.37/owa/login.php' }],
        attachments: [],
      },
    },
    {
      name: 'Invoice with executable disguised as PDF',
      expect: 'phishing',
      mustInclude: ['dangerous-attachment', 'urgency-language', 'credential-request'],
      email: {
        subject: 'Overdue invoice #20931',
        sender: { name: 'Accounts Department', email: 'billing@acme-supplies.com' },
        bodyText: 'Please see the attached invoice and pay immediately by wire transfer.',
        links: [],
        attachments: [{ name: 'Invoice_2026.pdf.exe' }],
      },
    },
    {
      name: 'Display name contains a spoofed Apple address',
      expect: 'phishing',
      mustInclude: ['display-name-email-mismatch', 'brand-impersonation'],
      email: {
        subject: 'Your Apple ID was used to sign in',
        sender: { name: 'support@apple.com', email: 'help@random-mailer.net' },
        bodyText: 'If this was not you, review your account.',
        links: [],
        attachments: [],
      },
    },
    {
      name: 'Amazon impersonation from free webmail',
      expect: 'suspicious',
      mustInclude: ['brand-impersonation'],
      email: {
        subject: 'Order problem',
        sender: { name: 'Amazon Support', email: 'amazon.support.team@gmail.com' },
        bodyText: 'There was a problem with your recent order. Reply to this message to resolve it.',
        links: [],
        attachments: [],
      },
    },
    {
      name: 'Brand name hidden in the subdomain of an unrelated domain',
      expect: 'suspicious',
      mustInclude: ['link-lookalike-domain'],
      email: {
        subject: 'Statement available',
        sender: { name: 'Billing', email: 'statements@notices-mail.com' },
        bodyText: 'Your monthly statement is ready.',
        links: [{ text: 'View statement', href: 'https://paypal.com.account-verify.ru/login' }],
        attachments: [],
      },
    },
    {
      name: 'Punycode (IDN homograph) link',
      expect: 'suspicious',
      mustInclude: ['punycode-domain'],
      email: {
        subject: 'Shared document',
        sender: { name: 'Docs', email: 'share@files-example.org' },
        bodyText: 'A document was shared with you.',
        links: [{ text: 'Open document', href: 'https://xn--pple-43d.com/doc' }],
        attachments: [],
      },
    },
    {
      name: 'Legitimate GitHub notification',
      expect: 'safe',
      mustExclude: ['brand-impersonation', 'link-text-mismatch', 'link-lookalike-domain'],
      maxScore: 0,
      email: {
        subject: '[org/repo] New pull request #42',
        sender: { name: 'GitHub', email: 'notifications@github.com' },
        bodyText: 'A new pull request was opened by octocat. View it on GitHub.',
        links: [
          { text: 'View it on GitHub', href: 'https://github.com/org/repo/pull/42' },
          { text: 'unsubscribe', href: 'https://github.com/notifications/unsubscribe-auth/abc' },
        ],
        attachments: [],
      },
    },
    {
      name: 'Legitimate Google security alert',
      expect: 'safe',
      maxScore: 0,
      email: {
        subject: 'Security alert',
        sender: { name: 'Google', email: 'no-reply@accounts.google.com' },
        bodyText: "We noticed a new sign-in to your Google Account on a Windows device. If this was you, you don't need to do anything. If not, we'll help you secure your account.",
        links: [
          { text: 'Check activity', href: 'https://accounts.google.com/AccountChooser?continue=https://myaccount.google.com/notifications' },
          { text: 'myaccount.google.com/notifications', href: 'https://myaccount.google.com/notifications' },
        ],
        attachments: [],
      },
    },
    {
      name: 'Newsletter with a shortened link stays below the warning threshold',
      expect: 'safe',
      mustInclude: ['url-shortener'],
      email: {
        subject: 'This week at the university library',
        sender: { name: 'Library Newsletter', email: 'news@library.example.edu' },
        bodyText: 'New arrivals, opening hours and upcoming workshops.',
        links: [{ text: 'Read more', href: 'https://bit.ly/3abcXYZ' }],
        attachments: [{ name: 'schedule.pdf' }],
      },
    },
    {
      name: 'Google redirect wrapper is unwrapped before checking',
      expect: 'suspicious',
      mustInclude: ['link-text-mismatch'],
      email: {
        subject: 'Document',
        sender: { name: 'Colleague', email: 'colleague@example.com' },
        bodyText: 'See the link.',
        links: [{ text: 'www.dropbox.com/s/report', href: 'https://www.google.com/url?q=https://files-share.example.net/report&sa=D' }],
        attachments: [],
      },
    },
  ];
});
