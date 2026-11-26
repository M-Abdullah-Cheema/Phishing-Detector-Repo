/*
 * Browser-only tests for the Gmail adapter, run against a static mock of Gmail's message markup.
 * They protect the extraction logic; if Gmail changes its class names, update providers/gmail.js
 * and this mock together.
 */
(function (root) {
  'use strict';

  const MOCK_THREAD = `
    <h2 class="hP">Urgent: verify your account</h2>
    <div class="adn ads" data-message-id="#msg-f:1001">
      <span class="gD" email="Security@PayPa1-Alerts.com" name="PayPal">PayPal</span>
      <div class="wrapper"><div class="a3s aiL">
        Dear Customer, please verify your account immediately.
        <a href="http://paypa1-alerts.com/login">https://www.paypal.com</a>
        <a href="mailto:help@example.com">help</a>
      </div></div>
      <span class="aV3">statement.pdf.exe</span>
      <div download_url="application/zip:archive.zip:https://mail.google.com/x"></div>
    </div>
    <div class="adn ads">
      <span class="gD" email="friend@example.com" name="Friend">Friend</span>
      <div class="a3s aiL">   </div>
    </div>`;

  root.registerGmailAdapterTests = function ({ describe, it, assert }, Analyzer) {
    const gmail = (root.PhishGuardProviders || []).find((p) => p.id === 'gmail');

    function mockDocument() {
      return new DOMParser().parseFromString(`<!DOCTYPE html><body>${MOCK_THREAD}</body>`, 'text/html');
    }

    describe('Gmail adapter', () => {
      it('is registered and matches mail.google.com only', () => {
        assert.ok(gmail, 'gmail provider should be registered');
        assert.ok(gmail.matches({ hostname: 'mail.google.com' }));
        assert.ok(!gmail.matches({ hostname: 'outlook.live.com' }));
      });

      it('finds expanded messages and skips ones whose body has not loaded', () => {
        const messages = gmail.findOpenMessages(mockDocument());
        assert.equal(messages.length, 1);
        assert.equal(messages[0].key, 'gmail:#msg-f:1001');
      });

      it('extracts sender, subject, links and attachments', () => {
        const email = gmail.findOpenMessages(mockDocument())[0].extract();
        assert.equal(email.subject, 'Urgent: verify your account');
        assert.equal(email.sender.email, 'security@paypa1-alerts.com');
        assert.equal(email.sender.name, 'PayPal');
        assert.equal(email.links.length, 2);
        assert.equal(email.links[0].text, 'https://www.paypal.com');
        assert.equal(email.links[0].href, 'http://paypa1-alerts.com/login');
        assert.ok(email.bodyText.includes('Dear Customer'));
        const names = email.attachments.map((a) => a.name);
        assert.includes(names, 'statement.pdf.exe');
        assert.includes(names, 'archive.zip');
      });

      it('produces a phishing verdict end to end', () => {
        const email = gmail.findOpenMessages(mockDocument())[0].extract();
        assert.equal(Analyzer.analyzeEmail(email).verdict, 'phishing');
      });
    });

    describe('Gmail adapter fallbacks', () => {
      // Same thread without the obfuscated class names (adn, a3s, gD, hP), as if Gmail renamed them.
      const RENAMED_MARKUP = `
        <div data-message-id="#msg-f:2002">
          <h3 class="x1"><span class="x2" email="alerts@paypa1-alerts.com" name="PayPal">PayPal</span></h3>
          <span class="x3" email="me@example.com" name="Me">to me</span>
          <div class="ii gt"><div dir="ltr">Verify your account now.
            <a href="http://paypa1-alerts.com/login">https://www.paypal.com</a></div></div>
        </div>`;

      function withWarnings(fn) {
        const warnings = [];
        const original = console.warn;
        console.warn = (...args) => warnings.push(args.join(' '));
        gmail.resetDiagnostics();
        try {
          fn(warnings);
        } finally {
          console.warn = original;
          gmail.resetDiagnostics();
        }
      }

      function parse(body, title) {
        return new DOMParser().parseFromString(`<!DOCTYPE html><title>${title || ''}</title><body>${body}</body>`, 'text/html');
      }

      it('still extracts the message when class names change, and warns', () => {
        withWarnings((warnings) => {
          const doc = parse(RENAMED_MARKUP, 'Verify now - me@example.com - Gmail');
          const messages = gmail.findOpenMessages(doc, { hash: '#inbox' });
          assert.equal(messages.length, 1);
          const email = messages[0].extract();
          assert.equal(email.sender.email, 'alerts@paypa1-alerts.com', 'sender must come from the h3, not the recipient');
          assert.equal(email.subject, 'Verify now');
          assert.equal(email.links.length, 1);
          assert.ok(warnings.some((w) => w.includes('div.adn')), 'warns about the message selector');
          assert.ok(warnings.some((w) => w.includes('div.a3s')), 'warns about the body selector');
          assert.ok(warnings.some((w) => w.includes('span.gD')), 'warns about the sender selector');
          assert.ok(warnings.some((w) => w.includes('page title')), 'warns about the subject fallback');
        });
      });

      it('warns only once per fallback', () => {
        withWarnings((warnings) => {
          const doc = parse(RENAMED_MARKUP);
          gmail.findOpenMessages(doc, { hash: '#inbox' });
          const first = warnings.length;
          gmail.findOpenMessages(doc, { hash: '#inbox' });
          assert.equal(warnings.length, first);
        });
      });

      it('does not warn for current Gmail markup', () => {
        withWarnings((warnings) => {
          gmail.findOpenMessages(mockDocument(), { hash: '#inbox' })[0].extract();
          assert.equal(warnings.length, 0, warnings.join(' | '));
        });
      });

      it('does not match nested elements twice when using attribute fallbacks', () => {
        withWarnings(() => {
          const doc = parse(`<div data-message-id="a"><div data-message-id="b">
            <h3><span email="x@example.com" name="X">X</span></h3><div class="ii gt">Hello</div></div></div>`);
          assert.equal(gmail.findOpenMessages(doc, { hash: '#inbox' }).length, 1);
        });
      });
    });
  };
})(globalThis);
