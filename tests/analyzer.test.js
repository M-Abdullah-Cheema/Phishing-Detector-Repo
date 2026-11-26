/* Analyzer unit tests. Registered by tests/run-node.js and tests/test-runner.js. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.registerAnalyzerTests = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  return function registerAnalyzerTests({ describe, it, assert }, Analyzer, fixtures) {
    const h = Analyzer.helpers;
    const ids = (result) => result.findings.map((f) => f.id);

    describe('helpers', () => {
      it('extracts registrable domains, including multi-part suffixes', () => {
        assert.equal(h.getRegistrableDomain('mail.google.com'), 'google.com');
        assert.equal(h.getRegistrableDomain('a.b.example.co.uk'), 'example.co.uk');
        assert.equal(h.getRegistrableDomain('shop.daraz.com.pk'), 'daraz.com.pk');
        assert.equal(h.getRegistrableDomain('Example.COM.'), 'example.com');
        assert.equal(h.getRegistrableDomain('10.0.0.1'), '10.0.0.1');
      });

      it('recognises IPv4 and IPv6 hosts', () => {
        assert.ok(h.isIpAddress('192.168.1.1'));
        assert.ok(h.isIpAddress('[2001:db8::1]'));
        assert.ok(!h.isIpAddress('999.1.1.1'));
        assert.ok(!h.isIpAddress('example.com'));
      });

      it('normalises look-alike characters', () => {
        assert.equal(h.skeleton('paypa1'), h.skeleton('paypal'));
        assert.equal(h.skeleton('rnicrosoft'), h.skeleton('microsoft'));
        assert.equal(h.skeleton('g00gle'), h.skeleton('google'));
      });

      it('computes edit distance', () => {
        assert.equal(h.levenshtein('kitten', 'sitting'), 3);
        assert.equal(h.levenshtein('google', 'goggle'), 1);
        assert.equal(h.levenshtein('', 'abc'), 3);
      });

      it('only treats link text as a domain when it really looks like one', () => {
        assert.equal(h.domainFromLinkText('https://www.paypal.com/signin'), 'paypal.com');
        assert.equal(h.domainFromLinkText('www.example.org'), 'example.org');
        assert.equal(h.domainFromLinkText('example.com.'), 'example.com');
        assert.equal(h.domainFromLinkText('invoice.pdf'), null);
        assert.equal(h.domainFromLinkText('Click here'), null);
      });

      it('ignores non-web links and unwraps Google redirects', () => {
        assert.equal(h.parseLink('mailto:someone@example.com'), null);
        assert.equal(h.parseLink('javascript:alert(1)'), null);
        assert.equal(h.parseLink('not a url'), null);
        assert.equal(h.parseLink('https://www.google.com/url?q=https://evil.example/x').hostname, 'evil.example');
      });

      it('classifies risky attachments', () => {
        assert.equal(h.classifyAttachment('report.pdf.exe').weight, 45);
        assert.equal(h.classifyAttachment('setup.exe').weight, 40);
        assert.equal(h.classifyAttachment('budget.xlsm').weight, 30);
        assert.equal(h.classifyAttachment('login.html').weight, 25);
        assert.equal(h.classifyAttachment('photos.zip').weight, 10);
        assert.equal(h.classifyAttachment('notes.pdf'), null);
        assert.equal(h.classifyAttachment('README'), null);
      });
    });

    describe('brand impersonation detection', () => {
      const flagged = {
        'paypa1.com': 'homoglyph',
        'rnicrosoft-login.com': 'homoglyph',
        'goggle.com': 'typo',
        'amazon-account-verify.net': 'combined',
        'appleid-support.com': 'combined',
        'pay-pal.com': 'combined',
        'paypal.xyz': 'unofficial-domain',
        'paypal.com.secure-login.ru': 'subdomain',
        'netflix-billing.web.app': 'subdomain',
      };
      for (const [host, reason] of Object.entries(flagged)) {
        it(`flags ${host} (${reason})`, () => {
          const hit = h.findImpersonation(host);
          assert.ok(hit, `${host} should be flagged`);
          assert.equal(hit.reason, reason);
        });
      }

      const clean = [
        'paypal.com', 'www.paypal.com', 'accounts.google.com', 'gmail.com', 'outlook.com', 'github.com',
        'cloud-services.com', 'apply-now.com', 'chase-design.com', 'applebees.com', 'groups.io', 'linked-data.org',
      ];
      for (const host of clean) {
        it(`does not flag ${host}`, () => {
          assert.equal(h.findImpersonation(host), null);
        });
      }
    });

    describe('fixtures', () => {
      for (const fixture of fixtures) {
        it(fixture.name, () => {
          const result = Analyzer.analyzeEmail(fixture.email);
          assert.equal(result.verdict, fixture.expect, `verdict (score ${result.score}, findings ${ids(result).join(', ')})`);
          for (const id of fixture.mustInclude || []) assert.includes(ids(result), id);
          for (const id of fixture.mustExclude || []) assert.notIncludes(ids(result), id);
          if (typeof fixture.maxScore === 'number') assert.ok(result.score <= fixture.maxScore, `score ${result.score} > ${fixture.maxScore}`);
        });
      }
    });

    describe('result shape and scoring', () => {
      const phish = fixtures[0].email;

      it('explains every finding', () => {
        const result = Analyzer.analyzeEmail(phish);
        assert.atLeast(result.findings.length, 1);
        for (const f of result.findings) {
          assert.ok(f.id && f.title && f.explanation, `finding ${f.id} needs id, title and explanation`);
          assert.includes(['low', 'medium', 'high'], f.severity);
          assert.ok(Array.isArray(f.evidence));
        }
      });

      it('sorts findings by weight and caps the score at 100', () => {
        const result = Analyzer.analyzeEmail(phish);
        for (let i = 1; i < result.findings.length; i++) {
          assert.ok(result.findings[i - 1].weight >= result.findings[i].weight, 'findings should be sorted by weight');
        }
        assert.ok(result.score <= 100);
      });

      it('handles empty or malformed input without throwing', () => {
        assert.equal(Analyzer.analyzeEmail(undefined).verdict, 'safe');
        assert.equal(Analyzer.analyzeEmail({ links: [null, { href: '::::' }], attachments: [null, 'a.exe'] }).verdict, 'suspicious');
      });

      it('caps evidence lists so the UI stays readable', () => {
        const links = Array.from({ length: 12 }, (_, i) => ({ text: 'Open', href: `http://10.0.0.${i + 1}/` }));
        const result = Analyzer.analyzeEmail({ links });
        const ipFinding = result.findings.find((f) => f.id === 'ip-address-link');
        assert.equal(ipFinding.evidence.length, 6);
        assert.ok(/7 more/.test(ipFinding.evidence[5]));
      });
    });

    describe('trusted senders', () => {
      const phish = fixtures[0].email;

      it('marks a trusted sender as trusted but still reports findings', () => {
        const result = Analyzer.analyzeEmail(phish, { trustedSenders: ['SERVICE@paypa1-security.com'] });
        assert.equal(result.verdict, 'trusted');
        assert.ok(result.trusted);
        assert.atLeast(result.findings.length, 1);
      });

      it('requires an exact address match', () => {
        const result = Analyzer.analyzeEmail(phish, { trustedSenders: ['paypa1-security.com', 'other@paypa1-security.com'] });
        assert.equal(result.verdict, 'phishing');
      });
    });
  };
});
