#!/usr/bin/env node
/*
 * Runs analyzer.js over the labeled evaluation set and reports a confusion matrix,
 * precision / recall / accuracy, and how often each detection rule fired.
 *
 *   node tests/evaluate-metrics.js            print the report and write EVALUATION.md
 *   node tests/evaluate-metrics.js --no-write print only
 */
'use strict';

const fs = require('fs');
const path = require('path');
const Analyzer = require('../analyzer.js');
const cases = require('./fixtures/evaluation-set.js');

const OUTPUT_FILE = path.resolve(__dirname, '..', 'EVALUATION.md');

const RULE_NAMES = {
  'sender-lookalike-domain': 'Sender domain imitates a brand',
  'brand-impersonation': 'Display name claims a brand the domain does not belong to',
  'display-name-email-mismatch': 'Display name shows a different email address',
  'link-text-mismatch': 'Link text hides a different destination',
  'link-lookalike-domain': 'Link goes to a domain imitating a brand',
  'punycode-domain': 'Punycode / international look-alike characters',
  'ip-address-link': 'Link to a raw IP address',
  'dangerous-attachment': 'Dangerous attachment type',
  'credential-request': 'Asks for passwords, payment or personal data',
  'urgency-language': 'Urgency or threat language',
  'url-shortener': 'URL shortener',
  'suspicious-tld': 'Abused top-level domain',
  'generic-greeting': 'Generic greeting',
};

const pct = (n) => (Number.isFinite(n) ? `${(n * 100).toFixed(1)}%` : 'n/a');
const ratio = (a, b) => (b ? a / b : NaN);

function confusion(rows, isPositive) {
  const m = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const r of rows) {
    const predicted = isPositive(r.result);
    const actual = r.label === 'phishing';
    if (predicted && actual) m.tp++;
    else if (predicted && !actual) m.fp++;
    else if (!predicted && actual) m.fn++;
    else m.tn++;
  }
  const precision = ratio(m.tp, m.tp + m.fp);
  const recall = ratio(m.tp, m.tp + m.fn);
  return {
    ...m,
    precision,
    recall,
    accuracy: ratio(m.tp + m.tn, rows.length),
    f1: ratio(2 * precision * recall, precision + recall),
    falsePositiveRate: ratio(m.fp, m.fp + m.tn),
  };
}

function scoreStats(rows) {
  const scores = rows.map((r) => r.result.score);
  if (!scores.length) return { mean: NaN, min: NaN, max: NaN };
  return {
    mean: scores.reduce((a, b) => a + b, 0) / scores.length,
    min: Math.min(...scores),
    max: Math.max(...scores),
  };
}

function ruleBreakdown(rows) {
  const phishingTotal = rows.filter((r) => r.label === 'phishing').length;
  const benignTotal = rows.length - phishingTotal;
  const stats = new Map(Object.keys(RULE_NAMES).map((id) => [id, { id, phishing: 0, benign: 0, weights: [] }]));
  for (const r of rows) {
    for (const f of r.result.findings) {
      if (!stats.has(f.id)) stats.set(f.id, { id: f.id, phishing: 0, benign: 0, weights: [] });
      const s = stats.get(f.id);
      s[r.label === 'phishing' ? 'phishing' : 'benign']++;
      s.weights.push(f.weight);
    }
  }
  return [...stats.values()]
    .map((s) => ({
      ...s,
      total: s.phishing + s.benign,
      phishingRate: ratio(s.phishing, phishingTotal),
      benignRate: ratio(s.benign, benignTotal),
      avgWeight: s.weights.length ? s.weights.reduce((a, b) => a + b, 0) / s.weights.length : 0,
      // Share of this rule's firings that were on real phishing emails.
      rulePrecision: ratio(s.phishing, s.phishing + s.benign),
    }))
    .sort((a, b) => b.total - a.total || b.phishing - a.phishing || a.id.localeCompare(b.id));
}

function table(headers, rows, align) {
  const line = (cells) => `| ${cells.join(' | ')} |`;
  const sep = headers.map((_, i) => (align && align[i] === 'r' ? '---:' : '---'));
  return [line(headers), line(sep), ...rows.map(line)].join('\n');
}

function matrixTable(m) {
  return table(
    ['', 'Actually phishing', 'Actually benign'],
    [
      ['**Flagged**', `TP = ${m.tp}`, `FP = ${m.fp}`],
      ['**Not flagged**', `FN = ${m.fn}`, `TN = ${m.tn}`],
    ],
  );
}

function metricsTable(m) {
  return table(
    ['Metric', 'Formula', 'Value'],
    [
      ['Precision', 'TP / (TP + FP)', pct(m.precision)],
      ['Recall (detection rate)', 'TP / (TP + FN)', pct(m.recall)],
      ['Accuracy', '(TP + TN) / total', pct(m.accuracy)],
      ['F1 score', '2 x P x R / (P + R)', pct(m.f1)],
      ['False-positive rate', 'FP / (FP + TN)', pct(m.falsePositiveRate)],
    ],
    [null, null, 'r'],
  );
}

function topFindings(result, n = 3) {
  return result.findings.slice(0, n).map((f) => `${f.id} (+${f.weight})`).join(', ') || 'none';
}

function buildReport(rows) {
  const phishingRows = rows.filter((r) => r.label === 'phishing');
  const benignRows = rows.filter((r) => r.label === 'benign');
  const flagged = (res) => res.verdict === 'suspicious' || res.verdict === 'phishing';
  const strict = (res) => res.verdict === 'phishing';
  const primary = confusion(rows, flagged);
  const strictM = confusion(rows, strict);
  const rules = ruleBreakdown(rows);
  const misclassified = rows.filter((r) => flagged(r.result) !== (r.label === 'phishing'));
  const pStats = scoreStats(phishingRows);
  const bStats = scoreStats(benignRows);
  const { suspicious, phishing } = Analyzer.THRESHOLDS;

  const verdictCounts = (subset) => ['phishing', 'suspicious', 'safe']
    .map((v) => `${subset.filter((r) => r.result.verdict === v).length} ${v === 'safe' ? 'low risk' : v}`)
    .join(', ');

  const md = [];
  md.push('# PhishGuard Mail Analyzer: Evaluation Report');
  md.push('');
  md.push('> Generated by `node tests/evaluate-metrics.js` from `analyzer.js` ' +
    `v${Analyzer.VERSION}. Re-run the script after any change to the analyzer; do not edit the numbers by hand.`);
  md.push('');
  md.push('## 1. Method');
  md.push('');
  md.push(`- **Dataset:** ${rows.length} labeled emails (${phishingRows.length} phishing, ${benignRows.length} benign) in ` +
    '`tests/fixtures/evaluation-set.js`. They are the 11 unit-test fixtures plus additional hand-written cases modelled on common real-world campaigns ' +
    '(delivery scams, account-verification lures, malicious attachments, business email compromise) and on everyday legitimate mail ' +
    '(university notices, OTPs, receipts, shipping updates, newsletters).');
  md.push('- **Ground truth** reflects what each email really is, not what PhishGuard outputs. Some cases are deliberately hard: phishing with no links or with a clean, newly registered domain, and legitimate newsletters that use click-tracking links.');
  md.push(`- **Analyzer:** the unmodified detection engine. A score of ${suspicious} or more is "suspicious" and ${phishing} or more is "likely phishing". No trusted senders are configured.`);
  md.push('- **Positive class = phishing.** The primary evaluation counts an email as *flagged* when PhishGuard shows any warning (orange "suspicious" or red "likely phishing"), because that is when the user is told to be careful. A stricter evaluation that only counts red "likely phishing" verdicts is also reported.');
  md.push('- **Caveat:** this is a small, author-constructed dataset for demonstrating and reasoning about the heuristics. It is not a sample of real inbox traffic, so the numbers indicate behaviour on known patterns rather than real-world performance.');
  md.push('');
  md.push('## 2. Results: any warning shown (primary)');
  md.push('');
  md.push(matrixTable(primary));
  md.push('');
  md.push(metricsTable(primary));
  md.push('');
  md.push('## 3. Results: red "likely phishing" verdict only (strict)');
  md.push('');
  md.push(matrixTable(strictM));
  md.push('');
  md.push(metricsTable(strictM));
  md.push('');
  md.push('## 4. Verdicts and score distribution');
  md.push('');
  md.push(table(
    ['Class', 'Emails', 'Verdicts', 'Mean score', 'Min', 'Max'],
    [
      ['Phishing', phishingRows.length, verdictCounts(phishingRows), pStats.mean.toFixed(1), pStats.min, pStats.max],
      ['Benign', benignRows.length, verdictCounts(benignRows), bStats.mean.toFixed(1), bStats.min, bStats.max],
    ],
    [null, 'r', null, 'r', 'r', 'r'],
  ));
  md.push('');
  md.push('## 5. Rule-by-rule breakdown');
  md.push('');
  md.push('"Fired on phishing" is the share of phishing emails where the rule triggered. "Fired on benign" is the same for benign emails. ' +
    '"Rule precision" is the share of the rule\'s firings that were on real phishing emails.');
  md.push('');
  md.push(table(
    ['Rule', 'Id', 'Total', 'Fired on phishing', 'Fired on benign', 'Rule precision', 'Avg points'],
    rules.map((r) => [
      RULE_NAMES[r.id] || r.id,
      `\`${r.id}\``,
      r.total,
      `${r.phishing} (${pct(r.phishingRate)})`,
      `${r.benign} (${pct(r.benignRate)})`,
      r.total ? pct(r.rulePrecision) : 'n/a',
      r.total ? r.avgWeight.toFixed(1) : '-',
    ]),
    [null, null, 'r', 'r', 'r', 'r', 'r'],
  ));
  md.push('');
  md.push('## 6. Misclassified emails');
  md.push('');
  if (!misclassified.length) {
    md.push('None.');
  } else {
    md.push(table(
      ['Email', 'Truth', 'Verdict', 'Score', 'Rules that fired', 'Error type'],
      misclassified.map((r) => [
        r.name,
        r.label,
        r.result.verdict === 'safe' ? 'low risk' : r.result.verdict,
        r.result.score,
        topFindings(r.result, 4),
        r.label === 'phishing' ? 'False negative (missed)' : 'False positive (false alarm)',
      ]),
      [null, null, null, 'r', null, null],
    ));
    md.push('');
    md.push('**Why these happen:**');
    md.push('');
    if (misclassified.some((r) => r.label === 'phishing')) {
      md.push('- **False negatives** are phishing emails with no technical indicator a content-only heuristic can see: no brand name, no look-alike domain, no disguised link and no risky attachment. Business email compromise ("buy gift cards for me") and lures on clean, newly registered domains fall into this group. Catching them needs signals that are not in the page: sender reputation, domain age, or SPF/DKIM/DMARC results.');
      md.push('- **Known matching gap:** the phrase rules match whole words exactly, so "gift cards" (plural) does not match the `gift card` phrase and "urgently" does not match `urgent`. Matching word variants would raise recall on social-engineering emails like the gift-card case above, at some risk of extra false positives.');
    }
    if (misclassified.some((r) => r.label === 'benign')) {
      md.push('- **False positives** come from legitimate patterns that look like attacks, most commonly newsletters whose links go through a click-tracking domain, so the visible domain differs from the real destination. The "Trust sender" allowlist is the user-facing fix for repeat senders.');
    }
  }
  md.push('');
  md.push('## 7. Per-email results');
  md.push('');
  md.push(table(
    ['#', 'Email', 'Truth', 'Verdict', 'Score', 'Correct'],
    rows.map((r, i) => [
      i + 1,
      r.name,
      r.label,
      r.result.verdict === 'safe' ? 'low risk' : r.result.verdict,
      r.result.score,
      flagged(r.result) === (r.label === 'phishing') ? 'yes' : '**no**',
    ]),
    ['r', null, null, null, 'r', null],
  ));
  md.push('');
  md.push('## 8. Limitations of the detector');
  md.push('');
  md.push('- **DOM selector fragility:** Gmail\'s class names are undocumented and can change. `providers/gmail.js` has fallback selectors and logs a console warning when they are used, but a large redesign could still break extraction.');
  md.push('- **No authentication headers:** SPF, DKIM, DMARC and Reply-To are not exposed in the Gmail page, so PhishGuard cannot verify that the sender address is genuine.');
  md.push('- **Click-tracking false positives:** marketing links routed through tracking domains trigger the link-text-mismatch rule.');
  md.push('- **Curated lists:** brand, shortener and top-level-domain lists are hand-maintained, and domain parsing uses a small built-in suffix list instead of the full Public Suffix List.');
  md.push('- **Content-only analysis:** there is no reputation, domain-age or URL-scanning lookup, by design (privacy: nothing leaves the browser).');
  md.push('');

  return { markdown: md.join('\n'), primary, strict: strictM, rules, misclassified, phishingRows, benignRows };
}

function printConsole(report) {
  const { primary: m, strict: s, rules, misclassified } = report;
  const pad = (v, n) => String(v).padStart(n);
  console.log('\nPhishGuard evaluation');
  console.log(`  Dataset: ${report.phishingRows.length + report.benignRows.length} emails ` +
    `(${report.phishingRows.length} phishing, ${report.benignRows.length} benign)\n`);
  console.log('  Confusion matrix (flagged = suspicious or likely phishing)');
  console.log('                      actual phishing   actual benign');
  console.log(`    flagged           TP = ${pad(m.tp, 3)}         FP = ${pad(m.fp, 3)}`);
  console.log(`    not flagged       FN = ${pad(m.fn, 3)}         TN = ${pad(m.tn, 3)}\n`);
  console.log(`  Precision ${pct(m.precision)}   Recall ${pct(m.recall)}   Accuracy ${pct(m.accuracy)}   F1 ${pct(m.f1)}   FPR ${pct(m.falsePositiveRate)}`);
  console.log(`  Strict (red verdict only): Precision ${pct(s.precision)}   Recall ${pct(s.recall)}   Accuracy ${pct(s.accuracy)}\n`);
  console.log('  Rules (fired on phishing / benign)');
  for (const r of rules.filter((x) => x.total)) {
    console.log(`    ${r.id.padEnd(28)} ${pad(r.phishing, 3)} / ${pad(r.benign, 2)}`);
  }
  console.log(`\n  Misclassified: ${misclassified.length}`);
  for (const r of misclassified) {
    console.log(`    [${r.label === 'phishing' ? 'FN' : 'FP'}] ${r.name} (score ${r.result.score}, ${r.result.verdict})`);
  }
}

function main() {
  const labels = new Set(cases.map((c) => c.label));
  if ([...labels].some((l) => l !== 'phishing' && l !== 'benign')) throw new Error('Labels must be "phishing" or "benign"');
  const names = new Set();
  for (const c of cases) {
    if (names.has(c.name)) throw new Error(`Duplicate case name: ${c.name}`);
    names.add(c.name);
  }

  const rows = cases.map((c) => ({ ...c, result: Analyzer.analyzeEmail(c.email) }));
  const report = buildReport(rows);
  printConsole(report);

  if (!process.argv.includes('--no-write')) {
    fs.writeFileSync(OUTPUT_FILE, report.markdown + '\n');
    console.log(`\n  Wrote ${path.relative(process.cwd(), OUTPUT_FILE) || OUTPUT_FILE}`);
  }
}

main();
