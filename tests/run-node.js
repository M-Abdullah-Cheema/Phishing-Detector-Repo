#!/usr/bin/env node
/* Runs the analyzer tests in Node with no dependencies: `node tests/run-node.js` */
'use strict';

const Analyzer = require('../analyzer.js');
const { createHarness } = require('./harness.js');
const fixtures = require('./fixtures/emails.js');
const registerAnalyzerTests = require('./analyzer.test.js');

const harness = createHarness();
registerAnalyzerTests(harness, Analyzer, fixtures);
const results = harness.run();

let currentSuite = null;
for (const r of results) {
  if (r.suite !== currentSuite) {
    currentSuite = r.suite;
    console.log(`\n${currentSuite}`);
  }
  console.log(`  ${r.passed ? 'PASS' : 'FAIL'}  ${r.name}`);
  if (!r.passed) console.log(`        ${r.error}`);
}

const failed = results.filter((r) => !r.passed).length;
console.log(`\n${results.length - failed}/${results.length} tests passed`);
process.exitCode = failed ? 1 : 0;
