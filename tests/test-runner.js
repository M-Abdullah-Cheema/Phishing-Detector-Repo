/* Browser glue: runs every registered test suite and renders the results. */
(function () {
  'use strict';

  const harness = PhishGuardTestHarness.createHarness();
  registerAnalyzerTests(harness, PhishGuardAnalyzer, PhishGuardFixtures);
  registerGmailAdapterTests(harness, PhishGuardAnalyzer);
  const results = harness.run();

  const container = document.getElementById('results');
  let list = null;
  let currentSuite = null;
  for (const r of results) {
    if (r.suite !== currentSuite) {
      currentSuite = r.suite;
      const heading = document.createElement('h2');
      heading.textContent = currentSuite;
      list = document.createElement('ul');
      container.append(heading, list);
    }
    const item = document.createElement('li');
    item.className = r.passed ? 'pass-item' : 'fail-item';
    item.textContent = r.name;
    if (!r.passed) {
      const error = document.createElement('span');
      error.className = 'error';
      error.textContent = r.error;
      item.appendChild(error);
    }
    list.appendChild(item);
  }

  const failed = results.filter((r) => !r.passed).length;
  const summary = document.getElementById('summary');
  summary.textContent = `${results.length - failed}/${results.length} tests passed`;
  summary.classList.add(failed ? 'fail' : 'pass');
  document.title = `${failed ? 'FAIL' : 'PASS'} - PhishGuard tests`;
})();
