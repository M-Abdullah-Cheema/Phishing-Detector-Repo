/* Minimal dependency-free test harness that works in both Node and the browser. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PhishGuardTestHarness = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function format(value) {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }

  function createHarness() {
    const tests = [];
    let suite = '';

    function describe(name, fn) {
      const parent = suite;
      suite = parent ? `${parent} > ${name}` : name;
      try {
        fn();
      } finally {
        suite = parent;
      }
    }

    function it(name, fn) {
      tests.push({ suite, name, fn });
    }

    const assert = {
      ok(value, message) {
        if (!value) throw new Error(message || `Expected truthy value, got ${format(value)}`);
      },
      equal(actual, expected, message) {
        if (actual !== expected) {
          throw new Error(`${message ? message + ': ' : ''}expected ${format(expected)}, got ${format(actual)}`);
        }
      },
      includes(list, item, message) {
        if (!list.includes(item)) throw new Error(`${message ? message + ': ' : ''}expected ${format(list)} to include ${format(item)}`);
      },
      notIncludes(list, item, message) {
        if (list.includes(item)) throw new Error(`${message ? message + ': ' : ''}expected ${format(list)} not to include ${format(item)}`);
      },
      atLeast(actual, min, message) {
        if (!(actual >= min)) throw new Error(`${message ? message + ': ' : ''}expected >= ${min}, got ${format(actual)}`);
      },
      below(actual, max, message) {
        if (!(actual < max)) throw new Error(`${message ? message + ': ' : ''}expected < ${max}, got ${format(actual)}`);
      },
    };

    function run() {
      return tests.map(({ suite: s, name, fn }) => {
        try {
          fn();
          return { suite: s, name, passed: true };
        } catch (err) {
          return { suite: s, name, passed: false, error: err && err.message ? err.message : String(err) };
        }
      });
    }

    return { describe, it, assert, run };
  }

  return { createHarness };
});
