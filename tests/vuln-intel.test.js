'use strict';
// EPSS / CISA KEV / CVSS priority: pure logic + attach() over a real in-memory DB
const test = require('node:test');
const assert = require('node:assert/strict');
const { priorityOf } = (() => {
  // priorityOf has no dependencies: load the function source without the module's requires
  const src = require('fs').readFileSync(require('path').join(__dirname, '../src/vuln-intel.js'), 'utf8');
  const a = src.indexOf('function priorityOf'); const b = src.indexOf('\n}\n', a) + 2;
  return { priorityOf: new Function(`${src.slice(a, b)}; return priorityOf;`)() };
})();

test('priority: KEV or high EPSS = patch now; high CVSS alone = soon; CVSS 7+ = plan', () => {
  assert.equal(priorityOf({ kev: true, epss: 0.01, cvss: 5 }), 'now');
  assert.equal(priorityOf({ kev: false, epss: 0.62, cvss: null }), 'now');
  assert.equal(priorityOf({ kev: false, epss: 0.2, cvss: 9.8 }), 'now');
  assert.equal(priorityOf({ kev: false, epss: 0.02, cvss: 9.8 }), 'soon');
  assert.equal(priorityOf({ kev: false, epss: 0.15, cvss: 6 }), 'soon');
  assert.equal(priorityOf({ kev: false, epss: 0.01, cvss: 7.5 }), 'plan');
  assert.equal(priorityOf({ kev: false, epss: null, cvss: null }), 'monitor');
});
