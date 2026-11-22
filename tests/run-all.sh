#!/bin/sh
# Run every ThreatPulse test suite (no node_modules needed).
# The data suite and the auth/AI/server suites use different module shims,
# so they run as two separate node --test invocations.
cd "$(dirname "$0")/.." || exit 1
echo "== data / API / notifications suite"
sh tests/run.sh || exit 1
echo "== auth / admin / AI / server / authz-matrix suite"
node --no-warnings --test tests/auth.test.js tests/auth-hardening.test.js tests/ai.test.js tests/inputs-ai.test.js tests/server.test.js tests/authz-matrix.test.js || exit 1
echo "== feeds / net-guard / IOC / scraper suite"
node --no-warnings --test tests/classify.test.js tests/rss-fetch.test.js tests/net-guard.test.js tests/api-fetchers.test.js tests/ioc-enrich.test.js tests/scraper-browser.test.js tests/ransomware-live.test.js
