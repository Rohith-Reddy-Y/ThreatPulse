#!/bin/sh
# Run every ThreatPulse test suite (no node_modules needed).
# The data suite and the auth/AI/server suites use different module shims,
# so they run as two separate node --test invocations.
cd "$(dirname "$0")/.." || exit 1
echo "== data / API / notifications suite"
sh tests/run.sh || exit 1
echo "== auth / admin / AI / server suite"
node --no-warnings --test tests/auth.test.js tests/ai.test.js tests/server.test.js
