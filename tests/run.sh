#!/bin/sh
# Runs the ThreatPulse test suite without node_modules: better-sqlite3, express,
# axios and nodemailer resolve to the shims in tests/shims/node_modules.
cd "$(dirname "$0")/.." || exit 1
NODE_PATH="$PWD/tests/shims/node_modules" exec node --no-warnings --test --test-concurrency=1 "$@" tests/*.test.js
