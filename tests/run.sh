#!/bin/sh
# Runs the ThreatPulse test suite without node_modules: better-sqlite3, express,
# axios and nodemailer resolve to the shims in tests/shims/modules.
cd "$(dirname "$0")/.." || exit 1
NODE_PATH="$PWD/tests/shims/modules" exec node --no-warnings --test --test-concurrency=1 "$@" tests/schema.test.js tests/articles.test.js tests/routes.test.js tests/notifications.test.js tests/sources-seed.test.js tests/cleanup.test.js tests/guest-scope.test.js tests/flows-data.test.js
