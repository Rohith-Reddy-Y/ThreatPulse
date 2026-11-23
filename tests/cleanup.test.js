'use strict';
// deleteUser removes AI chats; disabled admins can be deleted; AI cache prunes expired rows.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { load } = require('./data-helpers');

test('deleteUser removes the user\'s AI threads and messages', () => {
  const { db } = load();
  const u = db.createUser('alice', 'Alice', 'h', 's', 'analyst', null, 'a@x.io');
  const t = db.createThread(u.id, 'hello');
  db.addMessage(t, 'user', 'hi');
  assert.equal(db.getDb().prepare('SELECT COUNT(*) c FROM ai_messages WHERE thread_id = ?').get(t).c, 1);
  assert.equal(db.deleteUser(u.id).success, true);
  const d = db.getDb();
  assert.equal(d.prepare('SELECT COUNT(*) c FROM ai_threads WHERE user_id = ?').get(u.id).c, 0);
  assert.equal(d.prepare('SELECT COUNT(*) c FROM ai_messages WHERE thread_id = ?').get(t).c, 0);
});

test('a disabled admin can be deleted while one active admin remains; the last active admin cannot', () => {
  const { db } = load();
  const a1 = db.createUser('admin1', 'A1', 'h', 's', 'admin', null, null);
  const a2 = db.createUser('admin2', 'A2', 'h', 's', 'admin', null, null);
  db.getDb().prepare('UPDATE users SET is_active = 0 WHERE id = ?').run(a2.id);
  assert.equal(db.deleteUser(a2.id).success, true);
  assert.equal(db.deleteUser(a1.id).success, false);
});

test('AI cache prune removes only expired entries', () => {
  const env = load();
  const cache = require(path.join(__dirname, '..', 'src', 'ai', 'cache.js'));
  const d = env.db.getDb();
  d.prepare('INSERT INTO ai_cache (cache_key, response, created_at) VALUES (?,?,?)')
    .run('old', 'x', new Date(Date.now() - 2 * 864e5).toISOString());
  cache.set('summary', 'fresh', 'y');
  assert.equal(cache.prune(), 1);
  assert.equal(d.prepare('SELECT COUNT(*) c FROM ai_cache').get().c, 1);
});
