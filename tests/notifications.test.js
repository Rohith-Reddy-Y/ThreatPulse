'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const axios = require('axios');
const nodemailer = require('nodemailer');
const { load, makeUser, art } = require('./helpers');

function telegramChats() {
  return axios.calls.filter(c => c.url.includes('api.telegram.org')).map(c => c.data.chat_id);
}

function insert(db, a) {
  const r = db.insertArticle(a);
  return { ...a, id: r.id };
}

test('alerts go only to the owning user, honouring threshold + keywords', async () => {
  const env = load();
  const { db } = env;
  const u1 = makeUser(db), u2 = makeUser(db), u3 = makeUser(db);
  db.updateNotificationSettings({ telegram_enabled: 1, telegram_bot_token: 't1', telegram_chat_id: 'chat1', severity_threshold: 'high' }, u1.id);
  db.updateNotificationSettings({ telegram_enabled: 1, telegram_bot_token: 't2', telegram_chat_id: 'chat2', severity_threshold: 'low', keywords_filter: 'ransomware' }, u2.id);
  // u3 has no settings row at all
  const arts = [
    insert(db, art({ user_id: u1.id, severity: 'critical' })),
    insert(db, art({ user_id: u1.id, severity: 'medium' })),
    insert(db, art({ user_id: u2.id, severity: 'low', title: 'New ransomware strain spotted in the wild' })),
    insert(db, art({ user_id: u2.id, severity: 'critical', title: 'Unrelated phishing kit sold on forums' })),
    insert(db, art({ user_id: u3.id, severity: 'critical' })),
  ];
  axios.calls.length = 0;
  await env.api.handleNotifications(arts);
  assert.deepStrictEqual(telegramChats().sort(), ['chat1', 'chat2']);
  const logs = db.getDb().prepare('SELECT user_id, article_id FROM notification_log ORDER BY id').all();
  assert.deepStrictEqual(logs.map(l => [l.user_id, l.article_id]), [[u1.id, arts[0].id], [u2.id, arts[2].id]]);
  // every processed article is flagged
  const unflagged = db.getDb().prepare('SELECT COUNT(*) c FROM articles WHERE notified = 0').get().c;
  assert.strictEqual(unflagged, 0);
});

test('deactivated users stop receiving alerts', async () => {
  const env = load();
  const { db } = env;
  const u = makeUser(db, { active: 0 });
  db.updateNotificationSettings({ telegram_enabled: 1, telegram_bot_token: 't', telegram_chat_id: 'disabled-user' }, u.id);
  axios.calls.length = 0;
  await env.api.handleNotifications([insert(db, art({ user_id: u.id, severity: 'critical' }))]);
  assert.deepStrictEqual(telegramChats(), []);
});

test('articles from system sources (user_id NULL on a fresh DB) alert the admin', async () => {
  // On a fresh DB (every Render boot) the admin is created AFTER initializeSchema,
  // so seeded system sources keep user_id NULL and their articles had no owner.
  const env = load();
  const { db } = env;
  const admin = makeUser(db, { username: 'admin', role: 'admin' });
  db.updateNotificationSettings({ telegram_enabled: 1, telegram_bot_token: 't', telegram_chat_id: 'admin-chat' }, admin.id);
  axios.calls.length = 0;
  await env.api.handleNotifications([insert(db, art({ user_id: null, severity: 'critical' }))]);
  assert.deepStrictEqual(telegramChats(), ['admin-chat']);
});

test('no SMTP configured: email alerts are logged as failed and nothing throws', async () => {
  const env = load();
  const { db } = env;
  const u = makeUser(db);
  db.updateNotificationSettings({ email_enabled: 1, email: 'u@example.com', severity_threshold: 'low' }, u.id);
  const a = insert(db, art({ user_id: u.id, severity: 'high' }));
  await env.api.handleNotifications([a]);
  const log = db.getDb().prepare('SELECT * FROM notification_log').get();
  assert.strictEqual(log.status, 'failed');
  assert.match(log.error_message, /SMTP not configured/);
  assert.strictEqual(db.getArticleById(a.id).notified, 1);
  await env.api.handleNotifications([]);
  await env.api.handleNotifications(undefined);
});

test('email alert HTML escapes feed-supplied content', async () => {
  process.env.SMTP_HOST = 'smtp.example.com'; process.env.SMTP_USER = 'u'; process.env.SMTP_PASS = 'p';
  try {
    load();
    const { sendAlertEmail } = require(path.join(__dirname, '..', 'src', 'notifications', 'email-notifier.js'));
    nodemailer.sent.length = 0;
    const r = await sendAlertEmail([{
      title: '<a href="https://evil.example">Reset your password</a>',
      description: '<img src=x onerror=alert(1)>',
      url: 'https://ok.example/"><script>x</script>',
      author: '<b>me</b>', source_name: 'AT&T <Labs>', severity: 'high',
      published_date: new Date().toISOString(),
    }], 'to@example.com');
    assert.strictEqual(r.success, true);
    const html = nodemailer.sent[0].html;
    assert.ok(!html.includes('<a href="https://evil.example">'), 'title injected raw');
    assert.ok(!html.includes('<img src=x'), 'description injected raw');
    assert.ok(!html.includes('"><script>'), 'url breaks out of href');
    assert.ok(html.includes('AT&amp;T &lt;Labs&gt;'));
  } finally {
    delete process.env.SMTP_HOST; delete process.env.SMTP_USER; delete process.env.SMTP_PASS;
  }
});

test('telegram message escapes source/author/cve/url (Bot API HTML rules)', async () => {
  load();
  const { sendTelegramAlert } = require(path.join(__dirname, '..', 'src', 'notifications', 'telegram-notifier.js'));
  axios.calls.length = 0;
  await sendTelegramAlert([{ title: 'T', source_name: 'MITRE ATT&CK Blog', author: 'A <b', cve_id: 'CVE-1&2',
    url: 'https://x.example/?a=1&b="2"', severity: 'high' }], 'tok', 'chat');
  const text = axios.calls[0].data.text;
  assert.ok(text.includes('MITRE ATT&amp;CK Blog'), text);
  assert.ok(text.includes('A &lt;b'));
  assert.ok(text.includes('href="https://x.example/?a=1&amp;b=&quot;2&quot;"'));
});
