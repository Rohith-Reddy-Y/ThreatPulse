'use strict';
// Default-source seeding: abuse.ch feeds follow ABUSE_CH_API_KEY; RansomWatch replaced; Fox-IT scraped.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { load } = require('./data-helpers');

function seed(dbPath) {
  const env = load(dbPath);
  const { seedDefaultSources } = require(path.join(__dirname, '..', 'src', 'feeds', 'default-sources.js'));
  seedDefaultSources(env.db);
  return env;
}
const abuse = (db) => db.getAllSources().filter(s => /threatfox|urlhaus|mb-api\.abuse\.ch/.test(s.url));

test('abuse.ch feeds are off without a key, back on once a key is set', () => {
  delete process.env.ABUSE_CH_API_KEY;
  const env = seed();
  assert.equal(abuse(env.db).length, 3);
  assert.ok(abuse(env.db).every(s => Number(s.enabled) === 0));

  process.env.ABUSE_CH_API_KEY = 'k';
  const env2 = seed(env.dbPath);                 // restart with a key
  assert.ok(abuse(env2.db).every(s => Number(s.enabled) === 1));
  delete process.env.ABUSE_CH_API_KEY;
});

test('RansomWatch default is replaced by Ransomware.live; Fox-IT uses the website scraper', () => {
  const env = seed();
  const all = env.db.getAllSources();
  assert.ok(!all.some(s => s.name === 'RansomWatch - Ransomware Leak Tracker'));
  const rl = all.find(s => s.name === 'Ransomware.live - Ransomware Leak Tracker');
  assert.equal(rl.url, 'https://api.ransomware.live/v2/recentvictims');
  assert.equal(rl.type, 'darkweb');
  const fox = all.find(s => s.name === 'Fox-IT International');
  assert.equal(fox.type, 'website');
  assert.equal(fox.url, 'https://www.fox-it.com/nl/research/');
  assert.ok(all.some(s => s.name === 'Trend Micro Research'));
  assert.ok(all.some(s => s.name === 'HackerOne Blog'));
});
