/**
 * ThreatPulse — AI Cache
 * TTL cache in SQLite to avoid re-calling the LLM (rate-limit + latency).
 */
const db = require('../database');

const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function getCacheKey(kind, payload) {
  const crypto = require('crypto');
  const h = crypto.createHash('sha256').update(`${kind}:${payload}`).digest('hex');
  return h;
}

function get(kind, payload) {
  try {
    const key = getCacheKey(kind, payload);
    const row = db.getDb().prepare(
      'SELECT response, created_at FROM ai_cache WHERE cache_key = ?'
    ).get(key);
    if (!row) return null;
    if (Date.now() - new Date(row.created_at).getTime() > TTL_MS) {
      db.getDb().prepare('DELETE FROM ai_cache WHERE cache_key = ?').run(key);
      return null;
    }
    return row.response;
  } catch (e) {
    return null;
  }
}

function set(kind, payload, response) {
  try {
    const key = getCacheKey(kind, payload);
    db.getDb().prepare(
      'INSERT OR REPLACE INTO ai_cache (cache_key, response, created_at) VALUES (?, ?, ?)'
    ).run(key, response, new Date().toISOString());
  } catch (e) {
    // cache write failure is non-fatal
  }
}

module.exports = { get, set };
