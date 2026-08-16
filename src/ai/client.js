/**
 * ThreatPulse — AI Client (Groq, OpenAI-compatible)
 * Free tier: no credit card, ~14,400 requests/day (~30/min).
 * Uses the OpenAI-compatible chat-completions endpoint directly via axios,
 * so no provider SDK is required.
 */
const axios = require('axios');

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const TIMEOUT_MS = 30000;
const MAX_RETRIES = 2;

// The API key can come from the environment OR from admin-configured settings
// (stored in the DB via the admin panel "AI Settings"). Env wins; DB is the
// fallback so an admin can configure the key through the UI without SSH.
let db = null;
try { db = require('../database'); } catch (e) { db = null; }

function getApiKey() {
  const envKey = process.env.GROQ_API_KEY;
  if (envKey) return envKey;
  if (db) {
    try { return db.getSetting('groq_api_key') || null; } catch (e) { return null; }
  }
  return null;
}

function isEnabled() {
  return !!getApiKey();
}

/**
 * Generate content. Structured callers (summary/triage/ioc/rag) want JSON;
 * the web-Q&A chat wants plain text. Default to JSON, opt out with { json: false }.
 * @returns {Promise<{ok:boolean, text:string|null, error?:string}>}
 */
async function generate(systemInstruction, userContent, opts = {}) {
  const apiKey = getApiKey();
  if (!apiKey) {
    return { ok: false, error: 'AI not configured (missing GROQ_API_KEY). Set it in .env or Admin -> AI Settings.' };
  }

  const temperature = opts.temperature ?? 0.3;
  const jsonMode = opts.json !== false;

  const body = {
    model: MODEL,
    messages: [
      { role: 'system', content: systemInstruction },
      { role: 'user', content: userContent }
    ],
    temperature,
    max_tokens: 2048
  };
  if (jsonMode) {
    body.response_format = { type: 'json_object' };
  }

  let lastError = null;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const resp = await Promise.race([
        axios.post(GROQ_URL, body, {
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          timeout: TIMEOUT_MS
        }),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), TIMEOUT_MS))
      ]);
      const text = resp.data?.choices?.[0]?.message?.content || '';
      return { ok: true, text };
    } catch (e) {
      lastError = e;
      const status = e.response?.status;
      const msg = e.response?.data?.error?.message || e.message || '';

      // Invalid / unauthorized key — not retryable.
      if (status === 401 || /invalid.*api key|unauthorized|authentication/i.test(msg)) {
        return { ok: false, error: 'Groq API key is invalid or unauthorized. Check it in Admin -> AI Settings.' };
      }
      // Rate limit — Groq free tier is per-minute limited, so a short retry usually recovers.
      if (status === 429 || /rate limit|quota/i.test(msg)) {
        if (attempt < MAX_RETRIES) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
          continue;
        }
        return { ok: false, error: 'Groq free-tier rate limit reached. Try again in a minute.' };
      }
      // Transient server errors / timeouts — retry with backoff.
      const retryable = /503|500|timeout|overloaded|resource exhausted/i.test(msg) || status === 503;
      if (!retryable || attempt === MAX_RETRIES) break;
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
  }

  // Clean, human-readable final error — never dump raw provider JSON at the user.
  const status = lastError?.response?.status;
  const raw = lastError?.message || 'AI request failed';
  if (status === 429) return { ok: false, error: 'Groq free-tier rate limit reached. Try again in a minute.' };
  if (status === 401) return { ok: false, error: 'Groq API key is invalid or unauthorized. Check it in Admin -> AI Settings.' };
  return { ok: false, error: raw };
}

/**
 * Parse a JSON response, tolerating markdown fences and double-encoded JSON
 * (some models wrap JSON in an extra string layer).
 */
function parseJson(text) {
  if (!text) return null;

  // Attempt 1: direct
  const direct = tryParse(text);
  if (direct !== undefined) {
    if (typeof direct === 'string') {
      const inner = tryParse(direct);
      if (inner !== undefined) return inner;
    }
    return direct;
  }

  // Attempt 2: strip markdown fences + whitespace
  const cleaned = text
    .replace(/^```(json)?/i, '')
    .replace(/```$/i, '')
    .trim();
  const c = tryParse(cleaned);
  if (c !== undefined) {
    if (typeof c === 'string') {
      const inner = tryParse(c);
      if (inner !== undefined) return inner;
    }
    return c;
  }

  // Attempt 3: extract the first {...} block
  const m = cleaned.match(/\{[\s\S]*\}/);
  if (m) {
    const b = tryParse(m[0]);
    if (b !== undefined) {
      if (typeof b === 'string') {
        const inner = tryParse(b);
        if (inner !== undefined) return inner;
      }
      return b;
    }
  }

  return null;
}

function tryParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

module.exports = { generate, parseJson, isEnabled, MODEL };
