/**
 * ThreatPulse — AI Client (Gemini 2.5 Flash, cloud)
 * Wraps @google/generative-ai with JSON mode, retries, and graceful fallback.
 */
const { GoogleGenerativeAI } = require('@google/generative-ai');

const MODEL = process.env.GEMINI_MODEL || 'gemini-3.5-flash';
const TIMEOUT_MS = 30000;
const MAX_RETRIES = 2;

// The API key can come from the environment OR from admin-configured settings
// (stored in the DB via the admin panel "AI Settings"). Env wins; DB is the
// fallback so an admin can configure the key through the UI without SSH.
let db = null;
try { db = require('../database'); } catch (e) { db = null; }

let cachedKey = null;
let genAI = null;

function getApiKey() {
  const envKey = process.env.GEMINI_API_KEY;
  if (envKey) return envKey;
  if (db) {
    try { return db.getSetting('gemini_api_key') || null; } catch (e) { return null; }
  }
  return null;
}

function getClient() {
  const key = getApiKey();
  if (!key) return null;
  if (key !== cachedKey) {
    cachedKey = key;
    genAI = new GoogleGenerativeAI(key);
  }
  return genAI;
}

function isEnabled() {
  return !!getClient();
}

/**
 * Generate content with JSON-mode output and exponential-backoff retries.
 * @param {string} systemInstruction
 * @param {string} userContent
 * @param {object} opts { temperature, json }
 * @returns {Promise<{ok:boolean, text:string|null, error?:string}>}
 */
async function generate(systemInstruction, userContent, opts = {}) {
  const client = getClient();
  if (!client) {
    return { ok: false, error: 'AI not configured (missing GEMINI_API_KEY). Set it in .env or Admin -> AI Settings.' };
  }

  const temperature = opts.temperature ?? 0.3;
  // Structured callers (summary/triage/ioc/rag) want JSON; the web-Q&A
  // chat wants plain text. Default to JSON, opt out with { json: false }.
  const jsonMode = opts.json !== false;

  const model = client.getGenerativeModel(
    { model: MODEL },
    { apiVersion: 'v1beta' }
  );

  const request = {
    contents: [{ role: 'user', parts: [{ text: userContent }] }],
    systemInstruction,
    generationConfig: {
      temperature,
      maxOutputTokens: 2048
    }
  };
  if (jsonMode) {
    request.generationConfig.responseMimeType = 'application/json';
  }

  let lastError = null;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    try {
      const result = await Promise.race([
        model.generateContent(request),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), TIMEOUT_MS))
      ]);
      const text = result?.response?.text?.() || '';
      return { ok: true, text };
    } catch (e) {
      lastError = e;
      const msg = e.message || '';
      // Daily/monthly quota exhausted — NOT retryable, surface a clean message.
      if (/quota/i.test(msg) && /exceeded|limit/i.test(msg)) {
        return { ok: false, error: 'Gemini free-tier daily limit reached (20 requests/day). It resets tomorrow — or upgrade your plan for higher limits.' };
      }
      // 429 / 503 → retry with backoff; others → give up immediately
      const retryable = /429|503|timeout|overloaded|resource exhausted/i.test(msg);
      if (!retryable || attempt === MAX_RETRIES) break;
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
  }

  // Clean, human-readable final error — never dump raw provider JSON at the user.
  const raw = lastError?.message || 'AI request failed';
  if (/429/i.test(raw)) return { ok: false, error: 'Gemini is rate-limiting requests right now. Try again in a minute.' };
  if (/invalid|api key|authentication|permission/i.test(raw)) return { ok: false, error: 'Gemini API key is invalid or unauthorized. Check it in Admin → AI Settings.' };
  return { ok: false, error: raw };
}

/**
 * Parse a JSON response, tolerating markdown fences, trailing commas,
 * and double-encoded JSON (Gemini sometimes wraps JSON in an extra string layer).
 */
function parseJson(text) {
  if (!text) return null;

  // Attempt 1: direct
  const direct = tryParse(text);
  if (direct !== undefined) {
    // Gemini with responseMimeType=application/json may return a JSON-encoded string.
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
