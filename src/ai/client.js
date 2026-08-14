/**
 * ThreatPulse — AI Client (Gemini 2.5 Flash, cloud)
 * Wraps @google/generative-ai with JSON mode, retries, and graceful fallback.
 */
const { GoogleGenerativeAI } = require('@google/generative-ai');

const MODEL = process.env.GEMINI_MODEL || 'gemini-3.5-flash';
const API_KEY = process.env.GEMINI_API_KEY || null;
const TIMEOUT_MS = 30000;
const MAX_RETRIES = 2;

let genAI = null;
if (API_KEY) {
  genAI = new GoogleGenerativeAI(API_KEY);
}

function isEnabled() {
  return !!API_KEY && !!genAI;
}

/**
 * Generate content with JSON-mode output and exponential-backoff retries.
 * @param {string} systemInstruction
 * @param {string} userContent
 * @param {object} opts { temperature, webSearch }
 * @returns {Promise<{ok:boolean, text:string|null, error?:string}>}
 */
async function generate(systemInstruction, userContent, opts = {}) {
  if (!isEnabled()) {
    return { ok: false, error: 'AI not configured (missing GEMINI_API_KEY)' };
  }

  const temperature = opts.temperature ?? 0.3;

  const model = genAI.getGenerativeModel(
    { model: MODEL },
    { apiVersion: 'v1beta' }
  );

  const parts = [];
  if (opts.webSearch) {
    // Ground the response in live Google Search
    parts.push({ text: userContent });
  } else {
    parts.push({ text: userContent });
  }

  const request = {
    contents: [{ role: 'user', parts }],
    systemInstruction,
    generationConfig: {
      temperature,
      maxOutputTokens: 2048,
      responseMimeType: 'application/json'
    }
  };

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
      // 429 / 503 → retry with backoff; others → give up immediately
      const msg = e.message || '';
      const retryable = /429|503|timeout|overloaded|resource exhausted/i.test(msg);
      if (!retryable || attempt === MAX_RETRIES) break;
      await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
    }
  }

  return { ok: false, error: lastError?.message || 'AI request failed' };
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
