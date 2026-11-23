/**
 * ThreatPulse — AI Client (Groq, OpenAI-compatible)
 * Free tier: no credit card, ~14,400 requests/day (~30/min).
 * Uses the OpenAI-compatible chat-completions endpoint directly via axios,
 * so no provider SDK is required.
 */
const axios = require('axios');

const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
// Groq retires model IDs (llama-3.3-70b-versatile was shut down 2026-08-16 and
// started returning 404). GROQ_MODEL wins; otherwise we use the first default
// and automatically fall through the list when a model is retired, then stick
// with whichever one answered.
const DEFAULT_MODELS = ['openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'llama-3.1-8b-instant'];
const CONFIGURED_MODEL = (process.env.GROQ_MODEL || '').trim();
let activeModel = CONFIGURED_MODEL || DEFAULT_MODELS[0];
function modelCandidates() {
  return [...new Set([activeModel, CONFIGURED_MODEL, ...DEFAULT_MODELS].filter(Boolean))];
}
const isReasoningModel = m => /^openai\/gpt-oss/i.test(m);
// Per-attempt timeout and an overall deadline for one generate() call (including
// retries + backoff), so a slow/hung provider can never hold a request open for
// minutes. Overridable for tests/tuning.
const TIMEOUT_MS = parseInt(process.env.AI_TIMEOUT_MS, 10) || 20000;
const DEADLINE_MS = parseInt(process.env.AI_DEADLINE_MS, 10) || 40000;
const MAX_RETRIES = 2;
// Hard cap on what we send in one request (characters) — last line of defence
// against token blow-ups if a caller forgets to bound its input.
const MAX_SYSTEM_CHARS = 8000;
const MAX_USER_CHARS = 24000;

const ERR = {
  rateLimit: 'Groq free-tier rate limit reached. Try again in a minute.',
  badKey: 'Groq API key is invalid or unauthorized. Check it in Admin -> AI Settings.',
  timeout: 'AI request timed out. Please try again.',
  tooLarge: 'The request was too large for the AI model. Try a shorter question or start a new chat.',
  noModel: 'None of the configured Groq models are available. Set GROQ_MODEL to a current model from console.groq.com/docs/models.',
  generic: 'AI service is temporarily unavailable. Please try again later.'
};

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function retryAfterMs(e) {
  const h = e.response?.headers;
  const v = h && (h['retry-after'] || (typeof h.get === 'function' ? h.get('retry-after') : undefined));
  const n = parseFloat(v);
  return Number.isFinite(n) && n >= 0 ? n * 1000 : null;
}

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

  // Prompt builders return { system, user } so untrusted data never sits in the
  // system message. Legacy (string, string) calls still work.
  let system = systemInstruction;
  let user = userContent;
  if (systemInstruction && typeof systemInstruction === 'object') {
    system = systemInstruction.system;
    user = systemInstruction.user;
  }
  system = String(system || '').slice(0, MAX_SYSTEM_CHARS);
  user = String(user || '').slice(0, MAX_USER_CHARS);

  const temperature = opts.temperature ?? 0.3;
  const jsonMode = opts.json !== false;

  // Per-model request body. gpt-oss models reason before answering, so they get
  // low reasoning effort and a larger token budget so the answer isn't cut off.
  // `dropped` holds optional params a model rejected (retried without them).
  const dropped = new Set();
  const buildBody = (model) => {
    const b = {
      model,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user }
      ],
      temperature,
      max_tokens: isReasoningModel(model) ? 4096 : 2048
    };
    if (jsonMode && !dropped.has('response_format')) b.response_format = { type: 'json_object' };
    if (isReasoningModel(model) && !dropped.has('reasoning_effort')) b.reasoning_effort = 'low';
    return b;
  };
  const candidates = modelCandidates();
  let modelIdx = 0;

  const deadline = Date.now() + DEADLINE_MS;
  let lastError = null;
  let lastKind = 'generic';
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) { lastKind = lastKind === 'generic' ? 'timeout' : lastKind; break; }
    const attemptTimeout = Math.min(TIMEOUT_MS, remaining);
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    let timer = null;
    try {
      const resp = await Promise.race([
        axios.post(GROQ_URL, buildBody(candidates[modelIdx]), {
          headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          timeout: attemptTimeout,
          ...(controller ? { signal: controller.signal } : {})
        }),
        new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), attemptTimeout); })
      ]);
      clearTimeout(timer);
      const content = resp?.data?.choices?.[0]?.message?.content;
      if (activeModel !== candidates[modelIdx]) {
        activeModel = candidates[modelIdx];
        console.log(`[AI] Using Groq model ${activeModel}`);
      }
      // gpt-oss cites like 【3】 or 【3†source】; normalise to the app's [3] style
      const out = typeof content === 'string' ? content.replace(/【(\d+)(?:†[^】]*)?】/g, '[$1]') : '';
      return { ok: true, text: out };
    } catch (e) {
      clearTimeout(timer);
      if (controller) { try { controller.abort(); } catch (_) { /* ignore */ } }
      lastError = e;
      const status = e.response?.status;
      const msg = String(e.response?.data?.error?.message || e.message || '');

      // Retired / unknown model — move to the next candidate (doesn't use a retry).
      if (status === 404 || /model.*(not found|does not exist|decommissioned|deprecated)|model_not_found|model_decommissioned/i.test(msg)) {
        console.error(`[AI] Groq model ${candidates[modelIdx]} unavailable (${status || ''} ${msg.slice(0, 120)})`);
        if (modelIdx + 1 < candidates.length) { modelIdx++; attempt--; continue; }
        return { ok: false, error: ERR.noModel };
      }
      // An optional parameter the model doesn't support — drop it and retry once.
      if (status === 400) {
        const PARAM_ERR = { reasoning_effort: /reasoning.?effort/i, response_format: /response.?format|json_validate|json mode/i };
        const p = Object.keys(PARAM_ERR).find(k => !dropped.has(k) && PARAM_ERR[k].test(msg));
        if (p) { dropped.add(p); attempt--; continue; }
      }
      // Invalid / unauthorized key — not retryable.
      if (status === 401 || status === 403 || /invalid.*api key|unauthorized|authentication/i.test(msg)) {
        return { ok: false, error: ERR.badKey };
      }
      // Request too large / context length — not retryable.
      if (status === 413 || /context.?length|too large|maximum context/i.test(msg)) {
        return { ok: false, error: ERR.tooLarge };
      }
      const left = deadline - Date.now();
      // Rate limit — only retry when the provider's wait is short and fits in the deadline.
      if (status === 429 || /rate limit|quota/i.test(msg)) {
        lastKind = 'rateLimit';
        const wait = retryAfterMs(e) ?? 1000 * (attempt + 1);
        if (attempt < MAX_RETRIES && wait <= 5000 && wait + 1000 < left) {
          await sleep(wait);
          continue;
        }
        return { ok: false, error: ERR.rateLimit };
      }
      // Transient server errors / timeouts — retry with backoff while time remains.
      const isTimeout = e.code === 'ECONNABORTED' || e.code === 'ERR_CANCELED' || /timeout/i.test(msg);
      lastKind = isTimeout ? 'timeout' : 'generic';
      const retryable = isTimeout || [500, 502, 503, 504].includes(status) ||
        /overloaded|resource exhausted|ECONNRESET|socket hang up/i.test(msg);
      const backoff = 1000 * (attempt + 1);
      if (!retryable || attempt === MAX_RETRIES || backoff + 1000 >= left) break;
      await sleep(backoff);
    }
  }

  // Clean, human-readable final error — never dump raw provider/network errors at the user.
  if (lastError) console.error('[AI] Groq request failed:', lastError.response?.status || lastError.code || '', lastError.message);
  return { ok: false, error: ERR[lastKind] || ERR.generic };
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

module.exports = {
  generate, parseJson, isEnabled,
  DEFAULT_MODELS,
  get MODEL() { return activeModel; }
};
