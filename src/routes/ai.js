/**
 * ThreatPulse — AI Routes
 * /api/ai/* — summary, triage, RAG chat, web-grounded Q&A (all auth-gated)
 */
const express = require('express');
const router = express.Router();
const db = require('../database');
const auth = require('../auth');
const { parseId } = require('../security');
const ai = require('../ai/client');
const prompts = require('../ai/prompts');
const cache = require('../ai/cache');
const websearch = require('../ai/websearch');
const crypto = require('crypto');
const { LIMITS } = require('../ai/prompts');

const GUEST_USERNAME = 'guest';
const MAX_QUESTION = LIMITS.question;
const HISTORY_TURNS = LIMITS.historyTurns;

function isGuest(user) {
  return !!user && user.username === GUEST_USERNAME;
}

// Admin sees all articles; the shared guest account only built-in system
// content (never other users' private articles); regular users only their own.
function scopeUserId(user) {
  if (user.role === 'admin') return null;
  if (isGuest(user)) return db.SYSTEM_SCOPE;
  return user.id;
}

// Same visibility rule as the article list (/api/articles).
function canAccessArticle(user, article) {
  const scope = scopeUserId(user);
  if (scope === null) return true;
  if (scope === db.SYSTEM_SCOPE) return db.isSystemArticle(article);
  return article.user_id === user.id;
}

function intEnv(name, def) {
  const n = parseInt(process.env[name], 10);
  return Number.isFinite(n) && n > 0 ? n : def;
}

// ── AI QUOTA ──
// Every AI call spends the single, shared Groq free-tier quota (and Tavily's).
// The global /api limiter (200 req/min/IP) is far above what Groq allows, so AI
// calls get their own budget: per signed-in user, per guest IP, and an aggregate
// cap for all anonymous guests (who share one account and can rotate IPs).
const QUOTA = {
  userPerMin: intEnv('AI_USER_PER_MIN', 8),
  guestIpPerMin: intEnv('AI_GUEST_IP_PER_MIN', 4),
  guestTotalPerMin: intEnv('AI_GUEST_TOTAL_PER_MIN', 15),
  guestTotalPerDay: intEnv('AI_GUEST_TOTAL_PER_DAY', 300)
};
const MINUTE = 60 * 1000;
const DAY = 24 * 60 * MINUTE;
const quotaStore = new Map();

function hit(key, limit, windowMs, now) {
  let e = quotaStore.get(key);
  if (!e || now >= e.resetAt) {
    e = { count: 0, resetAt: now + windowMs };
    quotaStore.set(key, e);
  }
  if (e.count >= limit) return Math.ceil((e.resetAt - now) / 1000);
  e.count++;
  return 0;
}

// Returns true if the caller may make an AI call; otherwise sends 429 and returns false.
function consumeAiQuota(req, res) {
  const now = Date.now();
  if (quotaStore.size > 5000) {
    for (const [k, e] of quotaStore) if (now >= e.resetAt) quotaStore.delete(k);
  }
  let wait = 0;
  if (isGuest(req.user)) {
    const ip = req.ip || 'unknown';
    wait = hit(`guest-ip:${ip}`, QUOTA.guestIpPerMin, MINUTE, now) ||
      hit('guest-all:min', QUOTA.guestTotalPerMin, MINUTE, now) ||
      hit('guest-all:day', QUOTA.guestTotalPerDay, DAY, now);
  } else {
    wait = hit(`user:${req.user.id}`, QUOTA.userPerMin, MINUTE, now);
  }
  if (!wait) return true;
  res.setHeader('Retry-After', String(wait));
  res.status(429).json({
    success: false,
    error: isGuest(req.user)
      ? 'Guest AI limit reached. Please wait a bit, or sign in for a higher limit.'
      : 'Too many AI requests. Please wait a minute and try again.'
  });
  return false;
}

// ── GUEST THREAD ISOLATION ──
// All anonymous visitors share ONE 'guest' account, so DB ownership (user_id)
// cannot tell them apart. Each guest browser gets a random httpOnly cookie, and a
// guest thread is only visible to the visitor whose cookie created it. The map is
// in memory (threads become unreachable — never shared — after a restart) and
// bounded; the oldest guest threads are deleted when it fills up.
const GUEST_SID_COOKIE = 'tp_ai_gsid';
const MAX_GUEST_THREADS = 2000;
const guestThreadOwner = new Map(); // threadId -> sid

function guestSid(req, res, create) {
  const v = req.cookies && req.cookies[GUEST_SID_COOKIE];
  if (typeof v === 'string' && /^[a-f0-9]{32}$/.test(v)) return v;
  if (!create) return null;
  const sid = crypto.randomBytes(16).toString('hex');
  res.cookie(GUEST_SID_COOKIE, sid, {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/api/ai',
    maxAge: 7 * DAY
  });
  if (req.cookies) req.cookies[GUEST_SID_COOKIE] = sid;
  return sid;
}

function guestOwnsThread(req, tid) {
  const sid = guestSid(req, null, false);
  return !!sid && guestThreadOwner.get(tid) === sid;
}

function registerGuestThread(req, res, tid) {
  guestThreadOwner.set(tid, guestSid(req, res, true));
  while (guestThreadOwner.size > MAX_GUEST_THREADS) {
    const oldest = guestThreadOwner.keys().next().value;
    guestThreadOwner.delete(oldest);
    try { db.deleteThread(oldest, req.user.id); } catch (e) { /* best effort */ }
  }
}

// Thread lookup with ownership: DB user_id match, plus the per-visitor check for guests.
function findThread(req, tid) {
  if (!Number.isInteger(tid) || tid <= 0) return null;
  if (isGuest(req.user) && !guestOwnsThread(req, tid)) return null;
  return db.getThread(tid, req.user.id);
}

// ── MODEL OUTPUT VALIDATION ──
// Model output is untrusted (it can be steered by injected article/web text):
// never spread it into responses; keep only expected fields with expected types.
function text(v, max) {
  if (v == null) return '';
  const s = typeof v === 'string' ? v : (typeof v === 'number' || typeof v === 'boolean') ? String(v) : '';
  return s.length > max ? s.slice(0, max) : s;
}

function score(v) {
  const n = typeof v === 'number' ? v : (typeof v === 'string' && /^\s*\d+(\.\d+)?\s*$/.test(v) ? parseFloat(v) : NaN);
  return Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : null;
}

const PRIORITIES = ['immediate', 'high', 'routine', 'informational'];

function cleanSummary(d) {
  if (!d || typeof d !== 'object') return null;
  const out = {
    summary: text(d.summary, 2000),
    keyTakeaway: text(d.keyTakeaway, 1000),
    affectedTech: (Array.isArray(d.affectedTech) ? d.affectedTech : [])
      .map(t => text(t, 100)).filter(Boolean).slice(0, 20)
  };
  return out.summary ? out : null;
}

function cleanTriage(d) {
  if (!d || typeof d !== 'object') return null;
  const p = typeof d.priority === 'string' ? d.priority.trim().toLowerCase() : '';
  const out = {
    relevance: score(d.relevance),
    confidence: score(d.confidence),
    reason: text(d.reason, 1000)
  };
  if (PRIORITIES.includes(p)) out.priority = p;
  return (out.priority || out.relevance !== null) ? out : null;
}

function cleanCitations(c, max) {
  if (!Array.isArray(c)) return [];
  const seen = new Set();
  for (const v of c) {
    const n = typeof v === 'number' ? v : (typeof v === 'string' && /^\s*\d+\s*$/.test(v) ? parseInt(v, 10) : NaN);
    if (Number.isInteger(n) && n >= 1 && n <= max) seen.add(n);
  }
  return [...seen].slice(0, 20);
}

function cachedJson(kind, key, cleaner) {
  const raw = cache.get(kind, key);
  if (!raw) return null;
  try { return cleaner(JSON.parse(raw)); } catch { return null; }
}

// ── AI SUMMARY ──
router.post('/summarize', auth.requireAuth, async (req, res) => {
  try {
    const articleId = parseId((req.body || {}).articleId);
    if (!articleId) return res.status(400).json({ error: 'articleId required' });

    const article = db.getArticleById(articleId);
    if (!article || !canAccessArticle(req.user, article)) return res.status(404).json({ error: 'Article not found' });

    const cached = cachedJson('summary', String(article.id), cleanSummary);
    if (cached) return res.json({ success: true, ...cached });

    if (!consumeAiQuota(req, res)) return;
    const result = await ai.generate(prompts.summaryPrompt(article));
    if (!result.ok) return res.status(503).json({ success: false, error: result.error });

    const data = cleanSummary(ai.parseJson(result.text));
    if (data) {
      cache.set('summary', String(article.id), JSON.stringify(data));
      res.json({ success: true, ...data });
    } else {
      res.status(502).json({ success: false, error: 'AI returned an empty result' });
    }
  } catch (e) {
    console.error('[AI] Summarize error:', e.message);
    res.status(500).json({ error: 'AI summary failed' });
  }
});

// ── AI TRIAGE ──
router.post('/triage', auth.requireAuth, async (req, res) => {
  try {
    const articleId = parseId((req.body || {}).articleId);
    if (!articleId) return res.status(400).json({ error: 'articleId required' });

    const article = db.getArticleById(articleId);
    if (!article || !canAccessArticle(req.user, article)) return res.status(404).json({ error: 'Article not found' });

    const cached = cachedJson('triage', String(article.id), cleanTriage);
    if (cached) return res.json({ success: true, ...cached });

    if (!consumeAiQuota(req, res)) return;
    const result = await ai.generate(prompts.triagePrompt(article));
    if (!result.ok) return res.status(503).json({ success: false, error: result.error });

    const data = cleanTriage(ai.parseJson(result.text));
    if (data) {
      cache.set('triage', String(article.id), JSON.stringify(data));
      res.json({ success: true, ...data });
    } else {
      res.status(502).json({ success: false, error: 'AI returned an empty result' });
    }
  } catch (e) {
    console.error('[AI] Triage error:', e.message);
    res.status(500).json({ error: 'AI triage failed' });
  }
});

// ── ASK (RAG over own DB, or web-grounded) — thread-aware with shared memory ──
function safeParseJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

router.post('/ask', auth.requireAuth, async (req, res) => {
  try {
    const body = req.body || {};
    if (typeof body.question !== 'string' || !body.question.trim()) {
      return res.status(400).json({ error: 'question required' });
    }
    const question = body.question.trim();
    if (question.length > MAX_QUESTION) {
      return res.status(400).json({ error: `Question is too long (max ${MAX_QUESTION} characters).` });
    }
    const mode = body.mode === 'web' ? 'web' : 'rag';

    // Threads are always per-user; guest threads are additionally per-visitor.
    const userId = req.user.id;
    let tid = null;
    if (body.threadId !== undefined && body.threadId !== null && body.threadId !== '') {
      tid = parseId(body.threadId);
      if (!findThread(req, tid)) return res.status(404).json({ error: 'Thread not found' });
    }

    if (!consumeAiQuota(req, res)) return;

    if (!tid) {
      tid = db.createThread(userId, question.slice(0, 60) || 'New chat');
      if (isGuest(req.user)) registerGuestThread(req, res, tid);
    }

    // Shared memory: load recent turns so the model keeps the topic across
    // RAG/web toggles and follow-up questions.
    const history = db.getThreadMessages(tid, userId, HISTORY_TURNS);

    // Persist the user's message first.
    db.addMessage(tid, 'user', question, mode);

    if (mode === 'web') {
      const results = await websearch.search(question, 5);
      const context = results.map((r, i) =>
        `[${i + 1}] ${r.title}\nURL: ${r.url}\n${r.snippet}`
      ).join('\n\n');

      const synth = await ai.generate(prompts.webQaPrompt(question, context, history), null, { temperature: 0.4, json: false });
      if (synth.ok && synth.text && synth.text.trim()) {
        const answer = synth.text.trim();
        db.addMessage(tid, 'assistant', answer, 'web', results);
        return res.json({ success: true, mode: 'web', threadId: tid, answer, sources: results });
      }
      // Fallback: raw search results (works even if the LLM is down/rate-limited)
      const fallback = results.length
        ? 'Here are relevant results:\n\n' + results.map(r => `- ${r.title}: ${r.url}`).join('\n')
        : 'No web results found. The AI could not generate an answer.';
      db.addMessage(tid, 'assistant', fallback, 'web', results);
      return res.json({ success: true, mode: 'web', threadId: tid, answer: fallback, sources: results });
    }

    // Primary: RAG over own article DB
    const scopedUserId = scopeUserId(req.user);
    const articles = db.searchArticlesRag(question, LIMITS.ragArticles, scopedUserId);
    const result = await ai.generate(prompts.ragPrompt(question, articles, history));
    if (!result.ok) return res.status(503).json({ success: false, error: result.error });

    const data = ai.parseJson(result.text);
    const parsed = data && typeof data === 'object' ? data : {};
    const answer = text(parsed.answer, 8000).trim() || '(no answer)';
    const citations = cleanCitations(parsed.citations, articles.length);
    const insufficientData = parsed.insufficientData === true;
    db.addMessage(tid, 'assistant', answer, 'rag', null);
    res.json({ success: true, mode: 'rag', threadId: tid, answer, citations, insufficientData });
  } catch (e) {
    console.error('[AI] Ask error:', e.message);
    res.status(500).json({ error: 'AI ask failed' });
  }
});

// ── CHAT THREADS (persistent history, per-user isolation) ──
router.get('/threads', auth.requireAuth, (req, res) => {
  try {
    let threads = db.getThreads(req.user.id);
    if (isGuest(req.user)) {
      const sid = guestSid(req, null, false);
      threads = sid ? threads.filter(t => guestThreadOwner.get(t.id) === sid) : [];
    }
    res.json({ threads });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch threads' });
  }
});

router.get('/threads/:id', auth.requireAuth, (req, res) => {
  try {
    const thread = findThread(req, parseId(req.params.id));
    if (!thread) return res.status(404).json({ error: 'Thread not found' });
    thread.messages = thread.messages.map(m => ({ ...m, sources: m.sources ? safeParseJson(m.sources) : null }));
    res.json({ thread });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch thread' });
  }
});

router.delete('/threads/:id', auth.requireAuth, (req, res) => {
  try {
    const tid = parseId(req.params.id);
    if (!findThread(req, tid)) return res.status(404).json({ success: false, error: 'Thread not found' });
    const result = db.deleteThread(tid, req.user.id);
    if (!result.success) return res.status(404).json(result);
    guestThreadOwner.delete(tid);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete thread' });
  }
});

// ── STATUS (is AI configured?) ──
router.get('/status', auth.requireAuth, (req, res) => {
  try {
    const envKey = process.env.GROQ_API_KEY;
    const dbKey = envKey ? null : db.getSetting('groq_api_key');
    res.json({
      enabled: ai.isEnabled(),
      model: ai.MODEL,
      provider: 'groq',
      keySource: envKey ? 'env' : (dbKey ? 'database' : 'none')
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch AI status' });
  }
});

module.exports = router;
