/**
 * ThreatPulse — AI Routes
 * /api/ai/* — summary, triage, RAG chat, web-grounded Q&A (all auth-gated)
 */
const express = require('express');
const router = express.Router();
const db = require('../database');
const auth = require('../auth');
const ai = require('../ai/client');
const prompts = require('../ai/prompts');
const cache = require('../ai/cache');
const websearch = require('../ai/websearch');

// Guest/admin see all articles; regular users only their own.
function scopeUserId(user) {
  return (user.role === 'admin' || user.username === 'guest') ? null : user.id;
}

// ── AI SUMMARY ──
router.post('/summarize', auth.requireAuth, async (req, res) => {
  try {
    const articleId = parseInt(req.body.articleId);
    if (!articleId) return res.status(400).json({ error: 'articleId required' });

    const article = db.getArticleById(articleId);
    if (!article) return res.status(404).json({ error: 'Article not found' });

    const cacheKey = `summary:${article.id}`;
    const cached = cache.get('summary', String(article.id));
    if (cached) return res.json({ success: true, ...JSON.parse(cached) });

    const result = await ai.generate(prompts.summaryPrompt(article), article.title);
    if (!result.ok) return res.status(503).json({ success: false, error: result.error });

    const data = ai.parseJson(result.text);
    if (data && Object.keys(data).length > 0) {
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
    const articleId = parseInt(req.body.articleId);
    if (!articleId) return res.status(400).json({ error: 'articleId required' });

    const article = db.getArticleById(articleId);
    if (!article) return res.status(404).json({ error: 'Article not found' });

    const cached = cache.get('triage', String(article.id));
    if (cached) return res.json({ success: true, ...JSON.parse(cached) });

    const result = await ai.generate(prompts.triagePrompt(article), article.title);
    if (!result.ok) return res.status(503).json({ success: false, error: result.error });

    const data = ai.parseJson(result.text);
    if (data && Object.keys(data).length > 0) {
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

// ── ASK (RAG over own DB, or web-grounded) ──
router.post('/ask', auth.requireAuth, async (req, res) => {
  try {
    const { question, mode = 'rag' } = req.body;
    if (!question || !question.trim()) return res.status(400).json({ error: 'question required' });

    if (mode === 'web') {
      // Secondary: web-grounded Q&A for anything outside ThreatPulse.
      // Fetch live results (free, no key), then have the AI synthesize a cited answer.
      const results = await websearch.search(question, 5);
      const context = results.map((r, i) =>
        `[${i + 1}] ${r.title}\nURL: ${r.url}\n${r.snippet}`
      ).join('\n\n');

      const synth = await ai.generate(prompts.webQaPrompt(question, context), question, { temperature: 0.4, json: false });
      if (synth.ok && synth.text && synth.text.trim()) {
        return res.json({ success: true, mode: 'web', answer: synth.text, sources: results });
      }
      // Fallback: raw search results without synthesis (works even with no AI key)
      return res.json({
        success: true,
        mode: 'web',
        answer: results.length
          ? 'Here are relevant results:\n\n' + results.map(r => `- ${r.title}: ${r.url}`).join('\n')
          : 'No web results found. Set GEMINI_API_KEY to let the AI answer from its own knowledge.',
        sources: results
      });
    }

    // Primary: RAG over own article DB
    const userId = scopeUserId(req.user);
    const articles = db.searchArticlesRag(question, 8, userId);
    const result = await ai.generate(prompts.ragPrompt(question, articles), question);
    if (!result.ok) return res.status(503).json({ success: false, error: result.error });

    const data = ai.parseJson(result.text) || {};
    res.json({ success: true, mode: 'rag', ...data });
  } catch (e) {
    console.error('[AI] Ask error:', e.message);
    res.status(500).json({ error: 'AI ask failed' });
  }
});

// ── STATUS (is AI configured?) ──
router.get('/status', auth.requireAuth, (req, res) => {
  res.json({ enabled: ai.isEnabled(), model: ai.MODEL });
});

module.exports = router;
