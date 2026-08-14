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

    const data = ai.parseJson(result.text) || {};
    cache.set('summary', String(article.id), JSON.stringify(data));
    res.json({ success: true, ...data });
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

    const data = ai.parseJson(result.text) || {};
    cache.set('triage', String(article.id), JSON.stringify(data));
    res.json({ success: true, ...data });
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
      // Secondary: web-grounded Q&A for anything outside ThreatPulse
      const result = await ai.generate(prompts.webQaPrompt(question), question, { webSearch: true, temperature: 0.4 });
      if (!result.ok) return res.status(503).json({ success: false, error: result.error });
      return res.json({ success: true, mode: 'web', answer: result.text });
    }

    // Primary: RAG over own article DB
    const userId = scopeUserId(req.user);
    const articles = db.searchArticles(question, 8, userId);
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
