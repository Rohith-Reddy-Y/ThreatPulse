# ThreatPulse AI Integration Plan

> **Goal:** Add a free LLM as the "brain" of ThreatPulse — AI inside the platform (triage, summarise, enrich) AND a web-grounded assistant for questions outside the platform.

---

## 1. Best free model recommendation

**Primary: Google Gemini 2.5 Flash (free tier)**

| Criterion | Gemini 2.5 Flash | Groq + Llama 3.3 70B | Ollama (local) |
|---|---|---|---|
| Free tier | ✅ Generous (≈1000 req/day) | ✅ Fast but tight daily caps | ✅ Unlimited, needs GPU |
| Native web search | ✅ **Google Search grounding built-in** | ❌ needs separate search API | ❌ |
| Context window | ✅ ~1M tokens | ⚠️ 128K | ⚠️ varies |
| JSON output | ✅ native | ✅ | ⚠️ manual |
| Latency | Fast | ⚡ Fastest | Depends on host |

**Why Gemini wins for this exact use case:** requirement #2 ("fetch info from the internet") is solved *for free* by Gemini's **Google Search grounding** — no extra Tavily/Serper subscription. One API key covers both the primary (platform intelligence) and secondary (web answers) needs.

**Fallback (optional):** Groq Llama 3.3 70B for pure text summarisation if you hit Gemini limits, + Tavily free tier (1000 credits/mo) for web search.

**Cost: $0.** Both tiers are free for a team-sized dashboard. No self-hosted GPU needed (avoid Ollama unless you already run a box).

---

## 2. Architecture

```
ThreatPulse (Node/Express)
├── src/ai/
│   ├── client.js          # Gemini SDK wrapper (API key, retries, JSON mode)
│   ├── prompts.js         # All system prompts (triage, summary, RAG, web Q&A)
│   └── cache.js           # TTL cache (SQLite) to avoid re-billing/rate-limit
├── routes: /api/ai/*      # New endpoints (auth-gated)
└── public/js/app.js       # "Ask ThreatPulse" panel + per-article AI actions
```

Two "lanes":
- **Primary (platform-intel):** AI reads articles *already inside* ThreatPulse DB.
- **Secondary (open Q&A):** AI answers anything, grounded by live Google Search.

---

## 3. Features (primary — AI inside ThreatPulse)

1. **Auto-summary** — 2–3 line executive summary per article (stored, shown on card expand).
2. **Threat triage score** — AI scores each article 0–100 on operational relevance + confidence, sortable.
3. **AI IOC extraction** — replace/augment regex `ioc-extractor.js` with LLM extraction (catches obfuscated IOCs regex misses).
4. **Threat-actor + MITRE classification** — cross-check the Synchrony 127-actor library and ATT&CK IDs with higher precision than regex.
5. **"Ask ThreatPulse" chat** — RAG over your own article DB: *"What critical vulnerabilities appeared this week involving ransomware?"* → grounded answer with citations to the actual articles.
6. **Daily briefing** — cron job each morning: AI writes a digest of last 24h critical/high threats (plugs into the existing email notifier).

## 4. Features (secondary — web-grounded Q&A)

1. **Chat panel** (same UI as #5, toggle "Search the web").
2. When toggled ON, Gemini grounds the answer in live Google Search → answers anything outside ThreatPulse: *"What is the latest on the MOVEit breach?"* or *"Explain the Log4Shell timeline."*
3. Responses cite sources (URLs) when grounded.

---

## 5. Implementation steps (bite-sized)

**Task 1 — Gemini client**
- `npm i @google/generative-ai`
- `src/ai/client.js`: init with `process.env.GEMINI_API_KEY`, model `gemini-2.5-flash`, JSON-mode helper, exponential-backoff retry, 30s timeout.
- `.env`: add `GEMINI_API_KEY=` (never committed).

**Task 2 — prompts module**
- `src/ai/prompts.js`: `summaryPrompt`, `triagePrompt`, `iocPrompt`, `ragPrompt`, `webQaPrompt`, `briefingPrompt` (each with strict JSON output schema).

**Task 3 — cache layer**
- `src/ai/cache.js`: reuse existing SQLite. Table `ai_cache(key TEXT PK, response TEXT, created_at)`, TTL 24h. Prevents duplicate LLM spend/rate-limit.

**Task 4 — API routes**
- `src/routes/ai.js` (mount at `/api/ai`, `auth.requireAuth`):
  - `POST /summarize`  { articleId }
  - `POST /triage`     { articleId }
  - `POST /ask`        { question, mode: 'rag' | 'web' }
  - `POST /enrich`     { articleId } → iocs + actor + mitre (batch, cron)
- Register in `server.js`.

**Task 5 — frontend panel**
- New "Ask ThreatPulse" chat widget (bottom-right, matches glassmorphism UI).
- Per-article "AI Summary" + "Triage score" badge on expand.
- Loading spinner + streaming-ish rendering.

**Task 6 — daily briefing cron**
- `server.js`: schedule `0 7 * * *` → `ai/buildBriefing()` → reuses `email-notifier`.

**Task 7 — settings**
- Admin toggle for AI features (on/off), model selection, rate-limit visibility.

---

## 6. Files likely to change

- `package.json` (+`@google/generative-ai`)
- `src/ai/client.js`, `src/ai/prompts.js`, `src/ai/cache.js` (new)
- `src/routes/ai.js` (new) + `server.js` (mount + cron)
- `src/database.js` (cache table + optional `ai_summary`/`ai_triage` columns)
- `public/js/app.js`, `public/index.html`, `public/css/styles.css` (chat panel + card badges)
- `.env.example`

## 7. Risks / tradeoffs

- **Rate limits:** free Gemini tier caps daily requests → cache + batch enrichment (don't call per-article on every page load).
- **Hallucination in triage:** always show AI output as *assistive*, keep human review workflow (Review/Escalate) as source of truth.
- **Prompt injection via article text:** sanitise/isolate article content as *data* (never let article text become instructions). System prompt must treat article body as untrusted.
- **Data egress:** article text is sent to Google. If articles contain sensitive internal intel, consider the local (Ollama) lane or redact before send.
- **Latency:** cap at ~30s with timeout + graceful "AI unavailable" fallback.

## 8. Validation

- `node --check` on all new/changed files.
- Manual: add a test article → click AI Summary → verify JSON renders on card.
- Manual: "Ask ThreatPulse" with a RAG question → confirm citations point to real DB articles.
- Manual: toggle web search → ask a current-events question → confirm source URLs returned.
- Verify daily briefing cron fires and email notifier sends.

---

**Bottom line:** Gemini 2.5 Flash (free) + its native Google Search grounding gives you both the primary in-platform AI and the secondary web Q&A with **one free API key** and no extra search vendor.
