# 🏗️ ThreatPulse — Free Deployment Architecture

A rendered version is in **`architecture.svg`** (open in any browser, or embed in slides/docs).

```
                              ┌───────────────────────┐
                              │   👤  Users / Browser  │
                              └───────────┬───────────┘
                                          │  HTTPS
                                          ▼
   INBOUND — Threat Intel        ┌──────────────────────────────────┐      OUTBOUND — Alerts
   (free public APIs/feeds)      │   ☁  Fly.io — 1 free container    │      (free, per-user)
 ┌─────────────────────────┐     │  ┌────────────────────────────┐  │    ┌────────────────────────┐
 │ • NVD API 2.0  (CVEs)   │     │  │ ⚙  Node + Express          │  │    │ • Email  (SMTP)        │
 │ • CISA KEV              │ ──► │  │    • Serves the SPA        │  │──► │ • Telegram             │
 │ • abuse.ch *            │     │  │    • REST API + JWT auth   │  │    │ • Microsoft Teams      │
 │ • RansomWatch           │     │  │    • Cron  (every 15 min)  │  │    │ • WhatsApp (CallMeBot) │
 │ • ~35 RSS feeds         │     │  └────────────────────────────┘  │    └────────────────────────┘
 └─────────────────────────┘     │  ┌────────────────────────────┐  │
          * free API key         │  │ 🗄  SQLite → volume /data   │  │
                                 │  └────────────────────────────┘  │
                                 └──────────────────────────────────┘

 Not used (unnecessary at this scale):  Cloudflare Pages · Koyeb · Neon Postgres · R2 · Supabase Auth
 Node serves the SPA · SQLite-on-volume is the DB · JWT is the auth · no file uploads = nothing to store
 Scale path:  SQLite is a single writer → run ONE machine. Outgrow it? Swap SQLite → Neon Postgres.
```

## Service summary

| Layer | Service | Free tier | Why |
|---|---|---|---|
| Host | **Fly.io** | Always-on machine + volume | Only common free host with a **persistent disk** (SQLite needs it) |
| Database | **SQLite** | Self-hosted, on the volume | Zero-ops, zero-cost, no rewrite |
| App | **Node + Express** | Self-hosted | Serves API **and** frontend from one process |
| Auth | **Built-in JWT** | Free | No third-party auth service (no Supabase) |
| Intel in | NVD · CISA KEV · abuse.ch* · RansomWatch · ~35 RSS | Free | The threat feed |
| Alerts out | Email · Telegram · Teams · WhatsApp | Free | Per-user notifications |
| Fonts | Google Fonts CDN | Free | Typography |

\* abuse.ch needs a free API key (`ABUSE_CH_API_KEY`).
