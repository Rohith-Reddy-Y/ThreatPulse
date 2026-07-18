# 🚀 ThreatPulse — Free Deployment Guide

This deploys ThreatPulse as a **single always-on service with a persistent volume**, 100% on
free tiers, with **no code/DB rewrite**. The app keeps using SQLite; the database lives on a
mounted volume at `/data` (the code already auto-detects it).

---

## Why this instead of the 5-service split?

Your original plan (Cloudflare Pages + Koyeb + Neon + R2 + Supabase) is powerful, but it forces:
- rewriting the whole data layer from **SQLite → Postgres** (sync → async — touches every query), and
- replacing the working **custom JWT auth → Supabase Auth**.

That's a large, risky migration for an app that currently has **no file uploads** and a **solid built-in auth**.

**Leaner stack (recommended):**

| Concern | This setup |
|---|---|
| Frontend + API | One Node service (Express already serves the SPA) |
| Database | SQLite on a **persistent volume** — zero rewrite |
| Auth | Existing JWT — free, already built |
| File uploads | Not needed (no upload feature) |
| Cost | **Free** on Fly.io's allowance |

> When you truly need horizontal scale / multi-region, *then* migrate SQLite → **Neon Postgres**
> (see the bottom of this doc). Until then, one machine handles this workload comfortably.

---

## Option 1 — Fly.io (recommended, persistent volume)

Fly's free allowance runs a small always-on machine **with a persistent volume**, which is exactly
what SQLite needs.

### Prerequisites
- A free Fly.io account: https://fly.io
- Install the CLI (`flyctl`):
  - macOS/Linux: `curl -L https://fly.io/install.sh | sh`
  - Windows (PowerShell): `iwr https://fly.io/install.sh -useb | iex`
- `fly auth login`

### Steps

```bash
# 1. From the project root — create the app WITHOUT deploying yet.
#    Accept the existing fly.toml. Choose a unique app name if prompted.
fly launch --no-deploy

# 2. Create the persistent volume (matches "source" in fly.toml). 1GB is plenty to start.
fly volumes create threatpulse_data --size 1 --region iad

# 3. Set your secrets (NEVER commit these). JWT_SECRET is REQUIRED in production.
fly secrets set JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")"
fly secrets set ADMIN_EMAIL="you@company.com"
fly secrets set ALLOWED_ORIGIN="https://<your-app>.fly.dev"
fly secrets set BASE_URL="https://<your-app>.fly.dev"

# Optional data-source / notification secrets:
fly secrets set NVD_API_KEY="..."          # https://nvd.nist.gov/developers/request-an-api-key
fly secrets set ABUSE_CH_API_KEY="..."     # https://auth.abuse.ch (ThreatFox/URLhaus/MalwareBazaar)
fly secrets set SMTP_HOST="smtp.gmail.com" SMTP_PORT="587" SMTP_USER="..." SMTP_PASS="..."

# 4. Deploy.
fly deploy

# 5. Watch logs to grab the one-time admin password printed on first boot.
fly logs
```

### First login
- Open `https://<your-app>.fly.dev`
- Log in as `admin` with the one-time password from `fly logs`.
- You'll be **forced to change it** immediately.

### Important: keep it to ONE machine
SQLite has a single writer, so do **not** scale to multiple machines:
```bash
fly scale count 1
```
`fly.toml` is already set with `auto_stop_machines = false` and `min_machines_running = 1`.

---

## Option 2 — Render / Koyeb (no persistent disk on free tier)

These are great for stateless apps but their **free tiers don't offer a persistent disk**, so a
SQLite file would be wiped on redeploy. Use them **only** if you also move the DB to Neon Postgres
(see below). Otherwise prefer Fly.io.

If you still want Render/Koyeb for free:
1. Provision a free **Neon** Postgres database (https://neon.tech).
2. Migrate the data layer to Postgres (tracked as a follow-up — it's the bulk of the 5-service plan).
3. Deploy this repo's Docker image; set the same secrets as above plus `DATABASE_URL`.

---

## Local Docker test (optional)

```bash
docker build -t threatpulse .
docker run -p 3000:3000 \
  -e JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")" \
  -e NODE_ENV=production \
  -v threatpulse_data:/data \
  threatpulse
# open http://localhost:3000  (admin password is printed in the container logs)
```

---

## Required / recommended environment variables

| Variable | Required | Notes |
|---|---|---|
| `JWT_SECRET` | **Yes (prod)** | ≥32 chars. App refuses to boot without it in production. |
| `NODE_ENV` | Yes | Set to `production`. |
| `DB_PATH` | Auto | Defaults to `/data/threatpulse.db` in the container. |
| `ADMIN_EMAIL` | Recommended | Enables admin forgot-password. |
| `BASE_URL` | Recommended | Public URL, used in password-reset links. |
| `ALLOWED_ORIGIN` | Recommended | Locks CORS to your domain. |
| `NVD_API_KEY` | Optional | Faster CVE fetches. |
| `ABUSE_CH_API_KEY` | Optional | ThreatFox / URLhaus / MalwareBazaar. |
| `SMTP_*`, `TELEGRAM_*`, `TEAMS_WEBHOOK`, `WHATSAPP_*` | Optional | Notification channels (also configurable per-user in the UI). |

---

## When to graduate to Neon Postgres

Move to Neon (free serverless Postgres) when you need **multiple app instances**, **multi-region**,
or **>a few GB** of data. That migration is the one meaningful rewrite (SQLite → `pg`), and it
unlocks Render/Koyeb/Cloudflare hosting. Everything else in this repo stays the same.
