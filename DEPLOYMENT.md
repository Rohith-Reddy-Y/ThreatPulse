# 🚀 ThreatPulse — Lifetime-Free Deployment Guide

Goal: **$0 forever**, always-on, with persistent storage — no surprise bills.

ThreatPulse runs 24/7 (it fetches threat feeds every 15 min) and stores data in SQLite, so it
needs a host that is **always-on** *and* has **persistent disk**. That rules out the "free" tiers
that sleep or wipe storage. The stack below is genuinely free for life.

---

## TL;DR — what's free and forever

| Layer | Service | Lifetime-free? | Notes |
|---|---|---|---|
| Compute + storage | **Oracle Cloud "Always Free"** VM | ✅ Yes, forever | 4 ARM cores / 24 GB RAM / 200 GB disk. Card for ID check only. |
| (alternative) | **Google Cloud "Always Free"** e2-micro | ✅ Yes, forever | 1 GB RAM (enough) / 30 GB disk. US regions only. |
| Database | **SQLite** on the VM disk | ✅ Free | No separate DB service. |
| Auth | Built-in **JWT** | ✅ Free | No Supabase. |
| Threat feeds | NVD, CISA KEV, abuse.ch*, RSS | ✅ Free | *abuse.ch needs a free key. |
| Alerts | Email, Telegram, Teams, WhatsApp | ✅ Free | Per-user. |
| TLS/CDN (optional) | **Cloudflare** free plan | ✅ Free | Free HTTPS in front of the VM. |

> ❗ **Not free-forever:** Fly.io (removed free allowance late 2024, ~$2–3/mo), AWS (12-month trial only),
> Railway (trial credit). Render/Koyeb free tiers **sleep or have no persistent disk** → not suitable
> for a 24/7 fetcher. See the bottom for the Fly option if you ever want the easiest paid path.

---

## Option A — Oracle Cloud Always Free (recommended)

Most generous free-forever VM. One-time setup, then it runs untouched.

### 1. Create the VM
1. Sign up at https://www.oracle.com/cloud/free/ (card is for identity verification, **not charged**).
2. **Compute → Instances → Create Instance.**
   - Image: **Ubuntu 22.04**
   - Shape: **VM.Standard.A1.Flex** (Ampere/ARM) — set 1 OCPU / 6 GB RAM (well within Always Free).
     *(If ARM capacity is unavailable in your region, use `VM.Standard.E2.1.Micro` — also Always Free.)*
   - Add your SSH public key.
3. **Networking → open port 80** (and 443 if using HTTPS):
   - VCN → Security List → **Add Ingress Rule**: Source `0.0.0.0/0`, TCP, dest port **80** (and **443**).

### 2. Install Docker on the VM
```bash
ssh ubuntu@<VM_PUBLIC_IP>
sudo apt-get update && sudo apt-get install -y git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
# open the OS firewall too (Oracle images ship with iptables closed):
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo netfilter-persistent save
```

### 3. Deploy ThreatPulse
```bash
git clone https://github.com/Rohith-Reddy-Y/ThreatPulse.git
cd ThreatPulse

# create your secrets file
cp .env.example .env
nano .env    # set NODE_ENV=production and a strong JWT_SECRET (see below), plus optional keys

# generate a strong JWT secret:
docker run --rm node:20-slim node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
#  ...paste the output as JWT_SECRET in .env

docker compose up -d --build
docker compose logs -f          # grab the one-time admin password printed on first boot
```

Open **http://\<VM_PUBLIC_IP\>/**, log in as `admin` with that password, and you'll be forced to change it.

---

## Option B — Google Cloud Always Free (e2-micro)

1. https://cloud.google.com/free → create a project.
2. **Compute Engine → Create Instance**: machine **e2-micro**, region **us-west1 / us-central1 / us-east1**
   (Always Free only in those), boot disk **Ubuntu 22.04, 30 GB standard**.
3. Firewall: check **Allow HTTP traffic** (and HTTPS).
4. SSH in (browser SSH works), then run the **same Docker + deploy steps** as Option A, step 2–3.

e2-micro has 1 GB RAM — plenty for this app.

---

## Optional: free HTTPS + custom domain (Cloudflare)

The VM serves plain HTTP on port 80. To add free TLS:
1. Point a domain (even a cheap one) at Cloudflare (free plan).
2. Create an **A record** → your VM's public IP, **proxied** (orange cloud).
3. Cloudflare terminates HTTPS for free. Set `ALLOWED_ORIGIN` and `BASE_URL` in `.env` to your domain.

(No domain? You can still use the raw `http://<IP>/` — fine for internal/team use.)

---

## Updating after you push new code
```bash
cd ThreatPulse
git pull
docker compose up -d --build     # rebuilds & restarts; data volume is untouched
```

## Required / recommended environment variables (.env)

| Variable | Required | Notes |
|---|---|---|
| `JWT_SECRET` | **Yes (prod)** | ≥32 chars. App refuses to boot without it in production. |
| `NODE_ENV` | Yes | `production` |
| `DB_PATH` | Auto | `/data/threatpulse.db` (set by compose) |
| `ADMIN_EMAIL` | Recommended | Enables admin forgot-password |
| `BASE_URL`, `ALLOWED_ORIGIN` | Recommended | Your public URL / domain |
| `NVD_API_KEY` | Optional | Faster CVE fetches |
| `ABUSE_CH_API_KEY` | Optional | Turns on ThreatFox / URLhaus / MalwareBazaar (free key at auth.abuse.ch) |
| `SMTP_*`, `TELEGRAM_*`, `TEAMS_WEBHOOK`, `WHATSAPP_*` | Optional | Alert channels (also per-user in the UI) |

---

## Option C — Fly.io (easiest, but ~$2–3/month, NOT free-forever)

If you ever prefer a managed platform over a VM and don't mind a few dollars/month, the repo also
ships `fly.toml` + `Dockerfile`:
```bash
fly launch --no-deploy
fly volumes create threatpulse_data --size 1 --region iad
fly secrets set JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")"
fly deploy
```
Keep it to **one machine** (`fly scale count 1`) — SQLite is a single writer.

---

## When to graduate to managed Postgres
Move SQLite → **Neon Postgres** (free tier, forever) only when you need **multiple app instances**
or **multi-region**. That's the one meaningful rewrite; everything else stays the same, and it
unlocks sleep-friendly hosts (Render/Koyeb/Cloudflare) since state no longer lives on local disk.
