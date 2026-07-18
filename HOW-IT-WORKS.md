# 🧭 ThreatPulse — How It All Works (Plain-English Guide)

A no-jargon walkthrough of what we built, every service we use, why we use it, and how the pieces
fit together. Read top to bottom — there's a glossary at the end for any word that's new.

---

## 1. What ThreatPulse is

A **threat-intelligence dashboard**. It automatically pulls cybersecurity news, vulnerabilities (CVEs),
malware indicators, and dark-web/ransomware intel from ~40 free sources every 15 minutes, tags each
item (severity, PoC available, MITRE ATT&CK technique, sector, threat actor, patched/unpatched), and
shows it in a searchable dashboard. Team members log in, filter, review items, and get alerts on the
channels they choose (Email / Telegram / Teams / WhatsApp).

---

## 2. The 30-second big picture

Think of it like a **restaurant**:

```
   The internet's threat feeds          Your cloud kitchen (GCP VM)             Your team
   (free ingredients)                   running in Docker                       (customers)
 ┌──────────────────────┐        ┌──────────────────────────────────┐     ┌────────────────┐
 │ NVD, CISA, abuse.ch, │        │  📦 caddy   → the front door /    │     │  Browser        │
 │ RSS blogs, ...       │ ─────► │             HTTPS security guard  │◄───►│  (HTTPS/padlock)│
 │                      │        │  📦 threatpulse → the kitchen     │     │                 │
 └──────────────────────┘        │             (Node app + SQLite)   │     └────────────────┘
                                 │  💾 volumes → the pantry (saved    │
                                 │             data + certificate)   │
                                 └──────────────────────────────────┘
```

- **Ingredients** = free threat-intel APIs/feeds on the internet.
- **Kitchen** = a small always-on computer in Google Cloud, running your app inside Docker.
- **Front door** = Caddy, which puts the app behind HTTPS (the padlock).
- **Pantry** = Docker volumes, where your database and security certificate are stored so nothing is
  lost when you restart.
- **Customers** = your team, using the site in a browser.

---

## 3. Every service & tool we use (what + why + cost)

### A) Your application (the code)
| Tool | What it is (plain) | Why we use it | Cost |
|---|---|---|---|
| **Node.js + Express** | The engine that runs your backend and serves the website | Lightweight, fast, one language (JavaScript) for everything | Free (open source) |
| **Vanilla JS + HTML/CSS** | The dashboard you see in the browser | No heavy framework = simple, fast, nothing extra to host | Free |
| **JWT auth (built-in)** | The login system (tokens prove who you are) | Secure logins with **no third-party auth service** needed | Free |

### B) Storage (the database)
| Tool | What it is | Why | Cost |
|---|---|---|---|
| **SQLite** | A database that's just a single file on disk | Zero setup, zero separate server, perfect for team scale | Free |
| **Docker volume** (`threatpulse_data`) | A protected folder Docker keeps outside the container | Keeps your data safe when containers restart/update | Free (uses the VM's disk) |

> Your whole database is one file: `threatpulse.db`. Even years of articles = only a few MB.

### C) Hosting (where it runs 24/7)
| Tool | What it is | Why | Cost |
|---|---|---|---|
| **Google Cloud (GCP) e2-micro VM** | A small always-on computer in Google's data center | It's **Always Free** forever, and stays on so the 15-min fetcher keeps working | **$0** (Always Free tier) |
| **Ubuntu 22.04** | The operating system on that computer | Standard, stable Linux for servers | Free |
| **Docker + Docker Compose** | Runs your app in sealed "containers" | One command to run everything; identical everywhere; easy updates | Free |

### D) HTTPS + domain name (the padlock)
| Tool | What it is | Why | Cost |
|---|---|---|---|
| **DuckDNS** | A free domain name (e.g. `tid-threatpulse.duckdns.org`) | You can't get HTTPS on a bare IP — you need a name | Free |
| **Caddy** | A "reverse proxy" that sits in front of the app | Automatically gets & renews the HTTPS certificate, forwards traffic to the app | Free |
| **Let's Encrypt** | A free certificate authority | Issues the actual HTTPS certificate that gives you the padlock | Free |

### E) Threat-intel data sources (the "ingredients")
| Source | What it gives | Key needed? | Cost |
|---|---|---|---|
| **NVD (NIST)** | Official CVE vulnerability data | Optional free key (faster) | Free |
| **CISA KEV** | Vulnerabilities actively being exploited right now | No | Free |
| **abuse.ch** (ThreatFox, URLhaus, MalwareBazaar) | Malware indicators, malicious URLs, malware samples | Free key (`ABUSE_CH_API_KEY`) | Free |
| **RansomWatch** | Ransomware leak-site tracking | No | Free |
| **~35 RSS feeds** | Blogs & CERT advisories (The Hacker News, BleepingComputer, DFIR Report, Red Canary, Elastic, etc.) | No | Free |

### F) Alert channels (how the team gets notified)
| Channel | How it works | Cost |
|---|---|---|
| **Email** | Standard SMTP (e.g. a Gmail app password) | Free |
| **Telegram** | A bot you create with @BotFather | Free |
| **Microsoft Teams** | An "incoming webhook" URL for a channel | Free |
| **WhatsApp** | Via CallMeBot (a free personal WhatsApp bridge) | Free |

### G) Development & version control
| Tool | What it is | Why | Cost |
|---|---|---|---|
| **Git** | Tracks every change to the code | History, safety, collaboration | Free |
| **GitHub** | Cloud home for the code (your repo) | Backup + the VM pulls the code from here | Free |

---

## 4. How your data flows (start to finish)

1. **Every 15 minutes**, the app's built-in scheduler wakes up.
2. It fetches from all your enabled sources (NVD, abuse.ch, RSS, etc.) over the internet.
3. It **tags** each new item — severity, PoC?, MITRE technique, sector, threat actor, patched?.
4. It **de-duplicates** (a hash of each URL) so you never see the same item twice, and saves new
   items into **SQLite**.
5. If any new item matches a user's filters, it **sends that user an alert** on their chosen channel.
6. When a team member opens the site, **Caddy** serves it over **HTTPS**, and the **Node app** returns
   only *that user's* data (everyone is isolated; admins see everything).

---

## 5. What we actually did, step by step (the journey)

1. **Fixed & hardened the app** — security (stable login secret, forced admin password change,
   stronger input checks), fixed bugs, and made each user's data private.
2. **Added detection-engineering features** — MITRE IDs, PoC/patch badges, "new TTP" highlighting,
   and filters for PoC / MITRE / sector / threat actor.
3. **Added notifications** — Email, Telegram, Teams, and WhatsApp, per user.
4. **Fixed the data sources** — repaired broken feeds, removed dead ones, added detection-focused
   blogs, and wired up abuse.ch with its new API key.
5. **Refreshed the UI** — cleaner steel-blue/teal theme with a light/dark toggle.
6. **Put the code on GitHub** — `https://github.com/Rohith-Reddy-Y/ThreatPulse`.
7. **Containerized it** — wrote a `Dockerfile` + `docker-compose.yml` so it runs anywhere with one command.
8. **Created a free cloud server** — a GCP Always-Free VM.
9. **Deployed with Docker** — installed Docker on the VM, pulled the code, ran `docker compose up`.
10. **Adding HTTPS** — a free DuckDNS domain + Caddy + Let's Encrypt for the padlock *(the step we're
    finishing now)*.

---

## 6. Operating it day-to-day (cheat sheet — run these on the VM)

```bash
cd ~/ThreatPulse

# see what's running
sudo docker compose ps

# view logs
sudo docker compose logs threatpulse | tail -50
sudo docker compose logs caddy | tail -50

# restart everything
sudo docker compose restart

# apply new settings from .env  (needed after editing .env)
sudo docker compose up -d --force-recreate

# update to the latest code you pushed to GitHub
git pull && sudo docker compose up -d --build

# stop everything (data is kept)
sudo docker compose down
```

Your one-time admin password is printed on first boot:
```bash
sudo docker compose logs threatpulse | grep "Password:"
```

---

## 7. What it costs

**$0 / month**, for life, as long as you stay within the free limits:
- GCP e2-micro in a US free region (us-central1/us-west1/us-east1), 1 instance, 30 GB standard disk.
- All APIs and feeds are free tiers.
- DuckDNS, Caddy, Let's Encrypt, Docker, SQLite — all free.

Set a **₹100 (~$1) budget alert** in GCP Billing as a safety net; in practice the bill stays ₹0.

---

## 8. Glossary (words that might be new)

- **VM (Virtual Machine)** — a computer you rent in the cloud. Yours lives in Google's data center.
- **Docker** — software that packs your app + everything it needs into a sealed box ("container") that
  runs the same anywhere.
- **Container** — one running instance of that sealed box. You have two: `threatpulse` and `caddy`.
- **Image** — the blueprint a container is built from (your `Dockerfile` builds the app image).
- **Volume** — a folder Docker keeps *outside* the container so data survives restarts (your DB, your cert).
- **docker-compose** — a file + command that runs multiple containers together with one command.
- **Reverse proxy** — a "front desk" (Caddy) that receives all web traffic and forwards it to your app,
  handling HTTPS along the way.
- **DNS** — the internet's phonebook: turns a name (`tid-threatpulse.duckdns.org`) into an IP (`34.30.175.229`).
- **Let's Encrypt / ACME** — the free service + process that issues your HTTPS certificate.
- **HTTPS / TLS certificate** — what gives you the padlock and encrypts traffic. Needs a domain name.
- **SSH** — a secure terminal into your VM (the black window in GCP's "SSH" button).
- **Cron / scheduler** — the built-in timer that fetches feeds every 15 minutes.
- **SQLite** — a database that's just one file; no separate database server to run.
- **JWT** — a signed token your browser holds after login to prove who you are.
- **Environment variables / `.env`** — settings & secrets (like `JWT_SECRET`, `DOMAIN`) the app reads at startup.
- **CVE** — a public ID for a specific vulnerability. **PoC** — proof-of-concept exploit code.
  **MITRE ATT&CK** — a standard catalog of attacker techniques (e.g. `T1059`). **KEV** — CISA's list
  of vulnerabilities being actively exploited.
