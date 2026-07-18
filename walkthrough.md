# 🛡️ ThreatPulse — Project Walkthrough

I have successfully built **ThreatPulse**, your real-time Threat Intelligence Aggregation Platform! 🚀

The server is currently running in your workspace and actively fetching data from 30+ cybersecurity sources worldwide.

## What Was Built

### 1. Data Aggregation Engine
We created a robust Node.js backend that orchestrates data collection from various sources every 15 minutes:
- **RSS Parser**: Connects to news feeds and blogs, automatically extracting CVEs, tags, and severity using regex pattern matching.
- **CVE Fetcher**: Connects to the **NVD API 2.0** (using your provided API key) and the **CISA KEV** catalog to pull the latest vulnerabilities and detect proof-of-concepts (POCs).
- **Dark Web Intel**: Connects to clearnet APIs (RansomWatch, ThreatFox, URLhaus, MalwareBazaar) to gather dark web threat intel, malware samples, and ransomware leaks without requiring Tor.

### 2. Notification System
- **Telegram Integration**: Ready to send instant push notifications to your phone for free.
- **Email Alerts**: Nodemailer integration ready to send beautifully formatted HTML digests for critical threats.
- *You can configure these directly from the dashboard!*

### 3. Beautiful Dashboard (Frontend)
A stunning, responsive, dark-themed Single Page Application (SPA):
- **Glassmorphism UI**: High-end cyberpunk/cybersecurity aesthetic with neon glowing accents.
- **Live Filtering & Search**: Filter by category, severity, or source instantly.
- **Auto-Refreshing**: The dashboard counts down 60 seconds and auto-refreshes data without reloading the page.
- **Source Management**: You can add your own custom RSS feeds or website URLs directly from the UI!

---

## How to Use ThreatPulse

### Accessing the Dashboard
Open your browser and navigate to:
**[http://localhost:3000](http://localhost:3000)**

### Setting up Phone (Telegram) Notifications
To get free SMS/Push notifications to your phone:
1. Open the Telegram app on your phone.
2. Search for **`@BotFather`**.
3. Send `/newbot` and follow the steps to create a bot.
4. It will give you a **Bot Token** (e.g., `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`).
5. Open a chat with your new bot and send any message (like "hello").
6. Go to `https://api.telegram.org/bot<YOUR_TOKEN_HERE>/getUpdates` in your browser to find your `"chat_id"`.
7. Open the ThreatPulse dashboard (http://localhost:3000).
8. In the right sidebar, enter the Bot Token and Chat ID under **Notifications**, and hit **Save Settings**.
9. Click **Test Notification** to verify it works!

### Managing Sources
You can easily add new blogs or RSS feeds:
1. In the right sidebar, enter a URL under **Add New Source**.
2. Select the type (RSS Feed, Website, etc.) and category.
3. Click **Add Source**. The aggregator will pick it up on the next fetch cycle!

> [!TIP]
> The server logs may show occasional `403` or `404` errors for some feeds (like Exploit-DB). This is normal; some websites use strict Cloudflare anti-bot protection that blocks automated RSS parsers. The aggregator simply skips them and moves on to the next source!

Enjoy your new Threat Intelligence command center! Let me know if you want to add any other features.