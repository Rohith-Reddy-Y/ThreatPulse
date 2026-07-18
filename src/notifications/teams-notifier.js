/**
 * ThreatPulse — Microsoft Teams Notification System
 * Sends alerts to a Teams channel via an Incoming Webhook (free, no approval needed).
 *
 * Setup:
 * 1. In Teams, open the target channel → ••• → Connectors (or Workflows) → Incoming Webhook.
 * 2. Name it "ThreatPulse", create, and copy the webhook URL.
 * 3. Paste the URL into the dashboard Notifications settings.
 */

const axios = require('axios');

const severityColor = {
  critical: 'FF3B30',
  high: 'FF9500',
  medium: 'FFCC00',
  low: '34C759'
};

function buildCard(articles) {
  const critical = articles.filter(a => a.severity === 'critical').length;
  const summary = critical > 0
    ? `${critical} critical + ${articles.length - critical} new threat(s)`
    : `${articles.length} new threat(s)`;

  // Sort most severe first, cap the card size
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const top = [...articles].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0)).slice(0, 10);

  const sections = top.map(a => {
    const facts = [];
    if (a.cve_id) facts.push({ name: 'CVE', value: a.cve_id });
    if (a.mitre_ids) facts.push({ name: 'MITRE', value: a.mitre_ids });
    if (a.sector) facts.push({ name: 'Sector', value: a.sector });
    if (a.threat_actors) facts.push({ name: 'Threat Actor', value: a.threat_actors });
    facts.push({ name: 'PoC', value: a.has_poc ? 'Yes ⚡' : 'No' });
    facts.push({ name: 'Patched', value: a.is_patched === 1 ? 'Yes' : a.is_patched === 0 ? 'No' : 'Unknown' });
    facts.push({ name: 'Severity', value: (a.severity || 'medium').toUpperCase() });
    if (a.source_name) facts.push({ name: 'Source', value: a.source_name });

    return {
      activityTitle: `**${a.title || 'Untitled'}**`,
      activitySubtitle: a.description ? String(a.description).substring(0, 200) : '',
      facts,
      markdown: true
    };
  });

  return {
    '@type': 'MessageCard',
    '@context': 'http://schema.org/extensions',
    themeColor: severityColor[top[0]?.severity] || '2DA8BD',
    summary: `ThreatPulse: ${summary}`,
    title: `🛡️ ThreatPulse Alert — ${summary}`,
    sections,
    potentialAction: top[0] ? [{
      '@type': 'OpenUri',
      name: 'Open first threat',
      targets: [{ os: 'default', uri: top[0].url }]
    }] : []
  };
}

async function sendTeamsAlert(articles, webhookUrl) {
  const url = webhookUrl || process.env.TEAMS_WEBHOOK;
  if (!url) return { success: false, error: 'Teams webhook not configured' };
  if (!articles || articles.length === 0) return { success: false, error: 'No articles to send' };

  try {
    await axios.post(url, buildCard(articles), {
      timeout: 10000,
      headers: { 'Content-Type': 'application/json' }
    });
    console.log(`[Teams] Sent alert with ${articles.length} threat(s)`);
    return { success: true, sent: articles.length };
  } catch (error) {
    const msg = error.response?.data || error.message;
    console.error(`[Teams] Send failed: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`);
    return { success: false, error: typeof msg === 'string' ? msg : 'Teams send failed' };
  }
}

module.exports = { sendTeamsAlert };
