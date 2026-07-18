/**
 * ThreatPulse — WhatsApp Notification System (via CallMeBot free API)
 *
 * WhatsApp has no free, no-approval official push API. CallMeBot provides a free
 * personal WhatsApp bridge that works well for individual/team-lead alerting.
 *
 * Setup (one-time, per recipient number):
 * 1. Add the phone number  +34 644 51 95 23  to your WhatsApp contacts (name it "CallMeBot").
 * 2. Send this WhatsApp message to it:  "I allow callmebot to send me messages"
 * 3. You'll receive an API key in reply.
 * 4. In the dashboard Notifications settings, enter your WhatsApp number (with country code,
 *    digits only) and the API key.
 *
 * Note: CallMeBot is best-effort and rate-limited. For high-volume/enterprise WhatsApp,
 * swap this module for the WhatsApp Business Cloud API (requires Meta verification + templates).
 */

const axios = require('axios');

const CALLMEBOT_URL = 'https://api.callmebot.com/whatsapp.php';

function severityEmoji(severity) {
  const map = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };
  return map[severity] || '⚪';
}

function buildMessage(articles) {
  const critical = articles.filter(a => a.severity === 'critical').length;
  const header = critical > 0
    ? `🛡️ ThreatPulse: ${critical} CRITICAL + ${articles.length - critical} new threat(s)`
    : `🛡️ ThreatPulse: ${articles.length} new threat(s)`;

  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  const top = [...articles].sort((a, b) => (order[b.severity] || 0) - (order[a.severity] || 0)).slice(0, 5);

  const lines = top.map(a => {
    const tags = [];
    if (a.has_poc) tags.push('⚡PoC');
    if (a.mitre_ids) tags.push(`🎯${a.mitre_ids.split(',')[0]}`);
    if (a.cve_id) tags.push(a.cve_id);
    if (a.is_patched === 0) tags.push('❌Unpatched');
    return `${severityEmoji(a.severity)} ${a.title}\n${tags.join(' ')}\n${a.url}`;
  });

  let msg = `${header}\n\n${lines.join('\n\n')}`;
  if (articles.length > top.length) msg += `\n\n…and ${articles.length - top.length} more.`;
  return msg;
}

async function sendWhatsAppAlert(articles, number, apiKey) {
  const phone = number || process.env.WHATSAPP_NUMBER;
  const key = apiKey || process.env.WHATSAPP_APIKEY;
  if (!phone || !key) return { success: false, error: 'WhatsApp not configured' };
  if (!articles || articles.length === 0) return { success: false, error: 'No articles to send' };

  try {
    await axios.get(CALLMEBOT_URL, {
      params: { phone: String(phone).replace(/[^\d]/g, ''), text: buildMessage(articles), apikey: key },
      timeout: 15000
    });
    console.log(`[WhatsApp] Sent alert with ${articles.length} threat(s)`);
    return { success: true, sent: articles.length };
  } catch (error) {
    const msg = error.response?.data || error.message;
    console.error(`[WhatsApp] Send failed: ${typeof msg === 'string' ? msg.slice(0, 120) : error.message}`);
    return { success: false, error: 'WhatsApp send failed (check number/API key)' };
  }
}

module.exports = { sendWhatsAppAlert };
