/**
 * ThreatPulse — Email Notification System
 * Sends formatted HTML email alerts for new threats
 */

const mailer = require('./mailer');
const templates = require('./account-emails');

/**
 * Kept for older callers: truthy when the server can send email (Brevo API or
 * SMTP). Per-user SMTP overrides were never exposed in the UI and are ignored.
 */
function initTransporter() {
  return mailer.isConfigured() ? { provider: mailer.provider() } : null;
}

// Feed-supplied text (titles, descriptions, URLs, authors) is untrusted: escape
// it before putting it into the email HTML.
function esc(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Build a beautiful HTML email for threat alerts
 */
function buildEmailHTML(articles) {
  const severityColors = {
    critical: '#ff3366',
    high: '#ff9500',
    medium: '#ffcc00',
    low: '#00ff88'
  };

  const categoryEmojis = {
    vulnerability: '🔴',
    malware: '☠️',
    breach: '💥',
    advisory: '📋',
    threat_intel: '🎯',
    darkweb: '🌑',
    news: '📰',
    community: '👥'
  };

  const articleRows = articles.map(a => `
    <tr style="border-bottom: 1px solid #1a2332;">
      <td style="padding: 16px; vertical-align: top;">
        <div style="display: flex; gap: 8px; margin-bottom: 8px;">
          <span style="background: ${severityColors[a.severity] || '#666'}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;">${esc(a.severity || 'MEDIUM')}</span>
          <span style="background: #1a2332; color: #8899aa; padding: 2px 8px; border-radius: 4px; font-size: 11px;">${categoryEmojis[a.category] || '📰'} ${esc((a.category || 'news').replace('_', ' '))}</span>
          ${a.has_poc ? '<span style="background: #ff3366; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">⚡ POC</span>' : ''}
          ${a.is_patched === 1 ? '<span style="background: #00ff88; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 11px;">✅ Patched</span>' : ''}
          ${a.is_patched === 0 ? '<span style="background: #ff3366; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">❌ Unpatched</span>' : ''}
        </div>
        <a href="${esc(a.url)}" style="color: #00f0ff; font-size: 16px; font-weight: 600; text-decoration: none;">${esc(a.title)}</a>
        ${a.cve_id ? `<div style="color: #ff9500; font-family: 'JetBrains Mono', monospace; font-size: 13px; margin-top: 4px;">${esc(a.cve_id)}</div>` : ''}
        <p style="color: #8899aa; font-size: 13px; margin: 8px 0; line-height: 1.5;">${esc((a.description || '').substring(0, 200))}${(a.description || '').length > 200 ? '...' : ''}</p>
        <div style="color: #556677; font-size: 12px;">
          ${a.source_name ? `📡 ${esc(a.source_name)}` : ''} ${a.author ? `• ✍️ ${esc(a.author)}` : ''} • 🕐 ${new Date(a.published_date).toLocaleString()}
        </div>
      </td>
    </tr>
  `).join('');

  return `
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin: 0; padding: 0; background: #0a0e17; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;">
      <div style="max-width: 680px; margin: 0 auto; padding: 24px;">
        <div style="text-align: center; padding: 24px 0;">
          <h1 style="color: #00f0ff; font-size: 28px; margin: 0;">🛡️ ThreatPulse Alert</h1>
          <p style="color: #556677; font-size: 14px; margin-top: 8px;">${articles.length} new threat(s) detected — ${new Date().toLocaleString()}</p>
        </div>

        <table style="width: 100%; border-collapse: collapse; background: rgba(15,20,35,0.9); border-radius: 12px; overflow: hidden; border: 1px solid #1a2332;">
          ${articleRows}
        </table>

        <div style="text-align: center; padding: 24px 0;">
          <a href="${esc(appUrl())}" style="display: inline-block; background: linear-gradient(135deg, #00f0ff, #0080ff); color: #000; padding: 12px 32px; border-radius: 8px; text-decoration: none; font-weight: 600;">Open ThreatPulse Dashboard →</a>
        </div>

        <p style="text-align: center; color: #334455; font-size: 12px; margin-top: 16px;">
          ThreatPulse — Threat Intelligence Aggregator<br>
          To manage notifications, visit your dashboard settings.
        </p>
      </div>
    </body>
    </html>
  `;
}

/**
 * Send a threat alert email
 */
async function sendAlertEmail(articles, recipientEmail) {
  if (!mailer.isConfigured()) {
    return { success: false, error: 'Email not configured (no Brevo API key / SMTP not configured)' };
  }
  const recipient = recipientEmail || process.env.NOTIFICATION_EMAIL;
  if (!recipient) {
    return { success: false, error: 'No recipient email configured' };
  }
  const criticalCount = articles.filter(a => a.severity === 'critical').length;
  const subject = criticalCount > 0
    ? `🚨 ThreatPulse: ${criticalCount} CRITICAL + ${articles.length - criticalCount} new threats`
    : `🛡️ ThreatPulse: ${articles.length} new threat(s) detected`;
  return mailer.sendMail({ to: recipient, subject, html: buildEmailHTML(articles) });
}

/**
 * Send a test email
 */
async function sendTestEmail(recipientEmail, smtpConfig = null) {
  const testArticles = [{
    title: '🧪 ThreatPulse Test Notification',
    description: 'This is a test notification from ThreatPulse. If you received this email, your notification settings are working correctly!',
    url: appUrl(),
    source_name: 'ThreatPulse',
    source_type: 'system',
    author: 'ThreatPulse System',
    published_date: new Date().toISOString(),
    category: 'news',
    severity: 'medium',
    cve_id: null,
    is_patched: -1,
    has_poc: 0,
    tags: 'test'
  }];

  return sendAlertEmail(testArticles, recipientEmail, smtpConfig);
}

// ---------------------------------------------------------------------------
// Account & security emails
// ---------------------------------------------------------------------------

function appUrl() {
  return (process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/+$/, '');
}

const notConfigured = () => ({ success: false, error: 'Email not configured' });

async function sendVerificationEmail(recipientEmail, name, type, code) {
  if (!mailer.isConfigured()) return notConfigured();
  return mailer.sendMail({ to: recipientEmail, ...templates.verificationCode({ name, type, code }) });
}

async function sendPasswordResetEmail(recipientEmail, name, link, ip) {
  if (!mailer.isConfigured()) return notConfigured();
  return mailer.sendMail({ to: recipientEmail, ...templates.passwordReset({ name, link, ip }) });
}

async function sendPasswordChangedEmail(recipientEmail, name, method, ip, link) {
  if (!mailer.isConfigured() || !recipientEmail) return notConfigured();
  return mailer.sendMail({ to: recipientEmail, ...templates.passwordChanged({ name, method, ip, link }) });
}

async function sendEmailChangedEmails(name, oldEmail, newEmail, link) {
  if (!mailer.isConfigured()) return notConfigured();
  const results = [await mailer.sendMail({ to: newEmail, ...templates.emailChanged({ name, oldEmail, newEmail, toOld: false, link }) })];
  if (oldEmail && oldEmail.toLowerCase() !== String(newEmail).toLowerCase()) {
    results.push(await mailer.sendMail({ to: oldEmail, ...templates.emailChanged({ name, oldEmail, newEmail, toOld: true, link }) }));
  }
  return { success: results.every(r => r.success), results };
}

async function sendWelcomeEmail(recipientEmail, name, username, link) {
  if (!mailer.isConfigured() || !recipientEmail) return notConfigured();
  return mailer.sendMail({ to: recipientEmail, ...templates.welcome({ name, username, link }) });
}

module.exports = {
  initTransporter, isEmailConfigured: mailer.isConfigured, describeEmail: mailer.describe,
  sendAlertEmail, sendTestEmail, sendVerificationEmail,
  sendPasswordResetEmail, sendPasswordChangedEmail, sendEmailChangedEmails, sendWelcomeEmail,
};
