/**
 * ThreatPulse — Email Notification System
 * Sends formatted HTML email alerts for new threats
 */

const nodemailer = require('nodemailer');

let transporter = null;

/**
 * Initialize the email transporter
 */
function initTransporter(smtpConfig) {
  const host = smtpConfig?.smtp_host || process.env.SMTP_HOST;
  const port = parseInt(smtpConfig?.smtp_port || process.env.SMTP_PORT || '587');
  const user = smtpConfig?.smtp_user || process.env.SMTP_USER;
  const pass = smtpConfig?.smtp_pass || process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    console.log('[Email] SMTP not configured — email notifications disabled');
    return null;
  }

  transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });

  console.log(`[Email] Transporter initialized (${host}:${port})`);
  return { transporter, user };
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
          <span style="background: ${severityColors[a.severity] || '#666'}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;">${a.severity || 'MEDIUM'}</span>
          <span style="background: #1a2332; color: #8899aa; padding: 2px 8px; border-radius: 4px; font-size: 11px;">${categoryEmojis[a.category] || '📰'} ${(a.category || 'news').replace('_', ' ')}</span>
          ${a.has_poc ? '<span style="background: #ff3366; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">⚡ POC</span>' : ''}
          ${a.is_patched === 1 ? '<span style="background: #00ff88; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 11px;">✅ Patched</span>' : ''}
          ${a.is_patched === 0 ? '<span style="background: #ff3366; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;">❌ Unpatched</span>' : ''}
        </div>
        <a href="${a.url}" style="color: #00f0ff; font-size: 16px; font-weight: 600; text-decoration: none;">${a.title}</a>
        ${a.cve_id ? `<div style="color: #ff9500; font-family: 'JetBrains Mono', monospace; font-size: 13px; margin-top: 4px;">${a.cve_id}</div>` : ''}
        <p style="color: #8899aa; font-size: 13px; margin: 8px 0; line-height: 1.5;">${(a.description || '').substring(0, 200)}${(a.description || '').length > 200 ? '...' : ''}</p>
        <div style="color: #556677; font-size: 12px;">
          ${a.source_name ? `📡 ${a.source_name}` : ''} ${a.author ? `• ✍️ ${a.author}` : ''} • 🕐 ${new Date(a.published_date).toLocaleString()}
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
          <a href="http://localhost:${process.env.PORT || 3000}" style="display: inline-block; background: linear-gradient(135deg, #00f0ff, #0080ff); color: #000; padding: 12px 32px; border-radius: 8px; text-decoration: none; font-weight: 600;">Open ThreatPulse Dashboard →</a>
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
async function sendAlertEmail(articles, recipientEmail, smtpConfig = null) {
  const t = initTransporter(smtpConfig);
  if (!t) {
    return { success: false, error: 'SMTP not configured' };
  }

  const recipient = recipientEmail || process.env.NOTIFICATION_EMAIL;
  if (!recipient) {
    return { success: false, error: 'No recipient email configured' };
  }

  try {
    const criticalCount = articles.filter(a => a.severity === 'critical').length;
    const subject = criticalCount > 0
      ? `🚨 ThreatPulse: ${criticalCount} CRITICAL + ${articles.length - criticalCount} new threats`
      : `🛡️ ThreatPulse: ${articles.length} new threat(s) detected`;

    const info = await t.transporter.sendMail({
      from: `"ThreatPulse 🛡️" <${t.user}>`,
      to: recipient,
      subject,
      html: buildEmailHTML(articles)
    });

    console.log(`[Email] Alert sent to ${recipient}: ${info.messageId}`);
    return { success: true, messageId: info.messageId };

  } catch (error) {
    console.error(`[Email] Send failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

/**
 * Send a test email
 */
async function sendTestEmail(recipientEmail, smtpConfig = null) {
  const testArticles = [{
    title: '🧪 ThreatPulse Test Notification',
    description: 'This is a test notification from ThreatPulse. If you received this email, your notification settings are working correctly!',
    url: `http://localhost:${process.env.PORT || 3000}`,
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

async function sendVerificationEmail(recipientEmail, username, type, code, smtpConfig = null) {
  const t = initTransporter(smtpConfig);
  if (!t) {
    console.log(`[Email Mock] SMTP not configured. Verification code for ${username} is: ${code}`);
    return { success: true, mock: true, code };
  }

  const subject = type === 'email_change' 
    ? '✉️ Verify your new ThreatPulse email address' 
    : '🔑 Verify your ThreatPulse password change';

  const html = `
    <!DOCTYPE html>
    <html>
    <head><meta charset="utf-8"></head>
    <body style="margin: 0; padding: 0; background: #0a0e17; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; color: #eaedf7;">
      <div style="max-width: 500px; margin: 0 auto; padding: 24px;">
        <div style="text-align: center; padding: 24px 0;">
          <h1 style="color: #00f0ff; font-size: 24px; margin: 0;">🛡️ ThreatPulse Verification</h1>
        </div>
        <div style="background: rgba(15,20,35,0.9); border-radius: 12px; padding: 24px; border: 1px solid #1a2332; text-align: center;">
          <p style="font-size: 15px; color: #8899aa; margin-bottom: 20px;">
            Hi ${username},<br>
            Please use the verification code below to complete your ${type === 'email_change' ? 'email' : 'password'} change.
          </p>
          <div style="background: #111424; border: 1px solid #7c5cff; border-radius: 8px; padding: 16px; font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #22d3ee; margin: 20px auto; max-width: 200px;">
            ${code}
          </div>
          <p style="font-size: 12px; color: #556677; margin-top: 20px;">
            This code will expire in 15 minutes. If you did not request this change, please ignore this email.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;

  try {
    const info = await t.transporter.sendMail({
      from: `"ThreatPulse 🛡️" <${t.user}>`,
      to: recipientEmail,
      subject,
      html
    });
    console.log(`[Email] Verification email sent to ${recipientEmail}: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error(`[Email] Verification send failed: ${error.message}`);
    return { success: false, error: error.message };
  }
}

module.exports = { initTransporter, sendAlertEmail, sendTestEmail, sendVerificationEmail };
