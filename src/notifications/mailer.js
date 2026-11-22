/**
 * ThreatPulse — outgoing mail transport.
 *
 * Every email the platform sends (threat alerts, password resets, verification
 * codes, security notices) goes through sendMail() here.
 *
 * Providers, first configured wins:
 *   1. Brevo HTTPS API  — BREVO_API_KEY + MAIL_FROM (a sender address verified in
 *      Brevo). Free plan: 300 emails/day. Works on Render's free tier, which blocks
 *      outbound SMTP ports 25/465/587.
 *   2. SMTP (nodemailer) — SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS. For hosts
 *      that allow SMTP (paid Render instances, a VM, local development).
 *
 * MAIL_FROM_NAME sets the display name (default "ThreatPulse").
 */

const axios = require('axios');
const nodemailer = require('nodemailer');

const BREVO_URL = 'https://api.brevo.com/v3/smtp/email';
const SEND_TIMEOUT_MS = 15000;
const EMAIL_RE = /^[^\s@,;<>"()\\]+@[^\s@,;<>"()\\]+\.[^\s@,;<>"()\\]+$/;

let smtpTransport = null;
let smtpKey = null;
let warnedNoProvider = false;

function env(name) {
  const v = process.env[name];
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

function fromName() {
  // Header-safe: no quotes, angle brackets or line breaks
  return (env('MAIL_FROM_NAME') || 'ThreatPulse').replace(/["<>\r\n]/g, '').slice(0, 60) || 'ThreatPulse';
}

/** Which provider is active: 'brevo' | 'smtp' | null. */
function provider() {
  if (env('BREVO_API_KEY') && env('MAIL_FROM') && EMAIL_RE.test(env('MAIL_FROM'))) return 'brevo';
  if (env('SMTP_HOST') && env('SMTP_USER') && env('SMTP_PASS')) return 'smtp';
  return null;
}

function isConfigured() {
  return provider() !== null;
}

/** Non-secret description for logs and the admin panel. */
function describe() {
  const p = provider();
  if (p === 'brevo') return { provider: 'brevo', from: env('MAIL_FROM') };
  if (p === 'smtp') return { provider: 'smtp', from: env('MAIL_FROM') || env('SMTP_USER'), host: env('SMTP_HOST') };
  const missing = env('BREVO_API_KEY') && !env('MAIL_FROM') ? 'MAIL_FROM is not set (the Brevo-verified sender address)' : null;
  return { provider: null, problem: missing };
}

function getSmtpTransport() {
  const host = env('SMTP_HOST');
  const port = parseInt(env('SMTP_PORT') || '587', 10);
  const user = env('SMTP_USER');
  const pass = env('SMTP_PASS');
  const key = `${host}|${port}|${user}|${pass}`;
  if (smtpTransport && smtpKey === key) return smtpTransport;
  smtpTransport = nodemailer.createTransport({
    host, port, secure: port === 465, auth: { user, pass },
    connectionTimeout: SEND_TIMEOUT_MS, greetingTimeout: SEND_TIMEOUT_MS, socketTimeout: SEND_TIMEOUT_MS,
  });
  smtpKey = key;
  console.log(`[Email] SMTP transport ready (${host}:${port})`);
  return smtpTransport;
}

function brevoError(err) {
  const r = err && err.response;
  if (r) {
    const d = r.data && typeof r.data === 'object' ? r.data : {};
    const msg = String(d.message || d.code || '').slice(0, 200);
    if (r.status === 401) return `Brevo rejected the API key (401)${msg ? `: ${msg}` : ''}. If the message mentions an unrecognised IP, turn off "Authorised IPs" blocking in Brevo → Security.`;
    if (r.status === 400 && /sender/i.test(msg)) return `Brevo refused the sender: ${msg}. MAIL_FROM must be a sender verified in Brevo → Senders.`;
    return `Brevo error ${r.status}${msg ? `: ${msg}` : ''}`;
  }
  return String((err && err.message) || err || 'send failed').slice(0, 200);
}

/**
 * Send one email. Never throws.
 * @param {{to: string, subject: string, html: string, text?: string}} msg
 * @returns {Promise<{success: boolean, messageId?: string, provider?: string, error?: string}>}
 */
async function sendMail({ to, subject, html, text }) {
  const p = provider();
  if (!p) {
    if (!warnedNoProvider) {
      console.log('[Email] Not configured — set BREVO_API_KEY + MAIL_FROM (or SMTP_*) to send email');
      warnedNoProvider = true;
    }
    return { success: false, error: 'Email not configured (no Brevo API key / SMTP not configured)' };
  }
  if (typeof to !== 'string' || !EMAIL_RE.test(to.trim())) {
    return { success: false, error: 'Invalid recipient address' };
  }
  to = to.trim();
  const safeSubject = String(subject || '').replace(/[\r\n]+/g, ' ').slice(0, 200);

  try {
    if (p === 'brevo') {
      const res = await axios.post(BREVO_URL, {
        sender: { name: fromName(), email: env('MAIL_FROM') },
        to: [{ email: to }],
        subject: safeSubject,
        htmlContent: html,
        ...(text ? { textContent: text } : {}),
      }, {
        headers: { 'api-key': env('BREVO_API_KEY'), 'content-type': 'application/json', accept: 'application/json' },
        timeout: SEND_TIMEOUT_MS,
        maxContentLength: 64 * 1024,
        maxRedirects: 0,
      });
      const messageId = res && res.data && res.data.messageId;
      console.log(`[Email] Sent via Brevo to ${to}${messageId ? ` (${messageId})` : ''}`);
      return { success: true, provider: 'brevo', messageId };
    }

    const from = `"${fromName()}" <${env('MAIL_FROM') || env('SMTP_USER')}>`;
    const info = await getSmtpTransport().sendMail({ from, to, subject: safeSubject, html, ...(text ? { text } : {}) });
    console.log(`[Email] Sent via SMTP to ${to}${info && info.messageId ? ` (${info.messageId})` : ''}`);
    return { success: true, provider: 'smtp', messageId: info && info.messageId };
  } catch (err) {
    const error = p === 'brevo' ? brevoError(err) : String(err && err.message || err).slice(0, 200);
    console.error(`[Email] Send to ${to} failed: ${error}`);
    return { success: false, provider: p, error };
  }
}

/** Startup log line. */
function logStatus() {
  const d = describe();
  if (d.provider) console.log(`[Email] Delivery enabled via ${d.provider} (from ${d.from})`);
  else console.log(`[Email] Delivery disabled${d.problem ? ` — ${d.problem}` : ' — set BREVO_API_KEY + MAIL_FROM'}`);
}

module.exports = { sendMail, isConfigured, provider, describe, logStatus };
